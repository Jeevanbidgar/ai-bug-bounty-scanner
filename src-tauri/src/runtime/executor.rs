use anyhow::{anyhow, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::time::timeout;
use uuid::Uuid;

use crate::adapters::AdapterRegistry;
use crate::runtime::process::configure_tokio_command;
use crate::tools::discovery::ToolDiscoveryService;
use crate::workflow::artifacts::ArtifactManager;
use crate::workflow::types::{WorkflowArtifact, WorkflowStep};

#[derive(Clone)]
pub struct ProcessExecutor {
    app_handle: AppHandle,
    tool_discovery: Arc<RwLock<ToolDiscoveryService>>,
    artifact_manager: Arc<ArtifactManager>,
}

impl ProcessExecutor {
    pub fn new(
        app_handle: AppHandle,
        tool_discovery: Arc<RwLock<ToolDiscoveryService>>,
        artifact_manager: Arc<ArtifactManager>,
    ) -> Self {
        Self {
            app_handle,
            tool_discovery,
            artifact_manager,
        }
    }

    /// Execute a workflow step with retry logic
    pub async fn execute_step(
        &self,
        step: &WorkflowStep,
        execution_id: &str,
        working_directory: &str,
        inputs: &HashMap<String, String>,
    ) -> Result<Vec<WorkflowArtifact>> {
        // Check if step has retry configuration
        if let Some(retry_config) = &step.retry {
            self.execute_step_with_retry(
                step,
                execution_id,
                working_directory,
                inputs,
                retry_config,
            )
            .await
        } else {
            // No retry, execute once
            self.execute_step_once(step, execution_id, working_directory, inputs)
                .await
        }
    }

    /// Execute a step with retry logic and exponential backoff
    async fn execute_step_with_retry(
        &self,
        step: &WorkflowStep,
        execution_id: &str,
        working_directory: &str,
        inputs: &HashMap<String, String>,
        retry_config: &crate::workflow::types::WorkflowRetry,
    ) -> Result<Vec<WorkflowArtifact>> {
        let mut last_error = None;
        let max_attempts = retry_config.max_attempts.max(1); // At least 1 attempt

        for attempt in 0..max_attempts {
            // Log retry attempt
            if attempt > 0 {
                let delay_ms = retry_config.calculate_delay(attempt - 1);
                eprintln!(
                    "Retrying step '{}' (attempt {}/{}) after {}ms delay...",
                    step.id,
                    attempt + 1,
                    max_attempts,
                    delay_ms
                );

                // Emit retry event
                let _ = self.app_handle.emit(
                    "workflow:step_retry",
                    serde_json::json!({
                        "execution_id": execution_id,
                        "step_id": step.id,
                        "attempt": attempt + 1,
                        "max_attempts": max_attempts,
                        "delay_ms": delay_ms,
                        "timestamp": Utc::now().to_rfc3339()
                    }),
                );

                // Wait before retrying (exponential backoff)
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }

            // Attempt execution
            match self
                .execute_step_once(step, execution_id, working_directory, inputs)
                .await
            {
                Ok(artifacts) => {
                    if attempt > 0 {
                        eprintln!(
                            "Step '{}' succeeded on attempt {}/{}",
                            step.id,
                            attempt + 1,
                            max_attempts
                        );
                    }
                    return Ok(artifacts);
                }
                Err(e) => {
                    last_error = Some(e);
                    eprintln!(
                        "Step '{}' failed on attempt {}/{}: {}",
                        step.id,
                        attempt + 1,
                        max_attempts,
                        last_error.as_ref().unwrap()
                    );

                    // If this was the last attempt, don't retry
                    if attempt + 1 >= max_attempts {
                        break;
                    }
                }
            }
        }

        // All attempts failed
        Err(last_error
            .unwrap_or_else(|| anyhow!("Step execution failed after {} attempts", max_attempts)))
    }

    /// Execute a workflow step once (no retry logic)
    async fn execute_step_once(
        &self,
        step: &WorkflowStep,
        execution_id: &str,
        working_directory: &str,
        inputs: &HashMap<String, String>,
    ) -> Result<Vec<WorkflowArtifact>> {
        let step_id = &step.id;

        // Emit step started event (only on first attempt)
        let _ = self.app_handle.emit(
            "workflow:step_started",
            serde_json::json!({
                "execution_id": execution_id,
                "step_id": step_id,
                "step_name": step.name,
                "timestamp": Utc::now().to_rfc3339()
            }),
        );

        // Build command with template variable substitution
        let empty_artifacts = HashMap::new();
        let mut command_args = Vec::new();
        for arg in &step.run {
            let resolved_arg =
                self.resolve_template_variables(arg, working_directory, inputs, &empty_artifacts);
            command_args.push(resolved_arg);
        }

        if command_args.is_empty() {
            return Err(anyhow!("Step '{}' has no command to execute", step_id));
        }

        // Try to use adapter first, fall back to original command
        let tool_name = &command_args[0];
        let final_command_args = self
            .try_build_command_with_adapter(tool_name, &command_args, inputs)
            .unwrap_or_else(|| {
                eprintln!("🔧 Using original command for tool: {}", tool_name);
                command_args.clone()
            });

        // Resolve tool path using ToolDiscoveryService
        let resolved_tool_path = {
            let discovery = self.tool_discovery.read().await;
            match discovery.get_tool_record(tool_name, false).await {
                Some(tool_record) => {
                    if tool_record.installed && tool_record.status == "available" {
                        // Use the discovered tool path
                        match tool_record.path {
                            Some(path) => path,
                            None => {
                                eprintln!("Warning: Tool '{}' marked as available but has no path, using tool name", tool_name);
                                tool_name.clone()
                            }
                        }
                    } else if !tool_record.installed {
                        // Tool exists in catalog but not installed
                        return Err(anyhow!(
                            "Tool '{}' is not installed. Status: {}. Missing dependencies: {:?}",
                            tool_name,
                            tool_record.status,
                            tool_record.missing_dependencies
                        ));
                    } else {
                        // Tool installed but not available (degraded/error state)
                        eprintln!(
                            "Warning: Tool '{}' is in '{}' state. Error: {:?}. Attempting execution anyway...",
                            tool_name,
                            tool_record.status,
                            tool_record.last_error
                        );
                        match tool_record.path {
                            Some(path) => path,
                            None => tool_name.clone(),
                        }
                    }
                }
                None => {
                    // Tool not found in catalog, try to use it directly (might be in PATH)
                    eprintln!(
                        "Warning: Tool '{}' not found in catalog, attempting direct execution",
                        tool_name
                    );
                    tool_name.clone()
                }
            }
        };

        let timeout_duration = Duration::from_secs(step.timeout.unwrap_or(300));
        let mut cmd = Command::new(&resolved_tool_path);
        cmd.args(&final_command_args[1..])
            .current_dir(working_directory)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_tokio_command(&mut cmd);

        let mut child = cmd.spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to capture stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("Failed to capture stderr"))?;

        // Stream output in real-time
        let app_handle_clone = self.app_handle.clone();
        let execution_id_clone = execution_id.to_string();
        let step_id_clone = step_id.to_string();

        tokio::spawn(async move {
            let _ = Self::stream_output(
                stdout,
                stderr,
                &app_handle_clone,
                &execution_id_clone,
                &step_id_clone,
            )
            .await;
        });

        // Wait for process completion with timeout
        let result = timeout(timeout_duration, child.wait()).await;

        let exit_code = match result {
            Ok(Ok(status)) => status.code().unwrap_or(-1),
            Ok(Err(e)) => {
                eprintln!("Process error: {}", e);
                -1
            }
            Err(_) => {
                // Timeout occurred
                let _ = child.kill().await;
                let _ = self.app_handle.emit(
                    "workflow:step_failed",
                    serde_json::json!({
                        "execution_id": execution_id,
                        "step_id": step_id,
                        "error": "Step timed out",
                        "timestamp": Utc::now().to_rfc3339()
                    }),
                );
                return Err(anyhow!(
                    "Step '{}' timed out after {} seconds",
                    step_id,
                    timeout_duration.as_secs()
                ));
            }
        };

        // Emit step completion event
        if exit_code == 0 {
            let _ = self.app_handle.emit(
                "workflow:step_completed",
                serde_json::json!({
                    "execution_id": execution_id,
                    "step_id": step_id,
                    "exit_code": exit_code,
                    "timestamp": Utc::now().to_rfc3339()
                }),
            );
        } else {
            let _ = self.app_handle.emit(
                "workflow:step_failed",
                serde_json::json!({
                    "execution_id": execution_id,
                    "step_id": step_id,
                    "error": format!("Process exited with code {}", exit_code),
                    "timestamp": Utc::now().to_rfc3339()
                }),
            );
        }

        // Collect artifacts
        let artifacts = self
            .collect_artifacts(step, working_directory, execution_id)
            .await?;

        Ok(artifacts)
    }

    async fn stream_output(
        stdout: tokio::process::ChildStdout,
        stderr: tokio::process::ChildStderr,
        app_handle: &AppHandle,
        execution_id: &str,
        step_id: &str,
    ) -> Result<()> {
        let stdout_reader = BufReader::new(stdout);
        let stderr_reader = BufReader::new(stderr);

        let mut stdout_lines = stdout_reader.lines();
        let mut stderr_lines = stderr_reader.lines();

        loop {
            tokio::select! {
                line = stdout_lines.next_line() => {
                    match line {
                        Ok(Some(line)) => {
                            let _ = app_handle.emit("workflow:stdout", serde_json::json!({
                                "execution_id": execution_id,
                                "step_id": step_id,
                                "line": line,
                                "timestamp": Utc::now().to_rfc3339()
                            }));
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("Error reading stdout: {}", e);
                            break;
                        }
                    }
                }
                line = stderr_lines.next_line() => {
                    match line {
                        Ok(Some(line)) => {
                            let _ = app_handle.emit("workflow:stderr", serde_json::json!({
                                "execution_id": execution_id,
                                "step_id": step_id,
                                "line": line,
                                "timestamp": Utc::now().to_rfc3339()
                            }));
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("Error reading stderr: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn collect_artifacts(
        &self,
        step: &WorkflowStep,
        working_directory: &str,
        execution_id: &str,
    ) -> Result<Vec<WorkflowArtifact>> {
        let mut artifacts = Vec::new();
        let empty_artifacts_map = HashMap::new();

        // Collect artifacts based on step outputs
        for output in &step.outputs {
            let artifact_path = self.resolve_template_variables(
                &output.path,
                working_directory,
                &HashMap::new(),
                &empty_artifacts_map,
            );
            let full_path = PathBuf::from(working_directory).join(&artifact_path);

            if full_path.exists() {
                let content = tokio::fs::read_to_string(&full_path).await.ok();

                let mut artifact = WorkflowArtifact {
                    id: Uuid::new_v4().to_string(),
                    execution_id: execution_id.to_string(),
                    step_id: step.id.clone(),
                    name: output.name.clone(),
                    artifact_type: output.artifact_type.clone(),
                    file_path: Some(full_path.to_string_lossy().to_string()),
                    content,
                    metadata_: None,
                    size: None,
                    hash: None,
                    created_at: Utc::now(),
                };

                // Enrich artifact with metadata
                if let Err(e) = self.artifact_manager.enrich_artifact(&mut artifact).await {
                    eprintln!(
                        "Warning: Failed to enrich artifact '{}': {}",
                        artifact.name, e
                    );
                }

                artifacts.push(artifact);
            }
        }

        // Also collect common artifacts that might have been generated
        let common_artifacts = self.find_common_artifacts(working_directory).await?;
        for mut artifact in common_artifacts {
            // Enrich common artifacts too
            if let Err(e) = self.artifact_manager.enrich_artifact(&mut artifact).await {
                eprintln!(
                    "Warning: Failed to enrich common artifact '{}': {}",
                    artifact.name, e
                );
            }
            artifacts.push(artifact);
        }

        Ok(artifacts)
    }

    async fn find_common_artifacts(
        &self,
        working_directory: &str,
    ) -> Result<Vec<WorkflowArtifact>> {
        let mut artifacts = Vec::new();

        let common_files = vec![
            "subdomains.txt",
            "ports.txt",
            "nuclei_output.jsonl",
            "nuclei_output.json",
            "httpx_output.txt",
            "gau_output.txt",
            "waybackurls_output.txt",
            "ffuf_output.json",
            "gobuster_output.txt",
            "sqlmap_output.txt",
            "arjun_output.txt",
        ];

        for filename in common_files {
            let file_path = PathBuf::from(working_directory).join(filename);
            if file_path.exists() {
                let content = tokio::fs::read_to_string(&file_path).await.ok();

                artifacts.push(WorkflowArtifact {
                    id: Uuid::new_v4().to_string(),
                    execution_id: "".to_string(), // Will be set by caller
                    step_id: "".to_string(),      // Will be set by caller
                    name: filename.to_string(),
                    artifact_type: "file".to_string(),
                    file_path: Some(file_path.to_string_lossy().to_string()),
                    content,
                    metadata_: None,
                    size: None,
                    hash: None,
                    created_at: Utc::now(),
                });
            }
        }

        Ok(artifacts)
    }

    /// Try to use an adapter to build the command if available
    /// Returns Some(command_args) if an adapter was used, None otherwise
    fn try_build_command_with_adapter(
        &self,
        tool_name: &str,
        original_args: &[String],
        inputs: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        let registry = AdapterRegistry::new();

        // Check if we have an adapter for this tool
        if !registry.has_adapter(tool_name) {
            return None;
        }

        eprintln!("📦 Using adapter for tool: {}", tool_name);

        // Try to extract target from inputs or original args
        let target = inputs.get("target").cloned().or_else(|| {
            // Try to find a domain/URL-like argument
            original_args
                .iter()
                .find(|arg| arg.contains(".") && !arg.starts_with("-"))
                .cloned()
        });

        // Try to extract output file from original args
        let output_file = original_args.iter().enumerate().find_map(|(i, arg)| {
            if (arg == "-o" || arg == "--output" || arg == "-oJ") && i + 1 < original_args.len() {
                Some(original_args[i + 1].clone())
            } else {
                None
            }
        });

        // If we have a target, use the adapter
        if let Some(target) = target {
            match registry.build_command_with_defaults(tool_name, target, output_file) {
                Ok(command) => {
                    eprintln!("✅ Adapter built command: {:?}", command);
                    Some(command)
                }
                Err(e) => {
                    eprintln!("⚠️  Adapter failed to build command: {}", e);
                    None
                }
            }
        } else {
            eprintln!("⚠️  No target found for adapter, using original command");
            None
        }
    }

    fn resolve_template_variables(
        &self,
        template: &str,
        working_directory: &str,
        inputs: &HashMap<String, String>,
        artifacts: &HashMap<String, Vec<WorkflowArtifact>>,
    ) -> String {
        let mut resolved = template.to_string();

        // Replace common variables
        resolved = resolved.replace("{{workdir}}", working_directory);
        resolved = resolved.replace(
            "{{target}}",
            inputs.get("target").unwrap_or(&"".to_string()),
        );

        // Replace input variables
        for (key, value) in inputs {
            let placeholder = format!("{{{{{}}}}}", key);
            resolved = resolved.replace(&placeholder, value);
        }

        // Replace artifact references (e.g., {{artifacts.step_id.artifact_name}})
        if resolved.contains("{{artifacts.") {
            // Extract all artifact references
            let re = regex::Regex::new(r"\{\{(artifacts\.[^}]+)\}\}").unwrap();
            for cap in re.captures_iter(&resolved.clone()) {
                if let Some(reference) = cap.get(1) {
                    let ref_str = reference.as_str();
                    if let Some(artifact_path) = self
                        .artifact_manager
                        .resolve_artifact_reference(ref_str, artifacts)
                    {
                        let placeholder = format!("{{{{{}}}}}", ref_str);
                        resolved = resolved.replace(&placeholder, &artifact_path);
                    } else {
                        eprintln!("Warning: Could not resolve artifact reference: {}", ref_str);
                    }
                }
            }
        }

        resolved
    }
}
