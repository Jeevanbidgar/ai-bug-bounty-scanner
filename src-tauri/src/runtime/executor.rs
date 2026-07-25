use anyhow::{anyhow, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{watch, RwLock};
use tokio::time::timeout;
use uuid::Uuid;

use crate::events::SharedEventSink;
use crate::runtime::process::configure_tokio_command;
use crate::settings::AppSettings;
use crate::tools::discovery::ToolDiscoveryService;
use crate::workflow::artifacts::ArtifactManager;
use crate::workflow::types::{WorkflowArtifact, WorkflowStep};

#[derive(Debug)]
pub struct StepOutcome {
    pub artifacts: Vec<WorkflowArtifact>,
    pub exit_code: i32,
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub started_at: chrono::DateTime<Utc>,
    pub completed_at: chrono::DateTime<Utc>,
}

struct RetryState<'a> {
    config: &'a crate::workflow::types::WorkflowRetry,
    cancellation: watch::Receiver<bool>,
}

#[derive(Clone)]
pub struct ProcessExecutor {
    events: SharedEventSink,
    tool_discovery: Arc<RwLock<ToolDiscoveryService>>,
    artifact_manager: Arc<ArtifactManager>,
    settings: Arc<RwLock<AppSettings>>,
}

impl ProcessExecutor {
    pub fn new(
        events: SharedEventSink,
        tool_discovery: Arc<RwLock<ToolDiscoveryService>>,
        artifact_manager: Arc<ArtifactManager>,
        settings: Arc<RwLock<AppSettings>>,
    ) -> Self {
        Self {
            events,
            tool_discovery,
            artifact_manager,
            settings,
        }
    }

    /// Execute a workflow step with retry logic
    pub async fn execute_step(
        &self,
        step: &WorkflowStep,
        execution_id: &str,
        working_directory: &str,
        inputs: &HashMap<String, String>,
        artifacts: &HashMap<String, Vec<WorkflowArtifact>>,
        cancellation: watch::Receiver<bool>,
    ) -> Result<StepOutcome> {
        // Check if step has retry configuration
        if let Some(retry_config) = &step.retry {
            self.execute_step_with_retry(
                step,
                execution_id,
                working_directory,
                inputs,
                artifacts,
                RetryState {
                    config: retry_config,
                    cancellation,
                },
            )
            .await
        } else {
            // No retry, execute once
            self.execute_step_once(
                step,
                execution_id,
                working_directory,
                inputs,
                artifacts,
                cancellation,
            )
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
        artifacts: &HashMap<String, Vec<WorkflowArtifact>>,
        retry: RetryState<'_>,
    ) -> Result<StepOutcome> {
        let retry_config = retry.config;
        let mut cancellation = retry.cancellation;
        let mut last_error = None;
        let mut last_outcome = None;
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
                let _ = self.events.emit(
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
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
                    _ = Self::wait_for_cancellation(&mut cancellation) => {
                        return Err(anyhow!("Execution cancelled"));
                    }
                }
            }

            // Attempt execution
            match self
                .execute_step_once(
                    step,
                    execution_id,
                    working_directory,
                    inputs,
                    artifacts,
                    cancellation.clone(),
                )
                .await
            {
                Ok(outcome) if step.is_success_exit_code(outcome.exit_code) => {
                    if attempt > 0 {
                        eprintln!(
                            "Step '{}' succeeded on attempt {}/{}",
                            step.id,
                            attempt + 1,
                            max_attempts
                        );
                    }
                    return Ok(outcome);
                }
                Ok(outcome) => {
                    eprintln!(
                        "Step '{}' exited with code {} on attempt {}/{}",
                        step.id,
                        outcome.exit_code,
                        attempt + 1,
                        max_attempts
                    );
                    last_outcome = Some(outcome);
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

        if let Some(outcome) = last_outcome {
            return Ok(outcome);
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
        artifacts: &HashMap<String, Vec<WorkflowArtifact>>,
        mut cancellation: watch::Receiver<bool>,
    ) -> Result<StepOutcome> {
        let step_id = &step.id;
        let started_at = Utc::now();

        if *cancellation.borrow() {
            return Err(anyhow!("Execution cancelled"));
        }

        // Build command with template variable substitution
        let mut command_args = Vec::new();
        for arg in &step.run {
            let resolved_arg =
                self.resolve_template_variables(arg, working_directory, inputs, artifacts);
            command_args.push(resolved_arg);
        }

        if command_args.is_empty() {
            return Err(anyhow!("Step '{}' has no command to execute", step_id));
        }

        // Workflow files already contain the complete argv contract. Rebuilding
        // them with an adapter's defaults discards workflow-specific flags.
        let tool_name = command_args[0].clone();
        let final_command_args = command_args;

        // Resolve tool path using ToolDiscoveryService
        let resolved_tool_path = {
            let discovery = self.tool_discovery.read().await;
            match discovery.get_tool_record(&tool_name, false).await {
                Some(tool_record) => {
                    if tool_record.installed && tool_record.status == "available" {
                        tool_record.path.ok_or_else(|| {
                            anyhow!(
                                "Tool '{}' is marked available but has no verified executable path",
                                tool_name
                            )
                        })?
                    } else if !tool_record.installed {
                        // Tool exists in catalog but not installed
                        return Err(anyhow!(
                            "Tool '{}' is not installed. Status: {}. Missing dependencies: {:?}",
                            tool_name,
                            tool_record.status,
                            tool_record.missing_dependencies
                        ));
                    } else {
                        return Err(anyhow!(
                            "Tool '{}' is not ready (status: '{}'). Last error: {:?}",
                            tool_name,
                            tool_record.status,
                            tool_record.last_error
                        ));
                    }
                }
                None => {
                    return Err(anyhow!(
                        "Workflow requested undeclared tool '{}'; register it before execution",
                        tool_name
                    ));
                }
            }
        };

        let settings = self.settings.read().await.clone();
        let timeout_duration = Duration::from_secs(
            step.timeout
                .unwrap_or(settings.default_step_timeout_seconds),
        );
        let mut cmd = Command::new(&resolved_tool_path);
        cmd.args(&final_command_args[1..])
            .current_dir(working_directory)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if step.stdin.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        if let Some(environment) = &step.env {
            for (key, value) in environment {
                cmd.env(
                    key,
                    self.resolve_template_variables(value, working_directory, inputs, artifacts),
                );
            }
        }
        configure_tokio_command(&mut cmd);

        let mut child = cmd.spawn()?;

        if let Some(stdin_template) = &step.stdin {
            let mut input = self.resolve_template_variables(
                stdin_template,
                working_directory,
                inputs,
                artifacts,
            );
            if input.len() > 65_536 {
                Self::terminate_process_tree(child.id());
                let _ = child.kill().await;
                return Err(anyhow!("Step '{}' resolved stdin is too large", step_id));
            }
            if !input.ends_with('\n') {
                input.push('\n');
            }
            let write_result = match child.stdin.take() {
                Some(mut child_stdin) => {
                    async {
                        child_stdin.write_all(input.as_bytes()).await?;
                        child_stdin.shutdown().await
                    }
                    .await
                }
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "child stdin was not piped",
                )),
            };
            if let Err(error) = write_result {
                Self::terminate_process_tree(child.id());
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(anyhow!(
                    "Failed to write stdin for step '{}': {}",
                    step_id,
                    error
                ));
            }
        }

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to capture stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("Failed to capture stderr"))?;

        let child_pid = child.id();

        // Drain stdout and stderr independently. The previous select loop stopped
        // as soon as either stream closed and could silently lose the remainder.
        let events_clone = self.events.clone();
        let execution_id_clone = execution_id.to_string();
        let step_id_clone = step_id.to_string();

        let stdout_task = tokio::spawn(Self::stream_output(
            stdout,
            events_clone,
            execution_id_clone,
            step_id_clone,
            "workflow:stdout",
            settings.max_output_lines_per_stream,
        ));
        let stderr_task = tokio::spawn(Self::stream_output(
            stderr,
            self.events.clone(),
            execution_id.to_string(),
            step_id.to_string(),
            "workflow:stderr",
            settings.max_output_lines_per_stream,
        ));

        // Wait for normal completion, timeout, or explicit cancellation.
        let result = tokio::select! {
            result = timeout(timeout_duration, child.wait()) => Some(result),
            _ = Self::wait_for_cancellation(&mut cancellation) => None,
        };

        let exit_code = match result {
            Some(Ok(Ok(status))) => status.code().unwrap_or(-1),
            Some(Ok(Err(e))) => {
                eprintln!("Process error: {}", e);
                -1
            }
            Some(Err(_)) => {
                // Timeout occurred
                Self::terminate_process_tree(child_pid);
                let _ = child.kill().await;
                let _ = child.wait().await;
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                return Err(anyhow!(
                    "Step '{}' timed out after {} seconds",
                    step_id,
                    timeout_duration.as_secs()
                ));
            }
            None => {
                Self::terminate_process_tree(child_pid);
                let _ = child.kill().await;
                let _ = child.wait().await;
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                return Err(anyhow!("Execution cancelled"));
            }
        };

        let stdout = match stdout_task.await {
            Ok(Ok(lines)) => lines,
            Ok(Err(error)) => {
                eprintln!("Failed to read step stdout: {}", error);
                Vec::new()
            }
            Err(error) => {
                eprintln!("Stdout reader task failed: {}", error);
                Vec::new()
            }
        };
        let stderr = match stderr_task.await {
            Ok(Ok(lines)) => lines,
            Ok(Err(error)) => {
                eprintln!("Failed to read step stderr: {}", error);
                Vec::new()
            }
            Err(error) => {
                eprintln!("Stderr reader task failed: {}", error);
                Vec::new()
            }
        };

        // Collect artifacts
        let artifacts = self
            .collect_artifacts(
                step,
                working_directory,
                execution_id,
                inputs,
                artifacts,
                &stdout,
            )
            .await?;

        Ok(StepOutcome {
            artifacts,
            exit_code,
            stdout,
            stderr,
            started_at,
            completed_at: Utc::now(),
        })
    }

    async fn stream_output<R>(
        stream: R,
        events: SharedEventSink,
        execution_id: String,
        step_id: String,
        event_name: &'static str,
        max_captured_lines: usize,
    ) -> Result<Vec<String>>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut lines = BufReader::new(stream).lines();
        let mut captured = Vec::new();

        while let Some(line) = lines.next_line().await? {
            let _ = events.emit(
                event_name,
                serde_json::json!({
                    "execution_id": execution_id,
                    "step_id": step_id,
                    "line": line,
                    "timestamp": Utc::now().to_rfc3339()
                }),
            );

            if captured.len() < max_captured_lines {
                captured.push(line);
            }
        }

        Ok(captured)
    }

    async fn collect_artifacts(
        &self,
        step: &WorkflowStep,
        working_directory: &str,
        execution_id: &str,
        inputs: &HashMap<String, String>,
        artifacts_by_step: &HashMap<String, Vec<WorkflowArtifact>>,
        stdout: &[String],
    ) -> Result<Vec<WorkflowArtifact>> {
        let mut artifacts = Vec::new();

        // Collect artifacts based on step outputs
        for output in &step.outputs {
            let artifact_path = self.resolve_template_variables(
                &output.path,
                working_directory,
                inputs,
                artifacts_by_step,
            );
            let artifact_path = PathBuf::from(artifact_path);
            let full_path = if artifact_path.is_absolute() {
                artifact_path
            } else {
                PathBuf::from(working_directory).join(artifact_path)
            };

            if output.artifact_type == "stdout" && !full_path.exists() && !stdout.is_empty() {
                let working_root = PathBuf::from(working_directory);
                if full_path.parent() != Some(working_root.as_path()) {
                    return Err(anyhow!(
                        "Stdout artifact '{}' must be a direct child of the scan working directory",
                        output.name
                    ));
                }
                tokio::fs::write(&full_path, format!("{}\n", stdout.join("\n"))).await?;
            }

            if full_path.exists() {
                let canonical_path = tokio::fs::canonicalize(&full_path).await?;
                if !canonical_path.starts_with(working_directory) {
                    return Err(anyhow!(
                        "Artifact '{}' resolves outside the scan working directory",
                        output.name
                    ));
                }

                let content = tokio::fs::read_to_string(&canonical_path).await.ok();

                let mut artifact = WorkflowArtifact {
                    id: Uuid::new_v4().to_string(),
                    execution_id: execution_id.to_string(),
                    step_id: step.id.clone(),
                    name: output.name.clone(),
                    artifact_type: output.artifact_type.clone(),
                    file_path: Some(canonical_path.to_string_lossy().to_string()),
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

        Ok(artifacts)
    }

    async fn wait_for_cancellation(cancellation: &mut watch::Receiver<bool>) {
        loop {
            if *cancellation.borrow() {
                return;
            }

            if cancellation.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    fn terminate_process_tree(root_pid: Option<u32>) {
        use sysinfo::{PidExt, ProcessExt, Signal, System, SystemExt};

        let Some(root_pid) = root_pid else {
            return;
        };

        let mut system = System::new_all();
        system.refresh_processes();
        let root = sysinfo::Pid::from_u32(root_pid);
        let mut descendants = Vec::new();
        let mut frontier = vec![root];

        while let Some(parent) = frontier.pop() {
            for (pid, process) in system.processes() {
                if process.parent() == Some(parent) && !descendants.contains(pid) {
                    descendants.push(*pid);
                    frontier.push(*pid);
                }
            }
        }

        for pid in descendants.into_iter().rev() {
            if let Some(process) = system.process(pid) {
                let _ = process
                    .kill_with(Signal::Kill)
                    .unwrap_or_else(|| process.kill());
            }
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
