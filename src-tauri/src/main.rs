// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::State;
use tauri::Manager;
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;
use tokio::io::{AsyncBufReadExt, BufReader};
use std::path::PathBuf;
use chrono;
use which::which;

// Tool discovery and execution state
#[derive(Default, Clone)]
pub struct AppState {
    tools: Arc<Mutex<HashMap<String, ToolInfo>>>,
    backend_pid: Arc<Mutex<Option<u32>>>,
    workflow_executions: Arc<Mutex<HashMap<String, WorkflowExecution>>>,
}

// Workflow execution structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub needs: Vec<String>,
    pub run: Vec<String>,
    pub env: HashMap<String, String>,
    pub timeout: u64,
    pub retry: WorkflowRetry,
    pub outputs: Vec<WorkflowOutput>,
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowOutput {
    pub name: String,
    pub r#type: String,
    pub path: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRetry {
    pub max_attempts: u32,
    pub delay: u64,
    pub backoff_factor: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub version: String,
    pub author: Option<String>,
    pub tags: Vec<String>,
    pub inputs: HashMap<String, String>,
    pub steps: Vec<WorkflowStep>,
    pub outputs: Vec<WorkflowOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecution {
    pub id: String,
    pub workflow_id: String,
    pub workflow_name: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub inputs: HashMap<String, String>,
    pub current_step: Option<String>,
    pub steps: HashMap<String, StepExecution>,
    pub artifacts: HashMap<String, Value>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExecution {
    pub step_id: String,
    pub status: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub error_message: Option<String>,
    pub artifacts: Vec<String>,
    pub attempts: u32,
}

// Tool information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub category: String,
    pub installed: bool,
    pub version: Option<String>,
    pub path: Option<String>,
    pub last_check: Option<String>,
}

// Tool execution result
#[derive(Debug, Serialize, Deserialize)]
pub struct ToolExecution {
    pub tool_name: String,
    pub success: bool,
    pub output: String,
    pub execution_time: f64,
    pub error: Option<String>,
}

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

// Workflow execution commands
#[tauri::command]
async fn load_workflow_templates() -> Result<Vec<serde_json::Value>, String> {
    let workflows_dir = std::env::current_dir()
        .map_err(|e| format!("Failed to get current directory: {}", e))?
        .join("app")
        .join("workflows");

    let mut templates = Vec::new();

    if let Ok(entries) = std::fs::read_dir(workflows_dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                if let Some(ext) = entry.path().extension() {
                    if ext == "yaml" || ext == "yml" {
                        if let Ok(content) = std::fs::read_to_string(entry.path()) {
                            match serde_yaml::from_str::<serde_json::Value>(&content) {
                                Ok(yaml_data) => {
                                    templates.push(yaml_data);
                                }
                                Err(e) => {
                                    eprintln!("Failed to parse YAML file {:?}: {}", entry.path(), e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(templates)
}

#[tauri::command]
async fn execute_workflow(
    state: tauri::State<'_, AppState>,
    app_handle: tauri::AppHandle,
    workflow_data: serde_json::Value,
    inputs: std::collections::HashMap<String, String>
) -> Result<String, String> {
    // Parse workflow template
    let workflow_template: WorkflowTemplate = serde_json::from_value(workflow_data)
        .map_err(|e| format!("Failed to parse workflow template: {}", e))?;

    // Create execution ID
    let execution_id = format!("exec_{}", chrono::Utc::now().timestamp());

    // Create execution context
    let mut execution = WorkflowExecution {
        id: execution_id.clone(),
        workflow_id: workflow_template.id.clone(),
        workflow_name: workflow_template.name.clone(),
        status: "running".to_string(),
        started_at: chrono::Utc::now().to_rfc3339(),
        completed_at: None,
        inputs: inputs.clone(),
        current_step: None,
        steps: HashMap::new(),
        artifacts: HashMap::new(),
        error_message: None,
    };

    // Initialize step executions
    for step in &workflow_template.steps {
        let step_exec = StepExecution {
            step_id: step.id.clone(),
            status: "pending".to_string(),
            started_at: None,
            completed_at: None,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            error_message: None,
            artifacts: Vec::new(),
            attempts: 0,
        };
        execution.steps.insert(step.id.clone(), step_exec);
    }

    // Store execution
    state.workflow_executions.lock().unwrap().insert(execution_id.clone(), execution);

    // Start workflow execution in background
    let execution_id_clone = execution_id.clone();
    let state_clone = state.inner().clone();
    tokio::spawn(async move {
        if let Err(e) = execute_workflow_async(state_clone, app_handle, execution_id_clone).await {
            eprintln!("Workflow execution failed: {}", e);
        }
    });

    Ok(execution_id)
}

#[tauri::command]
async fn get_workflow_status(
    state: tauri::State<'_, AppState>,
    execution_id: String
) -> Result<serde_json::Value, String> {
    let executions = state.workflow_executions.lock().unwrap();
    let execution = executions.get(&execution_id)
        .ok_or_else(|| format!("Execution {} not found", execution_id))?;

    Ok(serde_json::to_value(execution).unwrap())
}

async fn execute_workflow_async(
    state: AppState,
    app_handle: tauri::AppHandle,
    execution_id: String
) -> Result<(), String> {
    // Load workflow template first (outside mutex)
    let workflow_id = {
        let executions = state.workflow_executions.lock().unwrap();
        let execution = executions.get(&execution_id)
            .ok_or_else(|| "Execution not found".to_string())?;
        execution.workflow_id.clone()
    };

    let workflows_dir = std::env::current_dir()
        .map_err(|e| format!("Failed to get current directory: {}", e))?
        .join("app")
        .join("workflows");

    let workflow_file = workflows_dir.join(format!("{}.yaml", workflow_id));
    let content = std::fs::read_to_string(workflow_file)
        .map_err(|e| format!("Failed to read workflow file: {}", e))?;

    let workflow_template: WorkflowTemplate = serde_yaml::from_str(&content)
        .map_err(|e| format!("Failed to parse workflow template: {}", e))?;

    // Execute DAG (mutex will be locked/unlocked inside as needed)
    execute_dag(&state, &execution_id, &workflow_template, app_handle).await?;

    Ok(())
}

async fn execute_dag(
    state: &AppState,
    execution_id: &str,
    template: &WorkflowTemplate,
    app_handle: tauri::AppHandle
) -> Result<(), String> {
    use tauri::Manager;

    // Build dependency graph
    let dependency_graph = build_dependency_graph(template);

    // Helper to lock and get mutable execution
    let get_exec = || -> std::sync::MutexGuard<'_, HashMap<String, WorkflowExecution>> {
        state.workflow_executions.lock().unwrap()
    };

    // Determine initial ready steps
    let ready_steps_init = {
        let executions = get_exec();
        let execution = executions.get(execution_id).ok_or_else(|| "Execution not found".to_string())?;
        get_ready_steps(&execution.steps, &dependency_graph)
    };

    let mut ready_steps = ready_steps_init;

    while !ready_steps.is_empty() {
        // Prepare tasks
        let mut tasks = Vec::new();

        for step_id in &ready_steps {
            // Snapshot data under lock
            let (exec_id_owned, step_template, _prev_status) = {
                let mut executions = get_exec();
                let execution = executions.get_mut(execution_id).ok_or_else(|| "Execution not found".to_string())?;
                let step_template = template.steps.iter()
                    .find(|s| s.id == *step_id)
                    .ok_or_else(|| format!("Step {} not found in template", step_id))?;

                // Mark running
                if let Some(step_exec) = execution.steps.get_mut(step_id) {
                    step_exec.status = "running".to_string();
                    step_exec.started_at = Some(chrono::Utc::now().to_rfc3339());
                }

                (execution.id.clone(), step_template.clone(), ())
            };

            // Emit step started
            let _ = app_handle.emit_all("workflow:step_started", serde_json::json!({
                "execution_id": exec_id_owned,
                "step_id": step_id,
                "step_name": step_template.name
            }));

            // Spawn step execution
            let step_id_clone = step_id.clone();
            let command = step_template.run.clone();
            let env = step_template.env.clone();
            let timeout = step_template.timeout;
            let working_dir = step_template.working_directory.clone();
            let app_handle_clone = app_handle.clone();

            let task = tokio::spawn(async move {
                execute_step(exec_id_owned, step_id_clone, command, env, timeout, working_dir, app_handle_clone).await
            });

            tasks.push((step_id.clone(), task));
        }

        // Await tasks and update state
        for (step_id, task) in tasks {
            match task.await {
                Ok(Ok(step_result)) => {
                    let mut executions = get_exec();
                    let execution = executions.get_mut(execution_id).ok_or_else(|| "Execution not found".to_string())?;
                    if let Some(step_exec) = execution.steps.get_mut(&step_id) {
                        *step_exec = step_result.clone();
                    }
                    let _ = app_handle.emit_all("workflow:step_completed", serde_json::json!({
                        "execution_id": execution.id,
                        "step_id": step_id,
                        "status": step_result.status,
                        "exit_code": step_result.exit_code,
                        "artifacts": step_result.artifacts
                    }));
                }
                Ok(Err(e)) => {
                    let mut executions = get_exec();
                    let execution = executions.get_mut(execution_id).ok_or_else(|| "Execution not found".to_string())?;
                    if let Some(step_exec) = execution.steps.get_mut(&step_id) {
                        step_exec.status = "failed".to_string();
                        step_exec.error_message = Some(e.to_string());
                    }
                    let _ = app_handle.emit_all("workflow:step_failed", serde_json::json!({
                        "execution_id": execution.id,
                        "step_id": step_id,
                        "error": e
                    }));
                }
                Err(e) => {
                    let mut executions = get_exec();
                    let execution = executions.get_mut(execution_id).ok_or_else(|| "Execution not found".to_string())?;
                    if let Some(step_exec) = execution.steps.get_mut(&step_id) {
                        step_exec.status = "failed".to_string();
                        step_exec.error_message = Some(format!("Task panicked: {}", e));
                    }
                    let _ = app_handle.emit_all("workflow:step_failed", serde_json::json!({
                        "execution_id": execution.id,
                        "step_id": step_id,
                        "error": "Task panicked"
                    }));
                }
            }
        }

        // Recompute ready steps under lock
        ready_steps = {
            let executions = get_exec();
            let execution = executions.get(execution_id).ok_or_else(|| "Execution not found".to_string())?;
            get_ready_steps(&execution.steps, &dependency_graph)
        };
    }

    // Finalize status
    {
        let mut executions = get_exec();
        let execution = executions.get_mut(execution_id).ok_or_else(|| "Execution not found".to_string())?;
        let failed_steps: Vec<_> = execution.steps.values()
            .filter(|step| step.status == "failed")
            .map(|step| step.step_id.clone())
            .collect();

        if failed_steps.is_empty() {
            execution.status = "completed".to_string();
            execution.completed_at = Some(chrono::Utc::now().to_rfc3339());
            let _ = app_handle.emit_all("workflow:execution_completed", serde_json::json!({
                "execution_id": execution.id,
                "status": "completed"
            }));
        } else {
            execution.status = "failed".to_string();
            execution.error_message = Some(format!("Steps failed: {:?}", failed_steps));
            let _ = app_handle.emit_all("workflow:execution_failed", serde_json::json!({
                "execution_id": execution.id,
                "failed_steps": failed_steps
            }));
        }
    }

    Ok(())
}

async fn execute_step(
    execution_id: String,
    step_id: String,
    command: Vec<String>,
    env: HashMap<String, String>,
    timeout: u64,
    working_directory: Option<String>,
    app_handle: tauri::AppHandle
) -> Result<StepExecution, String> {
    // Resolve tool paths
    let resolved_command = resolve_tool_paths(command)?;

    // Set up working directory
    let working_dir = if let Some(dir) = working_directory {
        PathBuf::from(dir)
    } else {
        std::env::current_dir().map_err(|e| format!("Failed to get current directory: {}", e))?
    };

    // Execute command
    let mut cmd = TokioCommand::new(&resolved_command[0]);
    cmd.args(&resolved_command[1..])
        .current_dir(working_dir)
        .envs(env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Start process
    let mut child = cmd.spawn()
        .map_err(|e| format!("Failed to spawn process: {}", e))?;

    // Set up output capture
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    let stdout_reader = BufReader::new(stdout);
    let stderr_reader = BufReader::new(stderr);

    // Read stdout and stderr concurrently
    let execution_id_clone = execution_id.clone();
    let step_id_clone = step_id.clone();
    let app_handle_clone = app_handle.clone();
    let (stdout_handle, stderr_handle) = tokio::join!(
        read_stream(stdout_reader, execution_id.clone(), step_id.clone(), app_handle.clone()),
        read_stream(stderr_reader, execution_id_clone, step_id_clone, app_handle_clone)
    );

    let stdout_content = stdout_handle.unwrap_or_default();
    let stderr_content = stderr_handle.unwrap_or_default();

    // Wait for process with timeout
    let timeout_duration = Duration::from_secs(timeout);
    let exit_status = tokio::time::timeout(timeout_duration, child.wait()).await
        .map_err(|_| format!("Process timed out after {} seconds", timeout))?
        .map_err(|e| format!("Process failed: {}", e))?;

    let exit_code = exit_status.code();

    // Collect artifacts
    let artifacts = collect_step_artifacts(&step_id, &std::env::current_dir().unwrap())?;

    Ok(StepExecution {
        step_id,
        status: if exit_code == Some(0) { "completed".to_string() } else { "failed".to_string() },
        started_at: Some(chrono::Utc::now().to_rfc3339()),
        completed_at: Some(chrono::Utc::now().to_rfc3339()),
        exit_code,
        stdout: stdout_content,
        stderr: stderr_content,
        error_message: if exit_code != Some(0) {
            Some(format!("Process exited with code {:?}", exit_code))
        } else {
            None
        },
        artifacts,
        attempts: 1,
    })
}

async fn read_stream<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    execution_id: String,
    step_id: String,
    app_handle: tauri::AppHandle
) -> Result<String, String> {
    let mut reader = BufReader::new(reader);
    let mut content = String::new();
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                content.push_str(&line);
                // Emit line to frontend
                let _ = app_handle.emit_all("workflow:stdout", serde_json::json!({
                    "execution_id": execution_id,
                    "step_id": step_id,
                    "line": line.trim_end()
                }));
            }
            Err(e) => return Err(format!("Failed to read stream: {}", e)),
        }
    }

    Ok(content)
}

fn resolve_tool_paths(command: Vec<String>) -> Result<Vec<String>, String> {
    let mut resolved = Vec::new();

    for arg in command {
        if arg.starts_with("./") || arg.starts_with("../") || arg.starts_with("/") {
            // Keep absolute or relative paths as-is
            resolved.push(arg);
        } else {
            // Try to resolve as a tool name using 'which' crate
            match which(&arg) {
                Ok(path) => {
                    resolved.push(path.to_string_lossy().to_string());
                }
                Err(_) => {
                    // Tool not found in PATH, keep original (might be a flag or parameter)
                    resolved.push(arg);
                }
            }
        }
    }

    Ok(resolved)
}

fn collect_step_artifacts(_step_id: &str, working_dir: &PathBuf) -> Result<Vec<String>, String> {
    let mut artifacts = Vec::new();

    // Look for common artifact files
    let artifact_patterns = [
        "subdomains.txt", "ports.txt", "urls.txt", "nuclei.jsonl", "nuclei.json",
        "results.json", "output.json", "findings.json"
    ];

    for pattern in &artifact_patterns {
        let artifact_path = working_dir.join(pattern);
        if artifact_path.exists() {
            artifacts.push(pattern.to_string());
        }
    }

    Ok(artifacts)
}

fn build_dependency_graph(template: &WorkflowTemplate) -> HashMap<String, Vec<String>> {
    let mut graph = HashMap::new();

    for step in &template.steps {
        graph.insert(step.id.clone(), step.needs.clone());
    }

    graph
}

fn get_ready_steps(
    steps: &HashMap<String, StepExecution>,
    dependency_graph: &HashMap<String, Vec<String>>
) -> Vec<String> {
    let mut ready = Vec::new();

    for (step_id, dependencies) in dependency_graph {
        if steps.get(step_id).unwrap().status != "pending" {
            continue;
        }

        // Check if all dependencies are completed
        let all_deps_completed = dependencies.iter().all(|dep_id| {
            steps.get(dep_id).unwrap().status == "completed"
        });

        if all_deps_completed {
            ready.push(step_id.clone());
        }
    }

    ready
}

// Execute arbitrary commands for security tools
#[tauri::command]
async fn execute_command(
    command: String,
    args: Vec<String>,
    working_directory: Option<String>
) -> Result<String, String> {
    println!("Executing command: {} with args: {:?}", command, args);

    let mut cmd = TokioCommand::new(&command);
    cmd.args(&args);

    if let Some(dir) = working_directory {
        cmd.current_dir(dir);
    }

    cmd.stdout(Stdio::piped())
       .stderr(Stdio::piped());

    match cmd.output().await {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                println!("Command executed successfully");
                Ok(stdout.to_string())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("Command failed: {}", stderr);
                Err(format!("Command failed: {}", stderr))
            }
        }
        Err(e) => {
            println!("Failed to execute command: {}", e);
            Err(format!("Failed to execute command: {}", e))
        }
    }
}

// Enhanced backend management with proper process management
#[tauri::command]
async fn start_backend(state: State<'_, AppState>) -> Result<String, String> {
    let backend_path = std::env::current_dir()
        .map_err(|e| format!("Failed to get current directory: {}", e))?
        .join("backend");

    // Check if backend is already running
    if let Ok(response) = reqwest::get("http://127.0.0.1:8000/api/health/").await {
        if response.status().is_success() {
            return Ok("Backend is already running".to_string());
        }
    }

    let mut command = TokioCommand::new("python");
    command
        .current_dir(&backend_path)
        .args(["run.py"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    match command.spawn() {
        Ok(child) => {
            let pid = child.id().unwrap_or(0);
            *state.backend_pid.lock().unwrap() = Some(pid);
            println!("Backend started with PID: {}", pid);

            // Wait for backend to be ready
            for _ in 0..30 {
                if let Ok(response) = reqwest::get("http://127.0.0.1:8000/api/health/").await {
                    if response.status().is_success() {
                        return Ok(format!("Backend started successfully with PID: {}", pid));
                    }
                }
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }

            Ok(format!("Backend started with PID: {} (may take a moment to be ready)", pid))
        }
        Err(e) => Err(format!("Failed to start backend: {}", e))
    }
}

#[tauri::command]
async fn stop_backend(state: State<'_, AppState>) -> Result<String, String> {
    if let Some(pid) = *state.backend_pid.lock().unwrap() {
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .output();

            match output {
                Ok(result) if result.status.success() => {
                    *state.backend_pid.lock().unwrap() = None;
                    Ok(format!("Backend stopped (PID: {})", pid))
                }
                _ => Err(format!("Failed to stop backend process {}", pid))
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            use std::process::Command;
            let output = Command::new("kill")
                .arg(pid.to_string())
                .output();

            match output {
                Ok(result) if result.status.success() => {
                    *state.backend_pid.lock().unwrap() = None;
                    Ok(format!("Backend stopped (PID: {})", pid))
                }
                _ => Err(format!("Failed to stop backend process {}", pid))
            }
        }
    } else {
        Ok("No backend process to stop".to_string())
    }
}

#[tauri::command]
async fn check_backend_health() -> Result<String, String> {
    match timeout(Duration::from_secs(5), reqwest::get("http://127.0.0.1:8000/api/health/")).await {
        Ok(Ok(response)) => {
            if response.status().is_success() {
                Ok("Backend is healthy".to_string())
            } else {
                Err(format!("Backend health check failed: {}", response.status()))
            }
        }
        Ok(Err(e)) => Err(format!("Failed to connect to backend: {}", e)),
        Err(e) => Err(format!("Request failed: {}", e))
    }
}

// Enhanced tool discovery with Rust performance
#[tauri::command]
async fn discover_tools(state: State<'_, AppState>) -> Result<Vec<ToolInfo>, String> {
    let mut tools = Vec::new();

    // Common security tools to check
    let tool_definitions = vec![
        ("subfinder", "Fast passive subdomain discovery", "recon"),
        ("amass", "Comprehensive network reconnaissance", "recon"),
        ("nuclei", "Fast vulnerability scanner", "vulnerability"),
        ("nmap", "Network mapper and port scanner", "network"),
        ("sqlmap", "SQL injection testing tool", "web"),
        ("ffuf", "Web fuzzer", "web"),
        ("gobuster", "Directory brute force tool", "web"),
        ("waybackurls", "Wayback Machine URL fetcher", "recon"),
        ("gau", "URL discovery tool", "recon"),
        ("naabu", "Fast port scanner", "network"),
    ];

    for (name, description, category) in tool_definitions {
        let tool_info = check_tool_availability(name, description, category).await;
        tools.push(tool_info);
    }

    *state.tools.lock().unwrap() = tools.iter().cloned().map(|t| (t.name.clone(), t.clone())).collect();
    Ok(tools)
}

async fn check_tool_availability(name: &str, description: &str, category: &str) -> ToolInfo {
    let mut tool_info = ToolInfo {
        name: name.to_string(),
        description: description.to_string(),
        category: category.to_string(),
        installed: false,
        version: None,
        path: None,
        last_check: Some(chrono::Utc::now().to_rfc3339()),
    };

    // Check if tool is in PATH
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(if cfg!(target_os = "windows") { ";" } else { ":" }) {
            let tool_path = std::path::Path::new(dir).join(name);
            #[cfg(target_os = "windows")]
            let tool_path = tool_path.with_extension("exe");

            if tool_path.exists() && tool_path.is_file() {
                tool_info.installed = true;
                tool_info.path = Some(tool_path.to_string_lossy().to_string());

                // Try to get version
                if let Some(version) = get_tool_version(&tool_path).await {
                    tool_info.version = Some(version);
                }
                break;
            }
        }
    }

    tool_info
}

async fn get_tool_version(tool_path: &std::path::Path) -> Option<String> {
    let output = TokioCommand::new(tool_path)
        .arg("--version")
        .output()
        .await;

    match output {
        Ok(result) if result.status.success() => {
            let version_output = String::from_utf8_lossy(&result.stdout);
            // Extract version number (simple regex-like extraction)
            if let Some(captures) = regex::Regex::new(r"(\d+\.\d+(?:\.\d+)*)")
                .unwrap()
                .captures(&version_output)
            {
                Some(captures.get(1).unwrap().as_str().to_string())
            } else {
                None
            }
        }
        _ => None
    }
}

// Efficient tool execution with proper resource management
#[tauri::command]
async fn execute_tool(
    state: State<'_, AppState>,
    tool_name: String,
    target: String,
    parameters: Option<HashMap<String, String>>
) -> Result<ToolExecution, String> {
    let tool_info = {
        let tools = state.tools.lock().unwrap();
        tools.get(&tool_name).cloned()
            .ok_or_else(|| format!("Tool '{}' not found", tool_name))?
    };

    if !tool_info.installed {
        return Err(format!("Tool '{}' is not installed", tool_name));
    }

    let start_time = Instant::now();

    // Execute tool with timeout and proper error handling
    let execution_result = execute_tool_with_timeout(&tool_info, &target, parameters).await;

    let execution_time = start_time.elapsed().as_secs_f64();

    match execution_result {
        Ok(output) => Ok(ToolExecution {
            tool_name,
            success: true,
            output,
            execution_time,
            error: None,
        }),
        Err(error) => Ok(ToolExecution {
            tool_name,
            success: false,
            output: String::new(),
            execution_time,
            error: Some(error),
        }),
    }
}

async fn execute_tool_with_timeout(
    tool_info: &ToolInfo,
    target: &str,
    parameters: Option<HashMap<String, String>>
) -> Result<String, String> {
    let tool_path = tool_info.path.as_ref()
        .ok_or_else(|| format!("Tool path not found for {}", tool_info.name))?;

    let mut command = TokioCommand::new(tool_path);
    command.arg("-d").arg(target);

    // Add additional parameters if provided
    if let Some(params) = parameters {
        for (key, value) in params {
            command.arg(format!("--{}", key)).arg(value);
        }
    }

    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    // Execute with timeout
    let output = timeout(Duration::from_secs(300), command.output()).await
        .map_err(|_| format!("Tool execution timed out after 5 minutes"))?;

    match output {
        Ok(result) => {
            if result.status.success() {
                Ok(String::from_utf8_lossy(&result.stdout).to_string())
            } else {
                let stderr = String::from_utf8_lossy(&result.stderr);
                Err(format!("Tool execution failed: {}", stderr))
            }
        }
        Err(e) => Err(format!("Failed to execute tool: {}", e))
    }
}

// System information and performance monitoring
#[tauri::command]
async fn get_system_info() -> Result<HashMap<String, String>, String> {
    let mut info = HashMap::new();

    // OS information
    info.insert("os".to_string(), std::env::consts::OS.to_string());
    info.insert("arch".to_string(), std::env::consts::ARCH.to_string());

    // Memory information (approximate)
    if let Ok(mem_info) = sys_info::mem_info() {
        info.insert("total_memory_mb".to_string(), (mem_info.total / 1024 / 1024).to_string());
        info.insert("available_memory_mb".to_string(), (mem_info.avail / 1024 / 1024).to_string());
    }

    // CPU information
    if let Ok(cpu_info) = sys_info::cpu_num() {
        info.insert("cpu_cores".to_string(), cpu_info.to_string());
    }

    Ok(info)
}

// Application state management
#[tauri::command]
async fn get_application_state(state: State<'_, AppState>) -> Result<HashMap<String, serde_json::Value>, String> {
    let tools = state.tools.lock().unwrap();
    let backend_running = state.backend_pid.lock().unwrap().is_some();

    let mut state_info = HashMap::new();
    state_info.insert("tools_count".to_string(), serde_json::Value::Number(tools.len().into()));
    state_info.insert("installed_tools_count".to_string(),
                     serde_json::Value::Number(tools.values().filter(|t| t.installed).count().into()));
    state_info.insert("backend_running".to_string(), serde_json::Value::Bool(backend_running));

    Ok(state_info)
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            greet,
            execute_command,
            start_backend,
            stop_backend,
            check_backend_health,
            discover_tools,
            execute_tool,
            get_system_info,
            get_application_state,
            load_workflow_templates,
            execute_workflow,
            get_workflow_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
