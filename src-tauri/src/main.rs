// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

// Tool discovery and execution state
#[derive(Default)]
pub struct AppState {
    tools: Arc<Mutex<HashMap<String, ToolInfo>>>,
    backend_pid: Arc<Mutex<Option<u32>>>,
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

// Enhanced backend management with proper process management
#[tauri::command]
async fn start_backend(state: State<'_, AppState>) -> Result<String, String> {
    let backend_path = std::env::current_dir()
        .map_err(|e| format!("Failed to get current directory: {}", e))?
        .join("backend");

    // Check if backend is already running
    if let Ok(response) = reqwest::get("http://127.0.0.1:8000/health").await {
        if response.status().is_success() {
            return Ok("Backend is already running".to_string());
        }
    }

    let mut command = TokioCommand::new("python");
    command
        .current_dir(&backend_path)
        .args(["-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    match command.spawn() {
        Ok(child) => {
            let pid = child.id().unwrap_or(0);
            *state.backend_pid.lock().unwrap() = Some(pid);
            println!("Backend started with PID: {}", pid);

            // Wait for backend to be ready
            for _ in 0..30 {
                if let Ok(response) = reqwest::get("http://127.0.0.1:8000/health").await {
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
    match timeout(Duration::from_secs(5), reqwest::get("http://127.0.0.1:8000/health")).await {
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
            start_backend,
            stop_backend,
            check_backend_health,
            discover_tools,
            execute_tool,
            get_system_info,
            get_application_state
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
