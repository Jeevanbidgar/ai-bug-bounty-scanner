use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tauri::Manager;

use crate::events::{EventEmitter, TOOL_INSTALLATION_STARTED, TOOL_INSTALLATION_OUTPUT, TOOL_INSTALLATION_COMPLETED};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipxManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationResult {
    pub success: bool,
    pub message: String,
    pub tool_name: String,
    pub installed_path: Option<String>,
}

impl PipxManager {
    pub fn new() -> Self {
        Self
    }

    /// Check if pipx is installed and available
    pub async fn is_pipx_available(&self) -> bool {
        match Command::new("pipx")
            .arg("--version")
            .output()
            .await
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    /// Install a tool via pipx install with live output streaming
    /// 
    /// # Arguments
    /// * `package_name` - The Python package name (e.g., "sqlmap", "wpscan")
    /// * `tool_name` - The tool name (e.g., "sqlmap")
    /// * `app_handle` - Optional Tauri AppHandle for emitting events
    /// 
    /// # Returns
    /// * `InstallationResult` with success status and message
    pub async fn install(
        &self, 
        package_name: &str, 
        tool_name: &str,
        app_handle: Option<&tauri::AppHandle>
    ) -> Result<InstallationResult, String> {
        // Check if pipx is available
        if !self.is_pipx_available().await {
            return Ok(InstallationResult {
                success: false,
                message: "pipx is not installed or not in PATH. Please install pipx first.".to_string(),
                tool_name: tool_name.to_string(),
                installed_path: None,
            });
        }

        eprintln!("📦 Installing {} via pipx install {}", tool_name, package_name);

        // Emit installation started event
        if let Some(handle) = app_handle {
            let _ = handle.emit_all(
                TOOL_INSTALLATION_STARTED,
                EventEmitter::tool_installation_started(tool_name, "pipx")
            );
        }

        // Spawn process with piped stdout/stderr for live streaming
        let mut child = match Command::new("pipx")
            .arg("install")
            .arg(package_name)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                let error_msg = format!("Failed to spawn pipx command: {}", e);
                eprintln!("❌ {}", error_msg);
                
                if let Some(handle) = app_handle {
                    let _ = handle.emit_all(
                        TOOL_INSTALLATION_COMPLETED,
                        EventEmitter::tool_installation_completed(tool_name, false, &error_msg)
                    );
                }
                
                return Ok(InstallationResult {
                    success: false,
                    message: error_msg,
                    tool_name: tool_name.to_string(),
                    installed_path: None,
                });
            }
        };

        // Capture stdout and stderr
        let stdout = child.stdout.take().expect("Failed to capture stdout");
        let stderr = child.stderr.take().expect("Failed to capture stderr");

        // Create async readers
        let stdout_reader = BufReader::new(stdout).lines();
        let stderr_reader = BufReader::new(stderr).lines();

        // Read stdout in background
        let tool_name_clone = tool_name.to_string();
        let handle_clone = app_handle.map(|h| h.clone());
        let stdout_task = tokio::spawn(async move {
            let mut lines = stdout_reader;
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[pipx stdout] {}", line);
                if let Some(handle) = &handle_clone {
                    let _ = handle.emit_all(
                        TOOL_INSTALLATION_OUTPUT,
                        EventEmitter::tool_installation_output(&tool_name_clone, "stdout", &line)
                    );
                }
            }
        });

        // Read stderr in background
        let tool_name_clone = tool_name.to_string();
        let handle_clone = app_handle.map(|h| h.clone());
        let stderr_task = tokio::spawn(async move {
            let mut lines = stderr_reader;
            let mut error_output = Vec::new();
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[pipx stderr] {}", line);
                error_output.push(line.clone());
                if let Some(handle) = &handle_clone {
                    let _ = handle.emit_all(
                        TOOL_INSTALLATION_OUTPUT,
                        EventEmitter::tool_installation_output(&tool_name_clone, "stderr", &line)
                    );
                }
            }
            error_output
        });

        // Wait for process to complete
        let status = child.wait().await;
        
        // Wait for output tasks to complete
        let _ = stdout_task.await;
        let stderr_output = stderr_task.await.unwrap_or_default();

        // Check result
        match status {
            Ok(exit_status) => {
                let success = exit_status.success();
                let message = if success {
                    format!("✅ Successfully installed {} via pipx", tool_name)
                } else {
                    let error_msg = stderr_output.join("\n");
                    format!("❌ Failed to install {}: {}", tool_name, error_msg)
                };

                eprintln!("{}", message);

                // Emit completion event
                if let Some(handle) = app_handle {
                    let _ = handle.emit_all(
                        TOOL_INSTALLATION_COMPLETED,
                        EventEmitter::tool_installation_completed(tool_name, success, &message)
                    );
                }

                Ok(InstallationResult {
                    success,
                    message,
                    tool_name: tool_name.to_string(),
                    installed_path: None,
                })
            }
            Err(e) => {
                let error_msg = format!("Failed to execute pipx command: {}", e);
                eprintln!("❌ {}", error_msg);

                if let Some(handle) = app_handle {
                    let _ = handle.emit_all(
                        TOOL_INSTALLATION_COMPLETED,
                        EventEmitter::tool_installation_completed(tool_name, false, &error_msg)
                    );
                }

                Ok(InstallationResult {
                    success: false,
                    message: error_msg,
                    tool_name: tool_name.to_string(),
                    installed_path: None,
                })
            }
        }
    }

    /// Update a tool via pipx upgrade
    pub async fn update(&self, package_name: &str, tool_name: &str) -> Result<InstallationResult, String> {
        if !self.is_pipx_available().await {
            return Ok(InstallationResult {
                success: false,
                message: "pipx is not installed or not in PATH.".to_string(),
                tool_name: tool_name.to_string(),
                installed_path: None,
            });
        }

        eprintln!("🔄 Updating {} via pipx upgrade {}", tool_name, package_name);

        match Command::new("pipx")
            .arg("upgrade")
            .arg(package_name)
            .output()
            .await
        {
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                
                if output.status.success() {
                    Ok(InstallationResult {
                        success: true,
                        message: format!("Successfully updated {} via pipx", tool_name),
                        tool_name: tool_name.to_string(),
                        installed_path: None,
                    })
                } else {
                    Ok(InstallationResult {
                        success: false,
                        message: format!("Failed to update {}: {}", tool_name, stderr.trim()),
                        tool_name: tool_name.to_string(),
                        installed_path: None,
                    })
                }
            }
            Err(e) => {
                Ok(InstallationResult {
                    success: false,
                    message: format!("Failed to execute pipx upgrade: {}", e),
                    tool_name: tool_name.to_string(),
                    installed_path: None,
                })
            }
        }
    }

    /// Uninstall a tool via pipx uninstall
    pub async fn uninstall(&self, package_name: &str, tool_name: &str) -> Result<String, String> {
        if !self.is_pipx_available().await {
            return Err("pipx is not installed or not in PATH.".to_string());
        }

        eprintln!("🗑️  Uninstalling {} via pipx uninstall {}", tool_name, package_name);

        match Command::new("pipx")
            .arg("uninstall")
            .arg(package_name)
            .output()
            .await
        {
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                
                if output.status.success() {
                    Ok(format!("Successfully uninstalled {}", tool_name))
                } else {
                    Err(format!("Failed to uninstall {}: {}", tool_name, stderr.trim()))
                }
            }
            Err(e) => {
                Err(format!("Failed to execute pipx uninstall: {}", e))
            }
        }
    }
}
