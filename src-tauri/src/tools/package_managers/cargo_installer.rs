use crate::tools::catalog::ToolDefinition;
use crate::events::{EventEmitter, TOOL_INSTALLATION_OUTPUT};
use anyhow::{Context, Result, anyhow};
use std::process::Stdio;
use tauri::Manager;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use std::path::PathBuf;

pub struct CargoInstaller {
    app_handle: tauri::AppHandle,
}

impl CargoInstaller {
    pub fn new(app_handle: tauri::AppHandle) -> Self {
        Self { app_handle }
    }

    async fn check_cargo_installed(&self) -> Result<bool> {
        let output = Command::new("cargo")
            .arg("--version")
            .output()
            .await;
        match output {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }

    fn get_cargo_path(&self) -> PathBuf {
        if cfg!(windows) {
            let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".cargo").join("bin")
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".cargo").join("bin")
        }
    }

    fn emit_output(&self, tool_name: &str, message: &str) {
        let event = EventEmitter::tool_installation_output(tool_name, "stdout", message);
        let _ = self.app_handle.emit_all(TOOL_INSTALLATION_OUTPUT, event);
    }

    pub async fn install(&self, tool: &ToolDefinition, tool_name: &str) -> Result<String> {
        self.emit_output(tool_name, &format!("Starting Cargo installation for {}...\n", tool.name));

        if !self.check_cargo_installed().await? {
            return Err(anyhow!("Cargo is not installed. Please install Rust/Cargo first."));
        }

        let package_name = tool.cargo_package.as_ref()
            .ok_or_else(|| anyhow!("Tool {} does not have cargo_package defined", tool.name))?;

        self.emit_output(tool_name, &format!("Installing {} via cargo...\n", package_name));

        let mut child = Command::new("cargo")
            .args(&["install", package_name])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn cargo install")?;

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        
        let tool_name_clone = tool_name.to_string();
        let app_handle_clone = self.app_handle.clone();
        
        let stdout_task = tokio::spawn(async move {
            if let Some(stdout) = stdout {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let event = EventEmitter::tool_installation_output(&tool_name_clone, "stdout", &format!("{}\n", line));
                    let _ = app_handle_clone.emit_all(TOOL_INSTALLATION_OUTPUT, event);
                }
            }
        });
        
        let tool_name_clone2 = tool_name.to_string();
        let app_handle_clone2 = self.app_handle.clone();
        let stderr_task = tokio::spawn(async move {
            if let Some(stderr) = stderr {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let event = EventEmitter::tool_installation_output(&tool_name_clone2, "stderr", &format!("{}\n", line));
                    let _ = app_handle_clone2.emit_all(TOOL_INSTALLATION_OUTPUT, event);
                }
            }
        });
        
        let _ = tokio::join!(stdout_task, stderr_task);

        let status = child.wait().await.context("Failed to wait for cargo install")?;

        if !status.success() {
            let error_msg = if let Some(code) = status.code() {
                format!("❌ Failed to install {} via cargo (exit code: {})\n", tool.name, code)
            } else {
                format!("❌ Failed to install {} via cargo (process terminated)\n", tool.name)
            };
            self.emit_output(tool_name, &error_msg);
            self.emit_output(tool_name, "💡 Tip: Check if Rust/Cargo is properly installed and crate name is correct\n");
            return Err(anyhow!("Cargo install failed with status: {}. Verify Rust toolchain installation.", status));
        }

        self.emit_output(tool_name, &format!("Successfully installed {} via cargo\n", tool.name));
        Ok(format!("Successfully installed {} via cargo", tool.name))
    }

    pub async fn update(&self, tool: &ToolDefinition, tool_name: &str) -> Result<String> {
        self.emit_output(tool_name, &format!("Updating {}...\n", tool.name));

        let package_name = tool.cargo_package.as_ref()
            .ok_or_else(|| anyhow!("Tool {} does not have cargo_package defined", tool.name))?;

        let mut child = Command::new("cargo")
            .args(&["install", "--force", package_name])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn cargo install")?;

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        
        let tool_name_clone = tool_name.to_string();
        let app_handle_clone = self.app_handle.clone();
        
        let stdout_task = tokio::spawn(async move {
            if let Some(stdout) = stdout {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            let event = EventEmitter::tool_installation_output(&tool_name_clone, "stdout", &format!("{}\n", line));
                            let _ = app_handle_clone.emit_all(TOOL_INSTALLATION_OUTPUT, event);
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("Error reading cargo stdout: {}", e);
                            break;
                        }
                    }
                }
            }
        });
        
        let tool_name_clone2 = tool_name.to_string();
        let app_handle_clone2 = self.app_handle.clone();
        let stderr_task = tokio::spawn(async move {
            if let Some(stderr) = stderr {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            let event = EventEmitter::tool_installation_output(&tool_name_clone2, "stderr", &format!("{}\n", line));
                            let _ = app_handle_clone2.emit_all(TOOL_INSTALLATION_OUTPUT, event);
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("Error reading cargo stderr: {}", e);
                            break;
                        }
                    }
                }
            }
        });
        
        // Wait with timeout
        let timeout_duration = tokio::time::Duration::from_secs(900);
        let join_handle = tokio::spawn(async move {
            let _ = tokio::join!(stdout_task, stderr_task);
        });
        
        match tokio::time::timeout(timeout_duration, join_handle).await {
            Ok(_) => {},
            Err(_) => {
                // Timeout occurred
            }
        }

        let status = child.wait().await?;

        if !status.success() {
            let error_msg = if let Some(code) = status.code() {
                format!("❌ Failed to update {} (exit code: {})\n", tool.name, code)
            } else {
                format!("❌ Failed to update {} (process terminated)\n", tool.name)
            };
            self.emit_output(tool_name, &error_msg);
            self.emit_output(tool_name, "💡 Tip: The crate may not be installed or may require recompilation\n");
            return Err(anyhow!("Cargo update failed for {}. The crate may need to be reinstalled.", tool.name));
        }

        self.emit_output(tool_name, &format!("Successfully updated {}\n", tool.name));
        Ok(format!("Successfully updated {}", tool.name))
    }

    pub async fn uninstall(&self, tool: &ToolDefinition) -> Result<String> {
        let package_name = tool.cargo_package.as_ref()
            .ok_or_else(|| anyhow!("Tool {} does not have cargo_package defined", tool.name))?;

        let output = Command::new("cargo")
            .args(&["uninstall", package_name])
            .output()
            .await
            .context("Failed to uninstall cargo package")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not installed") || stderr.contains("package is not installed") {
                return Err(anyhow!("Crate '{}' is not installed or already removed", package_name));
            }
            return Err(anyhow!("Failed to uninstall {}: {}. Check if crate is installed.", package_name, stderr.trim()));
        }

        Ok(format!("Successfully uninstalled {}", package_name))
    }
}
