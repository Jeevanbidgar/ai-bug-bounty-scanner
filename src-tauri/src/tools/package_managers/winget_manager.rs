use std::process::Stdio;
use tokio::process::Command;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WingetManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationResult {
    pub success: bool,
    pub message: String,
    pub tool_name: String,
    pub installed_path: Option<String>,
}

impl WingetManager {
    pub fn new() -> Self {
        Self
    }

    /// Check if winget is available (Windows only)
    pub async fn is_winget_available(&self) -> bool {
        if !cfg!(target_os = "windows") {
            return false;
        }

        match Command::new("winget")
            .arg("--version")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                if let Ok(status) = child.wait().await {
                    return status.success();
                }
                false
            }
            Err(_) => false,
        }
    }

    /// Install a tool via winget install
    /// 
    /// # Arguments
    /// * `winget_id` - The winget package ID (e.g., "Nmap.Nmap", "Microsoft.Sysinternals")
    /// * `tool_name` - The tool name (e.g., "nmap")
    /// 
    /// # Returns
    /// * `InstallationResult` with success status and message
    pub async fn install(&self, winget_id: &str, tool_name: &str) -> Result<InstallationResult, String> {
        // Check if winget is available
        if !self.is_winget_available().await {
            return Ok(InstallationResult {
                success: false,
                message: "winget is not available. Please install App Installer from Microsoft Store.".to_string(),
                tool_name: tool_name.to_string(),
                installed_path: None,
            });
        }

        eprintln!("📦 Installing {} via winget install --id {} --accept-package-agreements --accept-source-agreements", 
                  tool_name, winget_id);
        eprintln!("⚠️  Note: This may require UAC elevation");

        // Run winget install with --accept-* flags for non-interactive mode
        match Command::new("winget")
            .arg("install")
            .arg("--id")
            .arg(winget_id)
            .arg("--accept-package-agreements")
            .arg("--accept-source-agreements")
            .arg("--silent")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                match child.wait().await {
                    Ok(status) => {
                        if status.success() {
                            Ok(InstallationResult {
                                success: true,
                                message: format!("Successfully installed {} via winget", tool_name),
                                tool_name: tool_name.to_string(),
                                installed_path: None, // winget installs to various locations
                            })
                        } else {
                            // Get error output
                            let stderr = child.stderr.take();
                            let error_msg = if let Some(mut stderr) = stderr {
                                let mut buf = String::new();
                                let _ = stderr.read_to_string(&mut buf).await;
                                buf
                            } else {
                                "Unknown error".to_string()
                            };

                            Ok(InstallationResult {
                                success: false,
                                message: format!("Failed to install {}: {}", tool_name, error_msg),
                                tool_name: tool_name.to_string(),
                                installed_path: None,
                            })
                        }
                    }
                    Err(e) => {
                        Ok(InstallationResult {
                            success: false,
                            message: format!("Failed to execute winget install: {}", e),
                            tool_name: tool_name.to_string(),
                            installed_path: None,
                        })
                    }
                }
            }
            Err(e) => {
                Ok(InstallationResult {
                    success: false,
                    message: format!("Failed to spawn winget command: {}", e),
                    tool_name: tool_name.to_string(),
                    installed_path: None,
                })
            }
        }
    }

    /// Update a tool via winget upgrade
    pub async fn update(&self, winget_id: &str, tool_name: &str) -> Result<InstallationResult, String> {
        if !self.is_winget_available().await {
            return Ok(InstallationResult {
                success: false,
                message: "winget is not available.".to_string(),
                tool_name: tool_name.to_string(),
                installed_path: None,
            });
        }

        eprintln!("🔄 Updating {} via winget upgrade --id {} --accept-package-agreements --accept-source-agreements", 
                  tool_name, winget_id);

        match Command::new("winget")
            .arg("upgrade")
            .arg("--id")
            .arg(winget_id)
            .arg("--accept-package-agreements")
            .arg("--accept-source-agreements")
            .arg("--silent")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                match child.wait().await {
                    Ok(status) => {
                        if status.success() {
                            Ok(InstallationResult {
                                success: true,
                                message: format!("Successfully updated {} via winget", tool_name),
                                tool_name: tool_name.to_string(),
                                installed_path: None,
                            })
                        } else {
                            let stderr = child.stderr.take();
                            let error_msg = if let Some(mut stderr) = stderr {
                                let mut buf = String::new();
                                let _ = stderr.read_to_string(&mut buf).await;
                                buf
                            } else {
                                "Unknown error".to_string()
                            };

                            Ok(InstallationResult {
                                success: false,
                                message: format!("Failed to update {}: {}", tool_name, error_msg),
                                tool_name: tool_name.to_string(),
                                installed_path: None,
                            })
                        }
                    }
                    Err(e) => {
                        Ok(InstallationResult {
                            success: false,
                            message: format!("Failed to execute winget upgrade: {}", e),
                            tool_name: tool_name.to_string(),
                            installed_path: None,
                        })
                    }
                }
            }
            Err(e) => {
                Ok(InstallationResult {
                    success: false,
                    message: format!("Failed to spawn winget command: {}", e),
                    tool_name: tool_name.to_string(),
                    installed_path: None,
                })
            }
        }
    }

    /// Uninstall a tool via winget uninstall
    pub async fn uninstall(&self, winget_id: &str, tool_name: &str) -> Result<String, String> {
        if !self.is_winget_available().await {
            return Err("winget is not available.".to_string());
        }

        eprintln!("🗑️  Uninstalling {} via winget uninstall --id {} --silent", tool_name, winget_id);

        match Command::new("winget")
            .arg("uninstall")
            .arg("--id")
            .arg(winget_id)
            .arg("--silent")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                match child.wait().await {
                    Ok(status) => {
                        if status.success() {
                            Ok(format!("Successfully uninstalled {}", tool_name))
                        } else {
                            let stderr = child.stderr.take();
                            let error_msg = if let Some(mut stderr) = stderr {
                                let mut buf = String::new();
                                let _ = stderr.read_to_string(&mut buf).await;
                                buf
                            } else {
                                "Unknown error".to_string()
                            };

                            Err(format!("Failed to uninstall {}: {}", tool_name, error_msg))
                        }
                    }
                    Err(e) => {
                        Err(format!("Failed to execute winget uninstall: {}", e))
                    }
                }
            }
            Err(e) => {
                Err(format!("Failed to spawn winget command: {}", e))
            }
        }
    }
}
