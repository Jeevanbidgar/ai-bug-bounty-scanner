use tokio::process::Command;
use serde::{Deserialize, Serialize};

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
            .output()
            .await
        {
            Ok(output) => output.status.success(),
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
            .output()
            .await
        {
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                
                if output.status.success() {
                    Ok(InstallationResult {
                        success: true,
                        message: format!("Successfully installed {} via winget", tool_name),
                        tool_name: tool_name.to_string(),
                        installed_path: None, // winget installs to various locations
                    })
                } else {
                    Ok(InstallationResult {
                        success: false,
                        message: format!("Failed to install {}: {}", tool_name, stderr.trim()),
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
            .output()
            .await
        {
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                
                if output.status.success() {
                    Ok(InstallationResult {
                        success: true,
                        message: format!("Successfully updated {} via winget", tool_name),
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
                    message: format!("Failed to execute winget upgrade: {}", e),
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
                Err(format!("Failed to execute winget uninstall: {}", e))
            }
        }
    }
}
