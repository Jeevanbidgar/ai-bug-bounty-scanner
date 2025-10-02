use tokio::process::Command;
use serde::{Deserialize, Serialize};

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

    /// Install a tool via pipx install
    /// 
    /// # Arguments
    /// * `package_name` - The Python package name (e.g., "sqlmap", "wpscan")
    /// * `tool_name` - The tool name (e.g., "sqlmap")
    /// 
    /// # Returns
    /// * `InstallationResult` with success status and message
    pub async fn install(&self, package_name: &str, tool_name: &str) -> Result<InstallationResult, String> {
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

        // Use .output() instead of spawn+wait to properly capture stdout/stderr
        match Command::new("pipx")
            .arg("install")
            .arg(package_name)
            .output()
            .await
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                
                if output.status.success() {
                    eprintln!("✅ pipx install succeeded");
                    Ok(InstallationResult {
                        success: true,
                        message: format!("Successfully installed {} via pipx", tool_name),
                        tool_name: tool_name.to_string(),
                        installed_path: None, // pipx manages paths internally
                    })
                } else {
                    eprintln!("❌ pipx install failed: {}", stderr);
                    Ok(InstallationResult {
                        success: false,
                        message: format!("Failed to install {}: {}", tool_name, stderr.trim()),
                        tool_name: tool_name.to_string(),
                        installed_path: None,
                    })
                }
            }
            Err(e) => {
                eprintln!("❌ Failed to execute pipx: {}", e);
                Ok(InstallationResult {
                    success: false,
                    message: format!("Failed to execute pipx install: {}", e),
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
