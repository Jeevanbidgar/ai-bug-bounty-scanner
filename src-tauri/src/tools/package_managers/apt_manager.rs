use tokio::process::Command;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AptManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationResult {
    pub success: bool,
    pub message: String,
    pub tool_name: String,
    pub installed_path: Option<String>,
}

impl AptManager {
    pub fn new() -> Self {
        Self
    }

    /// Check if apt is available (Linux only)
    pub async fn is_apt_available(&self) -> bool {
        if !cfg!(target_os = "linux") {
            return false;
        }

        match Command::new("apt")
            .arg("--version")
            .output()
            .await
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    /// Install a tool via apt install
    /// 
    /// # Arguments
    /// * `package_name` - The APT package name (e.g., "nmap", "curl")
    /// * `tool_name` - The tool name (e.g., "nmap")
    /// 
    /// # Returns
    /// * `InstallationResult` with success status and message
    pub async fn install(&self, package_name: &str, tool_name: &str) -> Result<InstallationResult, String> {
        // Check if apt is available
        if !self.is_apt_available().await {
            return Ok(InstallationResult {
                success: false,
                message: "apt is not available. This system is not Debian/Ubuntu-based.".to_string(),
                tool_name: tool_name.to_string(),
                installed_path: None,
            });
        }

        eprintln!("📦 Installing {} via sudo apt install -y {}", tool_name, package_name);
        eprintln!("⚠️  Note: This requires sudo permissions and may prompt for password");

        // Run apt install with -y flag for non-interactive mode
        match Command::new("sudo")
            .arg("apt")
            .arg("install")
            .arg("-y")
            .arg(package_name)
            .output()
            .await
        {
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                
                if output.status.success() {
                    Ok(InstallationResult {
                        success: true,
                        message: format!("Successfully installed {} via apt", tool_name),
                        tool_name: tool_name.to_string(),
                        installed_path: None, // apt installs to /usr/bin typically
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
                    message: format!("Failed to execute apt install: {}. Check if sudo is available.", e),
                    tool_name: tool_name.to_string(),
                    installed_path: None,
                })
            }
        }
    }

    /// Update a tool via apt upgrade
    pub async fn update(&self, package_name: &str, tool_name: &str) -> Result<InstallationResult, String> {
        if !self.is_apt_available().await {
            return Ok(InstallationResult {
                success: false,
                message: "apt is not available.".to_string(),
                tool_name: tool_name.to_string(),
                installed_path: None,
            });
        }

        eprintln!("🔄 Updating {} via sudo apt upgrade -y {}", tool_name, package_name);

        match Command::new("sudo")
            .arg("apt")
            .arg("install")
            .arg("--only-upgrade")
            .arg("-y")
            .arg(package_name)
            .output()
            .await
        {
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                
                if output.status.success() {
                    Ok(InstallationResult {
                        success: true,
                        message: format!("Successfully updated {} via apt", tool_name),
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
                    message: format!("Failed to execute apt upgrade: {}", e),
                    tool_name: tool_name.to_string(),
                    installed_path: None,
                })
            }
        }
    }

    /// Uninstall a tool via apt remove
    pub async fn uninstall(&self, package_name: &str, tool_name: &str) -> Result<String, String> {
        if !self.is_apt_available().await {
            return Err("apt is not available.".to_string());
        }

        eprintln!("🗑️  Uninstalling {} via sudo apt remove -y {}", tool_name, package_name);

        match Command::new("sudo")
            .arg("apt")
            .arg("remove")
            .arg("-y")
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
                Err(format!("Failed to execute apt remove: {}", e))
            }
        }
    }
}
