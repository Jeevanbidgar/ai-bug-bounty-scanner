use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoInstallManager {
    go_path: Option<PathBuf>,
    go_bin_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationResult {
    pub success: bool,
    pub message: String,
    pub tool_name: String,
    pub installed_path: Option<String>,
}

impl GoInstallManager {
    /// Create a new GoInstallManager instance
    pub fn new() -> Self {
        Self {
            go_path: Self::detect_gopath(),
            go_bin_path: Self::detect_go_bin_path(),
        }
    }

    /// Detect GOPATH from environment or use default
    fn detect_gopath() -> Option<PathBuf> {
        // Try GOPATH environment variable first
        if let Ok(gopath) = std::env::var("GOPATH") {
            return Some(PathBuf::from(gopath));
        }

        // Use default GOPATH based on OS
        if cfg!(windows) {
            // Windows: %USERPROFILE%\go
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                return Some(PathBuf::from(userprofile).join("go"));
            }
        } else {
            // Linux/Mac: ~/go
            if let Ok(home) = std::env::var("HOME") {
                return Some(PathBuf::from(home).join("go"));
            }
        }

        None
    }

    /// Detect GOPATH/bin directory where binaries are installed
    fn detect_go_bin_path() -> Option<PathBuf> {
        if let Some(gopath) = Self::detect_gopath() {
            return Some(gopath.join("bin"));
        }
        None
    }

    /// Get the GOPATH/bin directory as a string
    pub fn get_go_bin_path(&self) -> Option<String> {
        self.go_bin_path.as_ref().map(|p| p.to_string_lossy().to_string())
    }

    /// Check if Go is installed and available
    pub async fn is_go_available(&self) -> bool {
        match Command::new("go")
            .arg("version")
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

    /// Install a tool via go install
    /// 
    /// # Arguments
    /// * `module_path` - The full Go module path (e.g., "github.com/projectdiscovery/subfinder/v2/cmd/subfinder")
    /// * `tool_name` - The tool name (e.g., "subfinder")
    /// 
    /// # Returns
    /// * `InstallationResult` with success status and message
    pub async fn install(&self, module_path: &str, tool_name: &str) -> Result<InstallationResult, String> {
        // Check if Go is available
        if !self.is_go_available().await {
            return Ok(InstallationResult {
                success: false,
                message: "Go is not installed or not in PATH. Please install Go first.".to_string(),
                tool_name: tool_name.to_string(),
                installed_path: None,
            });
        }

        // Build the install command: go install module@latest
        let module_with_version = format!("{}@latest", module_path);
        
        println!("Installing {} via go install {}", tool_name, module_with_version);

        match Command::new("go")
            .arg("install")
            .arg(&module_with_version)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                match child.wait().await {
                    Ok(status) => {
                        if status.success() {
                            // Check if the binary was installed successfully
                            if let Some(installed_path) = self.get_tool_path(tool_name) {
                                Ok(InstallationResult {
                                    success: true,
                                    message: format!("Successfully installed {} to {}", tool_name, installed_path),
                                    tool_name: tool_name.to_string(),
                                    installed_path: Some(installed_path),
                                })
                            } else {
                                Ok(InstallationResult {
                                    success: false,
                                    message: format!("Installation completed but {} binary not found in GOPATH/bin", tool_name),
                                    tool_name: tool_name.to_string(),
                                    installed_path: None,
                                })
                            }
                        } else {
                            // Get error output
                            let stderr = child.stderr.take();
                            let error_msg = if let Some(mut stderr) = stderr {
                                use tokio::io::AsyncReadExt;
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
                            message: format!("Failed to wait for installation: {}", e),
                            tool_name: tool_name.to_string(),
                            installed_path: None,
                        })
                    }
                }
            }
            Err(e) => {
                Ok(InstallationResult {
                    success: false,
                    message: format!("Failed to start go install: {}", e),
                    tool_name: tool_name.to_string(),
                    installed_path: None,
                })
            }
        }
    }

    /// Update a tool (same as install for Go tools)
    /// 
    /// # Arguments
    /// * `module_path` - The full Go module path
    /// * `tool_name` - The tool name
    /// 
    /// # Returns
    /// * `InstallationResult` with success status and message
    pub async fn update(&self, module_path: &str, tool_name: &str) -> Result<InstallationResult, String> {
        // For Go tools, update is the same as install (always installs @latest)
        self.install(module_path, tool_name).await
    }

    /// Check if a tool is installed
    /// 
    /// # Arguments
    /// * `tool_name` - The tool name (e.g., "subfinder")
    /// 
    /// # Returns
    /// * `true` if the tool binary exists in GOPATH/bin, `false` otherwise
    pub fn is_installed(&self, tool_name: &str) -> bool {
        self.get_tool_path(tool_name).is_some()
    }

    /// Get the full path to a tool binary
    /// 
    /// # Arguments
    /// * `tool_name` - The tool name (e.g., "subfinder")
    /// 
    /// # Returns
    /// * `Some(path)` if the binary exists, `None` otherwise
    pub fn get_tool_path(&self, tool_name: &str) -> Option<String> {
        if let Some(bin_path) = &self.go_bin_path {
            // On Windows, add .exe extension
            let binary_name = if cfg!(windows) {
                format!("{}.exe", tool_name)
            } else {
                tool_name.to_string()
            };

            let tool_path = bin_path.join(&binary_name);
            
            if tool_path.exists() {
                return Some(tool_path.to_string_lossy().to_string());
            }
        }
        None
    }

    /// Get the version of an installed tool
    /// 
    /// # Arguments
    /// * `tool_name` - The tool name (e.g., "subfinder")
    /// 
    /// # Returns
    /// * `Some(version)` if the tool is installed and reports its version, `None` otherwise
    pub async fn get_version(&self, tool_name: &str) -> Option<String> {
        if !self.is_installed(tool_name) {
            return None;
        }

        // Try common version flags
        let version_flags = vec!["--version", "-version", "-v", "version"];

        for flag in version_flags {
            match Command::new(tool_name)
                .arg(flag)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
            {
                Ok(child) => {
                    if let Ok(output) = child.wait_with_output().await {
                        if output.status.success() {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            
                            // Version info might be in stdout or stderr
                            let version_output = if !stdout.is_empty() {
                                stdout.to_string()
                            } else {
                                stderr.to_string()
                            };

                            if !version_output.trim().is_empty() {
                                // Extract version number (first line usually)
                                return Some(version_output.lines().next()?.trim().to_string());
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        None
    }

    /// Uninstall a tool by removing its binary from GOPATH/bin
    /// 
    /// # Arguments
    /// * `tool_name` - The tool name (e.g., "subfinder")
    /// 
    /// # Returns
    /// * `Ok(())` if uninstalled successfully, `Err(message)` otherwise
    pub async fn uninstall(&self, tool_name: &str) -> Result<String, String> {
        if let Some(tool_path) = self.get_tool_path(tool_name) {
            match tokio::fs::remove_file(&tool_path).await {
                Ok(_) => {
                    println!("Successfully uninstalled {} from {}", tool_name, tool_path);
                    Ok(format!("Successfully uninstalled {} from {}", tool_name, tool_path))
                }
                Err(e) => {
                    let error_msg = format!("Failed to remove {}: {}", tool_path, e);
                    eprintln!("Error: {}", error_msg);
                    Err(error_msg)
                }
            }
        } else {
            Err(format!("{} is not installed or not found in GOPATH/bin", tool_name))
        }
    }

    /// List all Go tools installed in GOPATH/bin
    /// 
    /// # Returns
    /// * Vector of tool names found in GOPATH/bin
    pub async fn list_installed_tools(&self) -> Vec<String> {
        let mut tools = Vec::new();

        if let Some(bin_path) = &self.go_bin_path {
            if let Ok(mut entries) = tokio::fs::read_dir(bin_path).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if let Ok(metadata) = entry.metadata().await {
                        if metadata.is_file() {
                            if let Some(file_name) = entry.file_name().to_str() {
                                // Remove .exe extension on Windows
                                let tool_name = if cfg!(windows) && file_name.ends_with(".exe") {
                                    file_name.trim_end_matches(".exe").to_string()
                                } else {
                                    file_name.to_string()
                                };
                                tools.push(tool_name);
                            }
                        }
                    }
                }
            }
        }

        tools
    }

    /// Install multiple tools in sequence
    /// 
    /// # Arguments
    /// * `tools` - Vector of (module_path, tool_name) tuples
    /// 
    /// # Returns
    /// * Vector of InstallationResult for each tool
    pub async fn install_batch(&self, tools: Vec<(&str, &str)>) -> Vec<InstallationResult> {
        let mut results = Vec::new();

        for (module_path, tool_name) in tools {
            match self.install(module_path, tool_name).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    results.push(InstallationResult {
                        success: false,
                        message: e,
                        tool_name: tool_name.to_string(),
                        installed_path: None,
                    });
                }
            }
        }

        results
    }
}

impl Default for GoInstallManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_go_install_manager_creation() {
        let manager = GoInstallManager::new();
        assert!(manager.go_path.is_some() || manager.go_bin_path.is_some());
    }

    #[tokio::test]
    async fn test_gopath_detection() {
        let gopath = GoInstallManager::detect_gopath();
        // GOPATH should be detected or use default
        assert!(gopath.is_some());
    }

    #[tokio::test]
    async fn test_go_bin_path_detection() {
        let bin_path = GoInstallManager::detect_go_bin_path();
        assert!(bin_path.is_some());
    }

    #[tokio::test]
    async fn test_is_go_available() {
        let manager = GoInstallManager::new();
        // This will fail if Go is not installed, which is acceptable for tests
        let _ = manager.is_go_available().await;
    }
}
