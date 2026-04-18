use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use tauri::Emitter;
use tokio::io::{AsyncBufReadExt, BufReader};
use uuid::Uuid;

use crate::runtime::process::hidden_tokio_command as hidden_command;

pub struct GoInstallManager {
    _go_path: Option<PathBuf>,
    go_bin_path: Option<PathBuf>,
    app_handle: tauri::AppHandle,
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
    pub fn new(app_handle: tauri::AppHandle) -> Self {
        Self {
            _go_path: Self::detect_gopath(),
            go_bin_path: Self::detect_go_bin_path(),
            app_handle,
        }
    }

    /// Emit installation output to frontend
    fn emit_output(&self, event_id: &str, output: &str) {
        let _ = self.app_handle.emit(
            "tool:installation_output",
            serde_json::json!({
                "event_id": event_id,
                "output": output
            }),
        );
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
    #[allow(dead_code)]
    pub fn get_go_bin_path(&self) -> Option<String> {
        self.go_bin_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
    }

    /// Check if Go is installed and available
    pub async fn is_go_available(&self) -> bool {
        let mut cmd = hidden_command("go");
        match cmd
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
    pub async fn install(
        &self,
        module_path: &str,
        tool_name: &str,
    ) -> Result<InstallationResult, String> {
        let event_id = Uuid::new_v4().to_string();

        // Check if Go is available
        if !self.is_go_available().await {
            self.emit_output(
                &event_id,
                "❌ Go is not installed or not in PATH. Please install Go first.\n",
            );
            return Ok(InstallationResult {
                success: false,
                message: "Go is not installed or not in PATH. Please install Go first.".to_string(),
                tool_name: tool_name.to_string(),
                installed_path: None,
            });
        }

        // Build the install command: go install module@latest
        let module_with_version = format!("{}@latest", module_path);

        self.emit_output(
            &event_id,
            &format!(
                "🚀 Installing {} via go install {}\n",
                tool_name, module_with_version
            ),
        );

        let mut install_cmd = hidden_command("go");
        match install_cmd
            .arg("install")
            .arg(&module_with_version)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                // Stream stdout and stderr concurrently
                let stdout = child.stdout.take();
                let stderr = child.stderr.take();

                let event_id_clone = event_id.clone();
                let app_handle_clone = self.app_handle.clone();

                let stdout_task = tokio::spawn(async move {
                    if let Some(stdout) = stdout {
                        let reader = BufReader::new(stdout);
                        let mut lines = reader.lines();

                        while let Ok(Some(line)) = lines.next_line().await {
                            let _ = app_handle_clone.emit(
                                "tool:installation_output",
                                serde_json::json!({
                                    "event_id": event_id_clone,
                                    "output": format!("{}\n", line)
                                }),
                            );
                        }
                    }
                });

                let event_id_clone2 = event_id.clone();
                let app_handle_clone2 = self.app_handle.clone();
                let stderr_task = tokio::spawn(async move {
                    if let Some(stderr) = stderr {
                        let reader = BufReader::new(stderr);
                        let mut lines = reader.lines();

                        while let Ok(Some(line)) = lines.next_line().await {
                            let _ = app_handle_clone2.emit(
                                "tool:installation_output",
                                serde_json::json!({
                                    "event_id": event_id_clone2,
                                    "output": format!("{}\n", line)
                                }),
                            );
                        }
                    }
                });

                // Wait for both streams to complete
                let _ = tokio::join!(stdout_task, stderr_task);

                match child.wait().await {
                    Ok(status) => {
                        if status.success() {
                            // Check if the binary was installed successfully
                            if let Some(installed_path) = self.get_tool_path(tool_name) {
                                self.emit_output(
                                    &event_id,
                                    &format!(
                                        "✅ Successfully installed {} to {}\n",
                                        tool_name, installed_path
                                    ),
                                );
                                Ok(InstallationResult {
                                    success: true,
                                    message: format!(
                                        "Successfully installed {} to {}",
                                        tool_name, installed_path
                                    ),
                                    tool_name: tool_name.to_string(),
                                    installed_path: Some(installed_path),
                                })
                            } else {
                                self.emit_output(&event_id, &format!("⚠️ Installation completed but {} binary not found in GOPATH/bin\n", tool_name));
                                Ok(InstallationResult {
                                    success: false,
                                    message: format!("Installation completed but {} binary not found in GOPATH/bin", tool_name),
                                    tool_name: tool_name.to_string(),
                                    installed_path: None,
                                })
                            }
                        } else {
                            self.emit_output(
                                &event_id,
                                &format!("❌ Failed to install {}\n", tool_name),
                            );
                            Ok(InstallationResult {
                                success: false,
                                message: format!(
                                    "Failed to install {}: go install exited with non-zero status",
                                    tool_name
                                ),
                                tool_name: tool_name.to_string(),
                                installed_path: None,
                            })
                        }
                    }
                    Err(e) => Ok(InstallationResult {
                        success: false,
                        message: format!("Failed to wait for installation: {}", e),
                        tool_name: tool_name.to_string(),
                        installed_path: None,
                    }),
                }
            }
            Err(e) => Ok(InstallationResult {
                success: false,
                message: format!("Failed to start go install: {}", e),
                tool_name: tool_name.to_string(),
                installed_path: None,
            }),
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
    pub async fn update(
        &self,
        module_path: &str,
        tool_name: &str,
    ) -> Result<InstallationResult, String> {
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

        // Primary method: Use 'go version -m' for Go tools
        // This is reliable and consistent with update checking
        if let Some(tool_path) = self.get_tool_path(tool_name) {
            match self.get_version_from_binary(&tool_path).await {
                Ok(version) => {
                    eprintln!("   ✅ Got version from 'go version -m': {}", version);
                    return Some(version);
                }
                Err(e) => {
                    eprintln!("   ⚠️  Failed to get version from 'go version -m': {}", e);
                    // Fall through to try version flags
                }
            }
        }

        // Fallback: Try common version flags
        eprintln!("   🔄 Trying version flags as fallback...");
        let version_flags = vec!["--version", "-version", "-v", "version"];

        for flag in version_flags {
            let mut version_cmd = hidden_command(tool_name);
            match version_cmd
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
                                let version = version_output.lines().next()?.trim().to_string();
                                eprintln!("   ✅ Got version from '{}' flag: {}", flag, version);
                                return Some(version);
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        eprintln!("   ❌ Could not determine version for {}", tool_name);
        None
    }

    /// Get version from Go binary using 'go version -m'
    /// This method is consistent with update checking logic
    async fn get_version_from_binary(&self, tool_path: &str) -> Result<String, String> {
        let mut version_cmd = hidden_command("go");
        let output = version_cmd
            .arg("version")
            .arg("-m")
            .arg(tool_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("Failed to execute go version: {}", e))?;

        if !output.status.success() {
            return Err("go version command failed".to_string());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output: look for "mod" line with version
        // Format: "mod    module_path    version    hash"
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("mod") {
                // Split by any whitespace (spaces or tabs)
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                // parts[0] = "mod", parts[1] = module_path, parts[2] = version
                if parts.len() >= 3 {
                    let version = parts[2].trim_start_matches('v');
                    return Ok(version.to_string());
                }
            }
        }

        Err("Could not parse version from go version -m output".to_string())
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
                    Ok(format!(
                        "Successfully uninstalled {} from {}",
                        tool_name, tool_path
                    ))
                }
                Err(e) => {
                    let error_msg = format!("Failed to remove {}: {}", tool_path, e);
                    eprintln!("Error: {}", error_msg);
                    Err(error_msg)
                }
            }
        } else {
            Err(format!(
                "{} is not installed or not found in GOPATH/bin",
                tool_name
            ))
        }
    }

    /// List all Go tools installed in GOPATH/bin
    ///
    /// # Returns
    /// * Vector of tool names found in GOPATH/bin
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use tauri::AppHandle;

    fn mock_app_handle() -> AppHandle {
        // Create a minimal mock AppHandle for testing
        // In a real implementation, this would need proper Tauri setup
        // For now, we'll skip these tests that require AppHandle
        panic!("Mock AppHandle needed for testing")
    }

    #[tokio::test]
    async fn test_go_install_manager_creation() {
        // Skip this test for now as it requires AppHandle setup
        // let manager = GoInstallManager::new(mock_app_handle());
        // assert!(manager._go_path.is_some() || manager.go_bin_path.is_some());
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
        // Skip this test for now as it requires AppHandle setup
        // let manager = GoInstallManager::new(mock_app_handle());
        // This will fail if Go is not installed, which is acceptable for tests
        // let _ = manager.is_go_available().await;
    }
}
