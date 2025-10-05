use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::path::{Path, PathBuf};
use tauri::Manager;

use crate::events::{EventEmitter, TOOL_INSTALLATION_STARTED, TOOL_INSTALLATION_OUTPUT, TOOL_INSTALLATION_COMPLETED};

/// GitPipInstaller: Handles Python tool installations via git clone + pip install
/// This method is more reliable than pipx for Python CLI tools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitPipInstaller {
    install_base_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationResult {
    pub success: bool,
    pub message: String,
    pub tool_name: String,
    pub installed_path: Option<String>,
}

impl GitPipInstaller {
    pub fn new() -> Self {
        // Use a location outside src-tauri to avoid triggering Tauri's file watcher during dev
        // In production, this will be in the user's data directory
        // In dev mode, this will be at the workspace root, not inside src-tauri
        let install_base_dir = if cfg!(debug_assertions) {
            // Dev mode: Use workspace root/tools/python-tools (outside src-tauri)
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .parent() // Go up from src-tauri to workspace root
                .unwrap_or_else(|| Path::new("."))
                .join("tools")
                .join("python-tools")
        } else {
            // Production: Use app data directory
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("ai-bug-bounty-scanner")
                .join("tools")
                .join("python-tools")
        };
        
        Self { install_base_dir }
    }

    /// Check if git is installed
    pub async fn is_git_available(&self) -> bool {
        match Command::new("git")
            .arg("--version")
            .output()
            .await
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    /// Check if python/pip is installed
    pub async fn is_python_available(&self) -> bool {
        // Try python3 first, then python
        for python_cmd in &["python3", "python"] {
            if let Ok(output) = Command::new(python_cmd)
                .arg("--version")
                .output()
                .await
            {
                if output.status.success() {
                    return true;
                }
            }
        }
        false
    }

    /// Get the python command (python3 or python)
    async fn get_python_command(&self) -> Option<String> {
        for python_cmd in &["python3", "python"] {
            if let Ok(output) = Command::new(python_cmd)
                .arg("--version")
                .output()
                .await
            {
                if output.status.success() {
                    return Some(python_cmd.to_string());
                }
            }
        }
        None
    }

    /// Install a Python tool via git clone + pip install
    /// 
    /// # Arguments
    /// * `git_repo` - Git repository URL (e.g., "https://github.com/mschwager/fierce.git")
    /// * `tool_name` - Tool name (e.g., "fierce")
    /// * `app_handle` - Optional Tauri AppHandle for emitting events
    /// 
    /// # Returns
    /// * `InstallationResult` with success status and message
    pub async fn install(
        &self,
        git_repo: &str,
        tool_name: &str,
        app_handle: Option<&tauri::AppHandle>
    ) -> Result<InstallationResult, String> {
        // Check prerequisites
        if !self.is_git_available().await {
            return Ok(InstallationResult {
                success: false,
                message: "git is not installed. Please install git first.".to_string(),
                tool_name: tool_name.to_string(),
                installed_path: None,
            });
        }

        if !self.is_python_available().await {
            return Ok(InstallationResult {
                success: false,
                message: "Python is not installed. Please install Python first.".to_string(),
                tool_name: tool_name.to_string(),
                installed_path: None,
            });
        }

        let python_cmd = self.get_python_command().await.unwrap();

        eprintln!("📦 Installing {} via git clone + pip install", tool_name);
        eprintln!("   Repository: {}", git_repo);

        // Emit installation started event
        if let Some(handle) = app_handle {
            let _ = handle.emit_all(
                TOOL_INSTALLATION_STARTED,
                EventEmitter::tool_installation_started(tool_name, "git-pip")
            );
        }

        // Create install base directory
        if let Err(e) = std::fs::create_dir_all(&self.install_base_dir) {
            let error_msg = format!("Failed to create install directory: {}", e);
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

        let clone_path = self.install_base_dir.join(tool_name);

        // Remove existing directory if present
        if clone_path.exists() {
            eprintln!("🗑️  Removing existing installation at {}", clone_path.display());
            if let Err(e) = std::fs::remove_dir_all(&clone_path) {
                eprintln!("⚠️  Failed to remove existing directory: {}", e);
            }
        }

        // Step 1: Clone repository
        eprintln!("📥 Cloning repository...");
        let clone_result = self.run_command_with_output(
            "git",
            &["clone", git_repo, clone_path.to_str().unwrap()],
            tool_name,
            "git clone",
            app_handle
        ).await?;

        if !clone_result {
            let error_msg = format!("Failed to clone repository: {}", git_repo);
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

        // Step 2: Install with pip
        eprintln!("📦 Installing with pip...");
        
        // Check if requirements.txt exists
        let requirements_path = clone_path.join("requirements.txt");
        if requirements_path.exists() {
            eprintln!("📋 Found requirements.txt, installing dependencies...");
            let requirements_result = self.run_command_with_output(
                &python_cmd,
                &["-m", "pip", "install", "-r", requirements_path.to_str().unwrap()],
                tool_name,
                "pip install requirements",
                app_handle
            ).await?;

            if !requirements_result {
                eprintln!("⚠️  Failed to install requirements, continuing with main install...");
            }
        }

        // Install the package itself (editable mode for local development)
        let install_result = self.run_command_with_output(
            &python_cmd,
            &["-m", "pip", "install", "-e", clone_path.to_str().unwrap()],
            tool_name,
            "pip install",
            app_handle
        ).await?;

        if !install_result {
            // Try alternative: install setup.py if present
            let setup_py = clone_path.join("setup.py");
            if setup_py.exists() {
                eprintln!("📦 Trying setup.py install...");
                let setup_result = self.run_command_with_output(
                    &python_cmd,
                    &[setup_py.to_str().unwrap(), "install"],
                    tool_name,
                    "setup.py install",
                    app_handle
                ).await?;

                if !setup_result {
                    let error_msg = format!("Failed to install {} with pip or setup.py", tool_name);
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
                        installed_path: Some(clone_path.to_string_lossy().to_string()),
                    });
                }
            } else {
                let error_msg = format!("Failed to install {}: no setup.py found", tool_name);
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
                    installed_path: Some(clone_path.to_string_lossy().to_string()),
                });
            }
        }

        // Success
        let success_msg = format!("✅ Successfully installed {} via git-pip", tool_name);
        eprintln!("{}", success_msg);

        if let Some(handle) = app_handle {
            let _ = handle.emit_all(
                TOOL_INSTALLATION_COMPLETED,
                EventEmitter::tool_installation_completed(tool_name, true, &success_msg)
            );
        }

        Ok(InstallationResult {
            success: true,
            message: success_msg,
            tool_name: tool_name.to_string(),
            installed_path: Some(clone_path.to_string_lossy().to_string()),
        })
    }

    /// Run a command with live output streaming
    async fn run_command_with_output(
        &self,
        command: &str,
        args: &[&str],
        tool_name: &str,
        step_name: &str,
        app_handle: Option<&tauri::AppHandle>
    ) -> Result<bool, String> {
        eprintln!("🔧 Running: {} {}", command, args.join(" "));

        let mut child = match Command::new(command)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                let error_msg = format!("Failed to spawn command '{}': {}", command, e);
                eprintln!("❌ {}", error_msg);
                
                if let Some(handle) = app_handle {
                    let _ = handle.emit_all(
                        TOOL_INSTALLATION_OUTPUT,
                        EventEmitter::tool_installation_output(tool_name, "stderr", &error_msg)
                    );
                }
                
                return Ok(false);
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
        let step_name_clone = step_name.to_string();
        let handle_clone = app_handle.map(|h| h.clone());
        let stdout_task = tokio::spawn(async move {
            let mut lines = stdout_reader;
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[{}] {}", step_name_clone, line);
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
        let step_name_clone = step_name.to_string();
        let handle_clone = app_handle.map(|h| h.clone());
        let stderr_task = tokio::spawn(async move {
            let mut lines = stderr_reader;
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[{} stderr] {}", step_name_clone, line);
                if let Some(handle) = &handle_clone {
                    let _ = handle.emit_all(
                        TOOL_INSTALLATION_OUTPUT,
                        EventEmitter::tool_installation_output(&tool_name_clone, "stderr", &line)
                    );
                }
            }
        });

        // Wait for process and output tasks
        let (status, _, _) = tokio::join!(
            child.wait(),
            stdout_task,
            stderr_task
        );

        match status {
            Ok(exit_status) => Ok(exit_status.success()),
            Err(e) => {
                let error_msg = format!("Failed to execute command: {}", e);
                eprintln!("❌ {}", error_msg);
                Ok(false)
            }
        }
    }

    /// Uninstall a tool via pip uninstall
    pub async fn uninstall(&self, tool_name: &str) -> Result<String, String> {
        if !self.is_python_available().await {
            return Err("Python is not installed.".to_string());
        }

        let python_cmd = self.get_python_command().await.unwrap();

        eprintln!("🗑️  Uninstalling {} via pip", tool_name);

        match Command::new(&python_cmd)
            .args(&["-m", "pip", "uninstall", "-y", tool_name])
            .output()
            .await
        {
            Ok(output) => {
                if output.status.success() {
                    // Also remove cloned directory
                    let clone_path = self.install_base_dir.join(tool_name);
                    if clone_path.exists() {
                        if let Err(e) = std::fs::remove_dir_all(&clone_path) {
                            eprintln!("⚠️  Failed to remove directory {}: {}", clone_path.display(), e);
                        }
                    }
                    
                    Ok(format!("Successfully uninstalled {}", tool_name))
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(format!("Failed to uninstall {}: {}", tool_name, stderr.trim()))
                }
            }
            Err(e) => {
                Err(format!("Failed to execute pip uninstall: {}", e))
            }
        }
    }
}
