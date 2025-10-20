use crate::events::{EventEmitter, TOOL_INSTALLATION_OUTPUT};
use crate::tools::catalog::ToolDefinition;
use crate::tools::package_managers::{detection::detect_manager, PackageManagerType};
use anyhow::{anyhow, Context, Result};
use std::process::Stdio;
use tauri::Emitter;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[cfg(target_os = "windows")]
use crate::tools::package_managers::winget_manager::WingetManager;

/// Installer for Node.js tools using npm
pub struct NpmInstaller {
    app_handle: tauri::AppHandle,
}

impl NpmInstaller {
    pub fn new(app_handle: tauri::AppHandle) -> Self {
        Self { app_handle }
    }

    /// Get npm path using the detection system
    async fn get_npm_path(&self) -> Option<String> {
        let info = detect_manager(PackageManagerType::Npm).await;
        if info.available {
            info.path.or(Some({
                #[cfg(target_os = "windows")]
                {
                    "npm.cmd".to_string()
                }

                #[cfg(not(target_os = "windows"))]
                {
                    "npm".to_string()
                }
            }))
        } else {
            None
        }
    }

    /// Check if Node.js and npm are installed
    async fn check_node_installed(&self) -> Result<bool> {
        let output = Command::new("node").arg("--version").output().await;

        match output {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }

    async fn check_npm_installed(&self) -> Result<bool> {
        // Use detection system instead of hardcoded command
        let info = detect_manager(PackageManagerType::Npm).await;
        Ok(info.available)
    }

    /// Check if WinGet is available (Windows only)
    #[cfg(target_os = "windows")]
    async fn check_winget_available(&self) -> bool {
        let info = detect_manager(PackageManagerType::WinGet).await;
        info.available
    }

    /// Install Node.js (platform-specific)
    async fn install_nodejs(&self, tool_name: &str) -> Result<()> {
        self.emit_output(tool_name, "📦 Node.js/npm not found.\n");

        #[cfg(target_os = "windows")]
        {
            // Try WinGet first on Windows
            if self.check_winget_available().await {
                self.emit_output(
                    tool_name,
                    "🔍 Found WinGet. Installing Node.js automatically...\n",
                );
                self.emit_output(tool_name, "📦 Package: OpenJS.NodeJS\n");

                let winget_manager = WingetManager::new(self.app_handle.clone());
                match winget_manager.install("OpenJS.NodeJS", tool_name).await {
                    Ok(_) => {
                        self.emit_output(
                            tool_name,
                            "✅ Node.js installed successfully via WinGet\n",
                        );
                        self.emit_output(
                            tool_name,
                            "⚠️  Please restart the application for changes to take effect\n",
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        self.emit_output(
                            tool_name,
                            &format!("⚠️  WinGet installation failed: {}\n", e),
                        );
                        self.emit_output(
                            tool_name,
                            "Falling back to manual installation instructions...\n",
                        );
                    }
                }
            }

            // Fallback to manual instructions if WinGet not available or failed
            self.emit_output(tool_name, "⚠️  Automatic installation not available.\n");
            self.emit_output(tool_name, "\n📋 Manual Installation Options:\n");
            self.emit_output(tool_name, "\n1️⃣  Using WinGet (Recommended):\n");
            self.emit_output(tool_name, "   winget install OpenJS.NodeJS\n");
            self.emit_output(tool_name, "\n2️⃣  Direct Download:\n");
            self.emit_output(tool_name, "   Visit: https://nodejs.org/\n");
            self.emit_output(tool_name, "   Download the Windows installer and run it\n");
            self.emit_output(tool_name, "\n3️⃣  Using Chocolatey:\n");
            self.emit_output(tool_name, "   choco install nodejs\n");
            self.emit_output(
                tool_name,
                "\n⚠️  After installation, restart the application and try again.\n",
            );
            return Err(anyhow!(
                "Node.js must be installed. See installation options above."
            ));
        }

        #[cfg(target_os = "linux")]
        {
            let elevation = ElevationHelper::new();
            let elevation_msg = elevation.get_elevation_message().await;
            self.emit_output(tool_name, elevation_msg);
            self.emit_output(tool_name, "Installing Node.js via apt...\n");

            let (elevation_cmd, elevation_args) = elevation
                .elevate_command(&["apt", "install", "-y", "nodejs", "npm"])
                .await;

            let mut child = Command::new(elevation_cmd)
                .args(&elevation_args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to spawn apt install")?;

            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    self.emit_output(tool_name, &format!("{}\n", line));
                }
            }

            let status = child.wait().await?;
            if !status.success() {
                return Err(anyhow!("Failed to install Node.js via apt"));
            }

            self.emit_output(tool_name, "✅ Node.js installed successfully\n");
        }

        #[cfg(target_os = "macos")]
        {
            self.emit_output(tool_name, "Installing Node.js via Homebrew...\n");

            let mut child = Command::new("brew")
                .args(&["install", "node"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to spawn brew install")?;

            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    self.emit_output(tool_name, &format!("{}\n", line));
                }
            }

            let status = child.wait().await?;
            if !status.success() {
                return Err(anyhow!("Failed to install Node.js via Homebrew"));
            }

            self.emit_output(tool_name, "✅ Node.js installed successfully\n");
        }

        Ok(())
    }

    /// Install a tool using npm globally
    pub async fn install(&self, tool: &ToolDefinition, tool_name: &str) -> Result<String> {
        self.emit_output(
            tool_name,
            &format!("🚀 Starting npm installation for {}...\n", tool.name),
        );

        // Check if Node.js and npm are installed
        if !self.check_node_installed().await? || !self.check_npm_installed().await? {
            self.emit_output(
                tool_name,
                "⚠️  Node.js/npm not found. Attempting installation...\n",
            );
            self.install_nodejs(tool_name).await?;
        }

        // Get the npm path using detection system
        let npm_path = self.get_npm_path().await.ok_or_else(|| {
            anyhow!("npm is not available. Please install Node.js from: https://nodejs.org/")
        })?;

        self.emit_output(tool_name, &format!("📍 Using npm at: {}\n", npm_path));

        // Get the package name from npm_package field
        let package_name = tool
            .npm_package
            .as_ref()
            .ok_or_else(|| anyhow!("Tool {} does not have npm_package defined", tool.name))?;

        // Platform-specific installation strategy
        // Linux/macOS: Install to user directory (~/.local) to avoid permission issues
        // Windows: Install globally (standard behavior)
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let prefix_path = if let Ok(home) = std::env::var("HOME") {
            format!("{}/.local", home)
        } else {
            String::new()
        };

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let install_args: Vec<&str> = if !prefix_path.is_empty() {
            self.emit_output(
                tool_name,
                &format!(
                    "📦 Installing {} to user directory (~/.local)...\n",
                    package_name
                ),
            );
            self.emit_output(tool_name, "💡 Note: Ensure ~/.local/bin is in your PATH\n");
            vec!["install", "-g", package_name, "--prefix", &prefix_path]
        } else {
            // Fallback to global if HOME not found (unlikely)
            self.emit_output(
                tool_name,
                &format!("📦 Installing {} via npm globally...\n", package_name),
            );
            vec!["install", "-g", package_name]
        };

        #[cfg(target_os = "windows")]
        let install_args: Vec<&str> = {
            self.emit_output(
                tool_name,
                &format!("📦 Installing {} via npm globally...\n", package_name),
            );
            vec!["install", "-g", package_name]
        };

        // Run npm install with platform-specific args
        let mut child = Command::new(&npm_path)
            .args(&install_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn npm install")?;

        // Stream stdout and stderr concurrently
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
                            let event = EventEmitter::tool_installation_output(
                                &tool_name_clone,
                                "stdout",
                                &format!("{}\n", line),
                            );
                            let _ = app_handle_clone.emit(TOOL_INSTALLATION_OUTPUT, event);
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("Error reading npm stdout: {}", e);
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
                            // npm outputs warnings to stderr, emit them
                            let event = EventEmitter::tool_installation_output(
                                &tool_name_clone2,
                                "stderr",
                                &format!("{}\n", line),
                            );
                            let _ = app_handle_clone2.emit(TOOL_INSTALLATION_OUTPUT, event);
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("Error reading npm stderr: {}", e);
                            break;
                        }
                    }
                }
            }
        });

        // Wait for both streams with timeout
        let timeout_duration = tokio::time::Duration::from_secs(600); // 10 minute timeout
        let join_handle = tokio::spawn(async move {
            let _ = tokio::join!(stdout_task, stderr_task);
        });

        match tokio::time::timeout(timeout_duration, join_handle).await {
            Ok(_) => {}
            Err(_) => {
                // Timeout occurred but streams are still running in background
            }
        }

        let status = child
            .wait()
            .await
            .context("Failed to wait for npm install")?;

        if !status.success() {
            let error_msg = if let Some(code) = status.code() {
                format!(
                    "❌ Failed to install {} via npm (exit code: {})\n",
                    tool.name, code
                )
            } else {
                format!(
                    "❌ Failed to install {} via npm (process terminated)\n",
                    tool.name
                )
            };
            self.emit_output(tool_name, &error_msg);
            self.emit_output(
                tool_name,
                "💡 Tip: Check if Node.js/npm is properly installed and package name is correct\n",
            );
            return Err(anyhow!("npm install failed with status: {}. Verify Node.js installation and network connectivity.", status));
        }

        self.emit_output(
            tool_name,
            &format!("✅ Successfully installed {} via npm\n", tool.name),
        );

        // Verify installation with error recovery
        match self.verify_installation(tool).await {
            Ok(version) => {
                self.emit_output(tool_name, &format!("📋 Version: {}\n", version));
            }
            Err(e) => {
                self.emit_output(
                    tool_name,
                    &format!("⚠️  Warning: Could not verify installation: {}\n", e),
                );
                self.emit_output(tool_name, "💡 The tool may be installed globally but not in PATH. Try restarting your terminal.\n");
                // Don't fail the installation if verification fails
            }
        }

        Ok(format!(
            "Successfully installed {} globally via npm",
            tool.name
        ))
    }

    /// Verify that the tool is installed and get version
    pub async fn verify_installation(&self, tool: &ToolDefinition) -> Result<String> {
        let package_name = tool
            .npm_package
            .as_ref()
            .ok_or_else(|| anyhow!("Tool {} does not have npm_package defined", tool.name))?;

        // Extract command name (usually same as package name, but could differ)
        let command_name = if package_name.contains('/') {
            // Scoped package like @org/package - use last part
            package_name.split('/').last().unwrap_or(package_name)
        } else {
            package_name
        };

        // Try to get version
        let output = Command::new(command_name)
            .arg("--version")
            .output()
            .await
            .context(format!("Failed to verify {} installation", command_name))?;

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(version)
        } else {
            Err(anyhow!(
                "{} is not properly installed or not in PATH",
                command_name
            ))
        }
    }

    /// Update an npm package
    pub async fn update(&self, tool: &ToolDefinition, tool_name: &str) -> Result<String> {
        self.emit_output(tool_name, &format!("🔄 Updating {}...\n", tool.name));

        let package_name = tool
            .npm_package
            .as_ref()
            .ok_or_else(|| anyhow!("Tool {} does not have npm_package defined", tool.name))?;

        // Check if we need privilege elevation on Linux
        // npm global packages typically install to /usr/local which requires sudo/pkexec
        #[cfg(target_os = "linux")]
        {
            use crate::tools::package_managers::elevation_helper::ElevationHelper;

            let elevation = ElevationHelper::new();
            let elevation_msg = elevation.get_elevation_message().await;
            self.emit_output(tool_name, elevation_msg);

            let (elevation_cmd, elevation_args) = elevation
                .elevate_command(&["npm", "update", "-g", package_name])
                .await;

            let mut child = Command::new(elevation_cmd)
                .args(&elevation_args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to spawn npm update")?;

            // Stream output
            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    self.emit_output(tool_name, &format!("{}\n", line));
                }
            }

            if let Some(stderr) = child.stderr.take() {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    self.emit_output(tool_name, &format!("{}\n", line));
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
                self.emit_output(tool_name, "💡 Tip: The package may not be installed globally or may require different permissions\n");
                return Err(anyhow!(
                    "npm update failed for {}. Check if the package is installed globally.",
                    tool.name
                ));
            }

            self.emit_output(
                tool_name,
                &format!("✅ Successfully updated {}\n", tool.name),
            );
            return Ok(format!("Successfully updated {}", tool.name));
        }

        // Windows - no elevation needed, npm handles permissions
        #[cfg(not(target_os = "linux"))]
        {
            let mut child = Command::new("npm")
                .args(&["update", "-g", package_name])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to spawn npm update")?;

            // Stream output
            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    self.emit_output(tool_name, &format!("{}\n", line));
                }
            }

            if let Some(stderr) = child.stderr.take() {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    self.emit_output(tool_name, &format!("{}\n", line));
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
                self.emit_output(tool_name, "💡 Tip: The package may not be installed globally or may require different permissions\n");
                return Err(anyhow!(
                    "npm update failed for {}. Check if the package is installed globally.",
                    tool.name
                ));
            }

            self.emit_output(
                tool_name,
                &format!("✅ Successfully updated {}\n", tool.name),
            );
            return Ok(format!("Successfully updated {}", tool.name));
        }
    }

    /// Uninstall an npm package
    pub async fn uninstall(&self, tool: &ToolDefinition) -> Result<String> {
        let package_name = tool
            .npm_package
            .as_ref()
            .ok_or_else(|| anyhow!("Tool {} does not have npm_package defined", tool.name))?;

        let output = Command::new("npm")
            .args(&["uninstall", "-g", package_name])
            .output()
            .await
            .context("Failed to uninstall npm package")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not installed") || stderr.contains("ERR! 404") {
                return Err(anyhow!(
                    "Package '{}' is not installed globally or already removed",
                    package_name
                ));
            }
            return Err(anyhow!(
                "Failed to uninstall {}: {}. Check if package is installed globally.",
                package_name,
                stderr.trim()
            ));
        }

        Ok(format!("Successfully uninstalled {}", tool.name))
    }

    fn emit_output(&self, tool_name: &str, message: &str) {
        let event = EventEmitter::tool_installation_output(tool_name, "stdout", message);
        let _ = self.app_handle.emit(TOOL_INSTALLATION_OUTPUT, event);
    }
}
