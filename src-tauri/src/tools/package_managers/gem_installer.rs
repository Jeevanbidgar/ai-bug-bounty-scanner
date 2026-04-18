use crate::events::{EventEmitter, TOOL_INSTALLATION_OUTPUT};
use crate::runtime::process::hidden_tokio_command as hidden_command;
use crate::tools::catalog::ToolDefinition;
use crate::tools::package_managers::{detection::detect_manager, PackageManagerType};
use anyhow::{anyhow, Context, Result};
use std::process::Stdio;
use tauri::Emitter;
use tokio::io::{AsyncBufReadExt, BufReader};

#[cfg(target_os = "windows")]
use crate::tools::package_managers::winget_manager::WingetManager;

/// Installer for Ruby tools using gem
pub struct GemInstaller {
    app_handle: tauri::AppHandle,
}

impl GemInstaller {
    pub fn new(app_handle: tauri::AppHandle) -> Self {
        Self { app_handle }
    }

    /// Get gem path using the detection system
    async fn get_gem_path(&self) -> Option<String> {
        let info = detect_manager(PackageManagerType::Gem).await;
        if info.available {
            info.path.or(Some({
                #[cfg(target_os = "windows")]
                {
                    "gem.cmd".to_string()
                }

                #[cfg(not(target_os = "windows"))]
                {
                    "gem".to_string()
                }
            }))
        } else {
            None
        }
    }

    /// Check if Ruby and gem are installed
    async fn check_ruby_installed(&self) -> Result<bool> {
        let mut cmd = hidden_command("ruby");
        let output = cmd.arg("--version").output().await;

        match output {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }

    async fn check_gem_installed(&self) -> Result<bool> {
        // Use detection system for better Windows support
        let info = detect_manager(PackageManagerType::Gem).await;
        Ok(info.available)
    }

    /// Check if WinGet is available (Windows only)
    #[cfg(target_os = "windows")]
    async fn check_winget_available(&self) -> bool {
        let info = detect_manager(PackageManagerType::WinGet).await;
        info.available
    }

    /// Install Ruby (platform-specific)
    async fn install_ruby(&self, tool_name: &str) -> Result<()> {
        self.emit_output(tool_name, "📦 Ruby/gem not found.\n");

        #[cfg(target_os = "windows")]
        {
            // Try WinGet first on Windows
            if self.check_winget_available().await {
                self.emit_output(
                    tool_name,
                    "🔍 Found WinGet. Installing Ruby automatically...\n",
                );
                self.emit_output(
                    tool_name,
                    "📦 Package: RubyInstallerTeam.Ruby (with DevKit)\n",
                );

                let winget_manager = WingetManager::new(self.app_handle.clone());
                // Install Ruby with DevKit for gem native extensions
                match winget_manager
                    .install("RubyInstallerTeam.Ruby.3.3", tool_name)
                    .await
                {
                    Ok(_) => {
                        self.emit_output(tool_name, "✅ Ruby installed successfully via WinGet\n");
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
            self.emit_output(tool_name, "   winget install RubyInstallerTeam.Ruby.3.3\n");
            self.emit_output(tool_name, "\n2️⃣  Direct Download:\n");
            self.emit_output(tool_name, "   Visit: https://rubyinstaller.org/\n");
            self.emit_output(tool_name, "   Download Ruby+DevKit installer and run it\n");
            self.emit_output(tool_name, "\n3️⃣  Using Chocolatey:\n");
            self.emit_output(tool_name, "   choco install ruby\n");
            self.emit_output(
                tool_name,
                "\n⚠️  After installation, restart the application and try again.\n",
            );
            return Err(anyhow!(
                "Ruby must be installed. See installation options above."
            ));
        }

        #[cfg(target_os = "linux")]
        {
            let elevation = ElevationHelper::new();
            let elevation_msg = elevation.get_elevation_message().await;
            self.emit_output(tool_name, elevation_msg);
            self.emit_output(tool_name, "Installing Ruby via apt...\n");

            let (elevation_cmd, elevation_args) = elevation
                .elevate_command(&["apt", "install", "-y", "ruby", "ruby-dev"])
                .await;

            let mut install_cmd = hidden_command(elevation_cmd);
            let mut child = install_cmd
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
                return Err(anyhow!("Failed to install Ruby via apt"));
            }

            self.emit_output(tool_name, "✅ Ruby installed successfully\n");
        }

        #[cfg(target_os = "macos")]
        {
            // Try brew (macOS)
            self.emit_output(tool_name, "Installing Ruby via Homebrew...\n");

            let mut brew_cmd = hidden_command("brew");
            let mut child = brew_cmd
                .args(&["install", "ruby"])
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
                return Err(anyhow!("Failed to install Ruby via Homebrew"));
            }

            self.emit_output(tool_name, "✅ Ruby installed successfully\n");
        }

        Ok(())
    }

    /// Install a tool using gem
    pub async fn install(&self, tool: &ToolDefinition, tool_name: &str) -> Result<String> {
        self.emit_output(
            tool_name,
            &format!("🚀 Starting gem installation for {}...\n", tool.name),
        );

        // Check if Ruby and gem are installed
        if !self.check_ruby_installed().await? || !self.check_gem_installed().await? {
            self.emit_output(
                tool_name,
                "⚠️  Ruby/gem not found. Attempting installation...\n",
            );
            self.install_ruby(tool_name).await?;
        }

        // Get the gem path using detection system
        let gem_path = self.get_gem_path().await.ok_or_else(|| {
            anyhow!("gem is not available. Please install Ruby from: https://rubyinstaller.org/")
        })?;

        self.emit_output(tool_name, &format!("📍 Using gem at: {}\n", gem_path));

        // Get the package name from gem_package field
        let package_name = tool
            .gem_package
            .as_ref()
            .ok_or_else(|| anyhow!("Tool {} does not have gem_package defined", tool.name))?;

        self.emit_output(
            tool_name,
            &format!("💎 Installing {} via gem...\n", package_name),
        );

        // Run gem install with detected path
        let mut install_cmd = hidden_command(&gem_path);
        let mut child = install_cmd
            .args(&["install", package_name])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn gem install")?;

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
                        Ok(None) => break, // Stream ended
                        Err(e) => {
                            eprintln!("Error reading gem stdout: {}", e);
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
                            let event = EventEmitter::tool_installation_output(
                                &tool_name_clone2,
                                "stderr",
                                &format!("{}\n", line),
                            );
                            let _ = app_handle_clone2.emit(TOOL_INSTALLATION_OUTPUT, event);
                        }
                        Ok(None) => break, // Stream ended
                        Err(e) => {
                            eprintln!("Error reading gem stderr: {}", e);
                            break;
                        }
                    }
                }
            }
        });

        // Wait for both streams to complete with timeout
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
            .context("Failed to wait for gem install")?;

        if !status.success() {
            let error_msg = if let Some(code) = status.code() {
                format!(
                    "❌ Failed to install {} via gem (exit code: {})\n",
                    tool.name, code
                )
            } else {
                format!(
                    "❌ Failed to install {} via gem (process terminated)\n",
                    tool.name
                )
            };
            self.emit_output(tool_name, &error_msg);
            self.emit_output(
                tool_name,
                "💡 Tip: Check if Ruby is properly installed and gem command is in PATH\n",
            );
            return Err(anyhow!(
                "Gem install failed with status: {}. Check Ruby installation and permissions.",
                status
            ));
        }

        self.emit_output(
            tool_name,
            &format!("✅ Successfully installed {} via gem\n", tool.name),
        );

        // For wpscan, update the database
        if package_name == "wpscan" {
            self.emit_output(tool_name, "📡 Updating WPScan database...\n");
            let mut wpscan_cmd = hidden_command("wpscan");
            let _ = wpscan_cmd.arg("--update").output().await;
            self.emit_output(tool_name, "✅ WPScan database updated\n");
        }

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
                self.emit_output(
                    tool_name,
                    "💡 The tool may be installed but not in PATH. Try restarting your terminal.\n",
                );
                // Don't fail the installation if verification fails
            }
        }

        Ok(format!("Successfully installed {} via gem", tool.name))
    }

    /// Verify that the tool is installed and get version
    pub async fn verify_installation(&self, tool: &ToolDefinition) -> Result<String> {
        let package_name = tool
            .gem_package
            .as_ref()
            .ok_or_else(|| anyhow!("Tool {} does not have gem_package defined", tool.name))?;

        // Try to get version
        let mut verify_cmd = hidden_command(package_name);
        let output = verify_cmd
            .arg("--version")
            .output()
            .await
            .context(format!("Failed to verify {} installation", package_name))?;

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(version)
        } else {
            Err(anyhow!(
                "{} is not properly installed or not in PATH",
                package_name
            ))
        }
    }

    /// Update a gem package
    pub async fn update(&self, tool: &ToolDefinition, tool_name: &str) -> Result<String> {
        self.emit_output(tool_name, &format!("🔄 Updating {}...\n", tool.name));

        let package_name = tool
            .gem_package
            .as_ref()
            .ok_or_else(|| anyhow!("Tool {} does not have gem_package defined", tool.name))?;

        // On Linux, try to detect if we need elevated privileges
        // First, try without elevation (works for user-installed gems)
        #[cfg(target_os = "linux")]
        {
            use crate::tools::package_managers::elevation_helper::ElevationHelper;

            // First attempt without elevation (for user gems in ~/.local/share/gem)
            let mut update_cmd = hidden_command("gem");
            let mut child = update_cmd
                .args(&["update", package_name])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to spawn gem update")?;

            // Stream output
            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    self.emit_output(tool_name, &format!("{}\n", line));
                }
            }

            let mut stderr_output = String::new();
            if let Some(stderr) = child.stderr.take() {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    stderr_output.push_str(&line);
                    stderr_output.push('\n');
                    self.emit_output(tool_name, &format!("{}\n", line));
                }
            }

            let status = child.wait().await?;

            // If it failed due to permissions, retry with pkexec
            if !status.success()
                && (stderr_output.contains("Permission denied")
                    || stderr_output.contains("cannot open directory"))
            {
                self.emit_output(
                    tool_name,
                    "⚠️ Permission denied, retrying with elevated privileges...\n",
                );

                let elevation = ElevationHelper::new();
                let elevation_msg = elevation.get_elevation_message().await;
                self.emit_output(tool_name, elevation_msg);

                let (elevation_cmd, elevation_args) = elevation
                    .elevate_command(&["gem", "update", package_name])
                    .await;

                let mut elevated_cmd = hidden_command(elevation_cmd);
                let mut child = elevated_cmd
                    .args(&elevation_args)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .context("Failed to spawn gem update with elevation")?;

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
                        format!(
                            "❌ Failed to update {} with elevated privileges (exit code: {})\n",
                            tool.name, code
                        )
                    } else {
                        format!("❌ Failed to update {} with elevated privileges (process terminated)\n", tool.name)
                    };
                    self.emit_output(tool_name, &error_msg);
                    return Err(anyhow!(
                        "Gem update failed for {}. Check if the gem is installed.",
                        tool.name
                    ));
                }

                self.emit_output(
                    tool_name,
                    &format!(
                        "✅ Successfully updated {} with elevated privileges\n",
                        tool.name
                    ),
                );
                return Ok(format!("Successfully updated {}", tool.name));
            } else if !status.success() {
                let error_msg = if let Some(code) = status.code() {
                    format!("❌ Failed to update {} (exit code: {})\n", tool.name, code)
                } else {
                    format!("❌ Failed to update {} (process terminated)\n", tool.name)
                };
                self.emit_output(tool_name, &error_msg);
                self.emit_output(
                    tool_name,
                    "💡 Tip: The gem may not be installed or may require different permissions\n",
                );
                return Err(anyhow!("Gem update failed for {}. Check if the gem is installed and you have proper permissions.", tool.name));
            }

            self.emit_output(
                tool_name,
                &format!("✅ Successfully updated {}\n", tool.name),
            );
            return Ok(format!("Successfully updated {}", tool.name));
        }

        // Windows - no elevation needed
        #[cfg(not(target_os = "linux"))]
        {
            let mut update_cmd = hidden_command("gem");
            let mut child = update_cmd
                .args(&["update", package_name])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to spawn gem update")?;

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
                self.emit_output(
                    tool_name,
                    "💡 Tip: The gem may not be installed or may require different permissions\n",
                );
                return Err(anyhow!("Gem update failed for {}. Check if the gem is installed and you have proper permissions.", tool.name));
            }

            self.emit_output(
                tool_name,
                &format!("✅ Successfully updated {}\n", tool.name),
            );
            return Ok(format!("Successfully updated {}", tool.name));
        }
    }

    /// Uninstall a gem package
    pub async fn uninstall(&self, tool: &ToolDefinition) -> Result<String> {
        let package_name = tool
            .gem_package
            .as_ref()
            .ok_or_else(|| anyhow!("Tool {} does not have gem_package defined", tool.name))?;

        let mut uninstall_cmd = hidden_command("gem");
        let output = uninstall_cmd
            .args(&["uninstall", "-x", package_name])
            .output()
            .await
            .context("Failed to uninstall gem package")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not installed") {
                return Err(anyhow!(
                    "Gem '{}' is not installed or already removed",
                    package_name
                ));
            }
            return Err(anyhow!(
                "Failed to uninstall {}: {}. Check permissions and gem installation.",
                package_name,
                stderr.trim()
            ));
        }

        Ok(format!("Successfully uninstalled {}", package_name))
    }

    fn emit_output(&self, tool_name: &str, message: &str) {
        let event = EventEmitter::tool_installation_output(tool_name, "stdout", message);
        let _ = self.app_handle.emit(TOOL_INSTALLATION_OUTPUT, event);
    }
}
