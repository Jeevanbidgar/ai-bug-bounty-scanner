use crate::events::{EventEmitter, TOOL_INSTALLATION_OUTPUT};
use anyhow::{anyhow, Context, Result};
use std::process::Stdio;
use tauri::{Emitter, Manager};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

pub struct AptManager {
    app_handle: tauri::AppHandle,
}

impl AptManager {
    pub fn new(app_handle: tauri::AppHandle) -> Self {
        Self { app_handle }
    }

    /// Check if apt is available (Linux only)
    async fn is_apt_available(&self) -> bool {
        if !cfg!(target_os = "linux") {
            return false;
        }

        match Command::new("apt").arg("--version").output().await {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    fn emit_output(&self, tool_name: &str, message: &str) {
        let event = EventEmitter::tool_installation_output(tool_name, "stdout", message);
        let _ = self.app_handle.emit(TOOL_INSTALLATION_OUTPUT, event);
    }

    /// Check if pkexec is available (for GUI password prompt)
    async fn is_pkexec_available(&self) -> bool {
        // Try to run pkexec --version directly instead of using which
        match Command::new("pkexec").arg("--version").output().await {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    /// Install a tool via apt install with live streaming
    ///
    /// # Arguments
    /// * `package_name` - The APT package name (e.g., "nmap", "curl")
    /// * `tool_name` - The tool name (e.g., "nmap")
    ///
    /// # Returns
    /// * `Result<String>` with success message
    pub async fn install(&self, package_name: &str, tool_name: &str) -> Result<String> {
        self.emit_output(
            tool_name,
            &format!("Starting APT installation for {}...\n", tool_name),
        );

        // Check if apt is available
        if !self.is_apt_available().await {
            return Err(anyhow!(
                "apt is not available. This system is not Debian/Ubuntu-based."
            ));
        }

        self.emit_output(
            tool_name,
            &format!("Installing {} via apt...\n", package_name),
        );

        // Use pkexec for GUI password prompt if available, otherwise fall back to sudo
        let (elevation_cmd, elevation_args) = if self.is_pkexec_available().await {
            self.emit_output(
                tool_name,
                "🔐 Using pkexec (GUI password dialog will appear)...\n",
            );
            ("pkexec", vec!["apt", "install", "-y", package_name])
        } else {
            self.emit_output(
                tool_name,
                "⚠️  Using sudo (password prompt in terminal)...\n",
            );
            ("sudo", vec!["apt", "install", "-y", package_name])
        };

        // Run apt install with -y flag for non-interactive mode
        let mut child = Command::new(elevation_cmd)
            .args(&elevation_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn apt install")?;

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let tool_name_clone = tool_name.to_string();
        let app_handle_clone = self.app_handle.clone();

        let stdout_task = tokio::spawn(async move {
            if let Some(stdout) = stdout {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let event = EventEmitter::tool_installation_output(
                        &tool_name_clone,
                        "stdout",
                        &format!("{}\n", line),
                    );
                    let _ = app_handle_clone.emit(TOOL_INSTALLATION_OUTPUT, event);
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
                    let event = EventEmitter::tool_installation_output(
                        &tool_name_clone2,
                        "stderr",
                        &format!("{}\n", line),
                    );
                    let _ = app_handle_clone2.emit(TOOL_INSTALLATION_OUTPUT, event);
                }
            }
        });

        let _ = tokio::join!(stdout_task, stderr_task);

        let status = child
            .wait()
            .await
            .context("Failed to wait for apt install")?;

        if !status.success() {
            self.emit_output(
                tool_name,
                &format!("Failed to install {} via apt\n", tool_name),
            );
            return Err(anyhow!("apt install failed"));
        }

        self.emit_output(
            tool_name,
            &format!("Successfully installed {} via apt\n", tool_name),
        );
        Ok(format!("Successfully installed {} via apt", tool_name))
    }

    /// Update a tool via apt upgrade with live streaming
    pub async fn update(&self, package_name: &str, tool_name: &str) -> Result<String> {
        self.emit_output(tool_name, &format!("Updating {}...\n", tool_name));

        if !self.is_apt_available().await {
            return Err(anyhow!("apt is not available."));
        }

        // Use pkexec for GUI password prompt if available, otherwise fall back to sudo
        let (elevation_cmd, elevation_args) = if self.is_pkexec_available().await {
            self.emit_output(
                tool_name,
                "🔐 Using pkexec (GUI password dialog will appear)...\n",
            );
            (
                "pkexec",
                vec!["apt", "install", "--only-upgrade", "-y", package_name],
            )
        } else {
            self.emit_output(
                tool_name,
                "⚠️  Using sudo (password prompt in terminal)...\n",
            );
            (
                "sudo",
                vec!["apt", "install", "--only-upgrade", "-y", package_name],
            )
        };

        let mut child = Command::new(elevation_cmd)
            .args(&elevation_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn apt upgrade")?;

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let tool_name_clone = tool_name.to_string();
        let app_handle_clone = self.app_handle.clone();

        let stdout_task = tokio::spawn(async move {
            if let Some(stdout) = stdout {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let event = EventEmitter::tool_installation_output(
                        &tool_name_clone,
                        "stdout",
                        &format!("{}\n", line),
                    );
                    let _ = app_handle_clone.emit(TOOL_INSTALLATION_OUTPUT, event);
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
                    let event = EventEmitter::tool_installation_output(
                        &tool_name_clone2,
                        "stderr",
                        &format!("{}\n", line),
                    );
                    let _ = app_handle_clone2.emit(TOOL_INSTALLATION_OUTPUT, event);
                }
            }
        });

        let _ = tokio::join!(stdout_task, stderr_task);

        let status = child.wait().await?;

        if !status.success() {
            self.emit_output(tool_name, &format!("Failed to update {}\n", tool_name));
            return Err(anyhow!("apt upgrade failed"));
        }

        self.emit_output(tool_name, &format!("Successfully updated {}\n", tool_name));
        Ok(format!("Successfully updated {}", tool_name))
    }

    /// Uninstall a tool via apt remove
    pub async fn uninstall(&self, package_name: &str, tool_name: &str) -> Result<String> {
        if !self.is_apt_available().await {
            return Err(anyhow!("apt is not available."));
        }

        self.emit_output(tool_name, &format!("Uninstalling {}...\n", tool_name));

        // Use pkexec for GUI password prompt if available, otherwise fall back to sudo
        let (elevation_cmd, elevation_args) = if self.is_pkexec_available().await {
            self.emit_output(
                tool_name,
                "🔐 Using pkexec (GUI password dialog will appear)...\n",
            );
            ("pkexec", vec!["apt", "remove", "-y", package_name])
        } else {
            self.emit_output(
                tool_name,
                "⚠️  Using sudo (password prompt in terminal)...\n",
            );
            ("sudo", vec!["apt", "remove", "-y", package_name])
        };

        let output = Command::new(elevation_cmd)
            .args(&elevation_args)
            .output()
            .await
            .context("Failed to execute apt remove")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "Failed to uninstall {}: {}",
                tool_name,
                stderr.trim()
            ));
        }

        Ok(format!("Successfully uninstalled {}", tool_name))
    }
}
