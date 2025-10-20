use crate::events::{EventEmitter, TOOL_INSTALLATION_OUTPUT};
use crate::tools::package_managers::{detect_manager, PackageManagerType};
use anyhow::{anyhow, Context, Result};
use std::process::Stdio;
use tauri::Emitter;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

pub struct WingetManager {
    app_handle: tauri::AppHandle,
}

impl WingetManager {
    pub fn new(app_handle: tauri::AppHandle) -> Self {
        Self { app_handle }
    }

    /// Get the WinGet executable path (uses dynamic detection)
    async fn get_winget_path(&self) -> Option<String> {
        let info = detect_manager(PackageManagerType::WinGet).await;
        if info.available {
            // If a custom path was detected, use it; otherwise use "winget"
            Some(info.path.unwrap_or_else(|| "winget".to_string()))
        } else {
            None
        }
    }

    /// Check if winget is available (Windows only)
    #[allow(dead_code)]
    async fn is_winget_available(&self) -> bool {
        if !cfg!(target_os = "windows") {
            return false;
        }

        // Use dynamic detection
        let info = detect_manager(PackageManagerType::WinGet).await;
        info.available
    }

    fn emit_output(&self, tool_name: &str, message: &str) {
        let event = EventEmitter::tool_installation_output(tool_name, "stdout", message);
        let _ = self.app_handle.emit(TOOL_INSTALLATION_OUTPUT, event);
    }

    /// Install a tool via winget install with live streaming
    ///
    /// # Arguments
    /// * `winget_id` - The winget package ID (e.g., "Nmap.Nmap", "Microsoft.Sysinternals")
    /// * `tool_name` - The tool name (e.g., "nmap")
    ///
    /// # Returns
    /// * `Result<String>` with success message
    pub async fn install(&self, winget_id: &str, tool_name: &str) -> Result<String> {
        eprintln!("🚀 Starting winget...");
        self.emit_output(
            tool_name,
            &format!("Starting Winget installation for {}...\n", tool_name),
        );

        // Get the WinGet executable path
        let winget_path = self.get_winget_path().await.ok_or_else(|| {
            anyhow!("winget is not available. Please install App Installer from Microsoft Store.")
        })?;

        eprintln!("📍 Using WinGet at: {}", winget_path);
        self.emit_output(tool_name, &format!("Using winget at: {}\n", winget_path));
        self.emit_output(
            tool_name,
            &format!("Installing {} via winget...\n", winget_id),
        );
        self.emit_output(tool_name, "⚠️  This may require UAC elevation\n");

        // Run winget install with --accept-* flags for non-interactive mode
        let mut child = Command::new(&winget_path)
            .args(&[
                "install",
                "--id",
                winget_id,
                "--accept-package-agreements",
                "--accept-source-agreements",
                "--silent",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn winget install")?;

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
            .context("Failed to wait for winget install")?;

        if !status.success() {
            self.emit_output(
                tool_name,
                &format!("Failed to install {} via winget\n", tool_name),
            );
            return Err(anyhow!("winget install failed"));
        }

        self.emit_output(
            tool_name,
            &format!("Successfully installed {} via winget\n", tool_name),
        );
        Ok(format!("Successfully installed {} via winget", tool_name))
    }

    /// Update a tool via winget upgrade with live streaming
    pub async fn update(&self, winget_id: &str, tool_name: &str) -> Result<String> {
        self.emit_output(tool_name, &format!("Updating {}...\n", tool_name));

        // Get the WinGet executable path
        let winget_path = self
            .get_winget_path()
            .await
            .ok_or_else(|| anyhow!("winget is not available."))?;

        let mut child = Command::new(&winget_path)
            .args(&[
                "upgrade",
                "--id",
                winget_id,
                "--accept-package-agreements",
                "--accept-source-agreements",
                "--silent",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn winget upgrade")?;

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
            return Err(anyhow!("winget upgrade failed"));
        }

        self.emit_output(tool_name, &format!("Successfully updated {}\n", tool_name));
        Ok(format!("Successfully updated {}", tool_name))
    }

    /// Uninstall a tool via winget uninstall
    pub async fn uninstall(&self, winget_id: &str, tool_name: &str) -> Result<String> {
        // Get the WinGet executable path
        let winget_path = self
            .get_winget_path()
            .await
            .ok_or_else(|| anyhow!("winget is not available."))?;

        let output = Command::new(&winget_path)
            .args(&["uninstall", "--id", winget_id, "--silent"])
            .output()
            .await
            .context("Failed to execute winget uninstall")?;

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
