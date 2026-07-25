use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::runtime::process::configure_tokio_command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationProgress {
    pub step: String,
    pub output: String,
    pub success: bool,
    pub requires_elevation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationResult {
    pub success: bool,
    pub message: String,
    pub steps: Vec<InstallationProgress>,
    pub requires_restart: bool,
}

/// Install pipx using pip (user-scope, no elevation needed)
pub async fn install_pipx() -> Result<InstallationResult, String> {
    let mut steps = Vec::new();

    // Step 1: Install pipx via pip (user scope)
    steps.push(InstallationProgress {
        step: "Installing pipx".to_string(),
        output: "Running: python -m pip install --user pipx".to_string(),
        success: false,
        requires_elevation: false,
    });

    let install_output = execute_command_with_output(
        "python",
        &["-m", "pip", "install", "--user", "pipx"],
        60, // 60 second timeout
    )
    .await;

    match install_output {
        Ok(output) => {
            steps.last_mut().unwrap().success = true;
            steps.last_mut().unwrap().output = format!("✓ pipx installed successfully\n{}", output);

            // Step 2: Run pipx ensurepath
            steps.push(InstallationProgress {
                step: "Adding pipx to PATH".to_string(),
                output: "Running: pipx ensurepath".to_string(),
                success: false,
                requires_elevation: false,
            });

            let ensurepath_output = execute_command_with_output("pipx", &["ensurepath"], 30).await;

            match ensurepath_output {
                Ok(path_output) => {
                    steps.last_mut().unwrap().success = true;
                    steps.last_mut().unwrap().output = format!("✓ PATH updated\n{}", path_output);

                    Ok(InstallationResult {
                        success: true,
                        message: "pipx installed successfully! Restart your terminal to use pipx commands.".to_string(),
                        steps,
                        requires_restart: true, // Need to restart terminal for PATH changes
                    })
                }
                Err(e) => {
                    steps.last_mut().unwrap().output = format!(
                        "⚠ PATH update failed: {}\nYou may need to restart your terminal manually.",
                        e
                    );

                    Ok(InstallationResult {
                        success: true, // pipx is installed, just PATH might need manual fix
                        message: "pipx installed, but PATH update failed. Restart your terminal or run 'pipx ensurepath' manually.".to_string(),
                        steps,
                        requires_restart: true,
                    })
                }
            }
        }
        Err(e) => {
            steps.last_mut().unwrap().output = format!("✗ Failed: {}", e);
            Ok(InstallationResult {
                success: false,
                message: format!("Failed to install pipx: {}", e),
                steps,
                requires_restart: false,
            })
        }
    }
}

/// Install Go from official site (user can download, or use winget if available)
#[allow(dead_code)]
pub async fn install_go_windows() -> Result<InstallationResult, String> {
    let mut steps = Vec::new();

    // Check if winget is available
    let winget_check = execute_command_with_output("winget", &["--version"], 5).await;

    if winget_check.is_ok() {
        // Try WinGet installation (may require UAC)
        steps.push(InstallationProgress {
            step: "Installing Go via WinGet".to_string(),
            output: "Running: winget install GoLang.Go".to_string(),
            success: false,
            requires_elevation: true, // May trigger UAC
        });

        let install_output = execute_command_with_output(
            "winget",
            &["install", "GoLang.Go", "--silent"],
            180, // 3 minutes for download + install
        )
        .await;

        match install_output {
            Ok(output) => {
                steps.last_mut().unwrap().success = true;
                steps.last_mut().unwrap().output = format!("✓ Go installed via WinGet\n{}", output);

                Ok(InstallationResult {
                    success: true,
                    message: "Go installed successfully! Restart your terminal to use go commands."
                        .to_string(),
                    steps,
                    requires_restart: true,
                })
            }
            Err(e) => {
                steps.last_mut().unwrap().output = format!("✗ WinGet install failed: {}", e);
                steps.push(InstallationProgress {
                    step: "Alternative: Manual Download".to_string(),
                    output: "Please download Go from: https://go.dev/dl/".to_string(),
                    success: false,
                    requires_elevation: false,
                });

                Ok(InstallationResult {
                    success: false,
                    message: "WinGet installation failed. Please download Go manually from https://go.dev/dl/".to_string(),
                    steps,
                    requires_restart: false,
                })
            }
        }
    } else {
        // WinGet not available, guide to download
        steps.push(InstallationProgress {
            step: "Manual Download Required".to_string(),
            output: "WinGet not available. Please download Go from: https://go.dev/dl/\n\nAfter installing, Go will be available in your terminal.".to_string(),
            success: false,
            requires_elevation: false,
        });

        Ok(InstallationResult {
            success: false,
            message: "Please download and install Go manually from https://go.dev/dl/".to_string(),
            steps,
            requires_restart: false,
        })
    }
}

/// Install APT package (requires sudo on Linux)
#[allow(dead_code)]
pub async fn install_apt_package(package_name: &str) -> Result<InstallationResult, String> {
    let mut steps = Vec::new();

    // Step 1: Update package lists
    steps.push(InstallationProgress {
        step: "Updating package lists".to_string(),
        output: "Running: sudo apt update".to_string(),
        success: false,
        requires_elevation: true, // APT requires sudo
    });

    let update_output = execute_command_with_output("sudo", &["apt", "update"], 60).await;

    match update_output {
        Ok(output) => {
            steps.last_mut().unwrap().success = true;
            steps.last_mut().unwrap().output = format!(
                "✓ Package lists updated\n{}",
                output.lines().take(5).collect::<Vec<_>>().join("\n")
            );

            // Step 2: Install package
            steps.push(InstallationProgress {
                step: format!("Installing {}", package_name),
                output: format!("Running: sudo apt install -y {}", package_name),
                success: false,
                requires_elevation: true,
            });

            let install_output = execute_command_with_output(
                "sudo",
                &["apt", "install", "-y", package_name],
                180, // 3 minutes for download + install
            )
            .await;

            match install_output {
                Ok(_output) => {
                    steps.last_mut().unwrap().success = true;
                    steps.last_mut().unwrap().output =
                        format!("✓ {} installed successfully", package_name);

                    Ok(InstallationResult {
                        success: true,
                        message: format!("{} installed successfully!", package_name),
                        steps,
                        requires_restart: false,
                    })
                }
                Err(e) => {
                    steps.last_mut().unwrap().output = format!("✗ Installation failed: {}", e);
                    Ok(InstallationResult {
                        success: false,
                        message: format!("Failed to install {}: {}", package_name, e),
                        steps,
                        requires_restart: false,
                    })
                }
            }
        }
        Err(e) => {
            steps.last_mut().unwrap().output = format!("✗ Update failed: {}", e);
            Ok(InstallationResult {
                success: false,
                message: format!(
                    "Failed to update package lists: {}. Check sudo permissions.",
                    e
                ),
                steps,
                requires_restart: false,
            })
        }
    }
}

/// Open Microsoft Store to App Installer page
#[allow(dead_code)]
pub async fn install_winget_windows() -> Result<InstallationResult, String> {
    let mut steps = vec![InstallationProgress {
        step: "Opening Microsoft Store".to_string(),
        output: "Opening App Installer page in Microsoft Store...".to_string(),
        success: false,
        requires_elevation: false,
    }];

    // Open Microsoft Store to App Installer page
    let open_result = execute_command_with_output(
        "cmd",
        &[
            "/c",
            "start",
            "ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1",
        ],
        5,
    )
    .await;

    match open_result {
        Ok(_output) => {
            steps.last_mut().unwrap().success = true;
            steps.last_mut().unwrap().output = "✓ Microsoft Store opened\n\nPlease install 'App Installer' from the Store.\nWinGet is included with App Installer.".to_string();

            Ok(InstallationResult {
                success: true,
                message: "Microsoft Store opened. Please install 'App Installer' to get WinGet."
                    .to_string(),
                steps,
                requires_restart: false,
            })
        }
        Err(e) => {
            steps.last_mut().unwrap().output = format!(
                "✗ Failed to open Store: {}\n\nAlternative: Download from https://aka.ms/getwinget",
                e
            );
            Ok(InstallationResult {
                success: false,
                message: "Failed to open Store. Download WinGet from: https://aka.ms/getwinget"
                    .to_string(),
                steps,
                requires_restart: false,
            })
        }
    }
}

/// Execute command with output capture and timeout
async fn execute_command_with_output(
    command: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<String, String> {
    let mut command_builder = Command::new(command);
    command_builder
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_tokio_command(&mut command_builder);

    let cmd = command_builder.spawn();

    match cmd {
        Ok(mut child) => {
            let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;
            let stderr = child.stderr.take().ok_or("Failed to capture stderr")?;

            let read_output = async {
                let mut stdout_reader = BufReader::new(stdout);
                let mut stderr_reader = BufReader::new(stderr);

                let mut stdout_buf = String::new();
                let mut stderr_buf = String::new();

                let _ = stdout_reader.read_to_string(&mut stdout_buf).await;
                let _ = stderr_reader.read_to_string(&mut stderr_buf).await;

                let status = child.wait().await.map_err(|e| e.to_string())?;

                if status.success() {
                    Ok(if !stdout_buf.is_empty() {
                        stdout_buf
                    } else {
                        stderr_buf
                    })
                } else {
                    Err(format!(
                        "Command failed with exit code {:?}\nStderr: {}",
                        status.code(),
                        stderr_buf
                    ))
                }
            };

            match timeout(Duration::from_secs(timeout_secs), read_output).await {
                Ok(result) => result,
                Err(_) => Err(format!("Command timed out after {} seconds", timeout_secs)),
            }
        }
        Err(e) => Err(format!("Failed to execute {}: {}", command, e)),
    }
}
