use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::runtime::process::configure_tokio_command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ElevationMethod {
    /// No elevation required (user-scope operation)
    None,
    /// Windows UAC elevation
    WindowsUAC,
    /// Linux polkit (pkexec)
    LinuxPolkit,
    /// Linux sudo with GUI askpass
    LinuxSudoAskpass,
    /// macOS elevation via administrator prompt (osascript)
    MacOsAppleScript,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ElevationRequest {
    pub command: String,
    pub args: Vec<String>,
    pub reason: String, // User-facing explanation
    pub method: ElevationMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevationResult {
    pub success: bool,
    pub output: String,
    pub elevated: bool, // Whether elevation was actually used
    pub error: Option<String>,
}

/// Try to execute a command without elevation first, then with elevation if needed
pub async fn execute_with_smart_elevation(
    command: &str,
    args: &[&str],
    reason: &str,
    timeout_secs: u64,
) -> Result<ElevationResult, String> {
    eprintln!("🔐 Attempting command: {} {:?}", command, args);
    eprintln!("   Reason: {}", reason);

    // Step 1: Try without elevation first
    eprintln!("   → Trying user-scope first...");
    match execute_command_internal(command, args, timeout_secs).await {
        Ok(output) => {
            eprintln!("   ✓ Success without elevation!");
            Ok(ElevationResult {
                success: true,
                output,
                elevated: false,
                error: None,
            })
        }
        Err(e) => {
            eprintln!("   ✗ User-scope failed: {}", e);

            // Check if error indicates elevation is needed
            if needs_elevation(&e) {
                eprintln!("   → Elevation required, will prompt user");
                // Return a special result indicating elevation is needed
                // Frontend will show dialog and call execute_elevated if user approves
                Err(format!("ELEVATION_REQUIRED: {}", reason))
            } else {
                // Other error, not elevation-related
                Ok(ElevationResult {
                    success: false,
                    output: String::new(),
                    elevated: false,
                    error: Some(e),
                })
            }
        }
    }
}

/// Execute command with elevation (called after user approves in UI)
pub async fn execute_elevated(
    command: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<ElevationResult, String> {
    eprintln!("🔐 Executing with elevation: {} {:?}", command, args);

    #[cfg(target_os = "windows")]
    {
        execute_elevated_windows(command, args, timeout_secs).await
    }

    #[cfg(target_os = "linux")]
    {
        execute_elevated_linux(command, args, timeout_secs).await
    }

    #[cfg(target_os = "macos")]
    {
        execute_elevated_macos(command, args, timeout_secs).await
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = timeout_secs;
        Err("Elevation not supported on this platform".to_string())
    }
}

/// Execute command with Windows UAC elevation
#[cfg(target_os = "windows")]
async fn execute_elevated_windows(
    command: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<ElevationResult, String> {
    eprintln!("   → Using Windows UAC");

    // Use PowerShell Start-Process with -Verb RunAs to trigger UAC
    // We capture output by redirecting to a temp file
    let temp_file =
        std::env::temp_dir().join(format!("elevation_output_{}.txt", std::process::id()));
    let temp_file_str = temp_file.to_string_lossy().to_string();

    // Build PowerShell command that redirects output
    let ps_script = format!(
        "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs -Wait -RedirectStandardOutput '{}' -RedirectStandardError '{}' -NoNewWindow",
        command,
        args.join("','"),
        temp_file_str,
        temp_file_str
    );

    eprintln!("   → PowerShell script: {}", ps_script);

    let mut elevated_cmd = Command::new("powershell");
    elevated_cmd
        .args(&["-Command", &ps_script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_tokio_command(&mut elevated_cmd);

    let result = elevated_cmd.spawn();

    match result {
        Ok(mut child) => {
            let wait_result = timeout(Duration::from_secs(timeout_secs), child.wait()).await;

            match wait_result {
                Ok(Ok(status)) => {
                    // Read output from temp file
                    let output = tokio::fs::read_to_string(&temp_file)
                        .await
                        .unwrap_or_default();
                    let _ = tokio::fs::remove_file(&temp_file).await; // Clean up

                    if status.success() {
                        eprintln!("   ✓ Elevated command succeeded");
                        Ok(ElevationResult {
                            success: true,
                            output,
                            elevated: true,
                            error: None,
                        })
                    } else {
                        eprintln!(
                            "   ✗ Elevated command failed: exit code {:?}",
                            status.code()
                        );
                        Ok(ElevationResult {
                            success: false,
                            output,
                            elevated: true,
                            error: Some(format!(
                                "Command failed with exit code {:?}",
                                status.code()
                            )),
                        })
                    }
                }
                Ok(Err(e)) => {
                    let _ = tokio::fs::remove_file(&temp_file).await;
                    Err(format!("Failed to wait for elevated process: {}", e))
                }
                Err(_) => {
                    let _ = child.kill().await;
                    let _ = tokio::fs::remove_file(&temp_file).await;
                    Err(format!(
                        "Elevated command timed out after {} seconds",
                        timeout_secs
                    ))
                }
            }
        }
        Err(e) => {
            eprintln!("   ✗ Failed to spawn elevated process: {}", e);
            Err(format!("Failed to trigger UAC: {}", e))
        }
    }
}

/// Execute command with macOS elevation using AppleScript prompt
#[cfg(target_os = "macos")]
async fn execute_elevated_macos(
    command: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<ElevationResult, String> {
    eprintln!("   → Using macOS administrator privileges prompt");

    let command_line = std::iter::once(command)
        .chain(args.iter().copied())
        .map(shell_escape_arg)
        .collect::<Vec<_>>()
        .join(" ");

    let applescript = format!(
        "do shell script \"{}\" with administrator privileges",
        escape_for_applescript(&command_line)
    );

    let mut child = Command::new("osascript")
        .arg("-e")
        .arg(applescript)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn osascript: {}", e))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Failed to capture stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Failed to capture stderr".to_string())?;

    let mut stdout_buf = String::new();
    let mut stderr_buf = String::new();

    let read_task = async {
        let mut stdout_reader = tokio::io::BufReader::new(stdout);
        let mut stderr_reader = tokio::io::BufReader::new(stderr);

        let _ = stdout_reader.read_to_string(&mut stdout_buf).await;
        let _ = stderr_reader.read_to_string(&mut stderr_buf).await;

        child.wait().await
    };

    match timeout(Duration::from_secs(timeout_secs), read_task).await {
        Ok(Ok(status)) => {
            let output = if !stdout_buf.trim().is_empty() {
                stdout_buf.clone()
            } else {
                stderr_buf.clone()
            };

            if status.success() {
                eprintln!("   ✓ Elevated command succeeded");
                Ok(ElevationResult {
                    success: true,
                    output,
                    elevated: true,
                    error: None,
                })
            } else {
                let apple_error = if stderr_buf.trim().is_empty() {
                    format!("Command failed with exit code {:?}", status.code())
                } else {
                    stderr_buf.trim().to_string()
                };

                Ok(ElevationResult {
                    success: false,
                    output,
                    elevated: true,
                    error: Some(apple_error),
                })
            }
        }
        Ok(Err(e)) => Err(format!("Failed to wait for osascript: {}", e)),
        Err(_) => {
            let _ = child.kill().await;
            Err(format!(
                "Elevated command timed out after {} seconds",
                timeout_secs
            ))
        }
    }
}

#[cfg(target_os = "macos")]
fn escape_for_applescript(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(target_os = "macos")]
fn shell_escape_arg(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Execute command with Linux elevation (polkit or sudo with askpass)
#[cfg(target_os = "linux")]
async fn execute_elevated_linux(
    command: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<ElevationResult, String> {
    // Try polkit (pkexec) first, fallback to sudo with askpass
    eprintln!("   → Trying polkit (pkexec)...");

    match execute_with_pkexec(command, args, timeout_secs).await {
        Ok(result) => {
            eprintln!("   ✓ polkit succeeded");
            return Ok(result);
        }
        Err(e) => {
            eprintln!("   ✗ polkit failed: {}", e);
            eprintln!("   → Falling back to sudo with askpass...");
        }
    }

    // Fallback to sudo with askpass
    execute_with_sudo_askpass(command, args, timeout_secs).await
}

#[cfg(target_os = "linux")]
async fn execute_with_pkexec(
    command: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<ElevationResult, String> {
    let mut cmd = Command::new("pkexec");
    cmd.arg(command);
    cmd.args(args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let result = cmd.spawn();

    match result {
        Ok(mut child) => {
            let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;
            let stderr = child.stderr.take().ok_or("Failed to capture stderr")?;

            let mut stdout_buf = String::new();
            let mut stderr_buf = String::new();

            let read_task = async {
                let mut stdout_reader = tokio::io::BufReader::new(stdout);
                let mut stderr_reader = tokio::io::BufReader::new(stderr);

                let _ = stdout_reader.read_to_string(&mut stdout_buf).await;
                let _ = stderr_reader.read_to_string(&mut stderr_buf).await;

                child.wait().await
            };

            match timeout(Duration::from_secs(timeout_secs), read_task).await {
                Ok(Ok(status)) => {
                    let output = if !stdout_buf.is_empty() {
                        stdout_buf
                    } else {
                        stderr_buf
                    };

                    if status.success() {
                        Ok(ElevationResult {
                            success: true,
                            output,
                            elevated: true,
                            error: None,
                        })
                    } else {
                        Ok(ElevationResult {
                            success: false,
                            output,
                            elevated: true,
                            error: Some(format!(
                                "pkexec failed with exit code {:?}",
                                status.code()
                            )),
                        })
                    }
                }
                Ok(Err(e)) => Err(format!("Failed to wait for pkexec: {}", e)),
                Err(_) => {
                    let _ = child.kill().await;
                    Err(format!("pkexec timed out after {} seconds", timeout_secs))
                }
            }
        }
        Err(e) => Err(format!("Failed to spawn pkexec: {}", e)),
    }
}

#[cfg(target_os = "linux")]
async fn execute_with_sudo_askpass(
    command: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<ElevationResult, String> {
    // Set SUDO_ASKPASS to use GUI password prompt
    // Common askpass helpers: zenity, kdialog, ssh-askpass
    let askpass_helpers = [
        "/usr/bin/zenity",
        "/usr/bin/kdialog",
        "/usr/bin/ssh-askpass",
        "/usr/bin/lxqt-openssh-askpass",
    ];

    let askpass = askpass_helpers
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .ok_or("No GUI askpass helper found. Install zenity or kdialog.")?;

    eprintln!("   → Using askpass helper: {}", askpass);

    let mut cmd = Command::new("sudo");
    cmd.arg("-A"); // Use askpass
    cmd.arg(command);
    cmd.args(args);
    cmd.env("SUDO_ASKPASS", askpass);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let result = cmd.spawn();

    match result {
        Ok(mut child) => {
            let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;
            let stderr = child.stderr.take().ok_or("Failed to capture stderr")?;

            let mut stdout_buf = String::new();
            let mut stderr_buf = String::new();

            let read_task = async {
                let mut stdout_reader = tokio::io::BufReader::new(stdout);
                let mut stderr_reader = tokio::io::BufReader::new(stderr);

                let _ = stdout_reader.read_to_string(&mut stdout_buf).await;
                let _ = stderr_reader.read_to_string(&mut stderr_buf).await;

                child.wait().await
            };

            match timeout(Duration::from_secs(timeout_secs), read_task).await {
                Ok(Ok(status)) => {
                    let output = if !stdout_buf.is_empty() {
                        stdout_buf
                    } else {
                        stderr_buf
                    };

                    if status.success() {
                        eprintln!("   ✓ sudo with askpass succeeded");
                        Ok(ElevationResult {
                            success: true,
                            output,
                            elevated: true,
                            error: None,
                        })
                    } else {
                        Ok(ElevationResult {
                            success: false,
                            output,
                            elevated: true,
                            error: Some(format!("sudo failed with exit code {:?}", status.code())),
                        })
                    }
                }
                Ok(Err(e)) => Err(format!("Failed to wait for sudo: {}", e)),
                Err(_) => {
                    let _ = child.kill().await;
                    Err(format!("sudo timed out after {} seconds", timeout_secs))
                }
            }
        }
        Err(e) => Err(format!("Failed to spawn sudo: {}", e)),
    }
}

/// Check if error message indicates elevation is required
fn needs_elevation(error: &str) -> bool {
    let error_lower = error.to_lowercase();

    // Windows elevation indicators
    if error_lower.contains("access is denied")
        || error_lower.contains("requires elevation")
        || error_lower.contains("administrator privileges")
        || error_lower.contains("0x5")
    // Access denied error code
    {
        return true;
    }

    // Linux elevation indicators
    if error_lower.contains("permission denied")
        || error_lower.contains("operation not permitted")
        || error_lower.contains("must be root")
        || error_lower.contains("requires sudo")
    {
        return true;
    }

    false
}

/// Execute command without elevation (internal helper)
async fn execute_command_internal(
    command: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<String, String> {
    let mut cmd = Command::new(command);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    configure_tokio_command(&mut cmd);

    let result = cmd.spawn();

    match result {
        Ok(mut child) => {
            let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;
            let stderr = child.stderr.take().ok_or("Failed to capture stderr")?;

            let mut stdout_buf = String::new();
            let mut stderr_buf = String::new();

            let read_task = async {
                let mut stdout_reader = tokio::io::BufReader::new(stdout);
                let mut stderr_reader = tokio::io::BufReader::new(stderr);

                let _ = stdout_reader.read_to_string(&mut stdout_buf).await;
                let _ = stderr_reader.read_to_string(&mut stderr_buf).await;

                child.wait().await
            };

            match timeout(Duration::from_secs(timeout_secs), read_task).await {
                Ok(Ok(status)) => {
                    if status.success() {
                        Ok(if !stdout_buf.is_empty() {
                            stdout_buf
                        } else {
                            stderr_buf
                        })
                    } else {
                        Err(format!(
                            "Command failed with exit code {:?}\nStdout: {}\nStderr: {}",
                            status.code(),
                            stdout_buf,
                            stderr_buf
                        ))
                    }
                }
                Ok(Err(e)) => Err(format!("Failed to wait for command: {}", e)),
                Err(_) => {
                    let _ = child.kill().await;
                    Err(format!("Command timed out after {} seconds", timeout_secs))
                }
            }
        }
        Err(e) => Err(format!("Failed to execute {}: {}", command, e)),
    }
}

/// Check if elevation is available on this system
pub async fn check_elevation_support() -> ElevationMethod {
    #[cfg(target_os = "windows")]
    {
        // Windows always supports UAC
        ElevationMethod::WindowsUAC
    }

    #[cfg(target_os = "linux")]
    {
        // Check for polkit
        if Command::new("which")
            .arg("pkexec")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return ElevationMethod::LinuxPolkit;
        }

        // Check for sudo + askpass helper
        let has_sudo = Command::new("which")
            .arg("sudo")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);

        let askpass_helpers = [
            "/usr/bin/zenity",
            "/usr/bin/kdialog",
            "/usr/bin/ssh-askpass",
        ];

        let has_askpass = askpass_helpers
            .iter()
            .any(|p| std::path::Path::new(p).exists());

        if has_sudo && has_askpass {
            return ElevationMethod::LinuxSudoAskpass;
        }

        ElevationMethod::None
    }

    #[cfg(target_os = "macos")]
    {
        // macOS ships with osascript for GUI privilege prompts
        if Command::new("which")
            .arg("osascript")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            ElevationMethod::MacOsAppleScript
        } else {
            ElevationMethod::None
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        ElevationMethod::None
    }
}
