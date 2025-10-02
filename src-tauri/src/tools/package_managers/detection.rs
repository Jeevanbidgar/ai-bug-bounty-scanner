// Package manager detection
//
// Detects which package managers are available on the system

use super::PackageManagerType;
use serde::{Deserialize, Serialize};
use std::process::Command;
use tokio::time::{timeout, Duration};

/// Information about a detected package manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManagerInfo {
    /// Type of package manager
    pub manager_type: PackageManagerType,
    /// Whether the package manager is available
    pub available: bool,
    /// Version of the package manager (if detected)
    pub version: Option<String>,
    /// Path to the package manager executable (if found)
    pub path: Option<String>,
    /// Error message if detection failed
    pub error: Option<String>,
}

impl PackageManagerInfo {
    /// Create a new PackageManagerInfo for an unavailable manager
    pub fn unavailable(manager_type: PackageManagerType, error: String) -> Self {
        Self {
            manager_type,
            available: false,
            version: None,
            path: None,
            error: Some(error),
        }
    }

    /// Create a new PackageManagerInfo for an available manager
    pub fn available(
        manager_type: PackageManagerType,
        version: Option<String>,
        path: Option<String>,
    ) -> Self {
        Self {
            manager_type,
            available: true,
            version,
            path,
            error: None,
        }
    }
}

/// Detect all supported package managers
pub async fn detect_all_managers() -> Vec<PackageManagerInfo> {
    let managers = vec![
        PackageManagerType::Go,
        PackageManagerType::Pipx,
        PackageManagerType::Apt,
        PackageManagerType::WinGet,
    ];

    let mut results = Vec::new();
    for manager in managers {
        results.push(detect_manager(manager).await);
    }
    results
}

/// Detect a specific package manager
pub async fn detect_manager(manager_type: PackageManagerType) -> PackageManagerInfo {
    match manager_type {
        PackageManagerType::Go => detect_go().await,
        PackageManagerType::Pipx => detect_pipx().await,
        PackageManagerType::Apt => detect_apt().await,
        PackageManagerType::WinGet => detect_winget().await,
        _ => PackageManagerInfo::unavailable(
            manager_type,
            "Not implemented yet".to_string(),
        ),
    }
}

/// Detect Go installation
async fn detect_go() -> PackageManagerInfo {
    match execute_detection_command("go", &["version"]).await {
        Ok((stdout, _stderr)) => {
            // Parse version from output like "go version go1.21.0 windows/amd64"
            let version = parse_go_version(&stdout);
            PackageManagerInfo::available(PackageManagerType::Go, version, None)
        }
        Err(_e) => {
            let error_msg = if cfg!(target_os = "windows") {
                "Go is not installed. Install from: https://go.dev/dl/ or run: winget install GoLang.Go".to_string()
            } else {
                "Go is not installed. Run: sudo apt install golang-go (Debian/Ubuntu) or download from https://go.dev/dl/".to_string()
            };
            PackageManagerInfo::unavailable(PackageManagerType::Go, error_msg)
        }
    }
}

/// Detect pipx installation
async fn detect_pipx() -> PackageManagerInfo {
    match execute_detection_command("pipx", &["--version"]).await {
        Ok((stdout, _stderr)) => {
            // Output is like "1.2.0" or "pipx 1.2.0"
            let version = parse_simple_version(&stdout);
            PackageManagerInfo::available(PackageManagerType::Pipx, version, None)
        }
        Err(_e) => {
            let error_msg = "pipx is not installed. Run: pip install --user pipx (then restart terminal) or python -m pip install --user pipx".to_string();
            PackageManagerInfo::unavailable(PackageManagerType::Pipx, error_msg)
        }
    }
}

/// Detect APT installation (Debian/Ubuntu/Kali)
async fn detect_apt() -> PackageManagerInfo {
    // APT is Linux-only
    #[cfg(not(target_os = "linux"))]
    {
        return PackageManagerInfo::unavailable(
            PackageManagerType::Apt,
            "APT is only available on Linux".to_string(),
        );
    }

    #[cfg(target_os = "linux")]
    {
        // Check if apt exists
        match execute_detection_command("apt", &["--version"]).await {
            Ok((stdout, _stderr)) => {
                // Output is like "apt 2.4.8 (amd64)"
                let version = parse_apt_version(&stdout);
                PackageManagerInfo::available(PackageManagerType::Apt, version, None)
            }
            Err(e) => PackageManagerInfo::unavailable(PackageManagerType::Apt, e),
        }
    }
}

/// Detect WinGet installation (Windows)
async fn detect_winget() -> PackageManagerInfo {
    // WinGet is Windows-only
    #[cfg(not(target_os = "windows"))]
    {
        return PackageManagerInfo::unavailable(
            PackageManagerType::WinGet,
            "WinGet is only available on Windows".to_string(),
        );
    }

    #[cfg(target_os = "windows")]
    {
        // Try multiple methods to detect winget
        // Method 1: Try direct command execution
        match execute_detection_command("winget", &["--version"]).await {
            Ok((stdout, _stderr)) => {
                // Output is like "v1.6.2721"
                let version = parse_simple_version(&stdout);
                return PackageManagerInfo::available(PackageManagerType::WinGet, version, None);
            }
            Err(_) => {
                // Method 2: Try with .exe extension (some systems require this)
                if let Ok((stdout, _stderr)) = execute_detection_command("winget.exe", &["--version"]).await {
                    let version = parse_simple_version(&stdout);
                    return PackageManagerInfo::available(PackageManagerType::WinGet, version, None);
                }
                
                // Method 3: Check if App Installer package is installed using PowerShell
                let check_cmd = "powershell";
                let check_args = vec![
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-AppxPackage Microsoft.DesktopAppInstaller | Select-Object -ExpandProperty Version"
                ];
                
                if let Ok((stdout, _stderr)) = execute_detection_command(check_cmd, &check_args).await {
                    if !stdout.trim().is_empty() {
                        // App Installer is installed, winget should be available
                        let version = parse_simple_version(&stdout);
                        return PackageManagerInfo::available(PackageManagerType::WinGet, version, Some("Note: winget may require running in a regular terminal (not IDE terminal)".to_string()));
                    }
                }
            }
        }
        
        // WinGet not found
        let error_msg = "WinGet is not installed. Install 'App Installer' from Microsoft Store or update Windows 10/11 to the latest version.".to_string();
        PackageManagerInfo::unavailable(PackageManagerType::WinGet, error_msg)
    }
}

/// Execute a command with timeout for detection
async fn execute_detection_command(
    command: &str,
    args: &[&str],
) -> Result<(String, String), String> {
    let timeout_duration = Duration::from_secs(5);

    // Spawn the command
    let output_future = tokio::task::spawn_blocking({
        let command = command.to_string();
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        move || {
            Command::new(&command)
                .args(&args)
                .output()
                .map_err(|e| format!("Failed to execute {}: {}", command, e))
        }
    });

    // Wait with timeout
    match timeout(timeout_duration, output_future).await {
        Ok(Ok(Ok(output))) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            if output.status.success() || !stdout.is_empty() || !stderr.is_empty() {
                Ok((stdout, stderr))
            } else {
                Err(format!("{} command failed", command))
            }
        }
        Ok(Ok(Err(e))) => Err(e),
        Ok(Err(_)) => Err(format!("{} detection task panicked", command)),
        Err(_) => Err(format!("{} detection timed out (5s)", command)),
    }
}

/// Parse Go version from output
fn parse_go_version(output: &str) -> Option<String> {
    // Example: "go version go1.21.0 windows/amd64"
    output
        .split_whitespace()
        .find(|s| s.starts_with("go1."))
        .map(|s| s.trim_start_matches("go").to_string())
}

/// Parse APT version from output
fn parse_apt_version(output: &str) -> Option<String> {
    // Example: "apt 2.4.8 (amd64)"
    output
        .lines()
        .next()
        .and_then(|line| {
            line.split_whitespace()
                .nth(1)
                .map(|v| v.to_string())
        })
}

/// Parse simple version from output (just get first numeric version)
fn parse_simple_version(output: &str) -> Option<String> {
    // Find first thing that looks like a version (e.g., "1.2.0", "v1.6.2721")
    let version_regex = regex::Regex::new(r"v?(\d+\.\d+(?:\.\d+)?)").ok()?;
    version_regex
        .captures(output)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_go_version() {
        assert_eq!(
            parse_go_version("go version go1.21.0 windows/amd64"),
            Some("1.21.0".to_string())
        );
        assert_eq!(
            parse_go_version("go version go1.20.3 linux/amd64"),
            Some("1.20.3".to_string())
        );
    }

    #[test]
    fn test_parse_apt_version() {
        assert_eq!(
            parse_apt_version("apt 2.4.8 (amd64)"),
            Some("2.4.8".to_string())
        );
    }

    #[test]
    fn test_parse_simple_version() {
        assert_eq!(
            parse_simple_version("v1.6.2721"),
            Some("1.6.2721".to_string())
        );
        assert_eq!(
            parse_simple_version("1.2.0"),
            Some("1.2.0".to_string())
        );
        assert_eq!(
            parse_simple_version("pipx 1.4.3"),
            Some("1.4.3".to_string())
        );
    }

    #[tokio::test]
    async fn test_detect_all_managers() {
        let managers = detect_all_managers().await;
        assert_eq!(managers.len(), 4); // go, pipx, apt, winget

        // At least one should be available (depending on platform)
        // On development machines, usually Go or Python/pipx is available
        eprintln!("Detected managers:");
        for manager in &managers {
            eprintln!(
                "  - {:?}: available={}, version={:?}",
                manager.manager_type, manager.available, manager.version
            );
        }
    }
}
