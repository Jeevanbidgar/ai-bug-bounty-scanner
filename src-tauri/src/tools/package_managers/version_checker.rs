// Version checking and comparison across different package managers
//
// This module provides unified version checking for Go, APT, WinGet, and pipx tools

use super::version::Version;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionCheckResult {
    pub has_update: bool,
    pub current_version: Option<String>,
    pub latest_version: Option<String>,
    pub package_manager: String,
    pub error: Option<String>,
}

impl VersionCheckResult {
    pub fn no_update(current: String, package_manager: String) -> Self {
        Self {
            has_update: false,
            current_version: Some(current.clone()),
            latest_version: Some(current),
            package_manager,
            error: None,
        }
    }

    pub fn has_update(current: String, latest: String, package_manager: String) -> Self {
        Self {
            has_update: true,
            current_version: Some(current),
            latest_version: Some(latest),
            package_manager,
            error: None,
        }
    }

    pub fn error(error: String, package_manager: String) -> Self {
        Self {
            has_update: false,
            current_version: None,
            latest_version: None,
            package_manager,
            error: Some(error),
        }
    }
}

/// Check for updates for a Go tool using `go list -m -versions`
pub async fn check_go_update(
    tool_binary: &str,
    module_path: &str,
) -> Result<VersionCheckResult, String> {
    // Step 1: Get current version from binary using `go version -m`
    let current_version = match get_go_binary_version(tool_binary).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(VersionCheckResult::error(
                format!("Failed to get current version: {}", e),
                "go".to_string(),
            ));
        }
    };

    // Step 2: Get all available versions using `go list -m -versions`
    let latest_version = match get_go_latest_version(module_path).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(VersionCheckResult::error(
                format!("Failed to get latest version: {}", e),
                "go".to_string(),
            ));
        }
    };

    // Step 3: Compare versions using SemVer
    match (
        Version::parse(&current_version),
        Version::parse(&latest_version),
    ) {
        (Some(current), Some(latest)) => {
            if latest > current {
                Ok(VersionCheckResult::has_update(
                    current_version,
                    latest_version,
                    "go".to_string(),
                ))
            } else {
                Ok(VersionCheckResult::no_update(
                    current_version,
                    "go".to_string(),
                ))
            }
        }
        _ => {
            // Fallback to string comparison if parsing fails
            if latest_version != current_version {
                Ok(VersionCheckResult::has_update(
                    current_version,
                    latest_version,
                    "go".to_string(),
                ))
            } else {
                Ok(VersionCheckResult::no_update(
                    current_version,
                    "go".to_string(),
                ))
            }
        }
    }
}

/// Get version from Go binary using `go version -m <binary>`
async fn get_go_binary_version(tool_binary: &str) -> Result<String, String> {
    let output = Command::new("go")
        .arg("version")
        .arg("-m")
        .arg(tool_binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("Failed to execute go version: {}", e))?;

    if !output.status.success() {
        return Err("go version command failed".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output: look for "mod	<module>	v<version>"
    for line in stdout.lines() {
        if line.contains("mod") && line.contains("\t") {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                let version = parts[2].trim().trim_start_matches('v');
                return Ok(version.to_string());
            }
        }
    }

    Err("Could not parse version from go version -m output".to_string())
}

/// Get latest version from Go module using `go list -m -versions <module>`
async fn get_go_latest_version(module_path: &str) -> Result<String, String> {
    let output = Command::new("go")
        .arg("list")
        .arg("-m")
        .arg("-versions")
        .arg(module_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("Failed to execute go list: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("go list failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Output format: "module v1.0.0 v1.1.0 v1.2.0 ..."
    // We want the last version in the list
    let versions: Vec<&str> = stdout.split_whitespace().collect();

    if versions.len() < 2 {
        return Err("No versions found".to_string());
    }

    // Last version is the latest
    let latest = versions.last().unwrap().trim_start_matches('v');
    Ok(latest.to_string())
}

/// Check for updates for an APT package using `apt-cache policy`
pub async fn check_apt_update(package_name: &str) -> Result<VersionCheckResult, String> {
    let output = Command::new("apt-cache")
        .arg("policy")
        .arg(package_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("Failed to execute apt-cache: {}", e))?;

    if !output.status.success() {
        return Ok(VersionCheckResult::error(
            "apt-cache policy failed".to_string(),
            "apt".to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut installed_version: Option<String> = None;
    let mut candidate_version: Option<String> = None;

    // Parse output:
    // Installed: 1.2.3
    // Candidate: 1.2.4
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("Installed:") {
            installed_version = line
                .split(':')
                .nth(1)
                .map(|s| s.trim().to_string())
                .filter(|s| s != "(none)");
        } else if line.starts_with("Candidate:") {
            candidate_version = line.split(':').nth(1).map(|s| s.trim().to_string());
        }
    }

    match (installed_version, candidate_version) {
        (Some(installed), Some(candidate)) => {
            if installed != candidate {
                Ok(VersionCheckResult::has_update(
                    installed,
                    candidate,
                    "apt".to_string(),
                ))
            } else {
                Ok(VersionCheckResult::no_update(installed, "apt".to_string()))
            }
        }
        (Some(installed), None) => Ok(VersionCheckResult::no_update(installed, "apt".to_string())),
        _ => Ok(VersionCheckResult::error(
            "Could not determine installed/candidate version".to_string(),
            "apt".to_string(),
        )),
    }
}

/// Check for updates for a WinGet package using `winget upgrade`
pub async fn check_winget_update(package_id: &str) -> Result<VersionCheckResult, String> {
    let output = Command::new("winget")
        .arg("upgrade")
        .arg("--id")
        .arg(package_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("Failed to execute winget: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check if update is available
    // WinGet output includes version columns when update is available
    if stdout.contains("upgrades available") || stdout.contains("available") {
        // Try to parse versions from output
        // Format: Name  Id  Version  Available
        let mut current_version: Option<String> = None;
        let mut latest_version: Option<String> = None;

        for line in stdout.lines() {
            if line.contains(package_id) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    current_version = Some(parts[2].to_string());
                    latest_version = Some(parts[3].to_string());
                    break;
                }
            }
        }

        match (current_version, latest_version) {
            (Some(current), Some(latest)) => Ok(VersionCheckResult::has_update(
                current,
                latest,
                "winget".to_string(),
            )),
            _ => Ok(VersionCheckResult::error(
                "Could not parse version information".to_string(),
                "winget".to_string(),
            )),
        }
    } else if stdout.contains("No applicable update found")
        || stderr.contains("No applicable update found")
    {
        // No update available - try to get current version
        Ok(VersionCheckResult::no_update(
            "installed".to_string(),
            "winget".to_string(),
        ))
    } else {
        Ok(VersionCheckResult::error(
            format!("Could not determine update status: {}", stdout),
            "winget".to_string(),
        ))
    }
}

/// Check for updates for a pipx package using `pipx runpip <pkg> pip list --outdated`
pub async fn check_pipx_update(package_name: &str) -> Result<VersionCheckResult, String> {
    // Use pipx runpip to check for outdated packages
    let output = Command::new("pipx")
        .arg("runpip")
        .arg(package_name)
        .arg("list")
        .arg("--outdated")
        .arg("--format=json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("Failed to execute pipx: {}", e))?;

    if !output.status.success() {
        return Ok(VersionCheckResult::error(
            "pipx command failed".to_string(),
            "pipx".to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON output
    #[derive(Deserialize)]
    struct OutdatedPackage {
        name: String,
        version: String,
        latest_version: String,
    }

    match serde_json::from_str::<Vec<OutdatedPackage>>(&stdout) {
        Ok(packages) => {
            // Find our package in the list
            if let Some(pkg) = packages
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(package_name))
            {
                Ok(VersionCheckResult::has_update(
                    pkg.version.clone(),
                    pkg.latest_version.clone(),
                    "pipx".to_string(),
                ))
            } else {
                // Package not in outdated list = up to date
                Ok(VersionCheckResult::no_update(
                    "installed".to_string(),
                    "pipx".to_string(),
                ))
            }
        }
        Err(e) => Ok(VersionCheckResult::error(
            format!("Failed to parse JSON: {}", e),
            "pipx".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_go_version_parsing() {
        // This test requires a Go binary to be available
        // Skip if go not available
        if let Ok(output) = Command::new("go").arg("version").output().await {
            if output.status.success() {
                println!("Go is available, testing version parsing");
                // Add more specific tests here
            }
        }
    }

    #[test]
    fn test_version_check_result() {
        let result = VersionCheckResult::has_update(
            "1.0.0".to_string(),
            "1.1.0".to_string(),
            "go".to_string(),
        );
        assert!(result.has_update);
        assert_eq!(result.current_version, Some("1.0.0".to_string()));
        assert_eq!(result.latest_version, Some("1.1.0".to_string()));
    }
}
