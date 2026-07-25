// Version checking and comparison across different package managers
//
// This module provides unified version checking for Go, APT, WinGet, and pipx tools

use super::version::Version;
use crate::runtime::process::hidden_tokio_command as hidden_command;
use serde::{Deserialize, Serialize};
use std::process::Stdio;

/// Normalize version string by removing 'v' prefix and trimming whitespace
/// This ensures consistent version comparison across different sources
fn normalize_version(version: &str) -> String {
    version
        .trim()
        .trim_start_matches('v')
        .trim_start_matches('V')
        .to_string()
}

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

    // Step 3: Normalize versions to remove 'v' prefix inconsistencies
    let current_normalized = normalize_version(&current_version);
    let latest_normalized = normalize_version(&latest_version);

    eprintln!(
        "   📊 Version comparison: current='{}' (normalized: '{}'), latest='{}' (normalized: '{}')",
        current_version, current_normalized, latest_version, latest_normalized
    );

    // Step 4: Compare versions using SemVer
    match (
        Version::parse(&current_normalized),
        Version::parse(&latest_normalized),
    ) {
        (Some(current), Some(latest)) => {
            if latest > current {
                eprintln!(
                    "   ✅ SemVer comparison: {} < {} (update available)",
                    current_normalized, latest_normalized
                );
                Ok(VersionCheckResult::has_update(
                    current_version,
                    latest_version,
                    "go".to_string(),
                ))
            } else {
                eprintln!(
                    "   ✅ SemVer comparison: {} >= {} (up to date)",
                    current_normalized, latest_normalized
                );
                Ok(VersionCheckResult::no_update(
                    current_version,
                    "go".to_string(),
                ))
            }
        }
        _ => {
            // Fallback to string comparison if parsing fails
            eprintln!("   ⚠️  SemVer parse failed, using string comparison");
            if latest_normalized != current_normalized {
                eprintln!(
                    "   📝 String comparison: '{}' != '{}' (update available)",
                    current_normalized, latest_normalized
                );
                Ok(VersionCheckResult::has_update(
                    current_version,
                    latest_version,
                    "go".to_string(),
                ))
            } else {
                eprintln!(
                    "   📝 String comparison: '{}' == '{}' (up to date)",
                    current_normalized, latest_normalized
                );
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
    let mut go_cmd = hidden_command("go");
    let output = go_cmd
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

    // Parse output: look for "mod	<module>	v<version>	<hash>"
    // The actual format uses mixed whitespace (tabs and spaces)
    // Example: "mod     github.com/ffuf/ffuf/v2 v2.1.0  h1:..."
    for line in stdout.lines() {
        if line.trim_start().starts_with("mod") {
            // Split on any whitespace and filter out empty strings
            let parts: Vec<&str> = line.split_whitespace().collect();
            // parts[0] = "mod", parts[1] = module, parts[2] = version, parts[3] = hash
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
    let mut go_cmd = hidden_command("go");
    let output = go_cmd
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
    let mut apt_cmd = hidden_command("apt-cache");
    let output = apt_cmd
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
#[allow(dead_code)]
pub async fn check_winget_update(package_id: &str) -> Result<VersionCheckResult, String> {
    let mut winget_cmd = hidden_command("winget");
    let output = winget_cmd
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
    let mut pipx_cmd = hidden_command("pipx");
    let output = pipx_cmd
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

/// Check for updates for an npm package using `npm outdated -g`
#[allow(dead_code)]
pub async fn check_npm_update(package_name: &str) -> Result<VersionCheckResult, String> {
    // First check if npm is installed
    let npm_cmd = if cfg!(target_os = "windows") {
        "npm.cmd"
    } else {
        "npm"
    };

    let check_install = hidden_command(npm_cmd).arg("--version").output().await;

    if check_install.is_err() || !check_install.unwrap().status.success() {
        return Ok(VersionCheckResult::error(
            "npm is not installed".to_string(),
            "npm".to_string(),
        ));
    }

    // Get the current version using `npm list -g <package> --depth=0 --json`
    let list_output = hidden_command(npm_cmd)
        .args(["list", "-g", package_name, "--depth=0", "--json"])
        .output()
        .await
        .map_err(|e| format!("Failed to execute npm list: {}", e))?;

    let current_version = if list_output.status.success() {
        let stdout = String::from_utf8_lossy(&list_output.stdout);

        // Parse JSON to extract version
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            json["dependencies"][package_name]["version"]
                .as_str()
                .map(normalize_version)
        } else {
            None
        }
    } else {
        None
    };

    if current_version.is_none() {
        return Ok(VersionCheckResult::error(
            format!("Package {} is not installed via npm", package_name),
            "npm".to_string(),
        ));
    }

    let current = current_version.unwrap();

    // Check for updates using `npm outdated -g <package> --json`
    let outdated_output = hidden_command(npm_cmd)
        .args(["outdated", "-g", package_name, "--json"])
        .output()
        .await
        .map_err(|e| format!("Failed to execute npm outdated: {}", e))?;

    // npm outdated returns exit code 1 if there are outdated packages, so we check stdout instead
    let stdout = String::from_utf8_lossy(&outdated_output.stdout);

    if stdout.trim().is_empty() {
        // No output means package is up-to-date
        return Ok(VersionCheckResult::no_update(current, "npm".to_string()));
    }

    // Parse JSON output
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(package_info) = json.get(package_name) {
            if let Some(latest) = package_info["latest"].as_str() {
                let latest_version = normalize_version(latest);

                // Compare versions
                match (Version::parse(&current), Version::parse(&latest_version)) {
                    (Some(current_v), Some(latest_v)) => {
                        if latest_v > current_v {
                            return Ok(VersionCheckResult::has_update(
                                current,
                                latest_version,
                                "npm".to_string(),
                            ));
                        } else {
                            return Ok(VersionCheckResult::no_update(current, "npm".to_string()));
                        }
                    }
                    _ => {
                        // If version parsing fails, assume there's an update if versions differ
                        if current != latest_version {
                            return Ok(VersionCheckResult::has_update(
                                current,
                                latest_version,
                                "npm".to_string(),
                            ));
                        }
                    }
                }
            }
        }
    }

    // If we couldn't parse the output, assume no update
    Ok(VersionCheckResult::no_update(current, "npm".to_string()))
}

/// Check for updates for a Ruby gem using `gem list` and `gem search`
#[allow(dead_code)]
pub async fn check_gem_update(package_name: &str) -> Result<VersionCheckResult, String> {
    // First check if gem is installed
    let gem_cmd = if cfg!(target_os = "windows") {
        "gem.cmd"
    } else {
        "gem"
    };

    let check_install = hidden_command(gem_cmd).arg("--version").output().await;

    if check_install.is_err() || !check_install.unwrap().status.success() {
        return Ok(VersionCheckResult::error(
            "gem is not installed".to_string(),
            "gem".to_string(),
        ));
    }

    // Get the current version using `gem list <package> --exact --local`
    let list_output = hidden_command(gem_cmd)
        .args(["list", package_name, "--exact", "--local"])
        .output()
        .await
        .map_err(|e| format!("Failed to execute gem list: {}", e))?;

    let current_version = if list_output.status.success() {
        let stdout = String::from_utf8_lossy(&list_output.stdout);
        // Output format: "package_name (version, version2, ...)"
        // Extract the first version
        stdout
            .lines()
            .next()
            .and_then(|line| line.split('(').nth(1))
            .and_then(|versions| versions.split(',').next())
            .map(|version| normalize_version(version.trim().trim_end_matches(')')))
    } else {
        None
    };

    if current_version.is_none() {
        return Ok(VersionCheckResult::error(
            format!("Package {} is not installed via gem", package_name),
            "gem".to_string(),
        ));
    }

    let current = current_version.unwrap();

    // Check for the latest version using `gem search ^<package>$ --remote`
    let search_output = hidden_command(gem_cmd)
        .args(["search", &format!("^{}$", package_name), "--remote"])
        .output()
        .await
        .map_err(|e| format!("Failed to execute gem search: {}", e))?;

    if !search_output.status.success() {
        return Ok(VersionCheckResult::error(
            "Failed to search for gem updates".to_string(),
            "gem".to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&search_output.stdout);

    // Parse the output for the latest version
    // Output format: "package_name (version, version2, ...)"
    let latest_version = stdout
        .lines()
        .next()
        .and_then(|line| line.split('(').nth(1))
        .and_then(|versions| versions.split(',').next())
        .map(|version| normalize_version(version.trim().trim_end_matches(')')));

    if let Some(latest) = latest_version {
        // Compare versions
        match (Version::parse(&current), Version::parse(&latest)) {
            (Some(current_v), Some(latest_v)) => {
                if latest_v > current_v {
                    return Ok(VersionCheckResult::has_update(
                        current,
                        latest,
                        "gem".to_string(),
                    ));
                } else {
                    return Ok(VersionCheckResult::no_update(current, "gem".to_string()));
                }
            }
            _ => {
                // If version parsing fails, assume there's an update if versions differ
                if current != latest {
                    return Ok(VersionCheckResult::has_update(
                        current,
                        latest,
                        "gem".to_string(),
                    ));
                } else {
                    return Ok(VersionCheckResult::no_update(current, "gem".to_string()));
                }
            }
        }
    }

    Ok(VersionCheckResult::no_update(current, "gem".to_string()))
}

/// Check for updates for a Cargo package using `cargo install --list` and crates.io
#[allow(dead_code)]
pub async fn check_cargo_update(package_name: &str) -> Result<VersionCheckResult, String> {
    // First check if cargo is installed
    let check_install = hidden_command("cargo").arg("--version").output().await;

    if check_install.is_err() || !check_install.unwrap().status.success() {
        return Ok(VersionCheckResult::error(
            "cargo is not installed".to_string(),
            "cargo".to_string(),
        ));
    }

    // Get the current version using `cargo install --list`
    let list_output = hidden_command("cargo")
        .args(["install", "--list"])
        .output()
        .await
        .map_err(|e| format!("Failed to execute cargo install --list: {}", e))?;

    let current_version = if list_output.status.success() {
        let stdout = String::from_utf8_lossy(&list_output.stdout);

        // Find the package in the output
        // Format: "package_name v1.2.3:"
        let mut found_version: Option<String> = None;
        for line in stdout.lines() {
            if line.starts_with(package_name) && line.contains(" v") {
                if let Some(version_part) = line.split(" v").nth(1) {
                    let version = version_part.trim_end_matches(':');
                    found_version = Some(normalize_version(version));
                    break;
                }
            }
        }
        found_version
    } else {
        None
    };

    if current_version.is_none() {
        return Ok(VersionCheckResult::error(
            format!("Package {} is not installed via cargo", package_name),
            "cargo".to_string(),
        ));
    }

    let current = current_version.unwrap();

    // Check crates.io for the latest version using cargo search
    let search_output = hidden_command("cargo")
        .args(["search", package_name, "--limit", "1"])
        .output()
        .await
        .map_err(|e| format!("Failed to execute cargo search: {}", e))?;

    if !search_output.status.success() {
        return Ok(VersionCheckResult::error(
            "Failed to search for cargo updates".to_string(),
            "cargo".to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&search_output.stdout);

    // Parse the output for the latest version
    // Format: "package_name = "1.2.3"    # description"
    let latest_version = if let Some(line) = stdout.lines().next() {
        if let Some(version_part) = line.split('=').nth(1) {
            let version = version_part
                .trim()
                .trim_start_matches('"')
                .split('"')
                .next()
                .unwrap_or("");
            Some(normalize_version(version))
        } else {
            None
        }
    } else {
        None
    };

    if let Some(latest) = latest_version {
        // Compare versions
        match (Version::parse(&current), Version::parse(&latest)) {
            (Some(current_v), Some(latest_v)) => {
                if latest_v > current_v {
                    return Ok(VersionCheckResult::has_update(
                        current,
                        latest,
                        "cargo".to_string(),
                    ));
                } else {
                    return Ok(VersionCheckResult::no_update(current, "cargo".to_string()));
                }
            }
            _ => {
                // If version parsing fails, assume there's an update if versions differ
                if current != latest {
                    return Ok(VersionCheckResult::has_update(
                        current,
                        latest,
                        "cargo".to_string(),
                    ));
                } else {
                    return Ok(VersionCheckResult::no_update(current, "cargo".to_string()));
                }
            }
        }
    }

    Ok(VersionCheckResult::no_update(current, "cargo".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_go_version_parsing() {
        // This test requires a Go binary to be available
        // Skip if go not available
        if let Ok(output) = hidden_command("go").arg("version").output().await {
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
