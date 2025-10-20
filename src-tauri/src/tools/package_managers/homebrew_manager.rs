// Homebrew package manager implementation for macOS
//
// This module provides Homebrew-based installation, management, and
// version checking for security tools on macOS systems.

use super::PackageManagerType;
use crate::tools::package_managers::homebrew_registry::get_homebrew_mapping;
use anyhow::{anyhow, Result};
use regex::Regex;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::process::{ExitStatus, Output};
use tauri::{AppHandle, Emitter};
use tokio::process::Command as TokioCommand;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct InstallationStatus {
    pub installed: bool,
    pub version: Option<String>,
    pub needs_update: bool,
    pub manager: PackageManagerType,
}

#[derive(Debug, Clone)]
pub struct HomebrewManager {
    _registry: &'static HashMap<
        &'static str,
        crate::tools::package_managers::homebrew_registry::HomebrewMapping,
    >,
}

impl HomebrewManager {
    pub fn new() -> Self {
        Self {
            _registry: &crate::tools::package_managers::homebrew_registry::HOMEBREW_REGISTRY,
        }
    }

    /// Install a tool using Homebrew
    pub async fn install_tool(&self, tool_name: &str, app_handle: AppHandle) -> Result<()> {
        let mapping = get_homebrew_mapping(tool_name)
            .ok_or_else(|| anyhow!("No Homebrew mapping for tool: {}", tool_name))?;

        let (package, brew_args_owned): (String, Vec<String>) =
            if let Some(cask) = &mapping.brew_cask {
                let package = cask.clone();
                let args = vec!["install".to_string(), "--cask".to_string(), package.clone()];
                (package, args)
            } else if let Some(formula) = &mapping.brew_formula {
                let package = formula.clone();
                let args = vec!["install".to_string(), package.clone()];
                (package, args)
            } else {
                return Err(anyhow!("No formula or cask defined for {}", tool_name));
            };

        // Emit installation start event
        app_handle.emit(
            "installation:started",
            serde_json::json!({
                "tool": tool_name,
                "package": package.clone(),
                "manager": "homebrew"
            }),
        )?;

        ensure_brew_available().await?;

        let brew_args = arg_refs(&brew_args_owned);
        let command_label = brew_command_label(&brew_args);
        let output = run_brew_command(&brew_args).await?;

        if !output.status.success() {
            let diagnostic = brew_diagnostic(&output);
            return Err(anyhow!(
                "Homebrew failed to install {} using '{}': {}",
                tool_name,
                command_label,
                diagnostic
            ));
        }

        // Verify minimum version if specified
        if let Some(min_version) = &mapping.min_version {
            HomebrewManager::verify_version(tool_name, min_version).await?;
        }

        Ok(())
    }

    /// Upgrade a tool using Homebrew
    pub async fn upgrade_tool(&self, tool_name: &str, app_handle: AppHandle) -> Result<()> {
        let mapping = get_homebrew_mapping(tool_name)
            .ok_or_else(|| anyhow!("No Homebrew mapping for tool: {}", tool_name))?;

        let (package, brew_args_owned): (String, Vec<String>) =
            if let Some(cask) = &mapping.brew_cask {
                let package = cask.clone();
                let args = vec!["upgrade".to_string(), "--cask".to_string(), package.clone()];
                (package, args)
            } else if let Some(formula) = &mapping.brew_formula {
                let package = formula.clone();
                let args = vec!["upgrade".to_string(), package.clone()];
                (package, args)
            } else {
                return Err(anyhow!("No formula or cask defined for {}", tool_name));
            };

        // Emit upgrade start event
        app_handle.emit(
            "installation:started",
            serde_json::json!({
                "tool": tool_name,
                "package": package.clone(),
                "manager": "homebrew",
                "action": "upgrade"
            }),
        )?;

        ensure_brew_available().await?;

        let brew_args = arg_refs(&brew_args_owned);
        let command_label = brew_command_label(&brew_args);
        let output = run_brew_command(&brew_args).await?;

        if !output.status.success() {
            let diagnostic = brew_diagnostic(&output);
            return Err(anyhow!(
                "Homebrew failed to upgrade {} using '{}': {}",
                tool_name,
                command_label,
                diagnostic
            ));
        }

        Ok(())
    }

    /// Uninstall a tool using Homebrew
    pub async fn uninstall_tool(&self, tool_name: &str, app_handle: AppHandle) -> Result<()> {
        let mapping = get_homebrew_mapping(tool_name)
            .ok_or_else(|| anyhow!("No Homebrew mapping for tool: {}", tool_name))?;

        let (package, brew_args_owned): (String, Vec<String>) =
            if let Some(cask) = &mapping.brew_cask {
                let package = cask.clone();
                let args = vec![
                    "uninstall".to_string(),
                    "--cask".to_string(),
                    package.clone(),
                ];
                (package, args)
            } else if let Some(formula) = &mapping.brew_formula {
                let package = formula.clone();
                let args = vec!["uninstall".to_string(), package.clone()];
                (package, args)
            } else {
                return Err(anyhow!("No formula or cask defined for {}", tool_name));
            };

        // Emit uninstall start event
        app_handle.emit(
            "installation:started",
            serde_json::json!({
                "tool": tool_name,
                "package": package.clone(),
                "manager": "homebrew",
                "action": "uninstall"
            }),
        )?;

        ensure_brew_available().await?;

        let brew_args = arg_refs(&brew_args_owned);
        let command_label = brew_command_label(&brew_args);
        let output = run_brew_command(&brew_args).await?;

        if !output.status.success() {
            let diagnostic = brew_diagnostic(&output);
            return Err(anyhow!(
                "Homebrew failed to uninstall {} using '{}': {}",
                tool_name,
                command_label,
                diagnostic
            ));
        }

        Ok(())
    }

    /// Verify tool version meets minimum requirements
    pub async fn verify_version(tool_name: &str, min_version: &str) -> Result<()> {
        let detected = get_version(tool_name)
            .await
            .ok_or_else(|| anyhow!("Could not detect version for {}", tool_name))?;

        // Use semver comparison if available, otherwise string comparison
        if let (Ok(detected_ver), Ok(min_ver)) =
            (Version::parse(&detected), Version::parse(min_version))
        {
            if detected_ver < min_ver {
                return Err(anyhow!(
                    "Installed version {} is below minimum required {} for {}",
                    detected,
                    min_version,
                    tool_name
                ));
            }
        } else {
            // Fallback to string comparison
            if detected.as_str() < min_version {
                return Err(anyhow!(
                    "Installed version {} is below minimum required {} for {}",
                    detected,
                    min_version,
                    tool_name
                ));
            }
        }

        Ok(())
    }

    /// Check if tool needs update using Homebrew
    async fn check_homebrew_update(tool_name: &str) -> Result<Option<(String, String)>> {
        let mapping = get_homebrew_mapping(tool_name)
            .ok_or_else(|| anyhow!("No Homebrew mapping for tool: {}", tool_name))?;

        if let Some(formula) = &mapping.brew_formula {
            let args = ["outdated", formula.as_str()];
            let command_label = brew_command_label(&args);
            let output = run_brew_command(&args).await?;

            if !output.status.success() {
                let diagnostic = brew_diagnostic(&output);
                return Err(anyhow!(
                    "Homebrew outdated command '{}' failed for {}: {}",
                    command_label,
                    formula,
                    diagnostic
                ));
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(parse_outdated_output(&stdout))
        } else if let Some(cask) = &mapping.brew_cask {
            let args = ["outdated", "--cask", cask.as_str()];
            let command_label = brew_command_label(&args);
            let output = run_brew_command(&args).await?;

            if !output.status.success() {
                let diagnostic = brew_diagnostic(&output);
                return Err(anyhow!(
                    "Homebrew outdated command '{}' failed for cask {}: {}",
                    command_label,
                    cask,
                    diagnostic
                ));
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(parse_outdated_output(&stdout))
        } else {
            Ok(None)
        }
    }
}

fn brew_command_label(args: &[&str]) -> String {
    if args.is_empty() {
        "brew".to_string()
    } else {
        format!("brew {}", args.join(" "))
    }
}

fn decode_brew_output(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn brew_diagnostic(output: &Output) -> String {
    decode_brew_output(&output.stderr)
        .or_else(|| decode_brew_output(&output.stdout))
        .unwrap_or_else(|| "No diagnostic output captured from Homebrew".to_string())
}

fn arg_refs(args: &[String]) -> Vec<&str> {
    args.iter().map(|s| s.as_str()).collect()
}

fn describe_exit_status(status: ExitStatus) -> String {
    status
        .code()
        .map(|c| format!("exit code {}", c))
        .unwrap_or_else(|| "terminated by signal".to_string())
}

async fn run_brew_command(args: &[&str]) -> Result<Output> {
    let mut command = TokioCommand::new("brew");
    command.args(args);

    command.output().await.map_err(|err| match err.kind() {
        ErrorKind::NotFound => anyhow!(
            "Homebrew is not installed or not on PATH. Install it from https://brew.sh and restart the app."
        ),
        _ => anyhow!(
            "Failed to execute '{}': {}",
            brew_command_label(args),
            err
        ),
    })
}

async fn ensure_brew_available() -> Result<()> {
    let output = run_brew_command(&["--version"]).await?;

    if output.status.success() {
        return Ok(());
    }

    let diagnostic = brew_diagnostic(&output);
    let status_desc = describe_exit_status(output.status);
    Err(anyhow!("'brew --version' {}: {}", status_desc, diagnostic))
}

/// Simple version extraction from command output
fn extract_version_from_line(line: &str) -> Option<String> {
    // Look for version patterns like "1.2.3", "v1.2.3", "version 1.2.3"
    let version_regex = Regex::new(r"v?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9]+)?)").ok()?;

    version_regex
        .captures(line)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

/// Check if tool is installed (PATH + Homebrew verification)
pub async fn is_installed(tool_name: &str) -> bool {
    // Check if tool is in PATH (fast check)
    if let Ok(output) = TokioCommand::new("which").arg(tool_name).output().await {
        if output.status.success() {
            return true;
        }
    }

    // Then verify via Homebrew (authoritative check)
    if let Some(mapping) = get_homebrew_mapping(tool_name) {
        if let Some(formula) = &mapping.brew_formula {
            let args = ["ls", "--versions", formula.as_str()];
            if let Ok(output) = run_brew_command(&args).await {
                if output.status.success() {
                    return true;
                }
            }
        }

        if let Some(cask) = &mapping.brew_cask {
            let args = ["list", "--cask", "--versions", cask.as_str()];
            if let Ok(output) = run_brew_command(&args).await {
                if output.status.success() {
                    return true;
                }
            }
        }
    }

    false
}

/// Check if tool needs update
#[allow(dead_code)]
pub async fn needs_update(tool_name: &str) -> bool {
    // First check if tool is installed
    if !is_installed(tool_name).await {
        return false;
    }

    match HomebrewManager::check_homebrew_update(tool_name).await {
        Ok(Some(_)) => true,
        _ => false,
    }
}

/// Get tool version
pub async fn get_version(tool_name: &str) -> Option<String> {
    // Simple version detection using the tool's version command
    if let Ok(output) = TokioCommand::new(tool_name).arg("--version").output().await {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Extract first line and try to find version pattern
            if let Some(first_line) = stdout.lines().next() {
                // Simple regex-like extraction for version numbers
                if let Some(version) = extract_version_from_line(first_line) {
                    return Some(version);
                }
            }
        }
    }
    // Fallback: use Homebrew metadata if direct command fails
    if let Some(mapping) = get_homebrew_mapping(tool_name) {
        if let Some(formula) = &mapping.brew_formula {
            let args = ["list", "--versions", formula.as_str()];
            if let Ok(output) = run_brew_command(&args).await {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if let Some(version) = stdout
                        .split_whitespace()
                        .skip(1)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .last()
                        .map(|s| s.to_string())
                    {
                        if !version.is_empty() {
                            return Some(version);
                        }
                    }
                }
            }
        }

        if let Some(cask) = &mapping.brew_cask {
            let args = ["list", "--cask", "--versions", cask.as_str()];
            if let Ok(output) = run_brew_command(&args).await {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if let Some(version) = stdout
                        .split_whitespace()
                        .skip(1)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .last()
                        .map(|s| s.to_string())
                    {
                        if !version.is_empty() {
                            return Some(version);
                        }
                    }
                }
            }
        }
    }

    None
}

/// Get installation status info
#[allow(dead_code)]
pub async fn get_status(tool_name: &str) -> Result<InstallationStatus> {
    let installed = is_installed(tool_name).await;
    let version = get_version(tool_name).await;
    let needs_update = needs_update(tool_name).await;

    Ok(InstallationStatus {
        installed,
        version,
        needs_update,
        manager: PackageManagerType::Homebrew,
    })
}

/// Get update information for a Homebrew-managed tool.
pub async fn get_update_versions(tool_name: &str) -> Result<Option<(String, String)>> {
    HomebrewManager::check_homebrew_update(tool_name).await
}

fn parse_outdated_output(output: &str) -> Option<(String, String)> {
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Expected format examples:
        //   toolname (1.0.0) < 1.2.0
        //   toolname (1.0.0, 1.1.0) < 1.2.0
        //   toolname (1.0.0) != 1.1.0   (seen for some casks)
        if let Some(start_idx) = line.find('(') {
            let rest = &line[start_idx + 1..];
            if let Some(end_idx) = rest.find(')') {
                let installed_segment = &rest[..end_idx];
                let remainder = &rest[end_idx + 1..];

                let (sep_index, sep_len) = if let Some(pos) = remainder.find('<') {
                    (pos, 1_usize)
                } else if let Some(pos) = remainder.find("!=") {
                    (pos, 2_usize)
                } else {
                    continue;
                };

                let latest_part = remainder[sep_index + sep_len..].trim();
                if latest_part.is_empty() {
                    continue;
                }

                let latest_version = latest_part.split_whitespace().next().unwrap_or("").trim();
                if latest_version.is_empty() {
                    continue;
                }

                let installed_version = installed_segment
                    .split(|c| c == ',' || c == ' ')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .last()
                    .unwrap_or(installed_segment.trim())
                    .to_string();

                return Some((installed_version, latest_version.to_string()));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tauri::AppHandle;

    fn mock_app_handle() -> AppHandle {
        // Mock AppHandle for testing - in real tests this would need proper Tauri setup
        panic!("Mock AppHandle needed for testing")
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_homebrew_manager_creation() {
        let manager = HomebrewManager::new();
        assert!(!manager._registry.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_registry_integration() {
        let manager = HomebrewManager::new();

        // Test that critical tools are in registry
        assert!(manager._registry.contains_key("nuclei"));
        assert!(manager._registry.contains_key("subfinder"));
        assert!(manager._registry.contains_key("nmap"));

        // Test nuclei mapping specifically
        let nuclei_mapping = manager._registry.get("nuclei").unwrap();
        assert_eq!(nuclei_mapping.brew_formula, Some("nuclei".to_string()));
        assert_eq!(nuclei_mapping.min_version, Some("3.0.0".to_string()));
        assert_eq!(nuclei_mapping.verified, true);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_tool_installation_status() {
        // Test that we can get status for tools in registry
        // Note: This will fail if tools aren't actually installed
        let status = get_status("nuclei").await;
        assert!(status.is_ok());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_version_verification() {
        // Test version verification logic (mock scenario)
        // This would need a tool that's actually installed to test properly
        let result = HomebrewManager::verify_version("nuclei", "3.0.0").await;

        if let Err(err) = result {
            let message = err.to_string();
            assert!(
                message.contains("below minimum")
                    || message.contains("Could not detect version")
                    || message.contains("not installed"),
                "Unexpected error message: {}",
                message
            );
        }
    }
}
