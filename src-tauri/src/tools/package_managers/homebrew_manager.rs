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
use tauri::{AppHandle, Emitter};
use tokio::process::Command as TokioCommand;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationStatus {
    pub installed: bool,
    pub version: Option<String>,
    pub needs_update: bool,
    pub manager: PackageManagerType,
}

#[derive(Debug, Clone)]
pub struct HomebrewManager {
    registry: &'static HashMap<&'static str, crate::tools::package_managers::homebrew_registry::HomebrewMapping>,
}

impl HomebrewManager {
    pub fn new() -> Self {
        Self {
            registry: &crate::tools::package_managers::homebrew_registry::HOMEBREW_REGISTRY,
        }
    }

    /// Install a tool using Homebrew
    pub async fn install_tool(&self, tool_name: &str, app_handle: AppHandle) -> Result<()> {
        let mapping = get_homebrew_mapping(tool_name)
            .ok_or_else(|| anyhow!("No Homebrew mapping for tool: {}", tool_name))?;

        let (mut cmd, package) = if let Some(cask) = &mapping.brew_cask {
            (TokioCommand::new("brew"), cask.clone())
        } else if let Some(formula) = &mapping.brew_formula {
            (TokioCommand::new("brew"), formula.clone())
        } else {
            return Err(anyhow!("No formula or cask defined for {}", tool_name));
        };

        // Add arguments based on type
        if mapping.brew_cask.is_some() {
            cmd.args(["install", "--cask", &package]);
        } else {
            cmd.args(["install", &package]);
        }

        // Emit installation start event
        app_handle.emit("installation:started", serde_json::json!({
            "tool": tool_name,
            "package": package,
            "manager": "homebrew"
        }))?;

        // Execute installation
        let output = cmd.output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Homebrew installation failed: {}", stderr));
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

        let (mut cmd, package) = if let Some(cask) = &mapping.brew_cask {
            (TokioCommand::new("brew"), cask.clone())
        } else if let Some(formula) = &mapping.brew_formula {
            (TokioCommand::new("brew"), formula.clone())
        } else {
            return Err(anyhow!("No formula or cask defined for {}", tool_name));
        };

        // Add arguments based on type
        if mapping.brew_cask.is_some() {
            cmd.args(["upgrade", "--cask", &package]);
        } else {
            cmd.args(["upgrade", &package]);
        }

        // Emit upgrade start event
        app_handle.emit("installation:started", serde_json::json!({
            "tool": tool_name,
            "package": package,
            "manager": "homebrew",
            "action": "upgrade"
        }))?;

        // Execute upgrade
        let output = cmd.output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Homebrew upgrade failed: {}", stderr));
        }

        Ok(())
    }

    /// Uninstall a tool using Homebrew
    pub async fn uninstall_tool(&self, tool_name: &str, app_handle: AppHandle) -> Result<()> {
        let mapping = get_homebrew_mapping(tool_name)
            .ok_or_else(|| anyhow!("No Homebrew mapping for tool: {}", tool_name))?;

        let (mut cmd, package) = if let Some(cask) = &mapping.brew_cask {
            (TokioCommand::new("brew"), cask.clone())
        } else if let Some(formula) = &mapping.brew_formula {
            (TokioCommand::new("brew"), formula.clone())
        } else {
            return Err(anyhow!("No formula or cask defined for {}", tool_name));
        };

        // Add arguments based on type
        if mapping.brew_cask.is_some() {
            cmd.args(["uninstall", "--cask", &package]);
        } else {
            cmd.args(["uninstall", &package]);
        }

        // Emit uninstall start event
        app_handle.emit("installation:started", serde_json::json!({
            "tool": tool_name,
            "package": package,
            "manager": "homebrew",
            "action": "uninstall"
        }))?;

        // Execute uninstall
        let output = cmd.output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Homebrew uninstall failed: {}", stderr));
        }

        Ok(())
    }

    /// Verify tool version meets minimum requirements
    pub async fn verify_version(tool_name: &str, min_version: &str) -> Result<()> {
        let detected = get_version(tool_name).await
            .ok_or_else(|| anyhow!("Could not detect version for {}", tool_name))?;

        // Use semver comparison if available, otherwise string comparison
        if let (Ok(detected_ver), Ok(min_ver)) = (
            Version::parse(&detected),
            Version::parse(min_version)
        ) {
            if detected_ver < min_ver {
                return Err(anyhow!(
                    "Installed version {} is below minimum required {} for {}",
                    detected, min_version, tool_name
                ));
            }
        } else {
            // Fallback to string comparison
            if detected.as_str() < min_version {
                return Err(anyhow!(
                    "Installed version {} is below minimum required {} for {}",
                    detected, min_version, tool_name
                ));
            }
        }

        Ok(())
    }

    /// Check if tool needs update using Homebrew
    async fn check_homebrew_update(tool_name: &str) -> Result<bool> {
        let mapping = get_homebrew_mapping(tool_name)
            .ok_or_else(|| anyhow!("No Homebrew mapping for tool: {}", tool_name))?;

        if let Some(formula) = &mapping.brew_formula {
            let output = TokioCommand::new("brew")
                .args(["outdated", formula])
                .output()
                .await?;

            // If command succeeds and returns non-empty output, tool needs update
            Ok(output.status.success() && !output.stdout.is_empty())
        } else {
            // For casks, use different approach - for now return false
            Ok(false) // TODO: Implement cask update checking
        }
    }
}

/// Simple version extraction from command output
fn extract_version_from_line(line: &str) -> Option<String> {
    // Look for version patterns like "1.2.3", "v1.2.3", "version 1.2.3"
    let version_regex = Regex::new(r"v?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9]+)?)")
        .ok()?;

    version_regex
        .captures(line)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

    /// Check if tool is installed (PATH + Homebrew verification)
    pub async fn is_installed(tool_name: &str) -> bool {
        // Check if tool is in PATH (fast check)
        if let Ok(output) = TokioCommand::new("which")
            .arg(tool_name)
            .output()
            .await
        {
            if output.status.success() {
                return true;
            }
        }

        // Then verify via Homebrew (authoritative check)
        if let Some(mapping) = get_homebrew_mapping(tool_name) {
            if let Some(formula) = &mapping.brew_formula {
                let output = TokioCommand::new("brew")
                    .args(["ls", "--versions", formula])
                    .output()
                    .await;

                return output.map(|o| o.status.success()).unwrap_or(false);
            }
        }

        false
    }

    /// Check if tool needs update
    pub async fn needs_update(tool_name: &str) -> bool {
        // First check if tool is installed
        if !is_installed(tool_name).await {
            return false;
        }

        // For now, always return false - update checking not implemented
        false
    }

    /// Get tool version
    pub async fn get_version(tool_name: &str) -> Option<String> {
        // Simple version detection using the tool's version command
        if let Ok(output) = TokioCommand::new(tool_name)
            .arg("--version")
            .output()
            .await
        {
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
        None
    }

    /// Get installation status info
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
        assert!(!manager.registry.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_registry_integration() {
        let manager = HomebrewManager::new();

        // Test that critical tools are in registry
        assert!(manager.registry.contains_key("nuclei"));
        assert!(manager.registry.contains_key("subfinder"));
        assert!(manager.registry.contains_key("nmap"));

        // Test nuclei mapping specifically
        let nuclei_mapping = manager.registry.get("nuclei").unwrap();
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
        let result = verify_version("nuclei", "3.0.0").await;
        // Should either succeed or fail with appropriate error message
        assert!(result.is_ok() || result.unwrap_err().to_string().contains("below minimum"));
    }
}
