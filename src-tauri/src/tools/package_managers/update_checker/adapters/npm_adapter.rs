// NPM Update Checker Adapter
//
// Implements update checking for npm packages using npm outdated -g

use std::time::Duration;
use super::super::traits::{UpdateChecker, UpdateCheckResult, UpdateType};
use super::super::error_types::{UpdateCheckError, UpdateCheckErrorCode};
use super::super::command_runner::CommandRunner;
use super::super::version::Version;

/// NPM update checker
pub struct NpmUpdateChecker {
    command_runner: CommandRunner,
}

impl NpmUpdateChecker {
    pub fn new(command_runner: CommandRunner) -> Self {
        Self { command_runner }
    }

    /// Get the npm command name based on platform
    fn npm_command(&self) -> &str {
        if cfg!(target_os = "windows") {
            "npm.cmd"
        } else {
            "npm"
        }
    }

    /// Normalize version string
    fn normalize_version(version: &str) -> String {
        version.trim().to_string()
    }

    /// Get current version using `npm list -g <package> --depth=0 --json`
    async fn get_current_version(&self, package_name: &str) -> Result<String, UpdateCheckError> {
        let npm_cmd = self.npm_command();
        let output = self.command_runner.execute(
            npm_cmd,
            &["list", "-g", package_name, "--depth=0", "--json"],
        ).await?;

        if !output.success {
            return Err(UpdateCheckError::package_not_found(
                "npm".to_string(),
                package_name.to_string(),
            ));
        }

        // Parse JSON to extract version
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&output.stdout) {
            if let Some(version) = json["dependencies"][package_name]["version"].as_str() {
                return Ok(Self::normalize_version(version));
            }
        }

        Err(UpdateCheckError::invalid_version(
            "npm".to_string(),
            package_name.to_string(),
            output.stdout,
        ))
    }

    /// Check for updates using `npm outdated -g <package> --json`
    async fn check_outdated(&self, package_name: &str) -> Result<Option<String>, UpdateCheckError> {
        let npm_cmd = self.npm_command();
        let output = self.command_runner.execute(
            npm_cmd,
            &["outdated", "-g", package_name, "--json"],
        ).await?;

        // npm outdated returns exit code 1 if there are outdated packages
        if output.stdout.trim().is_empty() {
            return Ok(None); // No output means package is up-to-date
        }

        // Parse JSON output
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&output.stdout) {
            if let Some(package_info) = json.get(package_name) {
                if let Some(latest) = package_info["latest"].as_str() {
                    return Ok(Some(Self::normalize_version(latest)));
                }
            }
        }

        Ok(None)
    }

    /// Determine update type based on version comparison
    fn determine_update_type(current: &str, latest: &str) -> Option<UpdateType> {
        match (Version::parse(current), Version::parse(latest)) {
            (Some(current_v), Some(latest_v)) => {
                if latest_v > current_v {
                    if latest_v.major > current_v.major {
                        Some(UpdateType::Major)
                    } else if latest_v.minor > current_v.minor {
                        Some(UpdateType::Minor)
                    } else {
                        Some(UpdateType::Patch)
                    }
                } else {
                    None
                }
            }
            _ => Some(UpdateType::Unknown),
        }
    }
}

impl UpdateChecker for NpmUpdateChecker {
    fn check_update(&self, package_name: &str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<UpdateCheckResult, UpdateCheckError>> + Send + '_>> {
        let command_runner = self.command_runner.clone();
        let package_name = package_name.to_string();
        
        Box::pin(async move {
            let checker = NpmUpdateChecker::new(command_runner);
            
            // Get current version  
            let current_version = checker.get_current_version(&package_name).await?;
        
            // Check for updates
            let latest_version = checker.check_outdated(&package_name).await?;
            
            match latest_version {
                Some(latest) => {
                    // Compare versions
                    let has_update = match (Version::parse(&current_version), Version::parse(&latest)) {
                        (Some(current_v), Some(latest_v)) => latest_v > current_v,
                        _ => current_version != latest, // Fallback to string comparison
                    };

                    let update_type = if has_update {
                        Self::determine_update_type(&current_version, &latest)
                    } else {
                        None
                    };

                    Ok(UpdateCheckResult::success(
                        has_update,
                        Some(current_version),
                        Some(latest),
                        "npm".to_string(),
                        Some("npm outdated -g".to_string()),
                        update_type,
                    ))
                }
                None => {
                    // No update available
                    Ok(UpdateCheckResult::success(
                        false,
                        Some(current_version.clone()),
                        Some(current_version),
                        "npm".to_string(),
                        Some("npm outdated -g".to_string()),
                        None,
                    ))
                }
            }
        })
    }

    fn manager_name(&self) -> &str {
        "npm"
    }

    fn is_available(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let command_runner = self.command_runner.clone();
        let npm_cmd = self.npm_command().to_string();
        
        Box::pin(async move {
            command_runner.is_available(&npm_cmd).await
        })
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn priority(&self) -> u8 {
        50 // Medium priority
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_version() {
        assert_eq!(NpmUpdateChecker::normalize_version("1.2.3"), "1.2.3");
        assert_eq!(NpmUpdateChecker::normalize_version(" 1.2.3 "), "1.2.3");
    }

    #[test]
    fn test_determine_update_type() {
        assert_eq!(
            NpmUpdateChecker::determine_update_type("1.0.0", "1.0.1"),
            Some(UpdateType::Patch)
        );
        assert_eq!(
            NpmUpdateChecker::determine_update_type("1.0.0", "1.1.0"),
            Some(UpdateType::Minor)
        );
        assert_eq!(
            NpmUpdateChecker::determine_update_type("1.0.0", "2.0.0"),
            Some(UpdateType::Major)
        );
        assert_eq!(
            NpmUpdateChecker::determine_update_type("1.0.0", "1.0.0"),
            None
        );
    }
}
