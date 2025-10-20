// Gem Update Checker Adapter
//
// Implements update checking for Ruby gems using gem list and gem search

use std::time::Duration;
use super::super::traits::{UpdateChecker, UpdateCheckResult, UpdateType};
use super::super::error_types::{UpdateCheckError, UpdateCheckErrorCode};
use super::super::command_runner::CommandRunner;
use super::super::version::Version;

/// Gem update checker
pub struct GemUpdateChecker {
    command_runner: CommandRunner,
}

impl GemUpdateChecker {
    pub fn new(command_runner: CommandRunner) -> Self {
        Self { command_runner }
    }

    /// Get the gem command name based on platform
    fn gem_command(&self) -> &str {
        if cfg!(target_os = "windows") {
            "gem.cmd"
        } else {
            "gem"
        }
    }

    /// Normalize version string
    fn normalize_version(version: &str) -> String {
        version.trim().to_string()
    }

    /// Get current version using `gem list <package> --exact --local`
    async fn get_current_version(&self, package_name: &str) -> Result<String, UpdateCheckError> {
        let gem_cmd = self.gem_command();
        let output = self.command_runner.execute(
            gem_cmd,
            &["list", package_name, "--exact", "--local"],
        ).await?;

        if !output.success {
            return Err(UpdateCheckError::package_not_found(
                "gem".to_string(),
                package_name.to_string(),
            ));
        }

        // Parse output format: "package_name (version, version2, ...)"
        // Extract the first version
        if let Some(line) = output.stdout.lines().next() {
            if let Some(versions_part) = line.split('(').nth(1) {
                if let Some(first_version) = versions_part.split(',').next() {
                    return Ok(Self::normalize_version(
                        first_version.trim().trim_end_matches(')'),
                    ));
                }
            }
        }

        Err(UpdateCheckError::invalid_version(
            "gem".to_string(),
            package_name.to_string(),
            output.stdout,
        ))
    }

    /// Get latest version using `gem search ^<package>$ --remote`
    async fn get_latest_version(&self, package_name: &str) -> Result<String, UpdateCheckError> {
        let gem_cmd = self.gem_command();
        let output = self.command_runner.execute(
            gem_cmd,
            &["search", &format!("^{}$", package_name), "--remote"],
        ).await?;

        if !output.success {
            return Err(UpdateCheckError::command_failed(
                "gem".to_string(),
                package_name.to_string(),
                format!("gem search ^{}$ --remote", package_name),
                output.exit_code,
                output.stderr,
            ));
        }

        // Parse the output for the latest version
        // Output format: "package_name (version, version2, ...)"
        if let Some(line) = output.stdout.lines().next() {
            if let Some(versions_part) = line.split('(').nth(1) {
                if let Some(first_version) = versions_part.split(',').next() {
                    return Ok(Self::normalize_version(
                        first_version.trim().trim_end_matches(')'),
                    ));
                }
            }
        }

        Err(UpdateCheckError::invalid_version(
            "gem".to_string(),
            package_name.to_string(),
            output.stdout,
        ))
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

impl UpdateChecker for GemUpdateChecker {
    fn check_update(&self, package_name: &str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<UpdateCheckResult, UpdateCheckError>> + Send + '_>> {
        let command_runner = self.command_runner.clone();
        let package_name = package_name.to_string();
        
        Box::pin(async move {
            let checker = GemUpdateChecker::new(command_runner);
            // Get current version
            let current_version = checker.get_current_version(&package_name).await?;
            
            // Get latest version
            let latest_version = checker.get_latest_version(&package_name).await?;
            
            // Compare versions
            let has_update = match (Version::parse(&current_version), Version::parse(&latest_version)) {
            (Some(current_v), Some(latest_v)) => latest_v > current_v,
            _ => current_version != latest_version, // Fallback to string comparison
            };
    
            let update_type = if has_update {
            Self::determine_update_type(&current_version, &latest_version)
            } else {
            None
            };
    
            Ok(UpdateCheckResult::success(
            has_update,
            Some(current_version),
            Some(latest_version),
            "gem".to_string(),
            Some("gem search --remote".to_string()),
            update_type,
            ))
        })
    }

    fn manager_name(&self) -> &str {
        "gem"
    }

    fn is_available(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        Box::pin(async {
        self.command_runner.is_available(self.gem_command()).await
        })
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn priority(&self) -> u8 {
        60 // Lower priority for Ruby tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_version() {
        assert_eq!(GemUpdateChecker::normalize_version("1.2.3"), "1.2.3");
        assert_eq!(GemUpdateChecker::normalize_version(" 1.2.3 "), "1.2.3");
    }

    #[test]
    fn test_determine_update_type() {
        assert_eq!(
            GemUpdateChecker::determine_update_type("1.0.0", "1.0.1"),
            Some(UpdateType::Patch)
        );
        assert_eq!(
            GemUpdateChecker::determine_update_type("1.0.0", "1.1.0"),
            Some(UpdateType::Minor)
        );
        assert_eq!(
            GemUpdateChecker::determine_update_type("1.0.0", "2.0.0"),
            Some(UpdateType::Major)
        );
        assert_eq!(
            GemUpdateChecker::determine_update_type("1.0.0", "1.0.0"),
            None
        );
    }
}
