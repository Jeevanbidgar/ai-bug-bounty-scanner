// Homebrew Update Checker Adapter
//
// Implements update checking for Homebrew packages using brew outdated

use super::super::command_runner::CommandRunner;
use super::super::error_types::UpdateCheckError;
use super::super::traits::{UpdateCheckResult, UpdateChecker, UpdateType};
use super::super::version::Version;
use std::time::Duration;

/// Homebrew update checker
pub struct HomebrewUpdateChecker {
    command_runner: CommandRunner,
}

impl HomebrewUpdateChecker {
    pub fn new(command_runner: CommandRunner) -> Self {
        Self { command_runner }
    }

    /// Normalize version string
    fn normalize_version(version: &str) -> String {
        version.trim().to_string()
    }

    /// Check for updates using `brew outdated <package>`
    async fn check_outdated(
        &self,
        package_name: &str,
    ) -> Result<Option<(String, String)>, UpdateCheckError> {
        let output = self
            .command_runner
            .execute("brew", &["outdated", package_name])
            .await?;

        if !output.success {
            // If the command fails, it might mean the package is not installed
            // or there's an error. Check stderr for more info.
            if output.stderr.contains("not installed") {
                return Err(UpdateCheckError::package_not_found(
                    "homebrew".to_string(),
                    package_name.to_string(),
                ));
            }

            return Err(UpdateCheckError::command_failed(
                "homebrew".to_string(),
                package_name.to_string(),
                format!("brew outdated {}", package_name),
                output.exit_code,
                output.stderr,
            ));
        }

        // If stdout is empty, the package is up to date
        if output.stdout.trim().is_empty() {
            return Ok(None);
        }

        // Parse output format: "package_name (current_version) < latest_version"
        for line in output.stdout.lines() {
            if line.contains(package_name) {
                // Extract versions from the line
                if let Some(version_part) = line.split('(').nth(1) {
                    if let Some(versions) = version_part.split(')').next() {
                        let parts: Vec<&str> = versions.split('<').collect();
                        if parts.len() == 2 {
                            let current = Self::normalize_version(parts[0].trim());
                            let latest = Self::normalize_version(parts[1].trim());
                            return Ok(Some((current, latest)));
                        }
                    }
                }
            }
        }

        // If we can't parse the output, assume no update
        Ok(None)
    }

    /// Get current version using `brew list --versions <package>`
    async fn get_current_version(&self, package_name: &str) -> Result<String, UpdateCheckError> {
        let output = self
            .command_runner
            .execute("brew", &["list", "--versions", package_name])
            .await?;

        if !output.success {
            return Err(UpdateCheckError::package_not_found(
                "homebrew".to_string(),
                package_name.to_string(),
            ));
        }

        // Parse output format: "package_name version"
        for line in output.stdout.lines() {
            if line.starts_with(package_name) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return Ok(Self::normalize_version(parts[1]));
                }
            }
        }

        Err(UpdateCheckError::invalid_version(
            "homebrew".to_string(),
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

impl UpdateChecker for HomebrewUpdateChecker {
    fn check_update(
        &self,
        package_name: &str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<UpdateCheckResult, UpdateCheckError>>
                + Send
                + '_,
        >,
    > {
        let command_runner = self.command_runner.clone();
        let package_name = package_name.to_string();

        Box::pin(async move {
            let checker = HomebrewUpdateChecker::new(command_runner);
            // Check for updates
            let result = checker.check_outdated(&package_name).await?;

            match result {
                Some((current_version, latest_version)) => {
                    // Compare versions
                    let has_update = match (
                        Version::parse(&current_version),
                        Version::parse(&latest_version),
                    ) {
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
                        "homebrew".to_string(),
                        Some("brew outdated".to_string()),
                        update_type,
                    ))
                }
                None => {
                    // No update available - get current version
                    match checker.get_current_version(&package_name).await {
                        Ok(current_version) => Ok(UpdateCheckResult::success(
                            false,
                            Some(current_version.clone()),
                            Some(current_version),
                            "homebrew".to_string(),
                            Some("brew outdated".to_string()),
                            None,
                        )),
                        Err(_) => {
                            // If we can't get current version, assume it's installed but up to date
                            Ok(UpdateCheckResult::success(
                                false,
                                Some("installed".to_string()),
                                Some("installed".to_string()),
                                "homebrew".to_string(),
                                Some("brew outdated".to_string()),
                                None,
                            ))
                        }
                    }
                }
            }
        })
    }

    fn manager_name(&self) -> &str {
        "homebrew"
    }

    fn is_available(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let command_runner = self.command_runner.clone();

        Box::pin(async move { command_runner.is_available("brew").await })
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn priority(&self) -> u8 {
        25 // High priority for macOS packages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_version() {
        assert_eq!(HomebrewUpdateChecker::normalize_version("1.2.3"), "1.2.3");
        assert_eq!(HomebrewUpdateChecker::normalize_version(" 1.2.3 "), "1.2.3");
    }

    #[test]
    fn test_determine_update_type() {
        assert_eq!(
            HomebrewUpdateChecker::determine_update_type("1.0.0", "1.0.1"),
            Some(UpdateType::Patch)
        );
        assert_eq!(
            HomebrewUpdateChecker::determine_update_type("1.0.0", "1.1.0"),
            Some(UpdateType::Minor)
        );
        assert_eq!(
            HomebrewUpdateChecker::determine_update_type("1.0.0", "2.0.0"),
            Some(UpdateType::Major)
        );
        assert_eq!(
            HomebrewUpdateChecker::determine_update_type("1.0.0", "1.0.0"),
            None
        );
    }
}
