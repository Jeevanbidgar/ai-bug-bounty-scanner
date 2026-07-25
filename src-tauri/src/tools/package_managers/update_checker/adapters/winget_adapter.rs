// WinGet Update Checker Adapter
//
// Implements update checking for WinGet packages using winget upgrade

use super::super::command_runner::CommandRunner;
use super::super::error_types::{UpdateCheckError, UpdateCheckErrorCode};
use super::super::traits::{UpdateCheckResult, UpdateChecker, UpdateType};
use super::super::version::Version;
use std::time::Duration;

/// WinGet update checker
pub struct WingetUpdateChecker {
    command_runner: CommandRunner,
}

impl WingetUpdateChecker {
    pub fn new(command_runner: CommandRunner) -> Self {
        Self { command_runner }
    }

    /// Normalize version string
    fn normalize_version(version: &str) -> String {
        version.trim().to_string()
    }

    /// Check for updates using `winget upgrade --id <package_id>`
    async fn check_upgrade(
        &self,
        package_id: &str,
    ) -> Result<Option<(String, String)>, UpdateCheckError> {
        let output = self
            .command_runner
            .execute("winget", &["upgrade", "--id", package_id])
            .await?;

        // WinGet upgrade returns exit code 1 if there are updates available
        // and 0 if no updates are available
        if output.exit_code == 0 {
            // No updates available
            return Ok(None);
        }

        // Check if update is available
        if output.stdout.contains("upgrades available") || output.stdout.contains("available") {
            // Try to parse versions from output
            // Format: Name  Id  Version  Available
            let mut current_version: Option<String> = None;
            let mut latest_version: Option<String> = None;

            for line in output.stdout.lines() {
                if line.contains(package_id) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        current_version = Some(Self::normalize_version(parts[2]));
                        latest_version = Some(Self::normalize_version(parts[3]));
                        break;
                    }
                }
            }

            match (current_version, latest_version) {
                (Some(current), Some(latest)) => Ok(Some((current, latest))),
                _ => Err(UpdateCheckError::new(
                    UpdateCheckErrorCode::CommandFailed,
                    "Could not parse version information".to_string(),
                    super::super::error_types::UpdateCheckErrorContext::new(
                        "winget".to_string(),
                        package_id.to_string(),
                    )
                    .with_diagnostic(output.stdout),
                )),
            }
        } else if output.stdout.contains("No applicable update found") {
            Ok(None)
        } else {
            Err(UpdateCheckError::new(
                UpdateCheckErrorCode::CommandFailed,
                format!("Could not determine update status: {}", output.stdout),
                super::super::error_types::UpdateCheckErrorContext::new(
                    "winget".to_string(),
                    package_id.to_string(),
                )
                .with_diagnostic(output.stdout),
            ))
        }
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

impl UpdateChecker for WingetUpdateChecker {
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
            let checker = WingetUpdateChecker::new(command_runner);
            // Check for updates
            let result = checker.check_upgrade(&package_name).await?;

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
                        "winget".to_string(),
                        Some("winget upgrade".to_string()),
                        update_type,
                    ))
                }
                None => {
                    // No update available
                    Ok(UpdateCheckResult::success(
                        false,
                        Some("installed".to_string()),
                        Some("installed".to_string()),
                        "winget".to_string(),
                        Some("winget upgrade".to_string()),
                        None,
                    ))
                }
            }
        })
    }

    fn manager_name(&self) -> &str {
        "winget"
    }

    fn is_available(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let command_runner = self.command_runner.clone();

        Box::pin(async move { command_runner.is_available("winget").await })
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn priority(&self) -> u8 {
        40 // Medium priority for Windows packages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_version() {
        assert_eq!(WingetUpdateChecker::normalize_version("1.2.3"), "1.2.3");
        assert_eq!(WingetUpdateChecker::normalize_version(" 1.2.3 "), "1.2.3");
    }

    #[test]
    fn test_determine_update_type() {
        assert_eq!(
            WingetUpdateChecker::determine_update_type("1.0.0", "1.0.1"),
            Some(UpdateType::Patch)
        );
        assert_eq!(
            WingetUpdateChecker::determine_update_type("1.0.0", "1.1.0"),
            Some(UpdateType::Minor)
        );
        assert_eq!(
            WingetUpdateChecker::determine_update_type("1.0.0", "2.0.0"),
            Some(UpdateType::Major)
        );
        assert_eq!(
            WingetUpdateChecker::determine_update_type("1.0.0", "1.0.0"),
            None
        );
    }
}
