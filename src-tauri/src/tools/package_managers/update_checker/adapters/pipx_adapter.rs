// Pipx Update Checker Adapter
//
// Implements update checking for pipx packages using pipx runpip <pkg> pip list --outdated

use std::time::Duration;
use super::super::traits::{UpdateChecker, UpdateCheckResult, UpdateType};
use super::super::error_types::{UpdateCheckError, UpdateCheckErrorCode};
use super::super::command_runner::CommandRunner;
use super::super::version::Version;

/// Pipx update checker
pub struct PipxUpdateChecker {
    command_runner: CommandRunner,
}

impl PipxUpdateChecker {
    pub fn new(command_runner: CommandRunner) -> Self {
        Self { command_runner }
    }

    /// Normalize version string
    fn normalize_version(version: &str) -> String {
        version.trim().to_string()
    }

    /// Check for updates using `pipx runpip <pkg> pip list --outdated --format=json`
    async fn check_outdated(&self, package_name: &str) -> Result<Option<(String, String)>, UpdateCheckError> {
        let output = self.command_runner.execute(
            "pipx",
            &["runpip", package_name, "list", "--outdated", "--format=json"],
        ).await?;

        if !output.success {
            return Err(UpdateCheckError::command_failed(
                "pipx".to_string(),
                package_name.to_string(),
                format!("pipx runpip {} pip list --outdated", package_name),
                output.exit_code,
                output.stderr,
            ));
        }

        // Parse JSON output
        #[derive(serde::Deserialize)]
        struct OutdatedPackage {
            name: String,
            version: String,
            latest_version: String,
        }

        match serde_json::from_str::<Vec<OutdatedPackage>>(&output.stdout) {
            Ok(packages) => {
                // Find our package in the list
                if let Some(pkg) = packages
                    .iter()
                    .find(|p| p.name.eq_ignore_ascii_case(package_name))
                {
                    Ok(Some((
                        Self::normalize_version(&pkg.version),
                        Self::normalize_version(&pkg.latest_version),
                    )))
                } else {
                    Ok(None) // Package not in outdated list = up to date
                }
            }
            Err(e) => Err(UpdateCheckError::new(
                UpdateCheckErrorCode::CommandFailed,
                format!("Failed to parse JSON: {}", e),
                super::super::error_types::UpdateCheckErrorContext::new(
                    "pipx".to_string(),
                    package_name.to_string(),
                ).with_diagnostic(output.stdout),
            )),
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

impl UpdateChecker for PipxUpdateChecker {
    fn check_update(&self, package_name: &str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<UpdateCheckResult, UpdateCheckError>> + Send + '_>> {
        let command_runner = self.command_runner.clone();
        let package_name = package_name.to_string();
        
        Box::pin(async move {
            let checker = PipxUpdateChecker::new(command_runner);
            // Check for updates
            let result = checker.check_outdated(&package_name).await?;
            
            match result {
                Some((current_version, latest_version)) => {
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
                        "pipx".to_string(),
                        Some("pipx runpip pip list --outdated".to_string()),
                        update_type,
                    ))
                }
                None => {
                    // No update available - we don't have current version info
                    Ok(UpdateCheckResult::success(
                        false,
                        Some("installed".to_string()),
                        Some("installed".to_string()),
                        "pipx".to_string(),
                        Some("pipx runpip pip list --outdated".to_string()),
                        None,
                    ))
                }
            }
        })
    }

    fn manager_name(&self) -> &str {
        "pipx"
    }

    fn is_available(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let command_runner = self.command_runner.clone();
        
        Box::pin(async move {
            command_runner.is_available("pipx").await
        })
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn priority(&self) -> u8 {
        20 // High priority for Python tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_version() {
        assert_eq!(PipxUpdateChecker::normalize_version("1.2.3"), "1.2.3");
        assert_eq!(PipxUpdateChecker::normalize_version(" 1.2.3 "), "1.2.3");
    }

    #[test]
    fn test_determine_update_type() {
        assert_eq!(
            PipxUpdateChecker::determine_update_type("1.0.0", "1.0.1"),
            Some(UpdateType::Patch)
        );
        assert_eq!(
            PipxUpdateChecker::determine_update_type("1.0.0", "1.1.0"),
            Some(UpdateType::Minor)
        );
        assert_eq!(
            PipxUpdateChecker::determine_update_type("1.0.0", "2.0.0"),
            Some(UpdateType::Major)
        );
        assert_eq!(
            PipxUpdateChecker::determine_update_type("1.0.0", "1.0.0"),
            None
        );
    }
}
