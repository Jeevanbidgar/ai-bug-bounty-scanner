// APT Update Checker Adapter
//
// Implements update checking for APT packages using apt-cache policy

use super::super::command_runner::CommandRunner;
use super::super::error_types::{UpdateCheckError, UpdateCheckErrorCode};
use super::super::traits::{UpdateCheckResult, UpdateChecker, UpdateType};
use super::super::version::Version;
use std::time::Duration;

/// APT update checker
pub struct AptUpdateChecker {
    command_runner: CommandRunner,
}

impl AptUpdateChecker {
    pub fn new(command_runner: CommandRunner) -> Self {
        Self { command_runner }
    }

    /// Normalize version string
    fn normalize_version(version: &str) -> String {
        version.trim().to_string()
    }

    /// Check for updates using `apt-cache policy <package>`
    async fn check_policy(
        &self,
        package_name: &str,
    ) -> Result<(Option<String>, Option<String>), UpdateCheckError> {
        let output = self
            .command_runner
            .execute("apt-cache", &["policy", package_name])
            .await?;

        if !output.success {
            return Err(UpdateCheckError::command_failed(
                "apt".to_string(),
                package_name.to_string(),
                format!("apt-cache policy {}", package_name),
                output.exit_code,
                output.stderr,
            ));
        }

        let mut installed_version: Option<String> = None;
        let mut candidate_version: Option<String> = None;

        // Parse output:
        // Installed: 1.2.3
        // Candidate: 1.2.4
        for line in output.stdout.lines() {
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

        Ok((installed_version, candidate_version))
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

impl UpdateChecker for AptUpdateChecker {
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
            let checker = AptUpdateChecker::new(command_runner);
            // Check policy
            let (installed_version, candidate_version) =
                checker.check_policy(&package_name).await?;

            match (installed_version, candidate_version) {
                (Some(installed), Some(candidate)) => {
                    let installed_normalized = Self::normalize_version(&installed);
                    let candidate_normalized = Self::normalize_version(&candidate);

                    let has_update = installed_normalized != candidate_normalized;

                    let update_type = if has_update {
                        Self::determine_update_type(&installed_normalized, &candidate_normalized)
                    } else {
                        None
                    };

                    Ok(UpdateCheckResult::success(
                        has_update,
                        Some(installed),
                        Some(candidate),
                        "apt".to_string(),
                        Some("apt-cache policy".to_string()),
                        update_type,
                    ))
                }
                (Some(installed), None) => {
                    // Installed but no candidate (might be from a different source)
                    Ok(UpdateCheckResult::success(
                        false,
                        Some(installed),
                        None,
                        "apt".to_string(),
                        Some("apt-cache policy".to_string()),
                        None,
                    ))
                }
                _ => Err(UpdateCheckError::new(
                    UpdateCheckErrorCode::PackageNotFound,
                    "Could not determine installed/candidate version".to_string(),
                    super::super::error_types::UpdateCheckErrorContext::new(
                        "apt".to_string(),
                        package_name.to_string(),
                    ),
                )),
            }
        })
    }

    fn manager_name(&self) -> &str {
        "apt"
    }

    fn is_available(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let command_runner = self.command_runner.clone();

        Box::pin(async move { command_runner.is_available("apt-cache").await })
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn priority(&self) -> u8 {
        30 // Medium-high priority for system packages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_version() {
        assert_eq!(AptUpdateChecker::normalize_version("1.2.3"), "1.2.3");
        assert_eq!(AptUpdateChecker::normalize_version(" 1.2.3 "), "1.2.3");
    }

    #[test]
    fn test_determine_update_type() {
        assert_eq!(
            AptUpdateChecker::determine_update_type("1.0.0", "1.0.1"),
            Some(UpdateType::Patch)
        );
        assert_eq!(
            AptUpdateChecker::determine_update_type("1.0.0", "1.1.0"),
            Some(UpdateType::Minor)
        );
        assert_eq!(
            AptUpdateChecker::determine_update_type("1.0.0", "2.0.0"),
            Some(UpdateType::Major)
        );
        assert_eq!(
            AptUpdateChecker::determine_update_type("1.0.0", "1.0.0"),
            None
        );
    }
}
