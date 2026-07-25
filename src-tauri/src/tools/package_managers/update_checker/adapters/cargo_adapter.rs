// Cargo Update Checker Adapter
//
// Implements update checking for Cargo packages using cargo install --list and crates.io

use super::super::command_runner::CommandRunner;
use super::super::error_types::UpdateCheckError;
use super::super::traits::{UpdateCheckResult, UpdateChecker, UpdateType};
use super::super::version::Version;
use std::time::Duration;

/// Cargo update checker
pub struct CargoUpdateChecker {
    command_runner: CommandRunner,
}

impl CargoUpdateChecker {
    pub fn new(command_runner: CommandRunner) -> Self {
        Self { command_runner }
    }

    /// Normalize version string
    fn normalize_version(version: &str) -> String {
        version.trim().to_string()
    }

    /// Get current version using `cargo install --list`
    async fn get_current_version(&self, package_name: &str) -> Result<String, UpdateCheckError> {
        let output = self
            .command_runner
            .execute("cargo", &["install", "--list"])
            .await?;

        if !output.success {
            return Err(UpdateCheckError::command_failed(
                "cargo".to_string(),
                package_name.to_string(),
                "cargo install --list".to_string(),
                output.exit_code,
                output.stderr,
            ));
        }

        // Find the package in the output
        // Format: "package_name v1.2.3:"
        for line in output.stdout.lines() {
            if line.starts_with(package_name) && line.contains(" v") {
                if let Some(version_part) = line.split(" v").nth(1) {
                    let version = version_part.trim_end_matches(':');
                    return Ok(Self::normalize_version(version));
                }
            }
        }

        Err(UpdateCheckError::package_not_found(
            "cargo".to_string(),
            package_name.to_string(),
        ))
    }

    /// Get latest version using `cargo search <package> --limit 1`
    async fn get_latest_version(&self, package_name: &str) -> Result<String, UpdateCheckError> {
        let output = self
            .command_runner
            .execute("cargo", &["search", package_name, "--limit", "1"])
            .await?;

        if !output.success {
            return Err(UpdateCheckError::command_failed(
                "cargo".to_string(),
                package_name.to_string(),
                format!("cargo search {} --limit 1", package_name),
                output.exit_code,
                output.stderr,
            ));
        }

        // Parse the output for the latest version
        // Format: "package_name = "1.2.3"    # description"
        if let Some(line) = output.stdout.lines().next() {
            if let Some(version_part) = line.split('=').nth(1) {
                let version = version_part
                    .trim()
                    .trim_start_matches('"')
                    .split('"')
                    .next()
                    .unwrap_or("");
                return Ok(Self::normalize_version(version));
            }
        }

        Err(UpdateCheckError::invalid_version(
            "cargo".to_string(),
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

impl UpdateChecker for CargoUpdateChecker {
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
            let checker = CargoUpdateChecker::new(command_runner);
            // Get current version
            let current_version = checker.get_current_version(&package_name).await?;

            // Get latest version
            let latest_version = checker.get_latest_version(&package_name).await?;

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
                "cargo".to_string(),
                Some("cargo search".to_string()),
                update_type,
            ))
        })
    }

    fn manager_name(&self) -> &str {
        "cargo"
    }

    fn is_available(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let command_runner = self.command_runner.clone();

        Box::pin(async move { command_runner.is_available("cargo").await })
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn priority(&self) -> u8 {
        70 // Lower priority for Rust tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_version() {
        assert_eq!(CargoUpdateChecker::normalize_version("1.2.3"), "1.2.3");
        assert_eq!(CargoUpdateChecker::normalize_version(" 1.2.3 "), "1.2.3");
    }

    #[test]
    fn test_determine_update_type() {
        assert_eq!(
            CargoUpdateChecker::determine_update_type("1.0.0", "1.0.1"),
            Some(UpdateType::Patch)
        );
        assert_eq!(
            CargoUpdateChecker::determine_update_type("1.0.0", "1.1.0"),
            Some(UpdateType::Minor)
        );
        assert_eq!(
            CargoUpdateChecker::determine_update_type("1.0.0", "2.0.0"),
            Some(UpdateType::Major)
        );
        assert_eq!(
            CargoUpdateChecker::determine_update_type("1.0.0", "1.0.0"),
            None
        );
    }
}
