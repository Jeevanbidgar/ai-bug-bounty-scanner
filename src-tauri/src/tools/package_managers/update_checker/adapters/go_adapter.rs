// Go Update Checker Adapter
//
// Implements update checking for Go tools using go list -m -versions

use super::super::command_runner::CommandRunner;
use super::super::error_types::{UpdateCheckError, UpdateCheckErrorCode};
use super::super::traits::{UpdateCheckResult, UpdateChecker, UpdateType};
use super::super::version::Version;
use std::time::Duration;

/// Go update checker
pub struct GoUpdateChecker {
    command_runner: CommandRunner,
}

impl GoUpdateChecker {
    pub fn new(command_runner: CommandRunner) -> Self {
        Self { command_runner }
    }

    /// Get current version from Go binary using `go version -m`
    async fn get_current_version(&self, tool_binary: &str) -> Result<String, UpdateCheckError> {
        let output = self
            .command_runner
            .execute("go", &["version", "-m", tool_binary])
            .await?;

        if !output.success {
            return Err(UpdateCheckError::command_failed(
                "go".to_string(),
                "unknown".to_string(),
                format!("go version -m {}", tool_binary),
                output.exit_code,
                output.stderr,
            ));
        }

        // Parse output: look for "mod	<module>	v<version>	<hash>"
        for line in output.stdout.lines() {
            if line.trim_start().starts_with("mod") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let version = parts[2].trim().trim_start_matches('v');
                    return Ok(version.to_string());
                }
            }
        }

        Err(UpdateCheckError::invalid_version(
            "go".to_string(),
            "unknown".to_string(),
            output.stdout,
        ))
    }

    /// Get latest version from Go module using `go list -m -versions`
    async fn get_latest_version(&self, module_path: &str) -> Result<String, UpdateCheckError> {
        let output = self
            .command_runner
            .execute("go", &["list", "-m", "-versions", module_path])
            .await?;

        if !output.success {
            return Err(UpdateCheckError::command_failed(
                "go".to_string(),
                module_path.to_string(),
                format!("go list -m -versions {}", module_path),
                output.exit_code,
                output.stderr,
            ));
        }

        // Output format: "module v1.0.0 v1.1.0 v1.2.0 ..."
        let versions: Vec<&str> = output.stdout.split_whitespace().collect();

        if versions.len() < 2 {
            return Err(UpdateCheckError::new(
                UpdateCheckErrorCode::PackageNotFound,
                "No versions found".to_string(),
                super::super::error_types::UpdateCheckErrorContext::new(
                    "go".to_string(),
                    module_path.to_string(),
                )
                .with_diagnostic(output.stdout),
            ));
        }

        // Last version is the latest
        let latest = versions.last().unwrap().trim_start_matches('v');
        Ok(latest.to_string())
    }

    /// Normalize version string by removing 'v' prefix and trimming whitespace
    fn normalize_version(version: &str) -> String {
        version
            .trim()
            .trim_start_matches('v')
            .trim_start_matches('V')
            .to_string()
    }

    /// Determine update type based on version comparison
    fn determine_update_type(current: &str, latest: &str) -> Option<UpdateType> {
        let current_normalized = Self::normalize_version(current);
        let latest_normalized = Self::normalize_version(latest);

        match (
            Version::parse(&current_normalized),
            Version::parse(&latest_normalized),
        ) {
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

impl UpdateChecker for GoUpdateChecker {
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
            let checker = GoUpdateChecker::new(command_runner);
            // For Go tools, we need to determine the binary path and module path
            // This is a simplified version - in practice, we'd need to look up
            // the tool definition to get the binary path and module path

            // For now, assume the package_name is the module path
            let module_path = package_name.clone();

            // Try to find the binary in common locations (cross-platform)
            let binary_paths = if cfg!(target_os = "windows") {
                vec![
                    format!(
                        "{}\\go\\bin\\{}.exe",
                        std::env::var("USERPROFILE").unwrap_or_default(),
                        &package_name
                    ),
                    format!(
                        "{}\\go\\bin\\{}",
                        std::env::var("USERPROFILE").unwrap_or_default(),
                        &package_name
                    ),
                    format!("{}.exe", &package_name), // Assume it's in PATH
                    package_name.to_string(),
                ]
            } else {
                vec![
                    format!("/usr/local/bin/{}", &package_name),
                    format!("/usr/bin/{}", &package_name),
                    format!(
                        "{}/go/bin/{}",
                        std::env::var("HOME").unwrap_or_default(),
                        &package_name
                    ),
                    format!(
                        "{}/.local/bin/{}",
                        std::env::var("HOME").unwrap_or_default(),
                        &package_name
                    ),
                    package_name.to_string(), // Assume it's in PATH
                ]
            };

            let mut binary_path = None;
            for path in &binary_paths {
                if std::path::Path::new(path).exists() {
                    binary_path = Some(path.clone());
                    break;
                }
            }

            let binary_path = binary_path.ok_or_else(|| {
                UpdateCheckError::package_not_found("go".to_string(), package_name.to_string())
            })?;

            // Get current version
            let current_version = self.get_current_version(&binary_path).await?;

            // Get latest version
            let latest_version = checker.get_latest_version(&module_path).await?;

            // Normalize versions
            let current_normalized = Self::normalize_version(&current_version);
            let latest_normalized = Self::normalize_version(&latest_version);

            // Compare versions
            let has_update = match (
                Version::parse(&current_normalized),
                Version::parse(&latest_normalized),
            ) {
                (Some(current_v), Some(latest_v)) => latest_v > current_v,
                _ => latest_normalized != current_normalized, // Fallback to string comparison
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
                "go".to_string(),
                Some("go list -m -versions".to_string()),
                update_type,
            ))
        })
    }

    fn manager_name(&self) -> &str {
        "go"
    }

    fn is_available(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let command_runner = self.command_runner.clone();

        Box::pin(async move { command_runner.is_available("go").await })
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn priority(&self) -> u8 {
        10 // High priority for Go tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_version() {
        assert_eq!(GoUpdateChecker::normalize_version("v1.2.3"), "1.2.3");
        assert_eq!(GoUpdateChecker::normalize_version("V1.2.3"), "1.2.3");
        assert_eq!(GoUpdateChecker::normalize_version(" 1.2.3 "), "1.2.3");
        assert_eq!(GoUpdateChecker::normalize_version("1.2.3"), "1.2.3");
    }

    #[test]
    fn test_determine_update_type() {
        assert_eq!(
            GoUpdateChecker::determine_update_type("1.0.0", "1.0.1"),
            Some(UpdateType::Patch)
        );
        assert_eq!(
            GoUpdateChecker::determine_update_type("1.0.0", "1.1.0"),
            Some(UpdateType::Minor)
        );
        assert_eq!(
            GoUpdateChecker::determine_update_type("1.0.0", "2.0.0"),
            Some(UpdateType::Major)
        );
        assert_eq!(
            GoUpdateChecker::determine_update_type("1.0.0", "1.0.0"),
            None
        );
    }
}
