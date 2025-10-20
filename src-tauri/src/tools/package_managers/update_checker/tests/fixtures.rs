// Test Fixtures for Update Checker
//
// Provides test data and fixtures for update checker tests

use super::super::traits::{UpdateCheckResult, UpdateType};
use super::super::error_types::{UpdateCheckError, UpdateCheckErrorCode};
use std::time::Duration;

/// Test fixtures for update checker results
pub struct UpdateCheckerFixtures;

impl UpdateCheckerFixtures {
    /// Create a successful update result
    pub fn successful_update() -> UpdateCheckResult {
        UpdateCheckResult::success(
            true,
            Some("1.0.0".to_string()),
            Some("1.1.0".to_string()),
            "test".to_string(),
            Some("test source".to_string()),
            Some(UpdateType::Minor),
        )
    }

    /// Create a no-update result
    pub fn no_update() -> UpdateCheckResult {
        UpdateCheckResult::success(
            false,
            Some("1.0.0".to_string()),
            Some("1.0.0".to_string()),
            "test".to_string(),
            Some("test source".to_string()),
            None,
        )
    }

    /// Create an error result
    pub fn error_result() -> UpdateCheckResult {
        UpdateCheckResult::error(
            "Test error".to_string(),
            UpdateCheckErrorCode::CommandFailed,
            "test".to_string(),
            Some("Test diagnostic".to_string()),
        )
    }

    /// Create a patch update result
    pub fn patch_update() -> UpdateCheckResult {
        UpdateCheckResult::success(
            true,
            Some("1.0.0".to_string()),
            Some("1.0.1".to_string()),
            "test".to_string(),
            Some("test source".to_string()),
            Some(UpdateType::Patch),
        )
    }

    /// Create a major update result
    pub fn major_update() -> UpdateCheckResult {
        UpdateCheckResult::success(
            true,
            Some("1.0.0".to_string()),
            Some("2.0.0".to_string()),
            "test".to_string(),
            Some("test source".to_string()),
            Some(UpdateType::Major),
        )
    }

    /// Create a pre-release update result
    pub fn prerelease_update() -> UpdateCheckResult {
        UpdateCheckResult::success(
            true,
            Some("1.0.0".to_string()),
            Some("1.1.0-beta.1".to_string()),
            "test".to_string(),
            Some("test source".to_string()),
            Some(UpdateType::PreRelease),
        )
    }

    /// Create multiple update results for testing coordination
    pub fn multiple_results() -> Vec<UpdateCheckResult> {
        vec![
            Self::successful_update(),
            Self::no_update(),
            Self::patch_update(),
            Self::major_update(),
        ]
    }

    /// Create results with different package managers
    pub fn multi_manager_results() -> Vec<UpdateCheckResult> {
        vec![
            UpdateCheckResult::success(
                true,
                Some("1.0.0".to_string()),
                Some("1.1.0".to_string()),
                "go".to_string(),
                Some("go list -m -versions".to_string()),
                Some(UpdateType::Minor),
            ),
            UpdateCheckResult::success(
                false,
                Some("2.0.0".to_string()),
                Some("2.0.0".to_string()),
                "npm".to_string(),
                Some("npm outdated -g".to_string()),
                None,
            ),
            UpdateCheckResult::success(
                true,
                Some("3.0.0".to_string()),
                Some("3.0.1".to_string()),
                "pipx".to_string(),
                Some("pipx runpip pip list --outdated".to_string()),
                Some(UpdateType::Patch),
            ),
        ]
    }

    /// Create error results with different error codes
    pub fn error_results() -> Vec<UpdateCheckResult> {
        vec![
            UpdateCheckResult::error(
                "Manager not available".to_string(),
                UpdateCheckErrorCode::ManagerNotAvailable,
                "test1".to_string(),
                None,
            ),
            UpdateCheckResult::error(
                "Package not found".to_string(),
                UpdateCheckErrorCode::PackageNotFound,
                "test2".to_string(),
                None,
            ),
            UpdateCheckResult::error(
                "Command failed".to_string(),
                UpdateCheckErrorCode::CommandFailed,
                "test3".to_string(),
                Some("Exit code 1".to_string()),
            ),
            UpdateCheckResult::error(
                "Timeout".to_string(),
                UpdateCheckErrorCode::Timeout,
                "test4".to_string(),
                Some("Command timed out after 30s".to_string()),
            ),
        ]
    }

    /// Create mock command outputs for different package managers
    pub fn mock_command_outputs() -> MockCommandOutputs {
        MockCommandOutputs::new()
    }
}

/// Mock command outputs for testing
pub struct MockCommandOutputs {
    pub go_version_m: String,
    pub go_list_versions: String,
    pub npm_list: String,
    pub npm_outdated: String,
    pub pipx_outdated: String,
    pub apt_policy: String,
    pub winget_upgrade: String,
    pub homebrew_outdated: String,
    pub gem_list: String,
    pub gem_search: String,
    pub cargo_list: String,
    pub cargo_search: String,
}

impl MockCommandOutputs {
    pub fn new() -> Self {
        Self {
            go_version_m: "mod     github.com/test/tool v1.0.0  h1:abc123...".to_string(),
            go_list_versions: "github.com/test/tool v1.0.0 v1.0.1 v1.1.0".to_string(),
            npm_list: r#"{"dependencies":{"test-package":{"version":"1.0.0"}}}"#.to_string(),
            npm_outdated: r#"{"test-package":{"current":"1.0.0","latest":"1.1.0"}}"#.to_string(),
            pipx_outdated: r#"[{"name":"test-package","version":"1.0.0","latest_version":"1.1.0"}]"#.to_string(),
            apt_policy: "Installed: 1.0.0\nCandidate: 1.1.0".to_string(),
            winget_upgrade: "Name  Id  Version  Available\ntest-package test-package 1.0.0 1.1.0".to_string(),
            homebrew_outdated: "test-package (1.0.0) < 1.1.0".to_string(),
            gem_list: "test-package (1.0.0)".to_string(),
            gem_search: "test-package (1.1.0)".to_string(),
            cargo_list: "test-package v1.0.0:".to_string(),
            cargo_search: r#"test-package = "1.1.0"    # Test package"#.to_string(),
        }
    }

    /// Create outputs for error scenarios
    pub fn error_outputs() -> Self {
        Self {
            go_version_m: "go: command not found".to_string(),
            go_list_versions: "go: command not found".to_string(),
            npm_list: "npm: command not found".to_string(),
            npm_outdated: "npm: command not found".to_string(),
            pipx_outdated: "pipx: command not found".to_string(),
            apt_policy: "apt-cache: command not found".to_string(),
            winget_upgrade: "winget: command not found".to_string(),
            homebrew_outdated: "brew: command not found".to_string(),
            gem_list: "gem: command not found".to_string(),
            gem_search: "gem: command not found".to_string(),
            cargo_list: "cargo: command not found".to_string(),
            cargo_search: "cargo: command not found".to_string(),
        }
    }

    /// Create outputs for timeout scenarios
    pub fn timeout_outputs() -> Self {
        Self {
            go_version_m: "".to_string(),
            go_list_versions: "".to_string(),
            npm_list: "".to_string(),
            npm_outdated: "".to_string(),
            pipx_outdated: "".to_string(),
            apt_policy: "".to_string(),
            winget_upgrade: "".to_string(),
            homebrew_outdated: "".to_string(),
            gem_list: "".to_string(),
            gem_search: "".to_string(),
            cargo_list: "".to_string(),
            cargo_search: "".to_string(),
        }
    }
}

/// Test configuration for update checker
pub struct TestConfig {
    pub timeout: Duration,
    pub debug_logging: bool,
    pub max_concurrent: usize,
    pub cache_duration: Duration,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            debug_logging: true,
            max_concurrent: 3,
            cache_duration: Duration::from_secs(60),
        }
    }
}

/// Test utilities
pub struct TestUtils;

impl TestUtils {
    /// Create a test package name
    pub fn test_package_name() -> String {
        "test-package".to_string()
    }

    /// Create a test module path
    pub fn test_module_path() -> String {
        "github.com/test/test-package".to_string()
    }

    /// Create a test binary path
    pub fn test_binary_path() -> String {
        "/usr/local/bin/test-package".to_string()
    }

    /// Wait for a short duration (useful for testing async operations)
    pub async fn short_wait() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    /// Wait for a longer duration (useful for testing timeouts)
    pub async fn long_wait() {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixtures_creation() {
        let update_result = UpdateCheckerFixtures::successful_update();
        assert!(update_result.has_update);
        assert_eq!(update_result.current_version, Some("1.0.0".to_string()));
        assert_eq!(update_result.latest_version, Some("1.1.0".to_string()));

        let no_update_result = UpdateCheckerFixtures::no_update();
        assert!(!no_update_result.has_update);
        assert_eq!(no_update_result.current_version, no_update_result.latest_version);

        let error_result = UpdateCheckerFixtures::error_result();
        assert!(error_result.error.is_some());
        assert_eq!(error_result.error_code, Some(UpdateCheckErrorCode::CommandFailed));
    }

    #[test]
    fn test_mock_outputs() {
        let outputs = MockCommandOutputs::new();
        assert!(!outputs.go_version_m.is_empty());
        assert!(!outputs.npm_list.is_empty());
        assert!(!outputs.pipx_outdated.is_empty());

        let error_outputs = MockCommandOutputs::error_outputs();
        assert!(error_outputs.go_version_m.contains("command not found"));
        assert!(error_outputs.npm_list.contains("command not found"));
    }

    #[test]
    fn test_test_config() {
        let config = TestConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert!(config.debug_logging);
        assert_eq!(config.max_concurrent, 3);
    }
}
