// Unit Tests for Update Checker
//
// Unit tests for individual components of the update checker system

use super::super::traits::{UpdateChecker, UpdateCheckResult, UpdateCheckerConfig};
use super::super::error_types::{UpdateCheckError, UpdateCheckErrorCode};
use super::super::command_runner::CommandRunner;
use super::super::cache::{UpdateCache, CacheEntry};
use super::super::metrics::{MetricsCollector, UpdateCheckMetrics};
use super::fixtures::{UpdateCheckerFixtures, TestConfig, TestUtils};
use super::mock_adapters::MockUpdateCheckerFactory;
use std::time::Duration;

#[cfg(test)]
mod command_runner_tests {
    use super::*;

    #[tokio::test]
    async fn test_command_runner_success() {
        let runner = CommandRunner::new(Duration::from_secs(5), false);
        
        // Test with a simple command that should succeed
        let result = runner.execute("echo", &["hello"]).await;
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert!(result.success);
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("hello"));
    }

    #[tokio::test]
    async fn test_command_runner_failure() {
        let runner = CommandRunner::new(Duration::from_secs(5), false);
        
        // Test with a command that should fail
        let result = runner.execute("false", &[]).await;
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert!(!result.success);
        assert_eq!(result.exit_code, 1);
    }

    #[tokio::test]
    async fn test_command_runner_timeout() {
        let runner = CommandRunner::new(Duration::from_millis(100), false);
        
        // Test with a command that should timeout
        let result = runner.execute("sleep", &["1"]).await;
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.code, UpdateCheckErrorCode::Timeout);
    }

    #[tokio::test]
    async fn test_is_available() {
        let runner = CommandRunner::new(Duration::from_secs(5), false);
        
        // Test with a command that should be available
        assert!(runner.is_available("echo").await);
        
        // Test with a command that should not be available
        assert!(!runner.is_available("nonexistent_command_12345").await);
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_basic_operations() {
        let cache = UpdateCache::new(Duration::from_secs(1), 10);
        
        let result = UpdateCheckerFixtures::successful_update();
        
        // Test set and get
        cache.set("test:package".to_string(), result.clone()).await;
        let cached = cache.get("test:package").await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().current_version, result.current_version);
        
        // Test removal
        let removed = cache.remove("test:package").await;
        assert!(removed.is_some());
        
        // Test get after removal
        let cached = cache.get("test:package").await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = UpdateCache::new(Duration::from_millis(100), 10);
        
        let result = UpdateCheckerFixtures::successful_update();
        
        // Set entry
        cache.set("test:package".to_string(), result).await;
        
        // Should be available immediately
        assert!(cache.get("test:package").await.is_some());
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // Should be expired
        assert!(cache.get("test:package").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = UpdateCache::new(Duration::from_secs(1), 10);
        
        let result = UpdateCheckerFixtures::successful_update();
        
        // Add some entries
        cache.set("test:package1".to_string(), result.clone()).await;
        cache.set("test:package2".to_string(), result.clone()).await;
        
        let stats = cache.stats().await;
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.valid_entries, 2);
        assert_eq!(stats.expired_entries, 0);
        assert_eq!(stats.max_entries, 10);
    }

    #[tokio::test]
    async fn test_cache_key_generation() {
        assert_eq!(UpdateCache::cache_key("npm", "package"), "npm:package");
        assert_eq!(UpdateCache::cache_key("go", "tool"), "go:tool");
    }
}

#[cfg(test)]
mod metrics_tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collection() {
        let collector = MetricsCollector::new(10);
        
        // Record a successful check
        let mut metrics = UpdateCheckMetrics::new("npm".to_string(), "package".to_string());
        metrics = metrics.with_success(true).with_update(false);
        
        collector.record_check(metrics).await;
        
        let summary = collector.get_summary().await;
        assert_eq!(summary.total_checks, 1);
        assert_eq!(summary.success_rate, 1.0);
        assert_eq!(summary.updates_found, 0);
        
        // Record a failed check
        let mut metrics = UpdateCheckMetrics::new("npm".to_string(), "package2".to_string());
        metrics = metrics.with_success(false).with_error_code("CommandFailed".to_string());
        
        collector.record_check(metrics).await;
        
        let summary = collector.get_summary().await;
        assert_eq!(summary.total_checks, 2);
        assert_eq!(summary.success_rate, 0.5);
        
        // Check manager-specific metrics
        let manager_metrics = collector.get_manager_metrics("npm").await;
        assert!(manager_metrics.is_some());
        let manager_metrics = manager_metrics.unwrap();
        assert_eq!(manager_metrics.total_checks, 2);
        assert_eq!(manager_metrics.successful_checks, 1);
        assert_eq!(manager_metrics.failed_checks, 1);
    }

    #[tokio::test]
    async fn test_recent_checks_limit() {
        let collector = MetricsCollector::new(3);
        
        // Add more checks than the limit
        for i in 0..5 {
            let mut metrics = UpdateCheckMetrics::new("npm".to_string(), format!("package{}", i));
            metrics = metrics.with_success(true);
            collector.record_check(metrics).await;
        }
        
        let recent = collector.get_recent_checks(None).await;
        assert_eq!(recent.len(), 3); // Should be limited to 3
        
        // Check that we kept the most recent ones
        assert_eq!(recent[0].package, "package4");
        assert_eq!(recent[1].package, "package3");
        assert_eq!(recent[2].package, "package2");
    }
}

#[cfg(test)]
mod error_types_tests {
    use super::*;

    #[test]
    fn test_update_check_error_creation() {
        let error = UpdateCheckError::manager_not_available("test".to_string());
        assert_eq!(error.code, UpdateCheckErrorCode::ManagerNotAvailable);
        assert!(error.retryable);
        assert_eq!(error.context.manager, "test");

        let error = UpdateCheckError::package_not_found("test".to_string(), "package".to_string());
        assert_eq!(error.code, UpdateCheckErrorCode::PackageNotFound);
        assert!(!error.retryable);
        assert_eq!(error.context.package, "package");

        let error = UpdateCheckError::command_failed(
            "test".to_string(),
            "package".to_string(),
            "command".to_string(),
            1,
            "stderr".to_string(),
        );
        assert_eq!(error.code, UpdateCheckErrorCode::CommandFailed);
        assert!(!error.retryable);
        assert_eq!(error.context.exit_code, Some(1));

        let error = UpdateCheckError::timeout("test".to_string(), "package".to_string(), "command".to_string());
        assert_eq!(error.code, UpdateCheckErrorCode::Timeout);
        assert!(error.retryable);

        let error = UpdateCheckError::network_error("test".to_string(), "package".to_string(), "network error".to_string());
        assert_eq!(error.code, UpdateCheckErrorCode::NetworkError);
        assert!(error.retryable);
    }

    #[test]
    fn test_error_context_building() {
        let context = super::super::error_types::UpdateCheckErrorContext::new("test".to_string(), "package".to_string())
            .with_command("test command".to_string())
            .with_exit_code(1)
            .with_stderr("error output".to_string())
            .with_diagnostic("diagnostic info".to_string());

        assert_eq!(context.manager, "test");
        assert_eq!(context.package, "package");
        assert_eq!(context.command, Some("test command".to_string()));
        assert_eq!(context.exit_code, Some(1));
        assert_eq!(context.stderr, Some("error output".to_string()));
        assert_eq!(context.diagnostic, Some("diagnostic info".to_string()));
    }
}

#[cfg(test)]
mod traits_tests {
    use super::*;

    #[test]
    fn test_update_check_result_creation() {
        let result = UpdateCheckResult::success(
            true,
            Some("1.0.0".to_string()),
            Some("1.1.0".to_string()),
            "test".to_string(),
            Some("test source".to_string()),
            Some(super::super::traits::UpdateType::Minor),
        );

        assert!(result.has_update);
        assert_eq!(result.current_version, Some("1.0.0".to_string()));
        assert_eq!(result.latest_version, Some("1.1.0".to_string()));
        assert_eq!(result.package_manager, "test");
        assert_eq!(result.source, Some("test source".to_string()));
        assert!(result.error.is_none());
        assert!(result.error_code.is_none());
        assert!(result.checked_at.is_some());

        let result = UpdateCheckResult::error(
            "test error".to_string(),
            UpdateCheckErrorCode::CommandFailed,
            "test".to_string(),
            Some("diagnostic".to_string()),
        );

        assert!(!result.has_update);
        assert!(result.current_version.is_none());
        assert!(result.latest_version.is_none());
        assert_eq!(result.package_manager, "test");
        assert_eq!(result.error, Some("test error".to_string()));
        assert_eq!(result.error_code, Some(UpdateCheckErrorCode::CommandFailed));
        assert_eq!(result.diagnostic, Some("diagnostic".to_string()));
    }

    #[test]
    fn test_update_check_result_with_duration() {
        let result = UpdateCheckResult::success(
            false,
            Some("1.0.0".to_string()),
            Some("1.0.0".to_string()),
            "test".to_string(),
            None,
            None,
        ).with_duration(Duration::from_secs(5));

        assert_eq!(result.duration, Some(Duration::from_secs(5)));
    }

    #[test]
    fn test_update_checker_config() {
        let config = UpdateCheckerConfig::default();
        assert_eq!(config.default_timeout, Duration::from_secs(30));
        assert_eq!(config.max_concurrent, 10);
        assert_eq!(config.cache_duration, Duration::from_secs(300));
        assert!(!config.debug_logging);
        assert!(config.enable_metrics);
    }
}

#[cfg(test)]
mod mock_adapter_tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_successful_checker() {
        let checker = MockUpdateCheckerFactory::successful("test".to_string());
        assert!(checker.is_available().await);
        assert_eq!(checker.manager_name(), "test");

        let result = checker.check_update("test-package").await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.has_update);
    }

    #[tokio::test]
    async fn test_mock_error_checker() {
        let checker = MockUpdateCheckerFactory::error("test".to_string());
        assert!(checker.is_available().await);

        let result = checker.check_update("test-package").await;
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, UpdateCheckErrorCode::CommandFailed);
    }

    #[tokio::test]
    async fn test_mock_manager_not_available() {
        let checker = MockUpdateCheckerFactory::manager_not_available("test".to_string());
        assert!(!checker.is_available().await);

        let result = checker.check_update("test-package").await;
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, UpdateCheckErrorCode::ManagerNotAvailable);
    }
}
