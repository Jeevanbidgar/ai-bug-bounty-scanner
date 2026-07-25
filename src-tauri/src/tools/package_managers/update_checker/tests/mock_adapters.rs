// Mock Adapters for Update Checker Tests
//
// Provides mock implementations of update checkers for testing

use super::super::error_types::{UpdateCheckError, UpdateCheckErrorCode};
use super::super::traits::{UpdateCheckResult, UpdateChecker};
use super::fixtures::UpdateCheckerFixtures;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Mock update checker that always returns a successful update
pub struct MockSuccessfulUpdateChecker {
    pub manager_name: String,
    pub priority: u8,
    pub timeout: Duration,
}

impl MockSuccessfulUpdateChecker {
    pub fn new(manager_name: String) -> Self {
        Self {
            manager_name,
            priority: 100,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl UpdateChecker for MockSuccessfulUpdateChecker {
    fn check_update(
        &self,
        _package_name: &str,
    ) -> Pin<Box<dyn Future<Output = Result<UpdateCheckResult, UpdateCheckError>> + Send + '_>>
    {
        let manager_name = self.manager_name.clone();
        Box::pin(async move {
            let mut result = UpdateCheckerFixtures::successful_update();
            result.package_manager = manager_name;
            Ok(result)
        })
    }

    fn manager_name(&self) -> &str {
        &self.manager_name
    }

    fn is_available(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn priority(&self) -> u8 {
        self.priority
    }
}

/// Mock update checker that always returns no update
pub struct MockNoUpdateChecker {
    pub manager_name: String,
    pub priority: u8,
    pub timeout: Duration,
}

impl MockNoUpdateChecker {
    pub fn new(manager_name: String) -> Self {
        Self {
            manager_name,
            priority: 100,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl UpdateChecker for MockNoUpdateChecker {
    fn check_update(
        &self,
        _package_name: &str,
    ) -> Pin<Box<dyn Future<Output = Result<UpdateCheckResult, UpdateCheckError>> + Send + '_>>
    {
        let manager_name = self.manager_name.clone();
        Box::pin(async move {
            let mut result = UpdateCheckerFixtures::no_update();
            result.package_manager = manager_name;
            Ok(result)
        })
    }

    fn manager_name(&self) -> &str {
        &self.manager_name
    }

    fn is_available(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn priority(&self) -> u8 {
        self.priority
    }
}

/// Mock update checker that always returns an error
pub struct MockErrorUpdateChecker {
    pub manager_name: String,
    pub priority: u8,
    pub timeout: Duration,
    pub error_code: UpdateCheckErrorCode,
}

impl MockErrorUpdateChecker {
    pub fn new(manager_name: String) -> Self {
        Self {
            manager_name,
            priority: 100,
            timeout: Duration::from_secs(30),
            error_code: UpdateCheckErrorCode::CommandFailed,
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_error_code(mut self, error_code: UpdateCheckErrorCode) -> Self {
        self.error_code = error_code;
        self
    }
}

impl UpdateChecker for MockErrorUpdateChecker {
    fn check_update(
        &self,
        package_name: &str,
    ) -> Pin<Box<dyn Future<Output = Result<UpdateCheckResult, UpdateCheckError>> + Send + '_>>
    {
        let error_code = self.error_code;
        let manager_name = self.manager_name.clone();
        let package_name = package_name.to_string();

        Box::pin(async move {
            Err(UpdateCheckError::new(
                error_code,
                format!("Mock error for {}", package_name),
                super::super::error_types::UpdateCheckErrorContext::new(manager_name, package_name),
            ))
        })
    }

    fn manager_name(&self) -> &str {
        &self.manager_name
    }

    fn is_available(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn priority(&self) -> u8 {
        self.priority
    }
}

/// Mock update checker that simulates timeout
pub struct MockTimeoutUpdateChecker {
    pub manager_name: String,
    pub priority: u8,
    pub timeout: Duration,
}

impl MockTimeoutUpdateChecker {
    pub fn new(manager_name: String) -> Self {
        Self {
            manager_name,
            priority: 100,
            timeout: Duration::from_millis(100), // Very short timeout
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl UpdateChecker for MockTimeoutUpdateChecker {
    fn check_update(
        &self,
        _package_name: &str,
    ) -> Pin<Box<dyn Future<Output = Result<UpdateCheckResult, UpdateCheckError>> + Send + '_>>
    {
        let manager_name = self.manager_name.clone();

        Box::pin(async move {
            // Simulate a long-running operation that will timeout
            tokio::time::sleep(Duration::from_secs(10)).await;

            Ok(UpdateCheckResult::success(
                true,
                Some("1.0.0".to_string()),
                Some("1.1.0".to_string()),
                manager_name,
                Some("mock source".to_string()),
                None,
            ))
        })
    }

    fn manager_name(&self) -> &str {
        &self.manager_name
    }

    fn is_available(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn priority(&self) -> u8 {
        self.priority
    }
}

/// Mock update checker that simulates network error
pub struct MockNetworkErrorUpdateChecker {
    pub manager_name: String,
    pub priority: u8,
    pub timeout: Duration,
}

impl MockNetworkErrorUpdateChecker {
    pub fn new(manager_name: String) -> Self {
        Self {
            manager_name,
            priority: 100,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl UpdateChecker for MockNetworkErrorUpdateChecker {
    fn check_update(
        &self,
        package_name: &str,
    ) -> Pin<Box<dyn Future<Output = Result<UpdateCheckResult, UpdateCheckError>> + Send + '_>>
    {
        let manager_name = self.manager_name.clone();
        let package_name = package_name.to_string();

        Box::pin(async move {
            Err(UpdateCheckError::network_error(
                manager_name,
                package_name,
                "Mock network error".to_string(),
            ))
        })
    }

    fn manager_name(&self) -> &str {
        &self.manager_name
    }

    fn is_available(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn priority(&self) -> u8 {
        self.priority
    }
}

/// Mock update checker that simulates package not found
pub struct MockPackageNotFoundUpdateChecker {
    pub manager_name: String,
    pub priority: u8,
    pub timeout: Duration,
}

impl MockPackageNotFoundUpdateChecker {
    pub fn new(manager_name: String) -> Self {
        Self {
            manager_name,
            priority: 100,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl UpdateChecker for MockPackageNotFoundUpdateChecker {
    fn check_update(
        &self,
        package_name: &str,
    ) -> Pin<Box<dyn Future<Output = Result<UpdateCheckResult, UpdateCheckError>> + Send + '_>>
    {
        let manager_name = self.manager_name.clone();
        let package_name = package_name.to_string();

        Box::pin(async move {
            Err(UpdateCheckError::package_not_found(
                manager_name,
                package_name,
            ))
        })
    }

    fn manager_name(&self) -> &str {
        &self.manager_name
    }

    fn is_available(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn priority(&self) -> u8 {
        self.priority
    }
}

/// Mock update checker that simulates manager not available
pub struct MockManagerNotAvailableUpdateChecker {
    pub manager_name: String,
    pub priority: u8,
    pub timeout: Duration,
}

impl MockManagerNotAvailableUpdateChecker {
    pub fn new(manager_name: String) -> Self {
        Self {
            manager_name,
            priority: 100,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl UpdateChecker for MockManagerNotAvailableUpdateChecker {
    fn check_update(
        &self,
        _package_name: &str,
    ) -> Pin<Box<dyn Future<Output = Result<UpdateCheckResult, UpdateCheckError>> + Send + '_>>
    {
        let manager_name = self.manager_name.clone();

        Box::pin(async move { Err(UpdateCheckError::manager_not_available(manager_name)) })
    }

    fn manager_name(&self) -> &str {
        &self.manager_name
    }

    fn is_available(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async {
            false // This is the key difference
        })
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn priority(&self) -> u8 {
        self.priority
    }
}

/// Factory for creating mock update checkers
pub struct MockUpdateCheckerFactory;

impl MockUpdateCheckerFactory {
    /// Create a successful update checker
    pub fn successful(manager_name: String) -> Box<dyn UpdateChecker> {
        Box::new(MockSuccessfulUpdateChecker::new(manager_name))
    }

    /// Create a no-update checker
    pub fn no_update(manager_name: String) -> Box<dyn UpdateChecker> {
        Box::new(MockNoUpdateChecker::new(manager_name))
    }

    /// Create an error checker
    pub fn error(manager_name: String) -> Box<dyn UpdateChecker> {
        Box::new(MockErrorUpdateChecker::new(manager_name))
    }

    /// Create a timeout checker
    pub fn timeout(manager_name: String) -> Box<dyn UpdateChecker> {
        Box::new(MockTimeoutUpdateChecker::new(manager_name))
    }

    /// Create a network error checker
    pub fn network_error(manager_name: String) -> Box<dyn UpdateChecker> {
        Box::new(MockNetworkErrorUpdateChecker::new(manager_name))
    }

    /// Create a package not found checker
    pub fn package_not_found(manager_name: String) -> Box<dyn UpdateChecker> {
        Box::new(MockPackageNotFoundUpdateChecker::new(manager_name))
    }

    /// Create a manager not available checker
    pub fn manager_not_available(manager_name: String) -> Box<dyn UpdateChecker> {
        Box::new(MockManagerNotAvailableUpdateChecker::new(manager_name))
    }

    /// Create multiple mock checkers for testing coordination
    pub fn create_multiple() -> Vec<Box<dyn UpdateChecker>> {
        vec![
            Self::successful("go".to_string()),
            Self::no_update("npm".to_string()),
            Self::error("pipx".to_string()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_successful_checker() {
        let checker = MockSuccessfulUpdateChecker::new("test".to_string());
        assert!(checker.is_available().await);
        assert_eq!(checker.manager_name(), "test");
        assert_eq!(checker.priority(), 100);

        let result = checker.check_update("test-package").await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.has_update);
    }

    #[tokio::test]
    async fn test_mock_error_checker() {
        let checker = MockErrorUpdateChecker::new("test".to_string());
        assert!(checker.is_available().await);

        let result = checker.check_update("test-package").await;
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, UpdateCheckErrorCode::CommandFailed);
    }

    #[tokio::test]
    async fn test_mock_manager_not_available() {
        let checker = MockManagerNotAvailableUpdateChecker::new("test".to_string());
        assert!(!checker.is_available().await);

        let result = checker.check_update("test-package").await;
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, UpdateCheckErrorCode::ManagerNotAvailable);
    }

    #[tokio::test]
    async fn test_mock_factory() {
        let checkers = MockUpdateCheckerFactory::create_multiple();
        assert_eq!(checkers.len(), 3);

        let successful = checkers[0].check_update("test").await;
        assert!(successful.is_ok());
        assert!(successful.unwrap().has_update);

        let no_update = checkers[1].check_update("test").await;
        assert!(no_update.is_ok());
        assert!(!no_update.unwrap().has_update);

        let error = checkers[2].check_update("test").await;
        assert!(error.is_err());
    }
}
