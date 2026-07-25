// Update Checker Traits
//
// Defines the core interfaces for update checking across package managers

use super::error_types::{UpdateCheckError, UpdateCheckErrorCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Enhanced result structure for update checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    /// Whether an update is available
    pub has_update: bool,

    /// Current installed version
    pub current_version: Option<String>,

    /// Latest available version
    pub latest_version: Option<String>,

    /// Package manager identifier
    pub package_manager: String,

    /// Error information if check failed
    pub error: Option<String>,

    /// Error code for programmatic handling
    pub error_code: Option<UpdateCheckErrorCode>,

    /// Source of the version information
    pub source: Option<String>,

    /// Type of update (patch, minor, major)
    pub update_type: Option<UpdateType>,

    /// Diagnostic information for troubleshooting
    pub diagnostic: Option<String>,

    /// Timestamp when check was performed
    pub checked_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Duration of the check operation
    pub duration: Option<Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UpdateType {
    Patch,
    Minor,
    Major,
    PreRelease,
    Unknown,
}

impl UpdateCheckResult {
    pub fn success(
        has_update: bool,
        current_version: Option<String>,
        latest_version: Option<String>,
        package_manager: String,
        source: Option<String>,
        update_type: Option<UpdateType>,
    ) -> Self {
        Self {
            has_update,
            current_version,
            latest_version,
            package_manager,
            error: None,
            error_code: None,
            source,
            update_type,
            diagnostic: None,
            checked_at: Some(chrono::Utc::now()),
            duration: None,
        }
    }

    pub fn error(
        error: String,
        error_code: UpdateCheckErrorCode,
        package_manager: String,
        diagnostic: Option<String>,
    ) -> Self {
        Self {
            has_update: false,
            current_version: None,
            latest_version: None,
            package_manager,
            error: Some(error),
            error_code: Some(error_code),
            source: None,
            update_type: None,
            diagnostic,
            checked_at: Some(chrono::Utc::now()),
            duration: None,
        }
    }

    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    pub fn with_diagnostic(mut self, diagnostic: String) -> Self {
        self.diagnostic = Some(diagnostic);
        self
    }
}

/// Simple mock update checker for testing
#[derive(Debug)]
pub struct MockUpdateChecker {
    pub name: String,
    pub available: bool,
    pub has_update: bool,
    pub current_version: Option<String>,
    pub latest_version: Option<String>,
}

impl MockUpdateChecker {
    pub fn new(name: &str, available: bool, has_update: bool) -> Self {
        Self {
            name: name.to_string(),
            available,
            has_update,
            current_version: Some("1.0.0".to_string()),
            latest_version: if has_update {
                Some("1.1.0".to_string())
            } else {
                Some("1.0.0".to_string())
            },
        }
    }
}

/// Core trait for update checkers
pub trait UpdateChecker: Send + Sync {
    /// Check for updates for a specific package
    fn check_update(
        &self,
        package_name: &str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<UpdateCheckResult, UpdateCheckError>>
                + Send
                + '_,
        >,
    >;

    /// Get the package manager identifier
    fn manager_name(&self) -> &str;

    /// Check if this manager is available on the current platform
    fn is_available(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>>;

    /// Get the command timeout for this manager
    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    /// Get the priority of this manager (lower = higher priority)
    fn priority(&self) -> u8 {
        100
    }
}

impl UpdateChecker for MockUpdateChecker {
    fn check_update(
        &self,
        _package_name: &str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<UpdateCheckResult, UpdateCheckError>>
                + Send
                + '_,
        >,
    > {
        let has_update = self.has_update;
        let current_version = self.current_version.clone();
        let latest_version = self.latest_version.clone();
        let name = self.name.clone();

        Box::pin(async move {
            Ok(UpdateCheckResult::success(
                has_update,
                current_version,
                latest_version,
                name,
                Some("mock".to_string()),
                None,
            ))
        })
    }

    fn manager_name(&self) -> &str {
        &self.name
    }

    fn is_available(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let available = self.available;
        Box::pin(async move { available })
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn priority(&self) -> u8 {
        50
    }
}

/// Configuration for update checkers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckerConfig {
    /// Default timeout for commands
    pub default_timeout: Duration,

    /// Maximum number of concurrent checks
    pub max_concurrent: usize,

    /// Cache duration for results
    pub cache_duration: Duration,

    /// Whether to enable debug logging
    pub debug_logging: bool,

    /// Whether to enable metrics collection
    pub enable_metrics: bool,
}

impl Default for UpdateCheckerConfig {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(30),
            max_concurrent: 10,
            cache_duration: Duration::from_secs(300), // 5 minutes
            debug_logging: false,
            enable_metrics: true,
        }
    }
}
