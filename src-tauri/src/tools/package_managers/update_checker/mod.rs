// Unified Update Checker Module
//
// This module provides a trait-based architecture for checking package updates
// across different package managers with consistent error handling, logging,
// and async coordination.

pub mod coordinator;
pub mod traits;
pub mod adapters;
pub mod command_runner;
pub mod error_types;
pub mod metrics;
pub mod cache;
pub mod serde_models;
pub mod factory;
pub mod telemetry;
pub mod version;

#[cfg(test)]
pub mod tests;

pub use coordinator::UpdateCheckerCoordinator;
pub use traits::{UpdateChecker, UpdateCheckResult, UpdateCheckerConfig, MockUpdateChecker};
pub use error_types::{UpdateCheckError, UpdateCheckErrorCode, UpdateCheckErrorContext};
pub use command_runner::{CommandRunner, CommandResult};
pub use metrics::{UpdateMetrics, UpdateCheckMetrics};
pub use cache::{UpdateCache, CacheEntry};
pub use serde_models::{OutputParser, NpmPackageInfo, PipxOutdatedPackage, HomebrewFormula};
pub use factory::UpdateCheckerFactory;
pub use telemetry::{TelemetryCollector, TelemetryContext, TelemetryEvent, TelemetrySummary};

// Re-export the expanded VersionCheckResult for backward compatibility
pub use super::version_checker::VersionCheckResult;
