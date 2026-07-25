// Unified Update Checker Module
//
// This module provides a trait-based architecture for checking package updates
// across different package managers with consistent error handling, logging,
// and async coordination.

pub mod adapters;
pub mod cache;
pub mod command_runner;
pub mod coordinator;
pub mod error_types;
pub mod factory;
pub mod metrics;
pub mod serde_models;
pub mod telemetry;
pub mod traits;
pub mod version;

#[cfg(test)]
pub mod tests;

pub use coordinator::UpdateCheckerCoordinator;
pub use factory::UpdateCheckerFactory;
pub use traits::UpdateCheckerConfig;
