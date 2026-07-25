// Update Checker Coordinator
//
// Orchestrates update checking across multiple package managers with
// concurrency control, caching, and progress reporting

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{timeout, Instant};

use super::cache::UpdateCache;
use super::command_runner::CommandRunner;
use super::error_types::UpdateCheckError;
use super::metrics::{MetricsCollector, UpdateCheckMetrics};
use super::telemetry::{TelemetryCollector, TelemetryContext};
use super::traits::{UpdateCheckResult, UpdateChecker, UpdateCheckerConfig};

/// Progress callback type
pub type ProgressCallback = Box<dyn Fn(u8) + Send + Sync>;

/// Result of a coordinated update check
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoordinatedUpdateResult {
    /// Package name
    pub package: String,

    /// Results from each manager
    pub results: HashMap<String, UpdateCheckResult>,

    /// Best result (highest priority successful result)
    pub best_result: Option<UpdateCheckResult>,

    /// Whether any manager found an update
    pub has_update: bool,

    /// Total duration
    pub duration: Duration,

    /// Number of managers checked
    pub managers_checked: usize,
}

/// Update checker coordinator
pub struct UpdateCheckerCoordinator {
    /// Available update checkers
    checkers: Arc<RwLock<Vec<Box<dyn UpdateChecker>>>>,

    /// Command runner
    command_runner: Arc<CommandRunner>,

    /// Cache for results
    cache: Arc<UpdateCache>,

    /// Metrics collector
    metrics: Arc<MetricsCollector>,

    /// Telemetry collector
    telemetry: Arc<std::sync::Mutex<TelemetryCollector>>,
}

impl UpdateCheckerCoordinator {
    pub fn new(config: UpdateCheckerConfig) -> Self {
        let command_runner = Arc::new(CommandRunner::new(
            config.default_timeout,
            config.debug_logging,
        ));

        let cache = Arc::new(UpdateCache::new(
            config.cache_duration,
            1000, // Max 1000 cache entries
        ));

        let metrics = Arc::new(MetricsCollector::new(100));

        let telemetry = Arc::new(std::sync::Mutex::new(TelemetryCollector::new(
            1000, // Max 1000 events
            config.debug_logging,
            true, // Enable metrics collection
        )));

        Self {
            checkers: Arc::new(RwLock::new(Vec::new())),
            command_runner,
            cache,
            metrics,
            telemetry,
        }
    }

    /// Add an update checker
    pub async fn add_checker(&self, checker: Box<dyn UpdateChecker>) {
        let mut checkers = self.checkers.write().await;
        checkers.push(checker);

        // Sort by priority (lower priority = higher priority)
        checkers.sort_by_key(|c| c.priority());
    }

    /// Check for updates for a single package
    pub async fn check_update(
        &self,
        package_name: &str,
    ) -> Result<CoordinatedUpdateResult, UpdateCheckError> {
        self.check_update_with_progress(package_name, None).await
    }

    /// Check for updates with progress callback
    pub async fn check_update_with_progress(
        &self,
        package_name: &str,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<CoordinatedUpdateResult, UpdateCheckError> {
        let start_time = Instant::now();

        // Create telemetry context
        let telemetry_context =
            TelemetryContext::new(self.telemetry.clone(), package_name.to_string());

        // Get available managers
        let checkers = self.checkers.read().await;
        let manager_names: Vec<String> = checkers
            .iter()
            .map(|c| c.manager_name().to_string())
            .collect();
        drop(checkers);

        // Record update check started
        telemetry_context.record_update_check_started(manager_names);

        // Check cache first
        let cache_key = UpdateCache::cache_key("coordinated", package_name);
        if let Some(cached_result) = self.cache.get(&cache_key).await {
            if let Some(progress_callback) = &progress_callback {
                progress_callback(100);
            }

            // Record cache hit
            telemetry_context.record_cache_hit("coordinated".to_string(), Duration::ZERO);

            let has_update = cached_result.has_update;
            return Ok(CoordinatedUpdateResult {
                package: package_name.to_string(),
                results: HashMap::new(),
                best_result: Some(cached_result),
                has_update,
                duration: start_time.elapsed(),
                managers_checked: 0,
            });
        }

        let checkers = self.checkers.read().await;
        let mut results = HashMap::new();
        let mut best_result: Option<UpdateCheckResult> = None;
        let mut has_update = false;
        let mut managers_checked = 0;
        let mut updates_found = 0;
        let mut errors = 0;

        // Check each manager sequentially (not concurrent for now due to trait object limitations)
        for checker in checkers.iter() {
            let package_name_str = package_name.to_string();
            let telemetry_ctx = telemetry_context.clone();

            // Record manager check started
            telemetry_ctx.record_manager_check_started(checker.manager_name().to_string());

            let result = Self::check_with_manager(
                checker.as_ref(),
                &package_name_str,
                &self.cache,
                &self.metrics,
                &self.command_runner,
                &telemetry_ctx,
            )
            .await;

            // Record manager check completed
            match &result {
                Ok(update_result) => {
                    telemetry_ctx.record_manager_check_completed(
                        checker.manager_name().to_string(),
                        true,
                        update_result.has_update,
                        None,
                    );

                    let manager_name = update_result.package_manager.clone();
                    results.insert(manager_name, update_result.clone());

                    // Update best result based on priority and success
                    if update_result.error.is_none() {
                        if best_result.is_none() || update_result.has_update {
                            best_result = Some(update_result.clone());
                        }
                        if update_result.has_update {
                            has_update = true;
                            updates_found += 1;
                        }
                    }

                    managers_checked += 1;
                }
                Err(error) => {
                    telemetry_ctx.record_manager_check_completed(
                        checker.manager_name().to_string(),
                        false,
                        false,
                        Some(error.to_string()),
                    );
                    errors += 1;
                    eprintln!("⚠️ Update check failed for {}: {}", package_name, error);
                }
            }

            // Update progress
            if let Some(progress_callback) = &progress_callback {
                let progress = ((managers_checked + errors) * 100) / checkers.len();
                progress_callback(progress as u8);
            }
        }

        let duration = start_time.elapsed();

        // Record update check completed
        telemetry_context.record_update_check_completed(managers_checked, updates_found, errors);

        let coordinated_result = CoordinatedUpdateResult {
            package: package_name.to_string(),
            results,
            best_result: best_result.clone(),
            has_update,
            duration,
            managers_checked,
        };

        // Cache the best result
        if let Some(best) = best_result {
            self.cache.set(cache_key, best).await;
        }

        Ok(coordinated_result)
    }

    /// Check updates for multiple packages
    pub async fn check_updates_batch(
        &self,
        package_names: &[String],
    ) -> Result<Vec<CoordinatedUpdateResult>, UpdateCheckError> {
        let mut results = Vec::new();

        for package_name in package_names {
            match self.check_update(package_name).await {
                Ok(result) => results.push(result),
                Err(error) => {
                    eprintln!(
                        "⚠️ Batch update check failed for {}: {}",
                        package_name, error
                    );
                    // Continue with other packages
                }
            }
        }

        Ok(results)
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> super::cache::CacheStats {
        self.cache.stats().await
    }

    /// Get metrics summary
    pub async fn get_metrics_summary(&self) -> super::metrics::MetricsSummary {
        self.metrics.get_summary().await
    }

    /// Clear cache
    pub async fn clear_cache(&self) {
        self.cache.clear().await;
    }

    /// Reset metrics
    pub async fn reset_metrics(&self) {
        self.metrics.reset().await;
    }

    /// Get telemetry summary
    pub fn get_telemetry_summary(&self) -> super::telemetry::TelemetrySummary {
        if let Ok(telemetry) = self.telemetry.lock() {
            telemetry.get_summary()
        } else {
            super::telemetry::TelemetrySummary {
                total_events: 0,
                update_checks_started: 0,
                update_checks_completed: 0,
                manager_checks_started: 0,
                manager_checks_completed: 0,
                commands_executed: 0,
                cache_hits: 0,
                cache_misses: 0,
                errors: 0,
                total_duration: Duration::ZERO,
                average_duration: Duration::ZERO,
                success_rate: 0.0,
                error_rate: 0.0,
            }
        }
    }

    /// Get recent telemetry events
    pub fn get_recent_telemetry_events(
        &self,
        limit: Option<usize>,
    ) -> Vec<super::telemetry::TelemetryEvent> {
        if let Ok(telemetry) = self.telemetry.lock() {
            telemetry.get_recent_events(limit)
        } else {
            Vec::new()
        }
    }

    /// Export telemetry events to JSON
    pub fn export_telemetry_events(&self) -> Result<String, serde_json::Error> {
        if let Ok(telemetry) = self.telemetry.lock() {
            telemetry.export_events()
        } else {
            Ok("[]".to_string())
        }
    }

    /// Clear telemetry events
    pub fn clear_telemetry(&self) {
        if let Ok(mut telemetry) = self.telemetry.lock() {
            telemetry.clear();
        }
    }

    /// Check with a specific manager
    async fn check_with_manager(
        checker: &dyn UpdateChecker,
        package_name: &str,
        cache: &UpdateCache,
        metrics: &MetricsCollector,
        _command_runner: &CommandRunner,
        telemetry_context: &TelemetryContext,
    ) -> Result<UpdateCheckResult, UpdateCheckError> {
        let start_time = Instant::now();
        let mut check_metrics =
            UpdateCheckMetrics::new(checker.manager_name().to_string(), package_name.to_string());

        // Check if manager is available
        if !checker.is_available().await {
            let error = UpdateCheckError::manager_not_available(checker.manager_name().to_string());
            check_metrics = check_metrics
                .with_success(false)
                .with_error_code(error.code.to_string());
            metrics.record_check(check_metrics).await;
            return Err(error);
        }

        // Check cache first
        let cache_key = UpdateCache::cache_key(checker.manager_name(), package_name);
        if let Some(cached_result) = cache.get(&cache_key).await {
            check_metrics = check_metrics
                .with_success(true)
                .with_update(cached_result.has_update);
            metrics.record_check(check_metrics).await;

            // Record cache hit
            telemetry_context.record_cache_hit(checker.manager_name().to_string(), Duration::ZERO);

            return Ok(cached_result);
        }

        // Record cache miss
        telemetry_context.record_cache_miss(checker.manager_name().to_string());

        // Perform the actual check
        let result = timeout(checker.timeout(), checker.check_update(package_name))
            .await
            .map_err(|_| {
                UpdateCheckError::timeout(
                    checker.manager_name().to_string(),
                    package_name.to_string(),
                    format!("{} check", checker.manager_name()),
                )
            })?;

        let result = match result {
            Ok(mut result) => {
                result = result.with_duration(start_time.elapsed());
                check_metrics = check_metrics
                    .with_success(true)
                    .with_update(result.has_update);

                // Cache successful results
                cache.set(cache_key, result.clone()).await;

                result
            }
            Err(error) => {
                check_metrics = check_metrics
                    .with_success(false)
                    .with_error_code(error.code.to_string());
                metrics.record_check(check_metrics).await;
                return Err(error);
            }
        };

        metrics.record_check(check_metrics).await;
        Ok(result)
    }
}

impl Default for UpdateCheckerCoordinator {
    fn default() -> Self {
        Self::new(UpdateCheckerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Mock update checker for testing
    struct MockUpdateChecker {
        name: String,
        available: bool,
        result: UpdateCheckResult,
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
            let result = self.result.clone();
            Box::pin(async move { Ok(result) })
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
            100
        }
    }

    #[tokio::test]
    async fn test_coordinator_basic() {
        let coordinator = UpdateCheckerCoordinator::new(UpdateCheckerConfig::default());

        // Add a mock checker
        let mock_checker = MockUpdateChecker {
            name: "test".to_string(),
            available: true,
            result: UpdateCheckResult::success(
                false,
                Some("1.0.0".to_string()),
                Some("1.0.0".to_string()),
                "test".to_string(),
                None,
                None,
            ),
        };

        coordinator.add_checker(Box::new(mock_checker)).await;

        // Test update check
        let result = coordinator.check_update("test-package").await;
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.package, "test-package");
        assert_eq!(result.managers_checked, 1);
        assert!(!result.has_update);
    }

    #[tokio::test]
    async fn test_coordinator_cache() {
        let coordinator = UpdateCheckerCoordinator::new(UpdateCheckerConfig::default());

        // Add a mock checker
        let mock_checker = MockUpdateChecker {
            name: "test".to_string(),
            available: true,
            result: UpdateCheckResult::success(
                true,
                Some("1.0.0".to_string()),
                Some("1.1.0".to_string()),
                "test".to_string(),
                None,
                None,
            ),
        };

        coordinator.add_checker(Box::new(mock_checker)).await;

        // First check should populate cache
        let result1 = coordinator.check_update("test-package").await;
        assert!(result1.is_ok());

        // Second check should use cache
        let result2 = coordinator.check_update("test-package").await;
        assert!(result2.is_ok());

        // Both results should be the same
        assert_eq!(result1.unwrap().has_update, result2.unwrap().has_update);
    }
}
