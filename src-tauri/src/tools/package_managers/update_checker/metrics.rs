// Update Checker Metrics
//
// Provides metrics collection and reporting for update checking operations

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Metrics for a single update check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckMetrics {
    /// Package manager name
    pub manager: String,
    
    /// Package name
    pub package: String,
    
    /// Whether the check was successful
    pub success: bool,
    
    /// Duration of the check
    pub duration: Duration,
    
    /// Whether an update was found
    pub has_update: bool,
    
    /// Error code if failed
    pub error_code: Option<String>,
    
    /// Timestamp when check started
    #[serde(skip, default = "Instant::now")]
    pub started_at: Instant,
    
    /// Timestamp when check completed
    #[serde(skip, default = "Instant::now")]
    pub completed_at: Instant,
}

impl UpdateCheckMetrics {
    pub fn new(manager: String, package: String) -> Self {
        let now = Instant::now();
        Self {
            manager,
            package,
            success: false,
            duration: Duration::ZERO,
            has_update: false,
            error_code: None,
            started_at: now,
            completed_at: now,
        }
    }

    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self.completed_at = Instant::now();
        self.duration = self.completed_at.duration_since(self.started_at);
        self
    }

    pub fn with_update(mut self, has_update: bool) -> Self {
        self.has_update = has_update;
        self
    }

    pub fn with_error_code(mut self, error_code: String) -> Self {
        self.error_code = Some(error_code);
        self
    }
}

/// Aggregated metrics for update checking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateMetrics {
    /// Total number of checks performed
    pub total_checks: u64,
    
    /// Number of successful checks
    pub successful_checks: u64,
    
    /// Number of failed checks
    pub failed_checks: u64,
    
    /// Number of checks that found updates
    pub updates_found: u64,
    
    /// Total duration of all checks
    pub total_duration: Duration,
    
    /// Average duration per check
    pub average_duration: Duration,
    
    /// Metrics by package manager
    pub by_manager: HashMap<String, ManagerMetrics>,
    
    /// Recent check history
    pub recent_checks: Vec<UpdateCheckMetrics>,
}

/// Metrics for a specific package manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerMetrics {
    /// Manager name
    pub manager: String,
    
    /// Total checks for this manager
    pub total_checks: u64,
    
    /// Successful checks for this manager
    pub successful_checks: u64,
    
    /// Failed checks for this manager
    pub failed_checks: u64,
    
    /// Updates found for this manager
    pub updates_found: u64,
    
    /// Total duration for this manager
    pub total_duration: Duration,
    
    /// Average duration for this manager
    pub average_duration: Duration,
    
    /// Success rate (0.0 to 1.0)
    pub success_rate: f64,
}

impl ManagerMetrics {
    pub fn new(manager: String) -> Self {
        Self {
            manager,
            total_checks: 0,
            successful_checks: 0,
            failed_checks: 0,
            updates_found: 0,
            total_duration: Duration::ZERO,
            average_duration: Duration::ZERO,
            success_rate: 0.0,
        }
    }

    pub fn add_check(&mut self, metrics: &UpdateCheckMetrics) {
        self.total_checks += 1;
        self.total_duration += metrics.duration;
        
        if metrics.success {
            self.successful_checks += 1;
        } else {
            self.failed_checks += 1;
        }
        
        if metrics.has_update {
            self.updates_found += 1;
        }
        
        // Recalculate averages
        if self.total_checks > 0 {
            self.average_duration = self.total_duration / self.total_checks as u32;
            self.success_rate = self.successful_checks as f64 / self.total_checks as f64;
        }
    }
}

/// Thread-safe metrics collector
#[derive(Debug)]
pub struct MetricsCollector {
    /// Current metrics
    metrics: Arc<RwLock<UpdateMetrics>>,
    
    /// Maximum number of recent checks to keep
    max_recent_checks: usize,
}

impl MetricsCollector {
    pub fn new(max_recent_checks: usize) -> Self {
        Self {
            metrics: Arc::new(RwLock::new(UpdateMetrics {
                total_checks: 0,
                successful_checks: 0,
                failed_checks: 0,
                updates_found: 0,
                total_duration: Duration::ZERO,
                average_duration: Duration::ZERO,
                by_manager: HashMap::new(),
                recent_checks: Vec::new(),
            })),
            max_recent_checks,
        }
    }

    /// Record a completed update check
    pub async fn record_check(&self, check_metrics: UpdateCheckMetrics) {
        let mut metrics = self.metrics.write().await;
        
        // Update global metrics
        metrics.total_checks += 1;
        metrics.total_duration += check_metrics.duration;
        
        if check_metrics.success {
            metrics.successful_checks += 1;
        } else {
            metrics.failed_checks += 1;
        }
        
        if check_metrics.has_update {
            metrics.updates_found += 1;
        }
        
        // Recalculate global averages
        if metrics.total_checks > 0 {
            metrics.average_duration = metrics.total_duration / metrics.total_checks as u32;
        }
        
        // Update manager-specific metrics
        let manager_metrics = metrics.by_manager
            .entry(check_metrics.manager.clone())
            .or_insert_with(|| ManagerMetrics::new(check_metrics.manager.clone()));
        
        manager_metrics.add_check(&check_metrics);
        
        // Add to recent checks
        metrics.recent_checks.push(check_metrics);
        
        // Trim recent checks if we exceed the limit
        if metrics.recent_checks.len() > self.max_recent_checks {
            metrics.recent_checks.remove(0);
        }
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> UpdateMetrics {
        self.metrics.read().await.clone()
    }

    /// Get metrics for a specific manager
    pub async fn get_manager_metrics(&self, manager: &str) -> Option<ManagerMetrics> {
        let metrics = self.metrics.read().await;
        metrics.by_manager.get(manager).cloned()
    }

    /// Get recent checks
    pub async fn get_recent_checks(&self, limit: Option<usize>) -> Vec<UpdateCheckMetrics> {
        let metrics = self.metrics.read().await;
        let limit = limit.unwrap_or(self.max_recent_checks);
        metrics.recent_checks
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Reset all metrics
    pub async fn reset(&self) {
        let mut metrics = self.metrics.write().await;
        *metrics = UpdateMetrics {
            total_checks: 0,
            successful_checks: 0,
            failed_checks: 0,
            updates_found: 0,
            total_duration: Duration::ZERO,
            average_duration: Duration::ZERO,
            by_manager: HashMap::new(),
            recent_checks: Vec::new(),
        };
    }

    /// Get metrics summary
    pub async fn get_summary(&self) -> MetricsSummary {
        let metrics = self.metrics.read().await;
        
        MetricsSummary {
            total_checks: metrics.total_checks,
            success_rate: if metrics.total_checks > 0 {
                metrics.successful_checks as f64 / metrics.total_checks as f64
            } else {
                0.0
            },
            updates_found: metrics.updates_found,
            average_duration: metrics.average_duration,
            manager_count: metrics.by_manager.len(),
        }
    }
}

/// Summary of metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    /// Total number of checks
    pub total_checks: u64,
    
    /// Overall success rate
    pub success_rate: f64,
    
    /// Total updates found
    pub updates_found: u64,
    
    /// Average duration per check
    pub average_duration: Duration,
    
    /// Number of managers with metrics
    pub manager_count: usize,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new(100) // Keep 100 recent checks by default
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
