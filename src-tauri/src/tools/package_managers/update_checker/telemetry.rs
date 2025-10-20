// Telemetry and Logging for Update Checker
//
// Provides structured logging and event tracing for update checking operations

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use chrono::{DateTime, Utc};

/// Telemetry event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TelemetryEvent {
    /// Update check started
    UpdateCheckStarted {
        package_name: String,
        managers: Vec<String>,
        timestamp: DateTime<Utc>,
    },
    
    /// Update check completed
    UpdateCheckCompleted {
        package_name: String,
        duration: Duration,
        managers_checked: usize,
        updates_found: usize,
        errors: usize,
        timestamp: DateTime<Utc>,
    },
    
    /// Manager check started
    ManagerCheckStarted {
        package_name: String,
        manager: String,
        timestamp: DateTime<Utc>,
    },
    
    /// Manager check completed
    ManagerCheckCompleted {
        package_name: String,
        manager: String,
        duration: Duration,
        success: bool,
        has_update: bool,
        error: Option<String>,
        timestamp: DateTime<Utc>,
    },
    
    /// Command executed
    CommandExecuted {
        manager: String,
        command: String,
        duration: Duration,
        success: bool,
        exit_code: Option<i32>,
        stdout_length: usize,
        stderr_length: usize,
        timestamp: DateTime<Utc>,
    },
    
    /// Cache hit
    CacheHit {
        package_name: String,
        manager: String,
        cache_age: Duration,
        timestamp: DateTime<Utc>,
    },
    
    /// Cache miss
    CacheMiss {
        package_name: String,
        manager: String,
        timestamp: DateTime<Utc>,
    },
    
    /// Error occurred
    ErrorOccurred {
        package_name: String,
        manager: String,
        error_type: String,
        error_message: String,
        context: HashMap<String, String>,
        timestamp: DateTime<Utc>,
    },
}

/// Telemetry collector
pub struct TelemetryCollector {
    /// Events buffer
    events: Vec<TelemetryEvent>,
    
    /// Maximum events to keep in memory
    max_events: usize,
    
    /// Whether to enable debug logging
    debug_logging: bool,
    
    /// Whether to enable metrics collection
    enable_metrics: bool,
}

impl TelemetryCollector {
    pub fn new(max_events: usize, debug_logging: bool, enable_metrics: bool) -> Self {
        Self {
            events: Vec::new(),
            max_events,
            debug_logging,
            enable_metrics,
        }
    }

    /// Record a telemetry event
    pub fn record_event(&mut self, event: TelemetryEvent) {
        if self.enable_metrics {
            self.events.push(event.clone());
            
            // Trim events if we exceed the limit
            if self.events.len() > self.max_events {
                self.events.remove(0);
            }
        }

        if self.debug_logging {
            self.log_event(&event);
        }
    }

    /// Log an event to stdout/stderr
    fn log_event(&self, event: &TelemetryEvent) {
        match event {
            TelemetryEvent::UpdateCheckStarted { package_name, managers, .. } => {
                eprintln!("🔍 UPDATE_CHECK_STARTED: package={}, managers={:?}", package_name, managers);
            }
            TelemetryEvent::UpdateCheckCompleted { package_name, duration, managers_checked, updates_found, errors, .. } => {
                eprintln!("✅ UPDATE_CHECK_COMPLETED: package={}, duration={:?}, managers={}, updates={}, errors={}", 
                    package_name, duration, managers_checked, updates_found, errors);
            }
            TelemetryEvent::ManagerCheckStarted { package_name, manager, .. } => {
                eprintln!("🔄 MANAGER_CHECK_STARTED: package={}, manager={}", package_name, manager);
            }
            TelemetryEvent::ManagerCheckCompleted { package_name, manager, duration, success, has_update, error, .. } => {
                let status = if *success { "SUCCESS" } else { "FAILED" };
                let update_status = if *has_update { "UPDATE_AVAILABLE" } else { "UP_TO_DATE" };
                eprintln!("📊 MANAGER_CHECK_COMPLETED: package={}, manager={}, duration={:?}, status={}, update={}{}", 
                    package_name, manager, duration, status, update_status,
                    if let Some(err) = error { format!(", error={}", err) } else { String::new() });
            }
            TelemetryEvent::CommandExecuted { manager, command, duration, success, exit_code, stdout_length, stderr_length, .. } => {
                let status = if *success { "SUCCESS" } else { "FAILED" };
                eprintln!("⚡ COMMAND_EXECUTED: manager={}, command={}, duration={:?}, status={}, exit_code={:?}, stdout={}b, stderr={}b", 
                    manager, command, duration, status, exit_code, stdout_length, stderr_length);
            }
            TelemetryEvent::CacheHit { package_name, manager, cache_age, .. } => {
                eprintln!("💾 CACHE_HIT: package={}, manager={}, age={:?}", package_name, manager, cache_age);
            }
            TelemetryEvent::CacheMiss { package_name, manager, .. } => {
                eprintln!("❌ CACHE_MISS: package={}, manager={}", package_name, manager);
            }
            TelemetryEvent::ErrorOccurred { package_name, manager, error_type, error_message, context, .. } => {
                eprintln!("🚨 ERROR_OCCURRED: package={}, manager={}, type={}, message={}, context={:?}", 
                    package_name, manager, error_type, error_message, context);
            }
        }
    }

    /// Get recent events
    pub fn get_recent_events(&self, limit: Option<usize>) -> Vec<TelemetryEvent> {
        let limit = limit.unwrap_or(self.max_events);
        self.events
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get events by type
    pub fn get_events_by_type(&self, event_type: &str) -> Vec<TelemetryEvent> {
        self.events
            .iter()
            .filter(|event| {
                match event {
                    TelemetryEvent::UpdateCheckStarted { .. } => event_type == "UpdateCheckStarted",
                    TelemetryEvent::UpdateCheckCompleted { .. } => event_type == "UpdateCheckCompleted",
                    TelemetryEvent::ManagerCheckStarted { .. } => event_type == "ManagerCheckStarted",
                    TelemetryEvent::ManagerCheckCompleted { .. } => event_type == "ManagerCheckCompleted",
                    TelemetryEvent::CommandExecuted { .. } => event_type == "CommandExecuted",
                    TelemetryEvent::CacheHit { .. } => event_type == "CacheHit",
                    TelemetryEvent::CacheMiss { .. } => event_type == "CacheMiss",
                    TelemetryEvent::ErrorOccurred { .. } => event_type == "ErrorOccurred",
                }
            })
            .cloned()
            .collect()
    }

    /// Get telemetry summary
    pub fn get_summary(&self) -> TelemetrySummary {
        let mut summary = TelemetrySummary {
            total_events: self.events.len(),
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
        };

        let mut total_duration = Duration::ZERO;
        let mut successful_checks = 0;
        let mut total_checks = 0;

        for event in &self.events {
            match event {
                TelemetryEvent::UpdateCheckStarted { .. } => {
                    summary.update_checks_started += 1;
                }
                TelemetryEvent::UpdateCheckCompleted { duration, .. } => {
                    summary.update_checks_completed += 1;
                    total_duration += *duration;
                }
                TelemetryEvent::ManagerCheckStarted { .. } => {
                    summary.manager_checks_started += 1;
                }
                TelemetryEvent::ManagerCheckCompleted { duration, success, .. } => {
                    summary.manager_checks_completed += 1;
                    total_checks += 1;
                    if *success {
                        successful_checks += 1;
                    }
                }
                TelemetryEvent::CommandExecuted { .. } => {
                    summary.commands_executed += 1;
                }
                TelemetryEvent::CacheHit { .. } => {
                    summary.cache_hits += 1;
                }
                TelemetryEvent::CacheMiss { .. } => {
                    summary.cache_misses += 1;
                }
                TelemetryEvent::ErrorOccurred { .. } => {
                    summary.errors += 1;
                }
            }
        }

        summary.total_duration = total_duration;
        if summary.update_checks_completed > 0 {
            summary.average_duration = total_duration / summary.update_checks_completed as u32;
        }
        if total_checks > 0 {
            summary.success_rate = successful_checks as f64 / total_checks as f64;
            summary.error_rate = (total_checks - successful_checks) as f64 / total_checks as f64;
        }

        summary
    }

    /// Clear all events
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Export events to JSON
    pub fn export_events(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.events)
    }
}

/// Telemetry summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySummary {
    pub total_events: usize,
    pub update_checks_started: usize,
    pub update_checks_completed: usize,
    pub manager_checks_started: usize,
    pub manager_checks_completed: usize,
    pub commands_executed: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub errors: usize,
    pub total_duration: Duration,
    pub average_duration: Duration,
    pub success_rate: f64,
    pub error_rate: f64,
}

/// Telemetry context for tracking operations
#[derive(Clone)]
pub struct TelemetryContext {
    collector: std::sync::Arc<std::sync::Mutex<TelemetryCollector>>,
    package_name: String,
    start_time: Instant,
}

impl TelemetryContext {
    pub fn new(
        collector: std::sync::Arc<std::sync::Mutex<TelemetryCollector>>,
        package_name: String,
    ) -> Self {
        Self {
            collector,
            package_name,
            start_time: Instant::now(),
        }
    }

    /// Record update check started
    pub fn record_update_check_started(&self, managers: Vec<String>) {
        if let Ok(mut collector) = self.collector.lock() {
            collector.record_event(TelemetryEvent::UpdateCheckStarted {
                package_name: self.package_name.clone(),
                managers,
                timestamp: Utc::now(),
            });
        }
    }

    /// Record update check completed
    pub fn record_update_check_completed(
        &self,
        managers_checked: usize,
        updates_found: usize,
        errors: usize,
    ) {
        if let Ok(mut collector) = self.collector.lock() {
            collector.record_event(TelemetryEvent::UpdateCheckCompleted {
                package_name: self.package_name.clone(),
                duration: self.start_time.elapsed(),
                managers_checked,
                updates_found,
                errors,
                timestamp: Utc::now(),
            });
        }
    }

    /// Record manager check started
    pub fn record_manager_check_started(&self, manager: String) {
        if let Ok(mut collector) = self.collector.lock() {
            collector.record_event(TelemetryEvent::ManagerCheckStarted {
                package_name: self.package_name.clone(),
                manager,
                timestamp: Utc::now(),
            });
        }
    }

    /// Record manager check completed
    pub fn record_manager_check_completed(
        &self,
        manager: String,
        success: bool,
        has_update: bool,
        error: Option<String>,
    ) {
        if let Ok(mut collector) = self.collector.lock() {
            collector.record_event(TelemetryEvent::ManagerCheckCompleted {
                package_name: self.package_name.clone(),
                manager,
                duration: self.start_time.elapsed(),
                success,
                has_update,
                error,
                timestamp: Utc::now(),
            });
        }
    }

    /// Record command executed
    pub fn record_command_executed(
        &self,
        manager: String,
        command: String,
        success: bool,
        exit_code: Option<i32>,
        stdout_length: usize,
        stderr_length: usize,
    ) {
        if let Ok(mut collector) = self.collector.lock() {
            collector.record_event(TelemetryEvent::CommandExecuted {
                manager,
                command,
                duration: self.start_time.elapsed(),
                success,
                exit_code,
                stdout_length,
                stderr_length,
                timestamp: Utc::now(),
            });
        }
    }

    /// Record cache hit
    pub fn record_cache_hit(&self, manager: String, cache_age: Duration) {
        if let Ok(mut collector) = self.collector.lock() {
            collector.record_event(TelemetryEvent::CacheHit {
                package_name: self.package_name.clone(),
                manager,
                cache_age,
                timestamp: Utc::now(),
            });
        }
    }

    /// Record cache miss
    pub fn record_cache_miss(&self, manager: String) {
        if let Ok(mut collector) = self.collector.lock() {
            collector.record_event(TelemetryEvent::CacheMiss {
                package_name: self.package_name.clone(),
                manager,
                timestamp: Utc::now(),
            });
        }
    }

    /// Record error
    pub fn record_error(
        &self,
        manager: String,
        error_type: String,
        error_message: String,
        context: HashMap<String, String>,
    ) {
        if let Ok(mut collector) = self.collector.lock() {
            collector.record_event(TelemetryEvent::ErrorOccurred {
                package_name: self.package_name.clone(),
                manager,
                error_type,
                error_message,
                context,
                timestamp: Utc::now(),
            });
        }
    }
}

impl Default for TelemetryCollector {
    fn default() -> Self {
        Self::new(1000, false, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;

    #[test]
    fn test_telemetry_collector() {
        let mut collector = TelemetryCollector::new(10, true, true);
        
        // Record some events
        collector.record_event(TelemetryEvent::UpdateCheckStarted {
            package_name: "test".to_string(),
            managers: vec!["go".to_string(), "npm".to_string()],
            timestamp: Utc::now(),
        });
        
        collector.record_event(TelemetryEvent::UpdateCheckCompleted {
            package_name: "test".to_string(),
            duration: Duration::from_secs(1),
            managers_checked: 2,
            updates_found: 1,
            errors: 0,
            timestamp: Utc::now(),
        });
        
        // Check summary
        let summary = collector.get_summary();
        assert_eq!(summary.total_events, 2);
        assert_eq!(summary.update_checks_started, 1);
        assert_eq!(summary.update_checks_completed, 1);
        assert_eq!(summary.total_duration, Duration::from_secs(1));
    }

    #[test]
    fn test_telemetry_context() {
        let collector = Arc::new(Mutex::new(TelemetryCollector::new(10, false, true)));
        let context = TelemetryContext::new(collector.clone(), "test".to_string());
        
        // Record events through context
        context.record_update_check_started(vec!["go".to_string()]);
        context.record_manager_check_started("go".to_string());
        context.record_manager_check_completed("go".to_string(), true, true, None);
        context.record_update_check_completed(1, 1, 0);
        
        // Check that events were recorded
        let collector = collector.lock().unwrap();
        let summary = collector.get_summary();
        assert_eq!(summary.update_checks_started, 1);
        assert_eq!(summary.manager_checks_started, 1);
        assert_eq!(summary.manager_checks_completed, 1);
        assert_eq!(summary.update_checks_completed, 1);
    }

    #[test]
    fn test_event_export() {
        let mut collector = TelemetryCollector::new(10, false, true);
        
        collector.record_event(TelemetryEvent::UpdateCheckStarted {
            package_name: "test".to_string(),
            managers: vec!["go".to_string()],
            timestamp: Utc::now(),
        });
        
        let json = collector.export_events();
        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("UpdateCheckStarted"));
        assert!(json_str.contains("test"));
    }
}
