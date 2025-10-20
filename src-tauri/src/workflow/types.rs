use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub inputs: HashMap<String, String>,
    pub steps: Vec<WorkflowStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub needs: Vec<String>,
    pub run: Vec<String>,
    pub env: Option<HashMap<String, String>>,
    pub timeout: Option<u64>,
    pub retry: Option<WorkflowRetry>,
    pub outputs: Vec<WorkflowOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowOutput {
    pub name: String,
    pub path: String,
    pub artifact_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRetry {
    pub max_attempts: u32,       // Total attempts (including initial try)
    pub initial_delay_ms: u64,   // Initial delay in milliseconds
    pub max_delay_ms: u64,       // Maximum delay cap in milliseconds
    pub backoff_multiplier: f64, // Multiplier for exponential backoff (e.g., 2.0)
}

impl Default for WorkflowRetry {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 1000,  // 1 second
            max_delay_ms: 60000,     // 60 seconds
            backoff_multiplier: 2.0, // Double the delay each time
        }
    }
}

impl WorkflowRetry {
    /// Calculate the delay for a given attempt number (0-indexed)
    pub fn calculate_delay(&self, attempt: u32) -> u64 {
        let delay = (self.initial_delay_ms as f64) * self.backoff_multiplier.powi(attempt as i32);
        delay.min(self.max_delay_ms as f64) as u64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecution {
    pub id: String,
    pub scan_id: Option<String>,
    pub workflow_id: String,
    pub status: ExecutionStatus,
    pub started: DateTime<Utc>,
    pub completed: Option<DateTime<Utc>>,
    pub current_step: Option<String>,
    pub progress: u32,
    pub inputs: HashMap<String, String>,
    pub working_directory: String,
    pub logs: Vec<ExecutionLog>,
    pub steps: HashMap<String, StepExecution>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLog {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub message: String,
    pub step_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
    Debug,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExecution {
    pub step_id: String,
    pub status: StepStatus,
    pub started: Option<DateTime<Utc>>,
    pub completed: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub artifacts: Vec<WorkflowArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowArtifact {
    pub id: String,
    pub execution_id: String,
    pub step_id: String,
    pub name: String,
    pub artifact_type: String,
    pub file_path: Option<String>, // Path to the artifact file
    pub content: Option<String>,   // Optional inline content
    pub metadata_: Option<String>, // JSON metadata
    pub size: Option<u64>,         // File size in bytes
    pub hash: Option<String>,      // SHA256 hash
    pub created_at: DateTime<Utc>,
}

impl WorkflowArtifact {
    /// Get the path (alias for file_path for backwards compatibility)
    #[allow(dead_code)]
    pub fn path(&self) -> String {
        self.file_path.clone().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowCompatibility {
    pub compatible: bool,
    pub required_tools: Vec<String>,
    pub available_tools: Vec<String>,
    pub missing_tools: Vec<String>,
    pub compatibility_percentage: f64,
    pub warnings: Vec<String>,
}
