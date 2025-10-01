use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Event names for Tauri event system
pub const WORKFLOW_STARTED_EVENT: &str = "workflow://started";
pub const WORKFLOW_STATUS_CHANGED_EVENT: &str = "workflow://status_changed";
pub const WORKFLOW_STEP_CHANGED_EVENT: &str = "workflow://step_changed";
pub const WORKFLOW_PROGRESS_UPDATED_EVENT: &str = "workflow://progress_updated";
pub const WORKFLOW_STEP_COMPLETED_EVENT: &str = "workflow://step_completed";
pub const WORKFLOW_STEP_OUTPUT_EVENT: &str = "workflow://step_output";
pub const WORKFLOW_COMPLETED_EVENT: &str = "workflow://completed";
pub const WORKFLOW_FAILED_EVENT: &str = "workflow://failed";
pub const WORKFLOW_CANCELLED_EVENT: &str = "workflow://cancelled";

pub const SCAN_STARTED_EVENT: &str = "scan://started";
pub const SCAN_STATUS_CHANGED_EVENT: &str = "scan://status_changed";
pub const SCAN_PROGRESS_UPDATED_EVENT: &str = "scan://progress_updated";
pub const SCAN_COMPLETED_EVENT: &str = "scan://completed";
pub const SCAN_FAILED_EVENT: &str = "scan://failed";
pub const SCAN_CANCELLED_EVENT: &str = "scan://cancelled";

pub const SYSTEM_HEALTH_CHANGED_EVENT: &str = "system://health_changed";
pub const TOOL_AVAILABILITY_CHANGED_EVENT: &str = "tool://availability_changed";

/// Workflow execution started event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStartedPayload {
    pub execution_id: String,
    pub workflow_id: String,
    pub workflow_name: String,
    pub inputs: std::collections::HashMap<String, String>,
    pub working_directory: String,
    pub started_at: DateTime<Utc>,
}

/// Workflow status changed event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStatusChangedPayload {
    pub execution_id: String,
    pub old_status: String,
    pub new_status: String,
    pub error_message: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Workflow step changed event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStepChangedPayload {
    pub execution_id: String,
    pub step_id: String,
    pub step_name: String,
    pub timestamp: DateTime<Utc>,
}

/// Workflow progress updated event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowProgressUpdatedPayload {
    pub execution_id: String,
    pub progress: f32,
    pub current_step: Option<String>,
    pub total_steps: Option<u32>,
    pub timestamp: DateTime<Utc>,
}

/// Workflow step completed event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStepCompletedPayload {
    pub execution_id: String,
    pub step_id: String,
    pub step_name: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub stdout_lines_count: usize,
    pub stderr_lines_count: usize,
    pub artifacts_count: usize,
    pub timestamp: DateTime<Utc>,
}

/// Workflow step output event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStepOutputPayload {
    pub execution_id: String,
    pub step_id: String,
    pub stream_type: String, // "stdout" or "stderr"
    pub line: String,
    pub timestamp: DateTime<Utc>,
}

/// Workflow completed event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowCompletedPayload {
    pub execution_id: String,
    pub workflow_id: String,
    pub workflow_name: String,
    pub duration_ms: u64,
    pub total_steps: usize,
    pub completed_steps: usize,
    pub failed_steps: usize,
    pub artifacts_count: usize,
    pub vulnerabilities_found: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub timestamp: DateTime<Utc>,
}

/// Workflow failed event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowFailedPayload {
    pub execution_id: String,
    pub workflow_id: String,
    pub workflow_name: String,
    pub error_message: String,
    pub failed_step: Option<String>,
    pub duration_ms: u64,
    pub timestamp: DateTime<Utc>,
}

/// Scan started event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStartedPayload {
    pub scan_id: String,
    pub scan_name: String,
    pub target: String,
    pub workflow_id: Option<String>,
    pub started_at: DateTime<Utc>,
}

/// Scan status changed event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatusChangedPayload {
    pub scan_id: String,
    pub old_status: String,
    pub new_status: String,
    pub error_message: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Scan progress updated event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgressUpdatedPayload {
    pub scan_id: String,
    pub progress: f32,
    pub current_test: Option<String>,
    pub current_step: Option<u32>,
    pub total_steps: Option<u32>,
    pub timestamp: DateTime<Utc>,
}

/// System health changed event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthChangedPayload {
    pub status: String,
    pub tools_available: u32,
    pub tools_missing: u32,
    pub active_scans: u32,
    pub queued_scans: u32,
    pub timestamp: DateTime<Utc>,
}

/// Tool availability changed event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolAvailabilityChangedPayload {
    pub tool_name: String,
    pub available: bool,
    pub path: Option<String>,
    pub version: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Trait for event payload types
pub trait EventPayload: Serialize + Clone {
    fn event_type(&self) -> String;
    fn timestamp(&self) -> DateTime<Utc>;
}

/// Event dispatcher for sending events to Tauri
pub struct EventDispatcher {
    app_handle: Option<tauri::AppHandle>,
}

impl EventDispatcher {
    /// Create a new event dispatcher
    pub fn new() -> Self {
        Self {
            app_handle: None,
        }
    }

    /// Set the Tauri app handle for sending events
    pub fn set_app_handle(&mut self, app_handle: tauri::AppHandle) {
        self.app_handle = Some(app_handle);
    }

    /// Send a workflow started event
    pub async fn send_workflow_started(&self, payload: WorkflowStartedPayload) -> Result<(), tauri::Error> {
        if let Some(app_handle) = &self.app_handle {
            app_handle.emit(WORKFLOW_STARTED_EVENT, payload).await?;
        }
        Ok(())
    }

    /// Send a workflow status changed event
    pub async fn send_workflow_status_changed(&self, payload: WorkflowStatusChangedPayload) -> Result<(), tauri::Error> {
        if let Some(app_handle) = &self.app_handle {
            app_handle.emit(WORKFLOW_STATUS_CHANGED_EVENT, payload).await?;
        }
        Ok(())
    }

    /// Send a workflow step changed event
    pub async fn send_workflow_step_changed(&self, payload: WorkflowStepChangedPayload) -> Result<(), tauri::Error> {
        if let Some(app_handle) = &self.app_handle {
            app_handle.emit(WORKFLOW_STEP_CHANGED_EVENT, payload).await?;
        }
        Ok(())
    }

    /// Send a workflow progress updated event
    pub async fn send_workflow_progress_updated(&self, payload: WorkflowProgressUpdatedPayload) -> Result<(), tauri::Error> {
        if let Some(app_handle) = &self.app_handle {
            app_handle.emit(WORKFLOW_PROGRESS_UPDATED_EVENT, payload).await?;
        }
        Ok(())
    }

    /// Send a workflow step completed event
    pub async fn send_workflow_step_completed(&self, payload: WorkflowStepCompletedPayload) -> Result<(), tauri::Error> {
        if let Some(app_handle) = &self.app_handle {
            app_handle.emit(WORKFLOW_STEP_COMPLETED_EVENT, payload).await?;
        }
        Ok(())
    }

    /// Send a workflow step output event
    pub async fn send_workflow_step_output(&self, payload: WorkflowStepOutputPayload) -> Result<(), tauri::Error> {
        if let Some(app_handle) = &self.app_handle {
            app_handle.emit(WORKFLOW_STEP_OUTPUT_EVENT, payload).await?;
        }
        Ok(())
    }

    /// Send a workflow completed event
    pub async fn send_workflow_completed(&self, payload: WorkflowCompletedPayload) -> Result<(), tauri::Error> {
        if let Some(app_handle) = &self.app_handle {
            app_handle.emit(WORKFLOW_COMPLETED_EVENT, payload).await?;
        }
        Ok(())
    }

    /// Send a workflow failed event
    pub async fn send_workflow_failed(&self, payload: WorkflowFailedPayload) -> Result<(), tauri::Error> {
        if let Some(app_handle) = &self.app_handle {
            app_handle.emit(WORKFLOW_FAILED_EVENT, payload).await?;
        }
        Ok(())
    }

    /// Send a scan started event
    pub async fn send_scan_started(&self, payload: ScanStartedPayload) -> Result<(), tauri::Error> {
        if let Some(app_handle) = &self.app_handle {
            app_handle.emit(SCAN_STARTED_EVENT, payload).await?;
        }
        Ok(())
    }

    /// Send a scan status changed event
    pub async fn send_scan_status_changed(&self, payload: ScanStatusChangedPayload) -> Result<(), tauri::Error> {
        if let Some(app_handle) = &self.app_handle {
            app_handle.emit(SCAN_STATUS_CHANGED_EVENT, payload).await?;
        }
        Ok(())
    }

    /// Send a scan progress updated event
    pub async fn send_scan_progress_updated(&self, payload: ScanProgressUpdatedPayload) -> Result<(), tauri::Error> {
        if let Some(app_handle) = &self.app_handle {
            app_handle.emit(SCAN_PROGRESS_UPDATED_EVENT, payload).await?;
        }
        Ok(())
    }

    /// Send a system health changed event
    pub async fn send_system_health_changed(&self, payload: SystemHealthChangedPayload) -> Result<(), tauri::Error> {
        if let Some(app_handle) = &self.app_handle {
            app_handle.emit(SYSTEM_HEALTH_CHANGED_EVENT, payload).await?;
        }
        Ok(())
    }

    /// Send a tool availability changed event
    pub async fn send_tool_availability_changed(&self, payload: ToolAvailabilityChangedPayload) -> Result<(), tauri::Error> {
        if let Some(app_handle) = &self.app_handle {
            app_handle.emit(TOOL_AVAILABILITY_CHANGED_EVENT, payload).await?;
        }
        Ok(())
    }
}

impl Default for EventDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper macros for creating event payloads
#[macro_export]
macro_rules! workflow_started_event {
    ($execution_id:expr, $workflow_id:expr, $workflow_name:expr, $inputs:expr, $working_directory:expr) => {
        WorkflowStartedPayload {
            execution_id: $execution_id,
            workflow_id: $workflow_id,
            workflow_name: $workflow_name,
            inputs: $inputs,
            working_directory: $working_directory,
            started_at: chrono::Utc::now(),
        }
    };
}

#[macro_export]
macro_rules! workflow_status_changed_event {
    ($execution_id:expr, $old_status:expr, $new_status:expr, $error_message:expr) => {
        WorkflowStatusChangedPayload {
            execution_id: $execution_id,
            old_status: $old_status,
            new_status: $new_status,
            error_message: $error_message,
            timestamp: chrono::Utc::now(),
        }
    };
}

#[macro_export]
macro_rules! workflow_step_output_event {
    ($execution_id:expr, $step_id:expr, $stream_type:expr, $line:expr) => {
        WorkflowStepOutputPayload {
            execution_id: $execution_id,
            step_id: $step_id,
            stream_type: $stream_type,
            line: $line,
            timestamp: chrono::Utc::now(),
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_payload_creation() {
        let payload = workflow_started_event!(
            "exec-123".to_string(),
            "workflow-456".to_string(),
            "Test Workflow".to_string(),
            std::collections::HashMap::new(),
            "/tmp/workdir".to_string()
        );

        assert_eq!(payload.execution_id, "exec-123");
        assert_eq!(payload.workflow_name, "Test Workflow");
    }

    #[test]
    fn test_workflow_status_event() {
        let payload = workflow_status_changed_event!(
            "exec-123".to_string(),
            "pending".to_string(),
            "running".to_string(),
            None
        );

        assert_eq!(payload.execution_id, "exec-123");
        assert_eq!(payload.old_status, "pending");
        assert_eq!(payload.new_status, "running");
    }
}