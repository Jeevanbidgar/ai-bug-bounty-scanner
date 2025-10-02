use serde::{Deserialize, Serialize};
use chrono::Utc;

// Event payload structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowEvent {
    pub execution_id: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepEvent {
    pub execution_id: String,
    pub step_id: String,
    pub step_name: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEvent {
    pub execution_id: String,
    pub step_id: String,
    pub stream_type: String, // "stdout" or "stderr"
    pub line: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusEvent {
    pub execution_id: String,
    pub status: String,
    pub progress: u32,
    pub current_step: Option<String>,
    pub timestamp: String,
}

// Event name constants (namespaced to avoid conflicts)
pub const WORKFLOW_EXECUTION_STARTED: &str = "workflow:execution_started";
pub const WORKFLOW_EXECUTION_COMPLETED: &str = "workflow:execution_completed";
pub const WORKFLOW_EXECUTION_FAILED: &str = "workflow:execution_failed";
pub const WORKFLOW_EXECUTION_CANCELLED: &str = "workflow:execution_cancelled";

pub const WORKFLOW_STEP_STARTED: &str = "workflow:step_started";
pub const WORKFLOW_STEP_COMPLETED: &str = "workflow:step_completed";
pub const WORKFLOW_STEP_FAILED: &str = "workflow:step_failed";

pub const WORKFLOW_STDOUT: &str = "workflow:stdout";
pub const WORKFLOW_STDERR: &str = "workflow:stderr";

pub const WORKFLOW_STATUS_UPDATE: &str = "workflow:status_update";

// Scan event constants
pub const SCAN_PROGRESS_UPDATE: &str = "scan:progress_update";
pub const SCAN_STARTED: &str = "scan:started";
pub const SCAN_COMPLETED: &str = "scan:completed";
pub const SCAN_FAILED: &str = "scan:failed";
pub const SCAN_ERROR: &str = "scan:error";
pub const SYSTEM_NOTIFICATION: &str = "system:notification";

// Tool installation event constants
pub const TOOL_INSTALLATION_STARTED: &str = "tool:installation_started";
pub const TOOL_INSTALLATION_OUTPUT: &str = "tool:installation_output";
pub const TOOL_INSTALLATION_COMPLETED: &str = "tool:installation_completed";
pub const TOOL_INSTALLATION_FAILED: &str = "tool:installation_failed";

// Scan event structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgressEvent {
    pub scan_id: String,
    pub progress: i32,
    pub current_test: Option<String>,
    pub status: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEvent {
    pub scan_id: String,
    pub status: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanErrorEvent {
    pub scan_id: String,
    pub error: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemNotificationEvent {
    pub notification_type: String, // "info", "success", "warning", "error"
    pub title: String,
    pub message: String,
    pub timestamp: String,
}

// Tool installation event structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInstallationStartedEvent {
    pub tool_name: String,
    pub installation_method: String, // "pipx", "apt", "winget", "go"
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInstallationOutputEvent {
    pub tool_name: String,
    pub output_type: String, // "stdout" or "stderr"
    pub line: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInstallationCompletedEvent {
    pub tool_name: String,
    pub success: bool,
    pub message: String,
    pub timestamp: String,
}

// Event emission helpers
pub struct EventEmitter;

impl EventEmitter {
    pub fn workflow_execution_started(
        execution_id: &str,
        _workflow_name: &str,
        _inputs: std::collections::HashMap<String, String>,
        _working_directory: &str,
    ) -> WorkflowEvent {
        WorkflowEvent {
            execution_id: execution_id.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn workflow_step_started(
        execution_id: &str,
        step_id: &str,
        step_name: &str,
    ) -> StepEvent {
        StepEvent {
            execution_id: execution_id.to_string(),
            step_id: step_id.to_string(),
            step_name: step_name.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn workflow_step_completed(
        execution_id: &str,
        step_id: &str,
        _exit_code: i32,
        _artifacts_count: usize,
    ) -> StepEvent {
        StepEvent {
            execution_id: execution_id.to_string(),
            step_id: step_id.to_string(),
            step_name: "".to_string(), // Not needed for completion
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn workflow_stdout(
        execution_id: &str,
        step_id: &str,
        line: &str,
    ) -> StreamEvent {
        StreamEvent {
            execution_id: execution_id.to_string(),
            step_id: step_id.to_string(),
            stream_type: "stdout".to_string(),
            line: line.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn workflow_stderr(
        execution_id: &str,
        step_id: &str,
        line: &str,
    ) -> StreamEvent {
        StreamEvent {
            execution_id: execution_id.to_string(),
            step_id: step_id.to_string(),
            stream_type: "stderr".to_string(),
            line: line.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn workflow_status_update(
        execution_id: &str,
        status: &str,
        progress: u32,
        current_step: Option<String>,
    ) -> StatusEvent {
        StatusEvent {
            execution_id: execution_id.to_string(),
            status: status.to_string(),
            progress,
            current_step,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn scan_progress_update(
        scan_id: &str,
        progress: i32,
        current_test: Option<String>,
        status: &str,
    ) -> ScanProgressEvent {
        ScanProgressEvent {
            scan_id: scan_id.to_string(),
            progress,
            current_test,
            status: status.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn scan_started(scan_id: &str) -> ScanEvent {
        ScanEvent {
            scan_id: scan_id.to_string(),
            status: "running".to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn scan_completed(scan_id: &str) -> ScanEvent {
        ScanEvent {
            scan_id: scan_id.to_string(),
            status: "completed".to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn scan_failed(scan_id: &str) -> ScanEvent {
        ScanEvent {
            scan_id: scan_id.to_string(),
            status: "failed".to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn scan_error(scan_id: &str, error: &str) -> ScanErrorEvent {
        ScanErrorEvent {
            scan_id: scan_id.to_string(),
            error: error.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn system_notification(
        notification_type: &str,
        title: &str,
        message: &str,
    ) -> SystemNotificationEvent {
        SystemNotificationEvent {
            notification_type: notification_type.to_string(),
            title: title.to_string(),
            message: message.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    // Tool installation events
    pub fn tool_installation_started(
        tool_name: &str,
        installation_method: &str,
    ) -> ToolInstallationStartedEvent {
        ToolInstallationStartedEvent {
            tool_name: tool_name.to_string(),
            installation_method: installation_method.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn tool_installation_output(
        tool_name: &str,
        output_type: &str,
        line: &str,
    ) -> ToolInstallationOutputEvent {
        ToolInstallationOutputEvent {
            tool_name: tool_name.to_string(),
            output_type: output_type.to_string(),
            line: line.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn tool_installation_completed(
        tool_name: &str,
        success: bool,
        message: &str,
    ) -> ToolInstallationCompletedEvent {
        ToolInstallationCompletedEvent {
            tool_name: tool_name.to_string(),
            success,
            message: message.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

// Frontend event listener helpers
// Note: Event listeners are typically set up in the frontend using Tauri's listen API