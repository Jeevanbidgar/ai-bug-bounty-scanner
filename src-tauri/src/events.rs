#![allow(dead_code)]
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tauri::Emitter;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainEvent {
    pub name: String,
    pub payload: Value,
}

/// Transport-neutral event target used by the workflow runtime. The runtime
/// must not know whether its consumer is a Tauri window, daemon socket, MCP
/// subscription, or a test collector.
pub trait EventSink: Send + Sync {
    fn emit_value(&self, event_name: &str, payload: Value) -> Result<(), String>;
}

#[derive(Clone)]
pub struct SharedEventSink(Arc<dyn EventSink>);

impl SharedEventSink {
    pub fn new(sink: impl EventSink + 'static) -> Self {
        Self(Arc::new(sink))
    }

    pub fn tauri(app_handle: tauri::AppHandle) -> Self {
        Self::new(TauriEventSink { app_handle })
    }

    pub fn noop() -> Self {
        Self::new(NoopEventSink)
    }

    pub fn channel(capacity: usize) -> (Self, broadcast::Receiver<DomainEvent>) {
        let (sink, sender) = Self::broadcast(capacity);
        let receiver = sender.subscribe();
        (sink, receiver)
    }

    pub fn broadcast(capacity: usize) -> (Self, broadcast::Sender<DomainEvent>) {
        let (sender, receiver) = broadcast::channel(capacity.max(16));
        drop(receiver);
        (
            Self::new(BroadcastEventSink {
                sender: sender.clone(),
            }),
            sender,
        )
    }

    pub fn emit<T: Serialize>(&self, event_name: &str, payload: T) -> Result<(), String> {
        let payload = serde_json::to_value(payload).map_err(|error| error.to_string())?;
        self.0.emit_value(event_name, payload)
    }
}

struct TauriEventSink {
    app_handle: tauri::AppHandle,
}

impl EventSink for TauriEventSink {
    fn emit_value(&self, event_name: &str, payload: Value) -> Result<(), String> {
        self.app_handle
            .emit(event_name, payload)
            .map_err(|error| error.to_string())
    }
}

struct BroadcastEventSink {
    sender: broadcast::Sender<DomainEvent>,
}

impl EventSink for BroadcastEventSink {
    fn emit_value(&self, event_name: &str, payload: Value) -> Result<(), String> {
        // A daemon can temporarily have no subscribed clients; absence of a
        // receiver must not fail or cancel the owned workflow.
        let _ = self.sender.send(DomainEvent {
            name: event_name.to_string(),
            payload,
        });
        Ok(())
    }
}

struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn emit_value(&self, _event_name: &str, _payload: Value) -> Result<(), String> {
        Ok(())
    }
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
pub const SCAN_CANCELLED: &str = "scan:cancelled";
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

    pub fn workflow_step_started(execution_id: &str, step_id: &str, step_name: &str) -> StepEvent {
        StepEvent {
            execution_id: execution_id.to_string(),
            step_id: step_id.to_string(),
            step_name: step_name.to_string(),
            exit_code: None,
            artifacts_count: None,
            error: None,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn workflow_step_completed(
        execution_id: &str,
        step_id: &str,
        step_name: &str,
        exit_code: i32,
        artifacts_count: usize,
    ) -> StepEvent {
        StepEvent {
            execution_id: execution_id.to_string(),
            step_id: step_id.to_string(),
            step_name: step_name.to_string(),
            exit_code: Some(exit_code),
            artifacts_count: Some(artifacts_count),
            error: None,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn workflow_step_failed(
        execution_id: &str,
        step_id: &str,
        step_name: &str,
        error: &str,
    ) -> StepEvent {
        StepEvent {
            execution_id: execution_id.to_string(),
            step_id: step_id.to_string(),
            step_name: step_name.to_string(),
            exit_code: None,
            artifacts_count: None,
            error: Some(error.to_string()),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn workflow_stdout(execution_id: &str, step_id: &str, line: &str) -> StreamEvent {
        StreamEvent {
            execution_id: execution_id.to_string(),
            step_id: step_id.to_string(),
            stream_type: "stdout".to_string(),
            line: line.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn workflow_stderr(execution_id: &str, step_id: &str, line: &str) -> StreamEvent {
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

    pub fn scan_cancelled(scan_id: &str) -> ScanEvent {
        ScanEvent {
            scan_id: scan_id.to_string(),
            status: "cancelled".to_string(),
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

#[cfg(test)]
mod sink_tests {
    use super::SharedEventSink;
    use serde_json::json;

    #[tokio::test]
    async fn channel_sink_preserves_event_name_and_payload() {
        let (sink, mut receiver) = SharedEventSink::channel(16);
        sink.emit("workflow:test", json!({ "executionId": "run-1" }))
            .unwrap();
        let event = receiver.recv().await.unwrap();
        assert_eq!(event.name, "workflow:test");
        assert_eq!(event.payload["executionId"], "run-1");
    }
}

// Frontend event listener helpers
// Note: Event listeners are typically set up in the frontend using Tauri's listen API
