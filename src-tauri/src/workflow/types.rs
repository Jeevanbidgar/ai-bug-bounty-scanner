use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Unique identifier for workflow templates
pub type WorkflowId = String;

/// Unique identifier for workflow executions
pub type ExecutionId = Uuid;

/// Strongly typed workflow template model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTemplate {
    pub id: WorkflowId,
    pub name: String,
    pub description: String,
    pub category: WorkflowCategory,
    pub version: String,
    pub author: Option<String>,
    pub tags: Vec<String>,
    pub steps: Vec<WorkflowStep>,
    pub inputs: HashMap<String, InputDefinition>,
    pub outputs: HashMap<String, OutputDefinition>,
    pub compatibility: Option<WorkflowCompatibility>,
    pub metadata: WorkflowMetadata,
}

/// Categories of workflows
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkflowCategory {
    #[serde(rename = "reconnaissance")]
    Reconnaissance,
    #[serde(rename = "vulnerability")]
    Vulnerability,
    #[serde(rename = "web-application")]
    WebApplication,
    #[serde(rename = "network")]
    Network,
    #[serde(rename = "api")]
    Api,
    #[serde(rename = "comprehensive")]
    Comprehensive,
    #[serde(rename = "custom")]
    Custom,
}

/// Individual step in a workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub tool: String,
    pub argv: Vec<String>,
    pub needs: Vec<String>, // Step IDs that must complete before this step
    pub outputs: Vec<String>, // Output artifacts this step produces
    pub timeout_ms: Option<u64>,
    pub retry_count: Option<u32>,
    pub retry_delay_ms: Option<u64>,
    pub environment: HashMap<String, String>,
    pub cwd: Option<String>,
    pub continue_on_error: bool,
    pub condition: Option<String>, // Conditional expression for step execution
}

/// Input parameter definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDefinition {
    pub description: String,
    pub required: bool,
    pub default: Option<String>,
    pub validation: Option<InputValidation>,
}

/// Output artifact definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputDefinition {
    pub description: String,
    pub format: OutputFormat,
    pub required: bool,
}

/// Input validation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputValidation {
    pub pattern: Option<String>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub allowed_values: Option<Vec<String>>,
}

/// Supported output formats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OutputFormat {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "jsonl")]
    Jsonl,
    #[serde(rename = "xml")]
    Xml,
    #[serde(rename = "csv")]
    Csv,
    #[serde(rename = "txt")]
    Txt,
    #[serde(rename = "binary")]
    Binary,
}

/// Tool compatibility information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowCompatibility {
    pub compatible: bool,
    pub missing_tools: Vec<String>,
    pub version_requirements: HashMap<String, String>,
    pub warnings: Vec<String>,
}

/// Workflow metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowMetadata {
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub estimated_duration_minutes: Option<u32>,
    pub risk_level: RiskLevel,
    pub documentation_url: Option<String>,
}

/// Risk levels for workflows
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

/// Runtime workflow execution instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecution {
    pub id: ExecutionId,
    pub template_id: WorkflowId,
    pub name: String,
    pub status: ExecutionStatus,
    pub inputs: HashMap<String, String>,
    pub outputs: HashMap<String, ExecutionOutput>,
    pub step_states: HashMap<String, StepState>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub working_directory: String,
    pub current_step: Option<String>,
    pub progress: f32,
}

/// Execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExecutionStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "cancelled")]
    Cancelled,
    #[serde(rename = "paused")]
    Paused,
}

/// Individual step execution state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepState {
    pub step_id: String,
    pub status: StepStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub error_message: Option<String>,
    pub retry_count: u32,
    pub stdout_lines: Vec<String>,
    pub stderr_lines: Vec<String>,
    pub artifacts: Vec<ExecutionArtifact>,
}

/// Step execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StepStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "cancelled")]
    Cancelled,
    #[serde(rename = "skipped")]
    Skipped,
}

/// Execution artifact produced by a step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionArtifact {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub mime_type: Option<String>,
    pub checksum: Option<String>,
}

/// Execution output value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOutput {
    pub value: String,
    pub artifact_path: Option<String>,
    pub format: OutputFormat,
}

/// Workflow execution result summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub execution_id: ExecutionId,
    pub status: ExecutionStatus,
    pub duration_ms: Option<u64>,
    pub total_steps: usize,
    pub completed_steps: usize,
    pub failed_steps: usize,
    pub artifacts: Vec<ExecutionArtifact>,
    pub vulnerabilities_found: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
}

/// Scan model (replaces Python Scan model)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: String,
    pub name: String,
    pub target: String,
    pub status: ScanStatus,
    pub scan_type: String,
    pub workflow_id: Option<WorkflowId>,
    pub execution_id: Option<ExecutionId>,
    pub started: Option<DateTime<Utc>>,
    pub finished: Option<DateTime<Utc>>,
    pub duration: Option<String>,
    pub progress: f32,
    pub current_test: Option<String>,
    pub current_step: Option<u32>,
    pub total_steps: Option<u32>,
    pub vulnerabilities: Option<u32>,
    pub critical: Option<u32>,
    pub high: Option<u32>,
    pub medium: Option<u32>,
    pub low: Option<u32>,
    pub tags: Vec<String>,
    pub working_directory: Option<String>,
}

/// Scan status enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "cancelled")]
    Cancelled,
}

/// Tool information model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub path: String,
    pub version: Option<String>,
    pub description: String,
    pub category: ToolCategory,
    pub available: bool,
    pub last_checked: DateTime<Utc>,
}

/// Tool categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ToolCategory {
    #[serde(rename = "reconnaissance")]
    Reconnaissance,
    #[serde(rename = "scanning")]
    Scanning,
    #[serde(rename = "vulnerability")]
    Vulnerability,
    #[serde(rename = "exploitation")]
    Exploitation,
    #[serde(rename = "utility")]
    Utility,
}

/// Report model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: String,
    pub scan_id: String,
    pub title: String,
    pub format: ReportFormat,
    pub status: ReportStatus,
    pub generated_at: DateTime<Utc>,
    pub file_path: Option<String>,
    pub file_size: Option<u64>,
    pub summary: ReportSummary,
}

/// Report formats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReportFormat {
    #[serde(rename = "html")]
    Html,
    #[serde(rename = "pdf")]
    Pdf,
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "xml")]
    Xml,
    #[serde(rename = "markdown")]
    Markdown,
}

/// Report status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReportStatus {
    #[serde(rename = "generating")]
    Generating,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
}

/// Report summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_vulnerabilities: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub scan_duration: String,
    pub target: String,
    pub workflow_name: String,
    pub generated_by: String,
}

/// System health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub status: HealthStatus,
    pub version: String,
    pub uptime_seconds: u64,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f32,
    pub active_scans: u32,
    pub queued_scans: u32,
    pub database_connected: bool,
    pub tools_available: u32,
    pub tools_missing: u32,
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    #[serde(rename = "healthy")]
    Healthy,
    #[serde(rename = "degraded")]
    Degraded,
    #[serde(rename = "unhealthy")]
    Unhealthy,
}

/// System metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub timestamp: DateTime<Utc>,
    pub scans_today: u32,
    pub scans_this_week: u32,
    pub scans_this_month: u32,
    pub vulnerabilities_found_today: u32,
    pub average_scan_duration_minutes: f32,
    pub success_rate_percent: f32,
    pub tool_availability_percent: f32,
}