use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
#[cfg(test)]
use std::path::Component;
use std::path::{Path, PathBuf};
use tauri::Emitter;

use crate::tools::catalog::ToolDefinition;

use crate::database::Database;
use crate::events::{
    EventEmitter, SCAN_COMPLETED, SCAN_FAILED, SCAN_PROGRESS_UPDATE, TOOL_INSTALLATION_COMPLETED,
    TOOL_INSTALLATION_STARTED,
};
use crate::governance::ScopeBudget;
use crate::runtime::process::hidden_tokio_command;
use crate::service::{CreateEngagementRequest, RunStatus, StartWorkflowRequest};
use crate::tools::catalog::get_tool_catalog;
use crate::tools::discovery::ToolDiscoveryService;
use crate::tools::package_managers::{GoInstallManager, InstallationResult, VersionCheckResult};
use crate::workflow::{loader::WorkflowLoader, types::WorkflowCompatibility};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowExecuteRequest {
    pub workflow_id: String,
    pub inputs: HashMap<String, String>,
    pub working_directory: Option<String>,
    pub scan_id: Option<String>,
    pub scan_name: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub authorization_confirmed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowExecuteResponse {
    pub execution_id: String,
    pub scan_id: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowStatusResponse {
    pub execution_id: String,
    pub status: String,
    pub progress: u32,
    pub current_step: Option<String>,
    pub logs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub category: String,
    pub available: bool,
    pub path: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolTestResult {
    pub tool_name: String,
    pub success: bool,
    pub path: String,
    pub output: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowSummary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub steps_count: usize,
    pub inputs: HashMap<String, String>,
    pub compatibility: Option<WorkflowCompatibility>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportView {
    pub id: String,
    pub scan_id: String,
    pub title: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub target: String,
    pub vulnerability_count: usize,
    pub format: String,
    pub severity: String,
    pub file_path: Option<String>,
    pub size_bytes: Option<i64>,
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

// App state structure
pub struct AppState {
    pub db: std::sync::Arc<Database>,
    pub tool_discovery: std::sync::Arc<tokio::sync::RwLock<ToolDiscoveryService>>,
    #[allow(dead_code)]
    pub tool_registry: std::sync::Arc<crate::tools::registry::ToolRegistry>,
    pub workflows_dir: std::path::PathBuf,
    pub results_dir: std::path::PathBuf,
    pub reports_dir: std::path::PathBuf,
    pub settings: std::sync::Arc<tokio::sync::RwLock<crate::settings::AppSettings>>,
    pub auto_adapters: std::sync::Arc<crate::adapters::auto::AutoAdapterService>,
}

#[cfg(test)]
fn ensure_workflow_compatible(
    workflow_id: &str,
    compatibility: &WorkflowCompatibility,
) -> Result<(), String> {
    if compatibility.compatible {
        return Ok(());
    }

    Err(format!(
        "Workflow '{}' cannot start because required tools are unavailable: {}. Install or register the missing tools, then refresh tool discovery.",
        workflow_id,
        compatibility.missing_tools.join(", ")
    ))
}

#[cfg(test)]
fn resolve_results_directory(
    results_root: &Path,
    requested_directory: Option<&str>,
) -> Result<String, String> {
    let requested = requested_directory
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(requested) = requested else {
        return Ok(results_root
            .join(uuid::Uuid::new_v4().to_string())
            .to_string_lossy()
            .to_string());
    };

    let requested_path = Path::new(requested);
    let resolved = if requested_path.is_absolute() {
        if !requested_path.starts_with(results_root) {
            return Err(format!(
                "Scan results must stay under {}",
                results_root.display()
            ));
        }
        requested_path.to_path_buf()
    } else {
        let mut safe_relative = PathBuf::new();
        for component in requested_path.components() {
            match component {
                Component::CurDir => {}
                Component::Normal(value) => safe_relative.push(value),
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err("Working directory cannot contain path traversal".to_string());
                }
            }
        }

        // Older frontend versions suggested ./results/<name>. Treat that as a
        // results-root-relative path instead of nesting results/results.
        let safe_relative = safe_relative
            .strip_prefix("results")
            .unwrap_or(&safe_relative)
            .to_path_buf();
        let safe_relative = if safe_relative.as_os_str().is_empty() {
            PathBuf::from(uuid::Uuid::new_v4().to_string())
        } else {
            safe_relative
        };
        results_root.join(safe_relative)
    };

    Ok(resolved.to_string_lossy().to_string())
}

async fn resolve_execution_id(db: &Database, execution_or_scan_id: &str) -> Result<String, String> {
    if db
        .get_workflow_execution(execution_or_scan_id)
        .await
        .map_err(|error| format!("Failed to find workflow execution: {}", error))?
        .is_some()
    {
        return Ok(execution_or_scan_id.to_string());
    }

    db.get_latest_workflow_execution_for_scan(execution_or_scan_id)
        .await
        .map_err(|error| format!("Failed to find scan execution: {}", error))?
        .map(|execution| execution.id)
        .ok_or_else(|| format!("Execution or scan '{}' not found", execution_or_scan_id))
}

async fn report_view(
    db: &Database,
    report: crate::database::Report,
    include_content: bool,
) -> Result<ReportView, String> {
    let scan = db
        .get_scan(&report.scan_id)
        .await
        .map_err(|error| format!("Failed to load report scan: {}", error))?
        .ok_or_else(|| format!("Scan '{}' for report was not found", report.scan_id))?;
    let findings = db
        .get_vulnerabilities_by_scan(&report.scan_id)
        .await
        .map_err(|error| format!("Failed to load report findings: {}", error))?;
    let export = db
        .get_report_export(&report.id)
        .await
        .map_err(|error| format!("Failed to load report export: {}", error))?;

    Ok(ReportView {
        id: report.id,
        scan_id: report.scan_id,
        title: report.title,
        created_at: report.created_at,
        target: scan.target,
        vulnerability_count: findings.len(),
        format: report.format,
        severity: crate::reports::highest_severity(&findings).to_string(),
        file_path: export.as_ref().map(|value| value.file_path.clone()),
        size_bytes: export.as_ref().map(|value| value.size_bytes),
        sha256: export.map(|value| value.sha256),
        content: include_content.then_some(report.content),
    })
}

fn confined_report_export_path(reports_root: &Path, path: &Path) -> Result<(), String> {
    if path.parent() != Some(reports_root) || !path.starts_with(reports_root) {
        return Err(
            "Stored report export path is outside the managed reports directory".to_string(),
        );
    }
    Ok(())
}

async fn canonical_managed_path(root: &Path, path: &Path) -> Result<PathBuf, String> {
    let canonical_root = tokio::fs::canonicalize(root)
        .await
        .map_err(|error| format!("Failed to resolve managed directory: {}", error))?;
    let canonical_path = tokio::fs::canonicalize(path)
        .await
        .map_err(|error| format!("Managed file or directory is unavailable: {}", error))?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err("Requested path is outside UniHack managed storage".to_string());
    }
    Ok(canonical_path)
}

async fn reveal_in_file_manager(path: &Path, select_file: bool) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = hidden_tokio_command("open");
        if select_file {
            command.arg("-R");
        }
        command.arg(path);
        command
    };

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = hidden_tokio_command("explorer.exe");
        if select_file {
            command.arg(format!("/select,{}", path.display()));
        } else {
            command.arg(path);
        }
        command
    };

    #[cfg(target_os = "linux")]
    let mut command = {
        let mut command = hidden_tokio_command("xdg-open");
        let destination = if select_file {
            path.parent().unwrap_or(path)
        } else {
            path
        };
        command.arg(destination);
        command
    };

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    return Err("Opening the system file manager is unsupported on this platform".to_string());

    let output = command
        .output()
        .await
        .map_err(|error| format!("Failed to open the system file manager: {}", error))?;
    if output.status.success() {
        Ok(())
    } else {
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "The system file manager could not open this location: {}",
            diagnostic.trim()
        ))
    }
}

// Commands for workflow management
#[tauri::command]
pub async fn load_workflow_templates(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<WorkflowSummary>, String> {
    let workflow_loader = WorkflowLoader::new(state.workflows_dir.clone());

    match workflow_loader.load_all_workflows().await {
        Ok(workflows) => {
            eprintln!("Successfully loaded {} workflows", workflows.len());
            let mut summaries = Vec::new();

            for (id, workflow) in workflows {
                eprintln!("Processing workflow: {} ({})", workflow.name, id);
                let discovery_service = state.tool_discovery.read().await;
                let compatibility = discovery_service
                    .get_tool_compatibility(&workflow)
                    .await
                    .map_err(|e| {
                        eprintln!("Failed to check compatibility for {}: {}", id, e);
                        format!("Failed to check compatibility: {}", e)
                    })?;
                drop(discovery_service);

                eprintln!(
                    "Workflow {} compatibility: {} ({}%)",
                    id, compatibility.compatible, compatibility.compatibility_percentage
                );

                summaries.push(WorkflowSummary {
                    id: id.clone(),
                    name: workflow.name,
                    description: workflow.description,
                    category: workflow.category,
                    steps_count: workflow.steps.len(),
                    inputs: workflow.inputs,
                    compatibility: Some(compatibility),
                });
            }

            eprintln!("Returning {} workflow summaries", summaries.len());
            Ok(summaries)
        }
        Err(e) => {
            eprintln!("Failed to load workflows: {}", e);
            Err(format!("Failed to load workflows: {}", e))
        }
    }
}

#[tauri::command]
pub async fn get_workflow_details(
    state: tauri::State<'_, AppState>,
    workflow_id: String,
) -> Result<serde_json::Value, String> {
    let workflow_loader = WorkflowLoader::new(state.workflows_dir.clone());

    match workflow_loader.load_workflow(&workflow_id).await {
        Ok(workflow) => {
            let discovery_service = state.tool_discovery.read().await;
            let compatibility = discovery_service
                .get_tool_compatibility(&workflow)
                .await
                .map_err(|e| format!("Failed to check compatibility: {}", e))?;
            drop(discovery_service);

            // Convert workflow steps to a serializable format
            let steps_json: Vec<serde_json::Value> = workflow
                .steps
                .iter()
                .map(|step| {
                    serde_json::json!({
                        "id": step.id,
                        "name": step.name,
                        "description": step.description,
                        "run": step.run,
                        "needs": step.needs,
                        "timeout": step.timeout,
                    })
                })
                .collect();

            let details = serde_json::json!({
                "id": workflow.id,
                "name": workflow.name,
                "description": workflow.description,
                "category": workflow.category,
                "inputs": workflow.inputs,
                "steps": steps_json,
                "compatibility": compatibility,
            });

            Ok(details)
        }
        Err(e) => Err(format!("Failed to load workflow details: {}", e)),
    }
}

async fn start_desktop_authorized_workflow(
    workflow_id: &str,
    target: &str,
    scan_id: Option<String>,
    scan_name: Option<String>,
    description: Option<String>,
) -> Result<WorkflowExecuteResponse, String> {
    let daemon = crate::integrations::desktop_daemon().await?;
    let workflow = daemon
        .get_workflow(workflow_id)
        .await
        .map_err(|error| format!("Failed to load workflow: {error}"))?;
    if !workflow.compatibility.compatible {
        return Err(format!(
            "Workflow '{}' cannot start because required tools are unavailable: {}",
            workflow_id,
            workflow.compatibility.missing_tools.join(", ")
        ));
    }
    let budget = ScopeBudget {
        max_executions: 1,
        ..ScopeBudget::default()
    };
    let duration_minutes = (budget.max_runtime_seconds.div_ceil(60) + 10).min(43_200) as u32;
    let scope = daemon
        .create_engagement(CreateEngagementRequest {
            name: format!("Desktop authorization · {}", workflow.workflow.name),
            targets: vec![target.to_string()],
            workflow_ids: vec![workflow_id.to_string()],
            allowed_risk_tier: workflow.risk_tier,
            duration_minutes,
            authorization_confirmed: true,
            budget,
        })
        .await
        .map_err(|error| format!("Failed to create one-shot authorization: {error}"))?;
    let accepted = match daemon
        .start_workflow(StartWorkflowRequest {
            scope_id: scope.id.clone(),
            workflow_id: workflow_id.to_string(),
            revision_hash: workflow.revision_hash,
            target: target.to_string(),
            idempotency_key: format!("desktop/{}", uuid::Uuid::new_v4()),
            scan_id,
            scan_name,
            description,
            revoke_scope_on_completion: true,
        })
        .await
    {
        Ok(accepted) => accepted,
        Err(error) => {
            let _ = daemon.revoke_engagement(&scope.id).await;
            return Err(format!("Failed to start workflow: {error}"));
        }
    };
    Ok(WorkflowExecuteResponse {
        execution_id: accepted.run_id,
        scan_id: accepted.scan_id,
        status: accepted.status,
        message: "Workflow execution started through unihackd".to_string(),
    })
}

fn workflow_status_response(status: RunStatus) -> WorkflowStatusResponse {
    WorkflowStatusResponse {
        execution_id: status.run_id,
        status: status.status,
        progress: status.progress,
        current_step: status.current_step,
        logs: status.logs,
    }
}

#[tauri::command]
pub async fn execute_workflow(
    _state: tauri::State<'_, AppState>,
    request: WorkflowExecuteRequest,
) -> Result<WorkflowExecuteResponse, String> {
    if !request.authorization_confirmed {
        return Err(
            "Authorization confirmation is required before running security tools".to_string(),
        );
    }

    let target = request
        .inputs
        .get("target")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "A non-empty target input is required".to_string())?
        .to_string();
    let target = crate::security::validate_scan_target(&target)?;
    let response = start_desktop_authorized_workflow(
        &request.workflow_id,
        &target,
        request.scan_id,
        request.scan_name,
        request.description,
    )
    .await?;

    Ok(response)
}

#[tauri::command]
pub async fn start_scan(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] scanId: String,
    #[allow(non_snake_case)] authorizationConfirmed: bool,
) -> Result<WorkflowExecuteResponse, String> {
    if !authorizationConfirmed {
        return Err(
            "Authorization confirmation is required before running security tools".to_string(),
        );
    }

    let scan = state
        .db
        .get_scan(&scanId)
        .await
        .map_err(|e| format!("Failed to load scan: {}", e))?
        .ok_or_else(|| format!("Scan '{}' not found", scanId))?;

    if scan.status.eq_ignore_ascii_case("running") {
        return Err("Scan is already running".to_string());
    }

    let target = crate::security::validate_scan_target(&scan.target)?;
    let workflow_id = scan
        .workflow_id
        .clone()
        .ok_or_else(|| "Scan has no workflow assigned".to_string())?;
    let response = start_desktop_authorized_workflow(
        &workflow_id,
        &target,
        Some(scan.id.clone()),
        Some(scan.name.clone()),
        scan.description.clone(),
    )
    .await?;

    Ok(response)
}

#[tauri::command]
pub async fn get_workflow_status(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] executionId: String,
) -> Result<WorkflowStatusResponse, String> {
    let resolved_execution_id = resolve_execution_id(&state.db, &executionId).await?;
    let status = crate::integrations::desktop_daemon()
        .await?
        .get_run_status(&resolved_execution_id)
        .await
        .map_err(|error| format!("Failed to get execution status: {error}"))?;
    Ok(workflow_status_response(status))
}

#[tauri::command]
pub async fn stop_workflow_execution(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] executionId: String,
) -> Result<String, String> {
    let resolved_execution_id = resolve_execution_id(&state.db, &executionId).await?;
    crate::integrations::desktop_daemon()
        .await?
        .cancel_run(&resolved_execution_id)
        .await
        .map_err(|e| format!("Failed to stop execution: {}", e))?;

    Ok("Execution stopped".to_string())
}

#[tauri::command]
pub async fn stop_scan(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] scanId: String,
) -> Result<String, String> {
    let execution = state
        .db
        .get_running_workflow_execution_for_scan(&scanId)
        .await
        .map_err(|e| format!("Failed to find running execution: {}", e))?
        .ok_or_else(|| format!("Scan '{}' has no running execution", scanId))?;

    crate::integrations::desktop_daemon()
        .await?
        .cancel_run(&execution.id)
        .await
        .map_err(|e| format!("Failed to stop scan: {}", e))?;

    Ok(execution.id)
}

// Commands for tool management
#[tauri::command]
pub async fn list_tools(
    #[allow(non_snake_case)] forceRefresh: bool,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<crate::tools::discovery::ToolRecord>, String> {
    let discovery_service = state.tool_discovery.read().await;

    let tools = discovery_service.get_all_tool_records(forceRefresh).await;

    eprintln!(
        "list_tools called: force_refresh={}, found {} tools",
        forceRefresh,
        tools.len()
    );
    if !tools.is_empty() {
        eprintln!(
            "First 5 tools: {:?}",
            tools.iter().take(5).map(|t| &t.name).collect::<Vec<_>>()
        );
    }

    Ok(tools)
}

#[tauri::command]
pub async fn get_tool(
    #[allow(non_snake_case)] tool_name: String,
    #[allow(non_snake_case)] forceRefresh: bool,
    state: tauri::State<'_, AppState>,
) -> Result<Option<crate::tools::discovery::ToolRecord>, String> {
    let discovery_service = state.tool_discovery.read().await;

    let tool = discovery_service
        .get_tool_record(&tool_name, forceRefresh)
        .await;

    Ok(tool)
}

#[tauri::command]
pub async fn test_tool(
    #[allow(non_snake_case)] tool_name: String,
    state: tauri::State<'_, AppState>,
) -> Result<ToolTestResult, String> {
    let catalog = get_tool_catalog();
    let definition = catalog
        .get(&tool_name)
        .ok_or_else(|| format!("Tool '{}' is not declared in the catalog", tool_name))?;
    let discovery = state.tool_discovery.read().await;
    let record = discovery
        .get_tool_record(&tool_name, true)
        .await
        .ok_or_else(|| format!("Tool '{}' was not found", tool_name))?;
    drop(discovery);
    if !record.installed || record.status != "available" {
        return Err(format!(
            "Tool '{}' is not available for a health check",
            tool_name
        ));
    }
    let path = record
        .path
        .ok_or_else(|| format!("Tool '{}' has no verified executable path", tool_name))?;
    let started = std::time::Instant::now();
    let mut command = hidden_tokio_command(&path);
    command.args(&definition.version_args);
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), command.output())
        .await
        .map_err(|_| format!("Health check for '{}' timed out", tool_name))?
        .map_err(|error| format!("Failed to run '{}': {}", tool_name, error))?;
    let mut combined = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        if !combined.is_empty() {
            combined.push('\n');
        }
        combined.push_str(&stderr);
    }
    if combined.chars().count() > 8_000 {
        combined = combined.chars().take(8_000).collect::<String>();
        combined.push_str("\n… output truncated");
    }

    Ok(ToolTestResult {
        tool_name,
        success: output.status.success(),
        path,
        output: combined,
        exit_code: output.status.code(),
        duration_ms: started.elapsed().as_millis(),
    })
}

#[tauri::command]
pub async fn recheck_tool(
    #[allow(non_snake_case)] tool_name: String,
    state: tauri::State<'_, AppState>,
) -> Result<Option<crate::tools::discovery::ToolRecord>, String> {
    eprintln!("🔄 Rechecking tool: {}", tool_name);
    let discovery_service = state.tool_discovery.read().await;
    let record = discovery_service.get_tool_record(&tool_name, true).await;
    drop(discovery_service);
    if let Some(record) = &record {
        if let Err(error) = state.auto_adapters.ensure_profile(record).await {
            eprintln!(
                "Auto-adapter generation for '{}' requires attention: {}",
                tool_name, error
            );
        }
    }
    Ok(record)
}

#[tauri::command]
pub async fn refresh_tools(
    state: tauri::State<'_, AppState>,
) -> Result<HashMap<String, crate::tools::discovery::ToolRecord>, String> {
    let discovery_service = state.tool_discovery.read().await;

    let results = discovery_service.refresh_all_tools().await;
    drop(discovery_service);

    let failures = state
        .auto_adapters
        .sync_installed_tools(results.values().cloned())
        .await;
    for failure in failures {
        eprintln!("Auto-adapter generation requires attention: {}", failure);
    }

    Ok(results)
}

#[tauri::command]
pub async fn get_tool_categories(state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
    let discovery_service = state.tool_discovery.read().await;

    let categories = discovery_service.get_categories();

    Ok(categories)
}

#[tauri::command]
pub async fn get_tools_by_category(
    category: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<crate::tools::discovery::ToolRecord>, String> {
    let discovery_service = state.tool_discovery.read().await;

    let tools = discovery_service.get_tools_by_category(&category).await;

    Ok(tools)
}

#[tauri::command]
pub async fn add_manual_tool(
    #[allow(non_snake_case)] tool_name: String,
    #[allow(non_snake_case)] toolPath: String,
    category: String,
    state: tauri::State<'_, AppState>,
) -> Result<crate::tools::discovery::ToolRecord, String> {
    let discovery_service = state.tool_discovery.write().await;

    let tool = discovery_service
        .add_manual_tool(&tool_name, &toolPath, &category)
        .await
        .map_err(|e| format!("Failed to add manual tool: {}", e))?;

    Ok(tool)
}

#[tauri::command]
pub async fn remove_manual_tool(
    #[allow(non_snake_case)] tool_name: String,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    let discovery_service = state.tool_discovery.write().await;

    let success = discovery_service
        .remove_manual_tool(&tool_name)
        .await
        .map_err(|e| format!("Failed to remove manual tool: {}", e))?;

    Ok(success)
}

#[tauri::command]
pub async fn list_manual_tools(state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
    let discovery_service = state.tool_discovery.read().await;

    let manual_tools = discovery_service.list_manual_tools();

    Ok(manual_tools)
}

#[tauri::command]
pub async fn get_available_tools_count(state: tauri::State<'_, AppState>) -> Result<usize, String> {
    let discovery_service = state.tool_discovery.read().await;

    let count = discovery_service.get_available_count().await;

    Ok(count)
}

// Commands for scan management
#[tauri::command]
pub async fn list_scans(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<serde_json::Value>, String> {
    let scans = state
        .db
        .list_scans()
        .await
        .map_err(|e| format!("Failed to list scans: {}", e))?;

    let mut scan_data = Vec::new();
    for scan in scans {
        scan_data.push(serde_json::to_value(&scan).unwrap_or_default());
    }

    Ok(scan_data)
}

#[tauri::command]
pub async fn create_scan(
    state: tauri::State<'_, AppState>,
    scan_data: HashMap<String, serde_json::Value>,
) -> Result<String, String> {
    // Extract required fields
    let name = scan_data
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Unnamed Scan")
        .to_string();

    let target = scan_data
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("Target is required")?
        .to_string();

    let scan_type = scan_data
        .get("scan_type")
        .and_then(|v| v.as_str())
        .unwrap_or("Custom Scan")
        .to_string();

    let workflow_id = scan_data
        .get("workflow_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let description = scan_data
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let working_directory = scan_data
        .get("working_directory")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Create scan object
    let scan = crate::database::Scan {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        target,
        status: "pending".to_string(),
        scan_type,
        workflow_id,
        started: chrono::Utc::now(),
        completed: None,
        progress: 0,
        current_test: None,
        current_step: None,
        total_steps: None,
        duration: None,
        estimated_time: None,
        description,
        tags: None,
        working_directory,
        agents: None,
        command_log: None,
        target_validated: false,
        vulnerabilities: None,
        critical: None,
        high: None,
        medium: None,
        low: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    state
        .db
        .create_scan(&scan)
        .await
        .map_err(|e| format!("Failed to create scan: {}", e))?;

    Ok(scan.id)
}

#[tauri::command]
pub async fn get_scan(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] scanId: String,
) -> Result<Option<serde_json::Value>, String> {
    let scan = state
        .db
        .get_scan(&scanId)
        .await
        .map_err(|e| format!("Failed to get scan: {}", e))?;

    if let Some(scan) = scan {
        Ok(Some(serde_json::to_value(&scan).unwrap_or_default()))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub async fn update_scan(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    scan: crate::database::Scan,
) -> Result<(), String> {
    // Store old status for comparison
    let old_scan = state
        .db
        .get_scan(&scan.id)
        .await
        .map_err(|e| format!("Failed to get scan: {}", e))?;

    state
        .db
        .update_scan(&scan)
        .await
        .map_err(|e| format!("Failed to update scan: {}", e))?;

    // Emit events based on status changes
    if let Some(old) = old_scan {
        if old.status != scan.status {
            match scan.status.as_str() {
                "completed" => {
                    let event = EventEmitter::scan_completed(&scan.id);
                    let _ = app.emit(SCAN_COMPLETED, event);
                }
                "failed" => {
                    let event = EventEmitter::scan_failed(&scan.id);
                    let _ = app.emit(SCAN_FAILED, event);
                }
                _ => {}
            }
        }

        // Emit progress update if progress changed
        if old.progress != scan.progress {
            let event = EventEmitter::scan_progress_update(
                &scan.id,
                scan.progress,
                scan.current_test.clone(),
                &scan.status,
            );
            let _ = app.emit(SCAN_PROGRESS_UPDATE, event);
        }
    }

    Ok(())
}

#[tauri::command]
pub async fn delete_scan(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] scanId: String,
) -> Result<(), String> {
    let scan = state
        .db
        .get_scan(&scanId)
        .await
        .map_err(|error| format!("Failed to load scan: {}", error))?
        .ok_or_else(|| format!("Scan '{}' was not found", scanId))?;
    if scan.status.eq_ignore_ascii_case("running") {
        return Err("Stop the running scan before deleting it".to_string());
    }

    let mut report_exports = Vec::new();
    let reports = state
        .db
        .list_reports()
        .await
        .map_err(|error| format!("Failed to load scan reports: {}", error))?;
    for report in reports
        .into_iter()
        .filter(|report| report.scan_id == scanId)
    {
        if let Some(export) = state
            .db
            .get_report_export(&report.id)
            .await
            .map_err(|error| format!("Failed to load report export: {}", error))?
        {
            let path = PathBuf::from(export.file_path);
            confined_report_export_path(&state.reports_dir, &path)?;
            report_exports.push(path);
        }
    }

    state
        .db
        .delete_scan(&scanId)
        .await
        .map_err(|e| format!("Failed to delete scan: {}", e))?;

    for export_path in report_exports {
        match tokio::fs::remove_file(&export_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => eprintln!(
                "Warning: failed to remove deleted scan report {}: {}",
                export_path.display(),
                error
            ),
        }
    }

    Ok(())
}

// Commands for system information
#[tauri::command]
pub async fn get_system_info() -> Result<serde_json::Value, String> {
    use sysinfo::{ProcessExt, System, SystemExt};

    let mut sys = System::new_all();
    sys.refresh_all();
    let current_pid = sysinfo::get_current_pid().ok();
    if let Some(pid) = current_pid {
        // sysinfo CPU values need two samples separated by its minimum update
        // interval. The async wait keeps this measurement honest without
        // blocking the Tauri runtime thread.
        tokio::time::sleep(System::MINIMUM_CPU_UPDATE_INTERVAL).await;
        sys.refresh_process(pid);
    }
    let process = current_pid.and_then(|pid| sys.process(pid));

    let info = serde_json::json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "total_memory_mb": sys.total_memory() / 1024 / 1024,
        "available_memory_mb": sys.available_memory() / 1024 / 1024,
        "cpu_cores": sys.cpus().len(),
        "process_memory_mb": process.map(|value| value.memory() / 1024 / 1024).unwrap_or(0),
        "process_cpu_percent": process.map(|value| value.cpu_usage()).unwrap_or(0.0)
    });

    Ok(info)
}

#[tauri::command]
pub async fn get_settings(
    state: tauri::State<'_, AppState>,
) -> Result<crate::settings::AppSettings, String> {
    Ok(state.settings.read().await.clone())
}

#[tauri::command]
pub async fn update_settings(
    state: tauri::State<'_, AppState>,
    settings: crate::settings::AppSettings,
) -> Result<crate::settings::AppSettings, String> {
    settings.validate()?;
    let serialized = serde_json::to_string(&settings)
        .map_err(|error| format!("Failed to serialize settings: {}", error))?;
    state
        .db
        .upsert_setting("runtime", &serialized)
        .await
        .map_err(|error| format!("Failed to save settings: {}", error))?;
    *state.settings.write().await = settings.clone();
    Ok(settings)
}

// Commands for workflow artifacts and findings
#[tauri::command]
pub async fn get_workflow_artifacts(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] executionId: String,
) -> Result<Vec<serde_json::Value>, String> {
    let execution_id = resolve_execution_id(&state.db, &executionId).await?;
    let artifacts = state
        .db
        .get_workflow_artifacts(&execution_id)
        .await
        .map_err(|e| format!("Failed to get artifacts: {}", e))?;

    let mut artifact_data = Vec::new();
    for artifact in artifacts {
        artifact_data.push(serde_json::to_value(&artifact).unwrap_or_default());
    }

    Ok(artifact_data)
}

#[tauri::command]
pub async fn reveal_workflow_artifact(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] executionId: String,
    #[allow(non_snake_case)] artifactId: String,
) -> Result<(), String> {
    let execution_id = resolve_execution_id(&state.db, &executionId).await?;
    let artifact = state
        .db
        .get_workflow_artifacts(&execution_id)
        .await
        .map_err(|error| format!("Failed to load artifacts: {}", error))?
        .into_iter()
        .find(|artifact| artifact.id == artifactId)
        .ok_or_else(|| format!("Artifact '{}' was not found", artifactId))?;
    let path = artifact
        .file_path
        .as_deref()
        .map(Path::new)
        .ok_or_else(|| "Artifact has no managed file".to_string())?;
    let path = canonical_managed_path(&state.results_dir, path).await?;
    reveal_in_file_manager(&path, true).await
}

#[tauri::command]
pub async fn reveal_scan_results(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] scanId: String,
) -> Result<(), String> {
    let scan = state
        .db
        .get_scan(&scanId)
        .await
        .map_err(|error| format!("Failed to load scan: {}", error))?
        .ok_or_else(|| format!("Scan '{}' was not found", scanId))?;
    let path = scan
        .working_directory
        .as_deref()
        .map(Path::new)
        .ok_or_else(|| "Scan has no results directory".to_string())?;
    let path = canonical_managed_path(&state.results_dir, path).await?;
    reveal_in_file_manager(&path, false).await
}

#[tauri::command]
pub async fn get_workflow_findings(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] executionId: String,
) -> Result<Vec<serde_json::Value>, String> {
    let execution_id = resolve_execution_id(&state.db, &executionId).await?;
    let findings = state
        .db
        .get_workflow_findings(&execution_id)
        .await
        .map_err(|e| format!("Failed to get findings: {}", e))?;

    let mut finding_data = Vec::new();
    for finding in findings {
        finding_data.push(serde_json::to_value(&finding).unwrap_or_default());
    }

    Ok(finding_data)
}

// Commands for vulnerability management
#[tauri::command]
pub async fn list_vulnerabilities(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<serde_json::Value>, String> {
    let vulns = state
        .db
        .list_vulnerabilities()
        .await
        .map_err(|e| format!("Failed to list vulnerabilities: {}", e))?;

    let mut vuln_data = Vec::new();
    for vuln in vulns {
        vuln_data.push(serde_json::to_value(&vuln).unwrap_or_default());
    }

    Ok(vuln_data)
}

#[tauri::command]
pub async fn get_scan_vulnerabilities(
    state: tauri::State<'_, AppState>,
    scan_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let vulns = state
        .db
        .get_vulnerabilities_by_scan(&scan_id)
        .await
        .map_err(|e| format!("Failed to get vulnerabilities: {}", e))?;

    let mut vuln_data = Vec::new();
    for vuln in vulns {
        vuln_data.push(serde_json::to_value(&vuln).unwrap_or_default());
    }

    Ok(vuln_data)
}

#[tauri::command]
pub async fn create_vulnerability(
    state: tauri::State<'_, AppState>,
    vuln_data: HashMap<String, serde_json::Value>,
) -> Result<String, String> {
    let vuln = crate::database::Vulnerability {
        id: uuid::Uuid::new_v4().to_string(),
        scan_id: vuln_data
            .get("scan_id")
            .and_then(|v| v.as_str())
            .ok_or("scan_id is required")?
            .to_string(),
        title: vuln_data
            .get("title")
            .and_then(|v| v.as_str())
            .ok_or("title is required")?
            .to_string(),
        severity: vuln_data
            .get("severity")
            .and_then(|v| v.as_str())
            .ok_or("severity is required")?
            .to_string(),
        cvss: vuln_data.get("cvss").and_then(|v| v.as_f64()),
        description: vuln_data
            .get("description")
            .and_then(|v| v.as_str())
            .ok_or("description is required")?
            .to_string(),
        url: vuln_data
            .get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        parameter: vuln_data
            .get("parameter")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        payload: vuln_data
            .get("payload")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        remediation: vuln_data
            .get("remediation")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        discovered_by: vuln_data
            .get("discovered_by")
            .and_then(|v| v.as_str())
            .ok_or("discovered_by is required")?
            .to_string(),
        timestamp: chrono::Utc::now(),
        false_positive: vuln_data
            .get("false_positive")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        confirmed: vuln_data
            .get("confirmed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        evidence: vuln_data
            .get("evidence")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    };

    state
        .db
        .create_vulnerability(&vuln)
        .await
        .map_err(|e| format!("Failed to create vulnerability: {}", e))?;

    Ok(vuln.id)
}

#[tauri::command]
pub async fn delete_vulnerability(
    state: tauri::State<'_, AppState>,
    vuln_id: String,
) -> Result<(), String> {
    state
        .db
        .delete_vulnerability(&vuln_id)
        .await
        .map_err(|e| format!("Failed to delete vulnerability: {}", e))?;

    Ok(())
}

// Commands for report management
#[tauri::command]
pub async fn list_reports(state: tauri::State<'_, AppState>) -> Result<Vec<ReportView>, String> {
    let reports = state
        .db
        .list_reports()
        .await
        .map_err(|e| format!("Failed to list reports: {}", e))?;

    let mut report_data = Vec::with_capacity(reports.len());
    for report in reports {
        report_data.push(report_view(&state.db, report, false).await?);
    }

    Ok(report_data)
}

#[tauri::command]
pub async fn get_report(
    state: tauri::State<'_, AppState>,
    report_id: String,
) -> Result<Option<ReportView>, String> {
    let report = state
        .db
        .get_report(&report_id)
        .await
        .map_err(|e| format!("Failed to get report: {}", e))?;

    match report {
        Some(report) => Ok(Some(report_view(&state.db, report, true).await?)),
        None => Ok(None),
    }
}

#[tauri::command]
pub async fn reveal_report(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] reportId: String,
) -> Result<(), String> {
    let export = state
        .db
        .get_report_export(&reportId)
        .await
        .map_err(|error| format!("Failed to load report export: {}", error))?
        .ok_or_else(|| format!("Report export '{}' was not found", reportId))?;
    let path = Path::new(&export.file_path);
    confined_report_export_path(&state.reports_dir, path)?;
    let path = canonical_managed_path(&state.reports_dir, path).await?;
    reveal_in_file_manager(&path, true).await
}

#[tauri::command]
pub async fn create_report(
    state: tauri::State<'_, AppState>,
    report_data: HashMap<String, serde_json::Value>,
) -> Result<ReportView, String> {
    let scan_id = report_data
        .get("scan_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or("scan_id is required")?
        .to_string();
    let scan = state
        .db
        .get_scan(&scan_id)
        .await
        .map_err(|error| format!("Failed to load scan: {}", error))?
        .ok_or_else(|| format!("Scan '{}' not found", scan_id))?;
    let findings = state
        .db
        .get_vulnerabilities_by_scan(&scan_id)
        .await
        .map_err(|error| format!("Failed to load scan findings: {}", error))?;
    let format = report_data
        .get("format")
        .and_then(|value| value.as_str())
        .unwrap_or("html")
        .trim()
        .to_ascii_lowercase();
    let extension = crate::reports::extension(&format).map_err(|error| error.to_string())?;
    let content = crate::reports::generate_report(&format, &scan, &findings)
        .map_err(|error| format!("Failed to generate report: {}", error))?;
    let title = report_data
        .get("title")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{} Security Report", scan.name));
    if title.chars().count() > 200 {
        return Err("Report title must not exceed 200 characters".to_string());
    }

    let report = crate::database::Report {
        id: uuid::Uuid::new_v4().to_string(),
        scan_id,
        title,
        content,
        format,
        created_at: chrono::Utc::now(),
    };

    let export_path = state
        .reports_dir
        .join(format!("{}.{}", report.id, extension));
    confined_report_export_path(&state.reports_dir, &export_path)?;
    tokio::fs::write(&export_path, report.content.as_bytes())
        .await
        .map_err(|error| format!("Failed to write report export: {}", error))?;
    let export = crate::database::ReportExport {
        report_id: report.id.clone(),
        file_path: export_path.to_string_lossy().to_string(),
        size_bytes: report.content.len() as i64,
        sha256: format!("{:x}", Sha256::digest(report.content.as_bytes())),
        created_at: chrono::Utc::now(),
    };

    if let Err(error) = state.db.create_report(&report).await {
        let _ = tokio::fs::remove_file(&export_path).await;
        return Err(format!("Failed to create report: {}", error));
    }
    if let Err(error) = state.db.create_report_export(&export).await {
        let _ = state.db.delete_report(&report.id).await;
        let _ = tokio::fs::remove_file(&export_path).await;
        return Err(format!("Failed to store report export: {}", error));
    }

    report_view(&state.db, report, true).await
}

#[tauri::command]
pub async fn delete_report(
    state: tauri::State<'_, AppState>,
    report_id: String,
) -> Result<(), String> {
    let export = state
        .db
        .get_report_export(&report_id)
        .await
        .map_err(|error| format!("Failed to load report export: {}", error))?;
    if let Some(export) = export {
        let export_path = Path::new(&export.file_path);
        confined_report_export_path(&state.reports_dir, export_path)?;
        match tokio::fs::remove_file(export_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Failed to remove report export: {}", error)),
        }
    }
    state
        .db
        .delete_report(&report_id)
        .await
        .map_err(|e| format!("Failed to delete report: {}", e))?;

    Ok(())
}

// Commands for statistics
#[tauri::command]
pub async fn get_stats(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let scans = state
        .db
        .list_scans()
        .await
        .map_err(|e| format!("Failed to get scans: {}", e))?;
    let vulns = state
        .db
        .list_vulnerabilities()
        .await
        .map_err(|e| format!("Failed to get vulnerabilities: {}", e))?;

    let discovery_service = state.tool_discovery.read().await;
    let tools = discovery_service.get_all_tool_records(false).await;

    let active_scans = scans.iter().filter(|s| s.status == "running").count();
    let critical_vulns = vulns
        .iter()
        .filter(|v| v.severity.to_lowercase() == "critical")
        .count();
    let available_tools = tools.iter().filter(|t| t.installed).count();

    let stats = serde_json::json!({
        "totalScans": scans.len(),
        "activeScans": active_scans,
        "vulnerabilitiesFound": vulns.len(),
        "criticalIssues": critical_vulns,
        "toolsAvailable": available_tools,
        "systemHealth": "healthy"
    });

    Ok(stats)
}

#[tauri::command]
pub async fn get_system_metrics(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let scans = state
        .db
        .list_scans()
        .await
        .map_err(|e| format!("Failed to get scans: {}", e))?;
    let vulns = state
        .db
        .list_vulnerabilities()
        .await
        .map_err(|e| format!("Failed to get vulnerabilities: {}", e))?;

    let discovery_service = state.tool_discovery.read().await;
    let tools = discovery_service.get_all_tool_records(false).await;

    let total_scans = scans.len();
    let active_scans = scans.iter().filter(|s| s.status == "running").count();
    let completed_scans = scans.iter().filter(|s| s.status == "completed").count();
    let total_vulnerabilities = vulns.len();
    let critical_issues = vulns
        .iter()
        .filter(|v| v.severity.to_lowercase() == "critical")
        .count();
    let tools_available = tools.iter().filter(|t| t.installed).count();
    let tools_total = tools.len();
    let tools_unavailable = tools_total - tools_available;

    // Determine system health based on multiple factors
    let system_health = if tools_available >= tools_total / 2 && active_scans < 10 {
        "healthy"
    } else if tools_available >= tools_total / 3 && active_scans < 20 {
        "warning"
    } else {
        "degraded"
    };

    let metrics = serde_json::json!({
        "total_scans": total_scans,
        "active_scans": active_scans,
        "completed_scans": completed_scans,
        "total_vulnerabilities": total_vulnerabilities,
        "critical_issues": critical_issues,
        "tools_available": tools_available,
        "tools_total": tools_total,
        "tools_unavailable": tools_unavailable,
        "system_health": system_health,
        "health_details": {
            "scan_capacity": if active_scans < 10 { "good" } else { "limited" },
            "tool_availability": if tools_available >= tools_total / 2 { "good" } else { "poor" },
            "database": "connected"
        }
    });

    Ok(metrics)
}

#[tauri::command]
pub fn get_os_info() -> Result<serde_json::Value, String> {
    let os_type = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    };

    let os_info = serde_json::json!({
        "platform": os_type,
        "arch": std::env::consts::ARCH,
    });

    Ok(os_info)
}

// Package manager detection commands
#[tauri::command]
pub async fn detect_package_managers(
) -> Result<Vec<crate::tools::package_managers::PackageManagerInfo>, String> {
    eprintln!("🔍 Detecting available package managers...");

    let managers = crate::tools::package_managers::detect_all_managers().await;

    eprintln!("✅ Detection complete:");
    for manager in &managers {
        if manager.available {
            eprintln!(
                "  ✓ {} - v{}",
                manager.manager_type.display_name(),
                manager.version.as_ref().unwrap_or(&"unknown".to_string())
            );
        } else {
            eprintln!(
                "  ✗ {} - {}",
                manager.manager_type.display_name(),
                manager.error.as_ref().unwrap_or(&"not found".to_string())
            );
        }
    }

    Ok(managers)
}

#[tauri::command]
pub async fn check_package_manager(
    manager_name: String,
) -> Result<crate::tools::package_managers::PackageManagerInfo, String> {
    eprintln!("🔍 Checking package manager: {}", manager_name);

    let manager_type = match manager_name.to_lowercase().as_str() {
        "go" => crate::tools::package_managers::PackageManagerType::Go,
        "pipx" => crate::tools::package_managers::PackageManagerType::Pipx,
        "apt" => crate::tools::package_managers::PackageManagerType::Apt,
        "winget" => crate::tools::package_managers::PackageManagerType::WinGet,
        _ => return Err(format!("Unknown package manager: {}", manager_name)),
    };

    let info = crate::tools::package_managers::detect_manager(manager_type).await;

    if info.available {
        eprintln!(
            "✅ {} is available (v{})",
            info.manager_type.display_name(),
            info.version.as_ref().unwrap_or(&"unknown".to_string())
        );
    } else {
        eprintln!(
            "❌ {} is not available: {}",
            info.manager_type.display_name(),
            info.error.as_ref().unwrap_or(&"not found".to_string())
        );
    }

    Ok(info)
}

// Package Manager Installation Commands

#[tauri::command]
pub async fn install_package_manager_pipx(
) -> Result<crate::tools::package_managers::InstallationResult, String> {
    eprintln!("📦 Installing pipx...");
    let result = crate::tools::package_managers::install_pipx().await?;

    if result.success {
        eprintln!("✅ pipx installation completed");
    } else {
        eprintln!("❌ pipx installation failed: {}", result.message);
    }

    Ok(result)
}

#[tauri::command]
pub async fn install_package_manager_go(
) -> Result<crate::tools::package_managers::InstallationResult, String> {
    eprintln!("📦 Installing Go...");

    #[cfg(target_os = "windows")]
    {
        let result = crate::tools::package_managers::install_go_windows().await?;

        if result.success {
            eprintln!("✅ Go installation completed");
        } else {
            eprintln!("❌ Go installation failed: {}", result.message);
        }

        Ok(result)
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err(
            "Go installation on Linux should be done via APT. Use: sudo apt install golang-go"
                .to_string(),
        )
    }
}

#[tauri::command]
pub async fn install_package_manager_winget(
) -> Result<crate::tools::package_managers::InstallationResult, String> {
    eprintln!("📦 Opening WinGet installation page...");

    #[cfg(target_os = "windows")]
    {
        let result = crate::tools::package_managers::install_winget_windows().await?;

        if result.success {
            eprintln!("✅ Microsoft Store opened");
        } else {
            eprintln!("❌ Failed to open Store: {}", result.message);
        }

        Ok(result)
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("WinGet is only available on Windows systems".to_string())
    }
}

// Tool Installation Commands (Phase 7)

#[tauri::command]
pub async fn install_tool_with_method(
    #[allow(non_snake_case)] tool_name: String,
    #[allow(non_snake_case)] installMethod: String,
    app_handle: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<InstallationResult, String> {
    eprintln!("📦 Installing tool: {} via {}", tool_name, installMethod);

    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog
        .get(&tool_name)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", tool_name))?;
    let install_method = installMethod.trim().to_ascii_lowercase();
    let approved_methods = tool_def.install_methods_for(
        &tool_name,
        crate::tools::catalog::InstallPlatform::current(),
    );
    if !approved_methods.contains(&install_method) {
        return Err(format!(
            "Installation method '{}' is not approved for '{}' on this operating system. Available methods: {}",
            install_method,
            tool_name,
            approved_methods.join(", ")
        ));
    }

    eprintln!("   Installation method: {}", install_method);

    // Route to appropriate installer
    install_tool_internal(&tool_name, tool_def, &install_method, app_handle, state).await
}

#[tauri::command]
pub async fn install_tool(
    #[allow(non_snake_case)] tool_name: String,
    app_handle: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<InstallationResult, String> {
    eprintln!("📦 Installing tool: {}", tool_name);

    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog
        .get(&tool_name)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", tool_name))?;

    let resolved_method = resolve_install_method(&tool_name, tool_def);
    eprintln!("   Installation method: {}", resolved_method);

    // Route to appropriate installer
    install_tool_internal(&tool_name, tool_def, &resolved_method, app_handle, state).await
}

fn resolve_install_method(tool_name: &str, tool_def: &ToolDefinition) -> String {
    tool_def
        .recommended_install_method(tool_name, crate::tools::catalog::InstallPlatform::current())
        .unwrap_or_else(|| tool_def.install_method.clone())
}

async fn install_tool_internal(
    tool_name: &str,
    tool_def: &ToolDefinition,
    install_method: &str,
    app_handle: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<InstallationResult, String> {
    // Route to appropriate installer based on install_method
    match install_method {
        "go" => {
            // Install via Go
            let go_module = tool_def.go_module.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no go_module defined", tool_name))?;

            eprintln!("   Go module: {}", go_module);

            // Emit installation started event
            let started_event = EventEmitter::tool_installation_started(tool_name, "go");
            let _ = app_handle.emit(TOOL_INSTALLATION_STARTED, started_event);

            let manager = GoInstallManager::new(app_handle.clone());

            if !manager.is_go_available().await {
                // Emit failure event
                let completed_event = EventEmitter::tool_installation_completed(
                    tool_name,
                    false,
                    "Go is not installed. Please install Go first."
                );
                let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);
                return Err("Go is not installed. Please install Go first.".to_string());
            }

            let go_result = manager.install(go_module, tool_name).await?;

            if go_result.success {
                eprintln!("✅ Successfully installed {}", tool_name);

                // Trigger tool recheck to update UI
                let _ = recheck_tool(tool_name.to_string(), state).await;

                // Emit installation completed event
                let completed_event = EventEmitter::tool_installation_completed(
                    tool_name,
                    true,
                    &go_result.message
                );
                let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);
            } else {
                eprintln!("❌ Failed to install {}: {}", tool_name, go_result.message);

                // Emit installation failed event
                let completed_event = EventEmitter::tool_installation_completed(
                    tool_name,
                    false,
                    &go_result.message
                );
                let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);
            }

            // Convert go_install::InstallationResult to installation::InstallationResult
            Ok(InstallationResult {
                success: go_result.success,
                message: go_result.message,
                steps: vec![],
                requires_restart: false,
            })
        },
        "pipx" => {
            // pipx can install from PyPI packages or git repositories
            let package_or_repo = if let Some(pipx_pkg) = tool_def.pipx_package.as_ref() {
                pipx_pkg.clone()
            } else if let Some(git_repo) = tool_def.git_repo.as_ref() {
                // Use git+repo format for pipx
                format!("git+{}", git_repo)
            } else {
                return Err(format!("Tool '{}' has no pipx_package or git_repo defined", tool_name));
            };

            eprintln!("   Pipx package/repo: {}", package_or_repo);

            let manager = crate::tools::package_managers::PipxManager::new();

            if !manager.is_pipx_available().await {
                return Err("pipx is not installed. Please install pipx first.".to_string());
            }

            let pipx_result = manager
                .install(&package_or_repo, tool_name, Some(&app_handle))
                .await?;

            if pipx_result.success {
                eprintln!("✅ Successfully installed {}", tool_name);
                let _ = recheck_tool(tool_name.to_string(), state).await;
            } else {
                eprintln!("❌ Failed to install {}: {}", tool_name, pipx_result.message);
            }

            Ok(InstallationResult {
                success: pipx_result.success,
                message: pipx_result.message,
                steps: vec![],
                requires_restart: false,
            })
        },
        "apt" => {
            let apt_package = tool_def.apt_package.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no apt_package defined", tool_name))?;

            eprintln!("   APT package: {}", apt_package);

            let manager = crate::tools::package_managers::AptManager::new(app_handle.clone());
            let started_event = EventEmitter::tool_installation_started(tool_name, "apt");
            let _ = app_handle.emit(TOOL_INSTALLATION_STARTED, started_event);

            match manager.install(apt_package, tool_name).await {
                Ok(message) => {
                    eprintln!("✅ Successfully installed {}", tool_name);
                    let _ = recheck_tool(tool_name.to_string(), state).await;

                    let completed_event = EventEmitter::tool_installation_completed(tool_name, true, &message);
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Ok(InstallationResult {
                        success: true,
                        message,
                        steps: vec![],
                        requires_restart: false,
                    })
                }
                Err(e) => {
                    let error_msg = format!("Failed to install {}: {}", tool_name, e);
                    eprintln!("❌ {}", error_msg);

                    let completed_event = EventEmitter::tool_installation_completed(tool_name, false, &error_msg);
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Err(error_msg)
                }
            }
        },
        "winget" => {
            let winget_id = tool_def.winget_id.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no winget_id defined", tool_name))?;

            eprintln!("   WinGet ID: {}", winget_id);

            let manager = crate::tools::package_managers::WingetManager::new(app_handle.clone());
            let started_event = EventEmitter::tool_installation_started(tool_name, "winget");
            let _ = app_handle.emit(TOOL_INSTALLATION_STARTED, started_event);

            match manager.install(winget_id, tool_name).await {
                Ok(message) => {
                    eprintln!("✅ Successfully installed {}", tool_name);
                    let _ = recheck_tool(tool_name.to_string(), state).await;

                    let completed_event = EventEmitter::tool_installation_completed(tool_name, true, &message);
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Ok(InstallationResult {
                        success: true,
                        message,
                        steps: vec![],
                        requires_restart: false,
                    })
                }
                Err(e) => {
                    let error_msg = format!("Failed to install {}: {}", tool_name, e);
                    eprintln!("❌ {}", error_msg);

                    let completed_event = EventEmitter::tool_installation_completed(tool_name, false, &error_msg);
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Err(error_msg)
                }
            }
        },
        "git-pip" => {
            let git_repo = tool_def.git_repo.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no git_repo defined", tool_name))?;

            eprintln!("   Git repo: {}", git_repo);

            let manager = crate::tools::package_managers::GitPipInstaller::new();

            if !manager.is_git_available().await {
                return Err("git is not installed. Please install git first.".to_string());
            }

            if !manager.is_python_available().await {
                return Err("Python is not installed. Please install Python first.".to_string());
            }

            let git_pip_result = manager.install(git_repo, tool_name, Some(&app_handle)).await?;

            if git_pip_result.success {
                eprintln!("✅ Successfully installed {}", tool_name);
                let _ = recheck_tool(tool_name.to_string(), state).await;
            } else {
                eprintln!("❌ Failed to install {}: {}", tool_name, git_pip_result.message);
            }

            Ok(InstallationResult {
                success: git_pip_result.success,
                message: git_pip_result.message,
                steps: vec![],
                requires_restart: false,
            })
        },
        "cargo" => {
            eprintln!("   Cargo package: {:?}", tool_def.cargo_package);

            let manager = crate::tools::package_managers::CargoInstaller::new(app_handle.clone());

            // Emit installation started event
            let started_event = EventEmitter::tool_installation_started(tool_name, "cargo");
            let _ = app_handle.emit(TOOL_INSTALLATION_STARTED, started_event);

            match manager.install(tool_def, tool_name).await {
                Ok(message) => {
                    eprintln!("✅ {}", message);
                    let _ = recheck_tool(tool_name.to_string(), state).await;

                    // Emit installation completed event
                    let completed_event = EventEmitter::tool_installation_completed(
                        tool_name,
                        true,
                        &message
                    );
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Ok(InstallationResult {
                        success: true,
                        message,
                        steps: vec![],
                        requires_restart: false,
                    })
                }
                Err(e) => {
                    let error_msg = format!("Failed to install {}: {}", tool_name, e);
                    eprintln!("❌ {}", error_msg);

                    // Emit installation failed event
                    let completed_event = EventEmitter::tool_installation_completed(
                        tool_name,
                        false,
                        &error_msg
                    );
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Err(error_msg)
                }
            }
        },
        "gem" => {
            let gem_package = tool_def.gem_package.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no gem_package defined", tool_name))?;

            eprintln!("   Gem package: {}", gem_package);

            // Emit installation started event
            let started_event = EventEmitter::tool_installation_started(tool_name, "gem");
            let _ = app_handle.emit(TOOL_INSTALLATION_STARTED, started_event);

            let manager = crate::tools::package_managers::GemInstaller::new(app_handle.clone());

            match manager.install(tool_def, tool_name).await {
                Ok(message) => {
                    eprintln!("✅ {}", message);
                    let _ = recheck_tool(tool_name.to_string(), state).await;

                    // Emit installation completed event
                    let completed_event = EventEmitter::tool_installation_completed(
                        tool_name,
                        true,
                        &message
                    );
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Ok(InstallationResult {
                        success: true,
                        message,
                        steps: vec![],
                        requires_restart: false,
                    })
                }
                Err(e) => {
                    let error_msg = format!("Failed to install {}: {}", tool_name, e);
                    eprintln!("❌ {}", error_msg);

                    // Emit installation failed event
                    let completed_event = EventEmitter::tool_installation_completed(
                        tool_name,
                        false,
                        &error_msg
                    );
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Err(error_msg)
                }
            }
        },
        "npm" => {
            let npm_package = tool_def.npm_package.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no npm_package defined", tool_name))?;

            eprintln!("   NPM package: {}", npm_package);

            // Emit installation started event
            let started_event = EventEmitter::tool_installation_started(tool_name, "npm");
            let _ = app_handle.emit(TOOL_INSTALLATION_STARTED, started_event);

            let manager = crate::tools::package_managers::NpmInstaller::new(app_handle.clone());

            match manager.install(tool_def, tool_name).await {
                Ok(message) => {
                    eprintln!("✅ {}", message);
                    let _ = recheck_tool(tool_name.to_string(), state).await;

                    // Emit installation completed event
                    let completed_event = EventEmitter::tool_installation_completed(
                        tool_name,
                        true,
                        &message
                    );
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Ok(InstallationResult {
                        success: true,
                        message,
                        steps: vec![],
                        requires_restart: false,
                    })
                }
                Err(e) => {
                    let error_msg = format!("Failed to install {}: {}", tool_name, e);
                    eprintln!("❌ {}", error_msg);

                    // Emit installation failed event
                    let completed_event = EventEmitter::tool_installation_completed(
                        tool_name,
                        false,
                        &error_msg
                    );
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Err(error_msg)
                }
            }
        },
        "homebrew" => {
            #[cfg(not(target_os = "macos"))]
            {
                Err(format!(
                    "Homebrew installation is only supported on macOS (tool '{}')",
                    tool_name
                ))
            }

            #[cfg(target_os = "macos")]
            {
                let manager = crate::tools::package_managers::HomebrewManager::new();
                let started_event =
                    EventEmitter::tool_installation_started(tool_name, "homebrew");
                let _ = app_handle.emit(TOOL_INSTALLATION_STARTED, started_event);

                match manager.install_tool(tool_name, app_handle.clone()).await {
                    Ok(_) => {
                        let message = format!("Installed {} via Homebrew", tool_name);
                        eprintln!("✅ {}", message);
                        let _ = recheck_tool(tool_name.to_string(), state).await;

                        let completed_event = EventEmitter::tool_installation_completed(
                            tool_name,
                            true,
                            &message,
                        );
                        let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                        Ok(InstallationResult {
                            success: true,
                            message,
                            steps: vec![],
                            requires_restart: false,
                        })
                    }
                    Err(e) => {
                        let error_msg = format!(
                            "Failed to install {} via Homebrew: {}",
                            tool_name, e
                        );
                        eprintln!("❌ {}", error_msg);

                        let completed_event = EventEmitter::tool_installation_completed(
                            tool_name,
                            false,
                            &error_msg,
                        );
                        let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                        Err(error_msg)
                    }
                }
            }
        }
        "manual" => {
            if !crate::tools::package_managers::ManualInstaller::supports(tool_name) {
                return Err(format!(
                    "Tool '{}' requires manual installation and has no audited automation recipe",
                    tool_name
                ));
            }
            let manager = crate::tools::package_managers::ManualInstaller::new();
            let result = manager.install(tool_name, Some(&app_handle)).await?;
            if result.success {
                let _ = recheck_tool(tool_name.to_string(), state).await;
            }
            Ok(InstallationResult {
                success: result.success,
                message: result.message,
                steps: vec![],
                requires_restart: false,
            })
        },
        "runtime" => {
            Err(format!(
                "Tool '{}' is a runtime environment (e.g. Python, Node.js). Install via system package manager.",
                tool_name
            ))
        },
        _ => {
            Err(format!(
                "Unknown installation method '{}' for tool '{}'",
                install_method, tool_name
            ))
        }
    }
}

#[tauri::command]
pub async fn update_tool(
    #[allow(non_snake_case)] tool_name: String,
    state: tauri::State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<InstallationResult, String> {
    eprintln!("🔄 Updating tool: {}", tool_name);

    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog
        .get(&tool_name)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", tool_name))?;

    let install_method = resolve_install_method(&tool_name, tool_def);
    eprintln!("   Installation method: {}", install_method);

    // Route to appropriate installer
    match install_method.as_str() {
        "go" => {
            let go_module = tool_def
                .go_module
                .as_ref()
                .ok_or_else(|| format!("Tool '{}' has no go_module defined", tool_name))?;

            let manager = GoInstallManager::new(app_handle.clone());

            if !manager.is_go_available().await {
                return Err("Go is not installed. Please install Go first.".to_string());
            }

            let go_result = manager.update(go_module, &tool_name).await?;

            if go_result.success {
                eprintln!("✅ Successfully updated {}", tool_name);

                // Trigger tool recheck
                let _ = recheck_tool(tool_name.to_string(), state).await;
            } else {
                eprintln!("❌ Failed to update {}: {}", tool_name, go_result.message);
            }

            // Convert go_install::InstallationResult to installation::InstallationResult
            Ok(InstallationResult {
                success: go_result.success,
                message: go_result.message,
                steps: vec![],
                requires_restart: false,
            })
        }
        "pipx" => {
            let pipx_package = tool_def
                .pipx_package
                .as_ref()
                .ok_or_else(|| format!("Tool '{}' has no pipx_package defined", tool_name))?;

            let manager = crate::tools::package_managers::PipxManager::new();

            if !manager.is_pipx_available().await {
                return Err("pipx is not installed.".to_string());
            }

            let pipx_result = manager.update(pipx_package, &tool_name).await?;

            if pipx_result.success {
                eprintln!("✅ Successfully updated {}", tool_name);
                let _ = recheck_tool(tool_name.to_string(), state).await;
            } else {
                eprintln!("❌ Failed to update {}: {}", tool_name, pipx_result.message);
            }

            Ok(InstallationResult {
                success: pipx_result.success,
                message: pipx_result.message,
                steps: vec![],
                requires_restart: false,
            })
        }
        "homebrew" => {
            #[cfg(not(target_os = "macos"))]
            {
                Err("Homebrew is only available on macOS.".to_string())
            }

            #[cfg(target_os = "macos")]
            {
                let manager = crate::tools::package_managers::HomebrewManager::new();
                let started_event = EventEmitter::tool_installation_started(&tool_name, "homebrew");
                let _ = app_handle.emit(TOOL_INSTALLATION_STARTED, started_event);

                match manager.upgrade_tool(&tool_name, app_handle.clone()).await {
                    Ok(_) => {
                        let message = format!("Updated {} via Homebrew", tool_name);
                        eprintln!("✅ {}", message);
                        let _ = recheck_tool(tool_name.to_string(), state).await;

                        let completed_event =
                            EventEmitter::tool_installation_completed(&tool_name, true, &message);
                        let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                        Ok(InstallationResult {
                            success: true,
                            message,
                            steps: vec![],
                            requires_restart: false,
                        })
                    }
                    Err(e) => {
                        let error_msg =
                            format!("Failed to update {} via Homebrew: {}", tool_name, e);
                        eprintln!("❌ {}", error_msg);

                        let completed_event = EventEmitter::tool_installation_completed(
                            &tool_name, false, &error_msg,
                        );
                        let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                        Err(error_msg)
                    }
                }
            }
        }
        "apt" => {
            let apt_package = tool_def
                .apt_package
                .as_ref()
                .ok_or_else(|| format!("Tool '{}' has no apt_package defined", tool_name))?;

            let manager = crate::tools::package_managers::AptManager::new(app_handle.clone());
            let started_event = EventEmitter::tool_installation_started(&tool_name, "apt");
            let _ = app_handle.emit(TOOL_INSTALLATION_STARTED, started_event);

            match manager.update(apt_package, &tool_name).await {
                Ok(message) => {
                    eprintln!("✅ Successfully updated {}", tool_name);
                    let _ = recheck_tool(tool_name.to_string(), state).await;

                    let completed_event =
                        EventEmitter::tool_installation_completed(&tool_name, true, &message);
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Ok(InstallationResult {
                        success: true,
                        message,
                        steps: vec![],
                        requires_restart: false,
                    })
                }
                Err(e) => {
                    let error_msg = format!("Failed to update {}: {}", tool_name, e);
                    eprintln!("❌ {}", error_msg);

                    let completed_event =
                        EventEmitter::tool_installation_completed(&tool_name, false, &error_msg);
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Err(error_msg)
                }
            }
        }
        "winget" => {
            let winget_id = tool_def
                .winget_id
                .as_ref()
                .ok_or_else(|| format!("Tool '{}' has no winget_id defined", tool_name))?;

            let manager = crate::tools::package_managers::WingetManager::new(app_handle.clone());
            let started_event = EventEmitter::tool_installation_started(&tool_name, "winget");
            let _ = app_handle.emit(TOOL_INSTALLATION_STARTED, started_event);

            match manager.update(winget_id, &tool_name).await {
                Ok(message) => {
                    eprintln!("✅ Successfully updated {}", tool_name);
                    let _ = recheck_tool(tool_name.to_string(), state).await;

                    let completed_event =
                        EventEmitter::tool_installation_completed(&tool_name, true, &message);
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Ok(InstallationResult {
                        success: true,
                        message,
                        steps: vec![],
                        requires_restart: false,
                    })
                }
                Err(e) => {
                    let error_msg = format!("Failed to update {}: {}", tool_name, e);
                    eprintln!("❌ {}", error_msg);

                    let completed_event =
                        EventEmitter::tool_installation_completed(&tool_name, false, &error_msg);
                    let _ = app_handle.emit(TOOL_INSTALLATION_COMPLETED, completed_event);

                    Err(error_msg)
                }
            }
        }
        "git-pip" => {
            // For git-pip, we need to reinstall from the repo
            let git_repo = tool_def
                .git_repo
                .as_ref()
                .ok_or_else(|| format!("Tool '{}' has no git_repo defined", tool_name))?;

            let manager = crate::tools::package_managers::GitPipInstaller::new();

            // Reinstall to update
            let result = manager
                .install(git_repo, &tool_name, Some(&app_handle))
                .await?;

            if result.success {
                eprintln!("✅ Successfully updated {}", tool_name);
                let _ = recheck_tool(tool_name.to_string(), state).await;
            } else {
                eprintln!("❌ Failed to update {}: {}", tool_name, result.message);
            }

            Ok(InstallationResult {
                success: result.success,
                message: result.message,
                steps: vec![],
                requires_restart: false,
            })
        }
        "gem" => {
            if tool_def.gem_package.is_none() {
                return Err(format!("Tool '{}' has no gem_package defined", tool_name));
            }

            let manager = crate::tools::package_managers::GemInstaller::new(app_handle.clone());

            match manager.update(tool_def, &tool_name).await {
                Ok(message) => {
                    eprintln!("✅ {}", message);
                    let _ = recheck_tool(tool_name.to_string(), state).await;

                    Ok(InstallationResult {
                        success: true,
                        message,
                        steps: vec![],
                        requires_restart: false,
                    })
                }
                Err(e) => {
                    let error_msg = format!("Failed to update {}: {}", tool_name, e);
                    eprintln!("❌ {}", error_msg);
                    Err(error_msg)
                }
            }
        }
        "npm" => {
            if tool_def.npm_package.is_none() {
                return Err(format!("Tool '{}' has no npm_package defined", tool_name));
            }

            let manager = crate::tools::package_managers::NpmInstaller::new(app_handle.clone());

            match manager.update(tool_def, &tool_name).await {
                Ok(message) => {
                    eprintln!("✅ {}", message);
                    let _ = recheck_tool(tool_name.to_string(), state).await;

                    Ok(InstallationResult {
                        success: true,
                        message,
                        steps: vec![],
                        requires_restart: false,
                    })
                }
                Err(e) => {
                    let error_msg = format!("Failed to update {}: {}", tool_name, e);
                    eprintln!("❌ {}", error_msg);
                    Err(error_msg)
                }
            }
        }
        "cargo" => {
            if tool_def.cargo_package.is_none() {
                return Err(format!("Tool '{}' has no cargo_package defined", tool_name));
            }

            let manager = crate::tools::package_managers::CargoInstaller::new(app_handle.clone());

            match manager.update(tool_def, &tool_name).await {
                Ok(message) => {
                    eprintln!("✅ {}", message);
                    let _ = recheck_tool(tool_name.to_string(), state).await;

                    Ok(InstallationResult {
                        success: true,
                        message,
                        steps: vec![],
                        requires_restart: false,
                    })
                }
                Err(e) => {
                    let error_msg = format!("Failed to update {}: {}", tool_name, e);
                    eprintln!("❌ {}", error_msg);
                    Err(error_msg)
                }
            }
        }
        _ => Err(format!(
            "Cannot update tool '{}' with install method '{}'",
            tool_name, install_method
        )),
    }
}

#[tauri::command]
pub async fn uninstall_tool(
    #[allow(non_snake_case)] tool_name: String,
    state: tauri::State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<String, String> {
    eprintln!("🗑️  Uninstalling tool: {}", tool_name);

    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog
        .get(&tool_name)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", tool_name))?;

    let install_method = resolve_install_method(&tool_name, tool_def);
    eprintln!("   Installation method: {}", install_method);

    // Route to appropriate installer
    match install_method.as_str() {
        "go" => {
            let manager = GoInstallManager::new(app_handle.clone());

            let message = manager.uninstall(&tool_name).await?;

            eprintln!("✅ {}", message);

            // Trigger tool recheck
            let _ = recheck_tool(tool_name.to_string(), state).await;

            Ok(message)
        }
        "pipx" => {
            let pipx_package = tool_def
                .pipx_package
                .as_ref()
                .ok_or_else(|| format!("Tool '{}' has no pipx_package defined", tool_name))?;

            let manager = crate::tools::package_managers::PipxManager::new();

            let message = manager.uninstall(pipx_package, &tool_name).await?;

            eprintln!("✅ {}", message);

            let _ = recheck_tool(tool_name.to_string(), state).await;

            Ok(message)
        }
        "apt" => {
            let apt_package = tool_def
                .apt_package
                .as_ref()
                .ok_or_else(|| format!("Tool '{}' has no apt_package defined", tool_name))?;

            let manager = crate::tools::package_managers::AptManager::new(app_handle.clone());

            let message = manager
                .uninstall(apt_package, &tool_name)
                .await
                .map_err(|e| e.to_string())?;

            eprintln!("✅ {}", message);

            let _ = recheck_tool(tool_name.to_string(), state).await;

            Ok(message)
        }
        "winget" => {
            let winget_id = tool_def
                .winget_id
                .as_ref()
                .ok_or_else(|| format!("Tool '{}' has no winget_id defined", tool_name))?;

            let manager = crate::tools::package_managers::WingetManager::new(app_handle.clone());

            let message = manager
                .uninstall(winget_id, &tool_name)
                .await
                .map_err(|e| e.to_string())?;

            eprintln!("✅ {}", message);

            let _ = recheck_tool(tool_name.to_string(), state).await;

            Ok(message)
        }
        "git-pip" => {
            let manager = crate::tools::package_managers::GitPipInstaller::new();
            let message = manager.uninstall(&tool_name).await?;

            eprintln!("✅ {}", message);
            let _ = recheck_tool(tool_name.to_string(), state).await;

            Ok(message)
        }
        "gem" => {
            let manager = crate::tools::package_managers::GemInstaller::new(app_handle.clone());

            match manager.uninstall(tool_def).await {
                Ok(message) => {
                    eprintln!("✅ {}", message);
                    let _ = recheck_tool(tool_name.to_string(), state).await;
                    Ok(message)
                }
                Err(e) => {
                    let error_msg = format!("Failed to uninstall {}: {}", tool_name, e);
                    eprintln!("❌ {}", error_msg);
                    Err(error_msg)
                }
            }
        }
        "npm" => {
            let manager = crate::tools::package_managers::NpmInstaller::new(app_handle.clone());

            match manager.uninstall(tool_def).await {
                Ok(message) => {
                    eprintln!("✅ {}", message);
                    let _ = recheck_tool(tool_name.to_string(), state).await;
                    Ok(message)
                }
                Err(e) => {
                    let error_msg = format!("Failed to uninstall {}: {}", tool_name, e);
                    eprintln!("❌ {}", error_msg);
                    Err(error_msg)
                }
            }
        }
        "cargo" => {
            let manager = crate::tools::package_managers::CargoInstaller::new(app_handle.clone());

            match manager.uninstall(tool_def).await {
                Ok(message) => {
                    eprintln!("✅ {}", message);
                    let _ = recheck_tool(tool_name.to_string(), state).await;
                    Ok(message)
                }
                Err(e) => {
                    let error_msg = format!("Failed to uninstall {}: {}", tool_name, e);
                    eprintln!("❌ {}", error_msg);
                    Err(error_msg)
                }
            }
        }
        "homebrew" => {
            #[cfg(not(target_os = "macos"))]
            {
                Err(format!(
                    "Homebrew uninstall is only supported on macOS (tool '{}')",
                    tool_name
                ))
            }

            #[cfg(target_os = "macos")]
            {
                let manager = crate::tools::package_managers::HomebrewManager::new();

                match manager.uninstall_tool(&tool_name, app_handle.clone()).await {
                    Ok(_) => {
                        let message = format!("Uninstalled {} via Homebrew", tool_name);
                        eprintln!("✅ {}", message);
                        let _ = recheck_tool(tool_name.to_string(), state).await;
                        Ok(message)
                    }
                    Err(e) => {
                        let error_msg =
                            format!("Failed to uninstall {} via Homebrew: {}", tool_name, e);
                        eprintln!("❌ {}", error_msg);
                        Err(error_msg)
                    }
                }
            }
        }
        _ => Err(format!(
            "Cannot uninstall tool '{}' with install method '{}'",
            tool_name, install_method
        )),
    }
}

#[tauri::command]
pub async fn check_tool_installed(
    #[allow(non_snake_case)] tool_name: String,
    _state: tauri::State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<bool, String> {
    eprintln!("🔍 Checking if tool is installed: {}", tool_name);

    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog
        .get(&tool_name)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", tool_name))?;

    let install_method = resolve_install_method(&tool_name, tool_def);

    // Route to appropriate installer
    match install_method.as_str() {
        "go" => {
            let manager = GoInstallManager::new(app_handle.clone());
            let installed = manager.is_installed(&tool_name);

            eprintln!("   Installed: {}", installed);

            Ok(installed)
        }
        "pipx" => Err(format!(
            "pipx check not yet implemented for '{}'",
            tool_name
        )),
        "homebrew" => {
            #[cfg(not(target_os = "macos"))]
            {
                Ok(false)
            }

            #[cfg(target_os = "macos")]
            {
                let installed =
                    crate::tools::package_managers::homebrew_manager::is_installed(&tool_name)
                        .await;
                eprintln!("   Installed (Homebrew): {}", installed);
                Ok(installed)
            }
        }
        _ => {
            // For other methods, assume not installed via this command
            Ok(false)
        }
    }
}

#[tauri::command]
pub async fn get_tool_version(
    #[allow(non_snake_case)] tool_name: String,
    _state: tauri::State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<Option<String>, String> {
    eprintln!("🔍 Getting tool version: {}", tool_name);

    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog
        .get(&tool_name)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", tool_name))?;

    let install_method = resolve_install_method(&tool_name, tool_def);

    // Route to appropriate installer
    match install_method.as_str() {
        "go" => {
            let manager = GoInstallManager::new(app_handle.clone());
            let version = manager.get_version(&tool_name).await;

            if let Some(ref v) = version {
                eprintln!("   Version: {}", v);
            } else {
                eprintln!("   Version: unknown");
            }

            Ok(version)
        }
        "homebrew" => {
            #[cfg(not(target_os = "macos"))]
            {
                Ok(None)
            }

            #[cfg(target_os = "macos")]
            {
                let version =
                    crate::tools::package_managers::homebrew_manager::get_version(&tool_name).await;

                if let Some(ref v) = version {
                    eprintln!("   Version (Homebrew): {}", v);
                } else {
                    eprintln!("   Version (Homebrew): unknown");
                }

                Ok(version)
            }
        }
        _ => Ok(None),
    }
}

#[tauri::command]
pub async fn check_tool_update(
    #[allow(non_snake_case)] tool_name: String,
    _state: tauri::State<'_, AppState>,
    _app_handle: tauri::AppHandle,
) -> Result<VersionCheckResult, String> {
    eprintln!("🔄 Checking for updates: {}", tool_name);

    // Get tool definition to find its package manager
    let tool_catalog = crate::tools::get_tool_catalog();
    let tool_def = tool_catalog.get(&tool_name);

    if tool_def.is_none() {
        eprintln!(
            "   ⚠️  Tool '{}' not found in catalog, trying legacy...",
            tool_name
        );
        return check_tool_update_legacy(tool_name, _state, _app_handle).await;
    }

    let tool_def = tool_def.unwrap();
    let install_method = &tool_def.install_method;

    // Map install method to package manager name
    let manager_name = match install_method.as_str() {
        "go" => "go",
        "pipx" | "git-pip" => "pipx",
        "apt" => {
            #[cfg(not(target_os = "linux"))]
            {
                eprintln!("   ⚠️  APT is Linux-only, using legacy checker");
                return check_tool_update_legacy(tool_name, _state, _app_handle).await;
            }
            #[cfg(target_os = "linux")]
            "apt"
        }
        "winget" => {
            #[cfg(not(target_os = "windows"))]
            {
                eprintln!("   ⚠️  WinGet is Windows-only, using legacy checker");
                return check_tool_update_legacy(tool_name, _state, _app_handle).await;
            }
            #[cfg(target_os = "windows")]
            "winget"
        }
        "homebrew" => {
            #[cfg(not(target_os = "macos"))]
            {
                eprintln!("   ⚠️  Homebrew is macOS-only, using legacy checker");
                return check_tool_update_legacy(tool_name, _state, _app_handle).await;
            }
            #[cfg(target_os = "macos")]
            "homebrew"
        }
        "cargo" => "cargo",
        "gem" => "gem",
        "npm" => "npm",
        "manual" | "runtime" => {
            // Manual/runtime tools don't support automated updates
            eprintln!(
                "   ⚠️  Tool '{}' uses manual/runtime install, no automated updates",
                tool_name
            );
            return Ok(VersionCheckResult::error(
                format!("Tool '{}' requires manual update checking", tool_name),
                install_method.to_string(),
            ));
        }
        _ => {
            // Unknown install method, use legacy
            eprintln!(
                "   ⚠️  Unknown install method '{}', using legacy checker",
                install_method
            );
            return check_tool_update_legacy(tool_name, _state, _app_handle).await;
        }
    };

    eprintln!("   📦 Tool installed via: {}", manager_name);

    // Use the new unified update checker coordinator with specific manager
    let config = crate::tools::package_managers::UpdateCheckerConfig::default();
    let coordinator = crate::tools::package_managers::UpdateCheckerCoordinator::new(config.clone());

    // Only add the specific checker for this tool's package manager
    let checker = crate::tools::package_managers::UpdateCheckerFactory::create_checker_by_name(
        manager_name,
        &config,
    )
    .await;

    match checker {
        Some(checker) => {
            coordinator.add_checker(checker).await;

            // Check for updates using the coordinator with only the relevant manager
            match coordinator.check_update(&tool_name).await {
                Ok(coordinated_result) => {
                    if let Some(best_result) = coordinated_result.best_result {
                        let has_update = best_result.has_update;
                        let current_version = best_result.current_version.clone();
                        let latest_version = best_result.latest_version.clone();
                        let package_manager = best_result.package_manager.clone();
                        let error = best_result.error.clone();

                        // Convert new result to old format for backward compatibility
                        let old_result = VersionCheckResult {
                            has_update,
                            current_version: current_version.clone(),
                            latest_version: latest_version.clone(),
                            package_manager,
                            error,
                        };

                        if has_update {
                            eprintln!(
                                "   ⬆️  Update available: {} -> {}",
                                current_version.as_ref().unwrap_or(&"unknown".to_string()),
                                latest_version.as_ref().unwrap_or(&"unknown".to_string())
                            );
                        } else {
                            eprintln!(
                                "   ✅ Up to date: {}",
                                current_version.as_ref().unwrap_or(&"unknown".to_string())
                            );
                        }

                        Ok(old_result)
                    } else {
                        // No result from the specific manager - fallback to legacy
                        eprintln!("   ⚠️  Checker failed, trying legacy...");
                        check_tool_update_legacy(tool_name, _state, _app_handle).await
                    }
                }
                Err(error) => {
                    eprintln!("   ❌ Update check failed: {}, trying legacy...", error);
                    // Fallback to legacy on error
                    check_tool_update_legacy(tool_name, _state, _app_handle).await
                }
            }
        }
        None => {
            // Checker not available, use legacy
            eprintln!(
                "   ⚠️  Package manager '{}' not available, using legacy",
                manager_name
            );
            check_tool_update_legacy(tool_name, _state, _app_handle).await
        }
    }
}

#[tauri::command]
pub async fn check_tool_update_legacy(
    #[allow(non_snake_case)] tool_name: String,
    _state: tauri::State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<VersionCheckResult, String> {
    eprintln!("🔄 Checking for updates (legacy): {}", tool_name);

    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog
        .get(&tool_name)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", tool_name))?;

    let install_method = resolve_install_method(&tool_name, tool_def);

    // Route to appropriate version checker based on install method
    match install_method.as_str() {
        "go" => {
            let manager = GoInstallManager::new(app_handle.clone());

            // Get the binary path
            let binary_path = manager
                .get_tool_path(&tool_name)
                .ok_or_else(|| format!("Tool '{}' is not installed", tool_name))?;

            // Get the go module path
            let module_path = tool_def
                .go_module
                .as_ref()
                .ok_or_else(|| format!("Tool '{}' has no go_module defined", tool_name))?;

            // Check for updates using go version -m and go list -m -versions
            let result =
                crate::tools::package_managers::check_go_update(&binary_path, module_path).await?;

            if result.has_update {
                eprintln!(
                    "   ⬆️  Update available: {} -> {}",
                    result
                        .current_version
                        .as_ref()
                        .unwrap_or(&"unknown".to_string()),
                    result
                        .latest_version
                        .as_ref()
                        .unwrap_or(&"unknown".to_string())
                );
            } else {
                eprintln!(
                    "   ✅ Up to date: {}",
                    result
                        .current_version
                        .as_ref()
                        .unwrap_or(&"unknown".to_string())
                );
            }

            Ok(result)
        }
        "homebrew" => {
            #[cfg(not(target_os = "macos"))]
            {
                Ok(VersionCheckResult::error(
                    "Homebrew update checks are only available on macOS".to_string(),
                    "homebrew".to_string(),
                ))
            }

            #[cfg(target_os = "macos")]
            {
                use crate::tools::package_managers::homebrew_manager;

                match homebrew_manager::get_update_versions(&tool_name).await {
                    Ok(Some((current, latest))) => Ok(VersionCheckResult::has_update(
                        current,
                        latest,
                        "homebrew".to_string(),
                    )),
                    Ok(None) => {
                        if let Some(current) = homebrew_manager::get_version(&tool_name).await {
                            Ok(VersionCheckResult::no_update(
                                current,
                                "homebrew".to_string(),
                            ))
                        } else {
                            Ok(VersionCheckResult::error(
                                "Unable to determine Homebrew version".to_string(),
                                "homebrew".to_string(),
                            ))
                        }
                    }
                    Err(e) => Ok(VersionCheckResult::error(
                        format!("Homebrew update check failed: {}", e),
                        "homebrew".to_string(),
                    )),
                }
            }
        }
        "apt" => {
            let package_name = tool_def
                .apt_package
                .as_ref()
                .ok_or_else(|| format!("Tool '{}' has no apt_package defined", tool_name))?;

            let result = crate::tools::package_managers::check_apt_update(package_name).await?;

            if result.has_update {
                eprintln!(
                    "   ⬆️  Update available: {} -> {}",
                    result
                        .current_version
                        .as_ref()
                        .unwrap_or(&"unknown".to_string()),
                    result
                        .latest_version
                        .as_ref()
                        .unwrap_or(&"unknown".to_string())
                );
            }

            Ok(result)
        }
        "winget" => {
            // WinGet is Windows-only, return error on other platforms
            #[cfg(target_os = "windows")]
            {
                let winget_id = tool_def
                    .winget_id
                    .as_ref()
                    .ok_or_else(|| format!("Tool '{}' has no winget_id defined", tool_name))?;

                let result = crate::tools::package_managers::check_winget_update(winget_id).await?;

                if result.has_update {
                    eprintln!(
                        "   ⬆️  Update available: {} -> {}",
                        result
                            .current_version
                            .as_ref()
                            .unwrap_or(&"unknown".to_string()),
                        result
                            .latest_version
                            .as_ref()
                            .unwrap_or(&"unknown".to_string())
                    );
                }

                Ok(result)
            }

            #[cfg(not(target_os = "windows"))]
            {
                Err("WinGet is only available on Windows".to_string())
            }
        }
        "pipx" => {
            let package_name = tool_def
                .pipx_package
                .as_ref()
                .ok_or_else(|| format!("Tool '{}' has no pipx_package defined", tool_name))?;

            let result = crate::tools::package_managers::check_pipx_update(package_name).await?;

            if result.has_update {
                eprintln!(
                    "   ⬆️  Update available: {} -> {}",
                    result
                        .current_version
                        .as_ref()
                        .unwrap_or(&"unknown".to_string()),
                    result
                        .latest_version
                        .as_ref()
                        .unwrap_or(&"unknown".to_string())
                );
            }

            Ok(result)
        }
        _ => Err(format!(
            "Version check not supported for install method '{}'",
            install_method
        )),
    }
}

#[tauri::command]
pub async fn get_tool_installation_info(
    #[allow(non_snake_case)] tool_name: String,
    _state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    eprintln!("ℹ️  Getting installation info for: {}", tool_name);

    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog
        .get(&tool_name)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", tool_name))?;

    let platform = crate::tools::catalog::InstallPlatform::current();
    let available_methods = tool_def.install_methods_for(&tool_name, platform);
    let recommended_method = tool_def.recommended_install_method(&tool_name, platform);
    let automated_methods = available_methods
        .iter()
        .filter(|method| {
            method.as_str() != "runtime"
                && (method.as_str() != "manual"
                    || crate::tools::package_managers::ManualInstaller::supports(&tool_name))
        })
        .cloned()
        .collect::<Vec<_>>();

    let info = serde_json::json!({
        "name": tool_def.name,
        "platform": platform.as_str(),
        "install_method": recommended_method.clone(),
        "recommended_install_method": recommended_method,
        "available_install_methods": available_methods,
        "automated_install_methods": automated_methods,
        "go_module": tool_def.go_module,
        "pipx_package": tool_def.pipx_package,
        "apt_package": tool_def.apt_package,
        "winget_id": tool_def.winget_id,
        "description": tool_def.description,
        "category": tool_def.category,
    });

    Ok(info)
}

// Elevation Commands

#[tauri::command]
pub async fn check_elevation_support(
) -> Result<crate::tools::package_managers::ElevationMethod, String> {
    eprintln!("🔐 Checking elevation support...");
    let method = crate::tools::package_managers::check_elevation_support().await;
    eprintln!("✓ Elevation method: {:?}", method);
    Ok(method)
}

/// Check if pipx .local\bin is in PATH
#[tauri::command]
pub async fn check_pipx_path() -> Result<serde_json::Value, String> {
    #[cfg(target_os = "windows")]
    {
        let local_bin = std::env::var("USERPROFILE")
            .map(|p| format!(r"{p}\.local\bin"))
            .unwrap_or_default();

        let path = std::env::var("PATH").unwrap_or_default();
        let in_path = path
            .split(';')
            .any(|p| p.trim().eq_ignore_ascii_case(&local_bin));

        // Check for multiple pipx installations
        let old_pipx = std::env::var("USERPROFILE")
            .map(|p| format!(r"{p}\pipx"))
            .unwrap_or_default();
        let new_pipx = std::env::var("LOCALAPPDATA")
            .map(|p| format!(r"{p}\pipx"))
            .unwrap_or_default();

        let old_exists = std::path::Path::new(&old_pipx).exists();
        let new_exists = std::path::Path::new(&new_pipx).exists();

        Ok(serde_json::json!({
            "in_path": in_path,
            "local_bin": local_bin,
            "multiple_installations": old_exists && new_exists,
            "old_location": old_pipx,
            "new_location": new_pipx,
            "old_exists": old_exists,
            "new_exists": new_exists
        }))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let local_bin = std::env::var("HOME")
            .map(|p| format!("{p}/.local/bin"))
            .unwrap_or_default();

        let path = std::env::var("PATH").unwrap_or_default();
        let in_path = path.split(':').any(|p| p == local_bin);

        Ok(serde_json::json!({
            "in_path": in_path,
            "local_bin": local_bin,
            "multiple_installations": false
        }))
    }
}

/// Fix pipx PATH by running pipx ensurepath
#[tauri::command]
pub async fn fix_pipx_path() -> Result<String, String> {
    let mut pipx_cmd = hidden_tokio_command("pipx");
    match pipx_cmd.arg("ensurepath").output().await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                Ok(format!("✅ PATH updated successfully!\n\n{}\n\n⚠️ Please restart your terminal and this app for changes to take effect.", stdout))
            } else {
                Err(format!("Failed to fix PATH: {}", stderr))
            }
        }
        Err(e) => Err(format!("Failed to execute pipx ensurepath: {}", e)),
    }
}

/// Clean up old pipx installation
#[tauri::command]
pub async fn cleanup_old_pipx() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        let old_pipx = std::env::var("USERPROFILE")
            .map(|p| format!(r"{p}\pipx"))
            .map_err(|e| format!("Failed to get USERPROFILE: {}", e))?;

        if !std::path::Path::new(&old_pipx).exists() {
            return Ok("No old pipx installation found.".to_string());
        }

        // First, try to uninstall all tools from old pipx
        let mut cleanup_messages = Vec::new();

        // List tools in old venvs directory
        let old_venvs = format!(r"{}\venvs", old_pipx);
        if let Ok(entries) = std::fs::read_dir(&old_venvs) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if let Some(tool_name) = entry.file_name().to_str() {
                        eprintln!("Uninstalling old tool: {}", tool_name);
                        let mut pipx_cmd = hidden_tokio_command("pipx");
                        match pipx_cmd.arg("uninstall").arg(tool_name).output().await {
                            Ok(output) if output.status.success() => {
                                cleanup_messages.push(format!("✅ Uninstalled {}", tool_name));
                            }
                            _ => {
                                cleanup_messages
                                    .push(format!("⚠️  Could not uninstall {}", tool_name));
                            }
                        }
                    }
                }
            }
        }

        // Remove the old directory
        match std::fs::remove_dir_all(&old_pipx) {
            Ok(_) => {
                cleanup_messages.push(format!("✅ Removed old pipx directory: {}", old_pipx));
                Ok(cleanup_messages.join("\n"))
            }
            Err(e) => Err(format!("Failed to remove old pipx directory: {}", e)),
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        Ok("This feature is only needed on Windows.".to_string())
    }
}

// ============================================================================
// Adapter Commands - Tool Command Builders
// ============================================================================

/// Build a command for a specific tool with custom configuration
#[tauri::command]
pub async fn build_tool_command(
    adapter_type: crate::adapters::AdapterType,
) -> Result<crate::adapters::CommandPreview, String> {
    let registry = crate::adapters::AdapterRegistry::new();
    Ok(registry.build_command(&adapter_type))
}

/// Build a command for a tool with default configuration
#[tauri::command]
pub async fn build_tool_command_with_defaults(
    #[allow(non_snake_case)] tool_name: String,
    target: String,
    #[allow(non_snake_case)] outputFile: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<crate::adapters::CommandPreview, String> {
    let target_inputs = crate::security::workflow_target_inputs(&target)?;
    let registry = crate::adapters::AdapterRegistry::new();
    if let Some(target_kind) = registry.target_kind(&tool_name) {
        let normalized_target = target_inputs
            .get(target_kind)
            .ok_or_else(|| format!("{} requires a {} target", tool_name, target_kind))?;
        return registry.build_command_with_defaults(
            &tool_name,
            normalized_target.clone(),
            outputFile,
        );
    }

    let profile = state
        .auto_adapters
        .get_profile(&tool_name)
        .await
        .ok_or_else(|| format!("No adapter is available for '{}'", tool_name))?;
    let normalized_target = target_inputs
        .get(&profile.target_kind)
        .ok_or_else(|| format!("{} requires a {} target", tool_name, profile.target_kind))?;
    profile.build_command(normalized_target, outputFile.as_deref())
}

/// Get detailed information about a specific adapter
#[tauri::command]
pub async fn get_adapter_info(
    #[allow(non_snake_case)] tool_name: String,
    state: tauri::State<'_, AppState>,
) -> Result<crate::adapters::AdapterInfo, String> {
    let registry = crate::adapters::AdapterRegistry::new();
    match registry.get_adapter_info(&tool_name) {
        Ok(info) => Ok(info),
        Err(_) => state
            .auto_adapters
            .get_profile(&tool_name)
            .await
            .map(|profile| profile.to_info())
            .ok_or_else(|| format!("Unknown tool: {}", tool_name)),
    }
}

/// List all available adapters
#[tauri::command]
pub async fn list_adapters(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<crate::adapters::AdapterInfo>, String> {
    let registry = crate::adapters::AdapterRegistry::new();
    let records = state
        .tool_discovery
        .read()
        .await
        .get_all_tool_records(false)
        .await;
    let failures = state.auto_adapters.sync_installed_tools(records).await;
    for failure in failures {
        eprintln!("Auto-adapter generation requires attention: {}", failure);
    }

    let mut adapters = registry.list_adapters();
    adapters.extend(
        state
            .auto_adapters
            .list_profiles()
            .await
            .into_iter()
            .map(|profile| profile.to_info()),
    );
    adapters.sort_by(|left, right| left.tool_name.cmp(&right.tool_name));
    Ok(adapters)
}

/// Get adapters by category
#[tauri::command]
pub async fn get_adapters_by_category(
    category: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<crate::adapters::AdapterInfo>, String> {
    Ok(list_adapters(state)
        .await?
        .into_iter()
        .filter(|info| info.category.eq_ignore_ascii_case(&category))
        .collect())
}

/// Get adapters by risk level
#[tauri::command]
pub async fn get_adapters_by_risk_level(
    #[allow(non_snake_case)] riskLevel: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<crate::adapters::AdapterInfo>, String> {
    Ok(list_adapters(state)
        .await?
        .into_iter()
        .filter(|info| info.risk_level.eq_ignore_ascii_case(&riskLevel))
        .collect())
}

/// Check if an adapter exists for a tool
#[tauri::command]
pub async fn has_adapter(
    #[allow(non_snake_case)] tool_name: String,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    let registry = crate::adapters::AdapterRegistry::new();
    Ok(registry.has_adapter(&tool_name) || state.auto_adapters.has_ready_profile(&tool_name).await)
}

/// Get all adapter categories
#[tauri::command]
pub async fn get_adapter_categories(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let mut categories = list_adapters(state)
        .await?
        .into_iter()
        .map(|adapter| adapter.category)
        .collect::<Vec<_>>();
    categories.sort();
    categories.dedup();
    Ok(categories)
}

/// Enhanced update check with detailed results from multiple package managers
#[tauri::command]
pub async fn check_tool_update_enhanced(
    #[allow(non_snake_case)] tool_name: String,
    _state: tauri::State<'_, AppState>,
    _app_handle: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    eprintln!("🔄 Checking for updates (enhanced): {}", tool_name);

    // Use the new unified update checker coordinator
    let config = crate::tools::package_managers::UpdateCheckerConfig::default();
    let coordinator = crate::tools::package_managers::UpdateCheckerCoordinator::new(config.clone());

    // Add all available checkers
    let checkers =
        crate::tools::package_managers::UpdateCheckerFactory::create_all_checkers(&config).await;
    for checker in checkers {
        coordinator.add_checker(checker).await;
    }

    // Check for updates using the coordinator
    match coordinator.check_update(&tool_name).await {
        Ok(coordinated_result) => {
            // Convert to JSON for frontend
            let json_result = serde_json::to_value(coordinated_result)
                .map_err(|e| format!("Failed to serialize result: {}", e))?;

            eprintln!("   📊 Enhanced update check completed for {}", tool_name);
            Ok(json_result)
        }
        Err(error) => {
            eprintln!("   ❌ Enhanced update check failed: {}", error);
            Err(error.to_string())
        }
    }
}

#[tauri::command]
pub async fn get_update_checker_telemetry(
    _state: tauri::State<'_, AppState>,
    _app_handle: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    eprintln!("📊 Getting update checker telemetry");

    // Use the new unified update checker coordinator
    let config = crate::tools::package_managers::UpdateCheckerConfig::default();
    let coordinator = crate::tools::package_managers::UpdateCheckerCoordinator::new(config);

    // Get telemetry summary
    let summary = coordinator.get_telemetry_summary();

    // Get recent events
    let recent_events = coordinator.get_recent_telemetry_events(Some(50));

    // Export events to JSON
    let events_json = coordinator
        .export_telemetry_events()
        .map_err(|e| format!("Failed to export telemetry events: {}", e))?;

    let telemetry_data = serde_json::json!({
        "summary": summary,
        "recent_events": recent_events,
        "events_json": events_json
    });

    eprintln!("   📊 Telemetry data retrieved");
    Ok(telemetry_data)
}

#[tauri::command]
pub async fn clear_update_checker_telemetry(
    _state: tauri::State<'_, AppState>,
    _app_handle: tauri::AppHandle,
) -> Result<(), String> {
    eprintln!("🗑️ Clearing update checker telemetry");

    // Use the new unified update checker coordinator
    let config = crate::tools::package_managers::UpdateCheckerConfig::default();
    let coordinator = crate::tools::package_managers::UpdateCheckerCoordinator::new(config);

    // Clear telemetry
    coordinator.clear_telemetry();

    eprintln!("   ✅ Telemetry cleared");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ensure_workflow_compatible, resolve_results_directory};
    use crate::workflow::types::WorkflowCompatibility;

    #[test]
    fn confines_scan_results_to_managed_root() {
        let root = std::env::temp_dir().join("unihack-results");

        assert_eq!(
            std::path::PathBuf::from(
                resolve_results_directory(&root, Some("audit/example.com")).unwrap()
            ),
            root.join("audit").join("example.com")
        );
        assert_eq!(
            std::path::PathBuf::from(
                resolve_results_directory(&root, Some("./results/legacy-name")).unwrap()
            ),
            root.join("legacy-name")
        );
        assert!(resolve_results_directory(&root, Some("../escape")).is_err());
        let outside = std::env::temp_dir().join("unihack-outside");
        assert!(resolve_results_directory(&root, outside.to_str()).is_err());
    }

    #[test]
    fn rejects_workflows_with_missing_tools_before_execution() {
        let compatibility = WorkflowCompatibility {
            compatible: false,
            required_tools: vec!["subfinder".to_string(), "nuclei".to_string()],
            available_tools: vec!["subfinder".to_string()],
            missing_tools: vec!["nuclei".to_string()],
            compatibility_percentage: 50.0,
            warnings: vec![],
        };

        let error = ensure_workflow_compatible("quick-scan", &compatibility).unwrap_err();
        assert!(error.contains("quick-scan"));
        assert!(error.contains("nuclei"));
        assert!(error.contains("refresh tool discovery"));
    }
}
