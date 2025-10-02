use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use tauri::Manager;

use crate::database::Database;
use crate::workflow::{engine::WorkflowEngine, loader::WorkflowLoader, types::WorkflowCompatibility};
use crate::tools::discovery::ToolDiscoveryService;
use crate::events::{EventEmitter, SCAN_STARTED, SCAN_COMPLETED, SCAN_FAILED, SCAN_PROGRESS_UPDATE};
use crate::tools::catalog::get_tool_catalog;
use crate::tools::package_managers::{GoInstallManager, InstallationResult, VersionCheckResult};

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowExecuteRequest {
    pub workflow_id: String,
    pub inputs: HashMap<String, String>,
    pub working_directory: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowExecuteResponse {
    pub execution_id: String,
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
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub category: String,
    pub available: bool,
    pub path: Option<String>,
    pub version: Option<String>,
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

// App state structure
pub struct AppState {
    pub db: std::sync::Arc<Database>,
    pub workflow_engine: std::sync::Arc<WorkflowEngine>,
    pub tool_discovery: std::sync::Arc<tokio::sync::RwLock<ToolDiscoveryService>>,
    pub tool_registry: std::sync::Arc<crate::tools::registry::ToolRegistry>,
}

// Commands for workflow management
#[tauri::command]
pub async fn load_workflow_templates(
    state: tauri::State<'_, AppState>
) -> Result<Vec<WorkflowSummary>, String> {
    // Try multiple paths: relative, from project root, from current dir
    let possible_paths = vec![
        std::path::PathBuf::from("app/workflows"),
        std::path::PathBuf::from("../app/workflows"),
        std::path::PathBuf::from("../../app/workflows"),
        std::env::current_dir().unwrap_or_default().join("app/workflows"),
        std::env::current_dir().unwrap_or_default().parent().unwrap_or(std::path::Path::new(".")).join("app/workflows"),
    ];
    
    let workflows_dir = possible_paths.iter()
        .find(|p| p.exists())
        .cloned()
        .unwrap_or_else(|| std::path::PathBuf::from("app/workflows"));
    
    eprintln!("Loading workflows from: {:?}", workflows_dir);
    eprintln!("Workflows directory exists: {}", workflows_dir.exists());
    let workflow_loader = WorkflowLoader::new(workflows_dir.clone());

    match workflow_loader.load_all_workflows().await {
        Ok(workflows) => {
            eprintln!("Successfully loaded {} workflows", workflows.len());
            let mut summaries = Vec::new();

            for (id, workflow) in workflows {
                eprintln!("Processing workflow: {} ({})", workflow.name, id);
                let discovery_service = state.tool_discovery.read().await;
                let compatibility = discovery_service.get_tool_compatibility(&workflow).await
                    .map_err(|e| {
                        eprintln!("Failed to check compatibility for {}: {}", id, e);
                        format!("Failed to check compatibility: {}", e)
                    })?;
                drop(discovery_service);

                eprintln!("Workflow {} compatibility: {} ({}%)", 
                    id, compatibility.compatible, compatibility.compatibility_percentage);

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
    let possible_paths = vec![
        std::path::PathBuf::from("app/workflows"),
        std::path::PathBuf::from("../app/workflows"),
        std::path::PathBuf::from("../../app/workflows"),
        std::env::current_dir().unwrap_or_default().join("app/workflows"),
        std::env::current_dir().unwrap_or_default().parent().unwrap_or(std::path::Path::new(".")).join("app/workflows"),
    ];
    
    let workflows_dir = possible_paths.iter()
        .find(|p| p.exists())
        .cloned()
        .unwrap_or_else(|| std::path::PathBuf::from("app/workflows"));
    
    let workflow_loader = WorkflowLoader::new(workflows_dir.clone());

    match workflow_loader.load_workflow(&workflow_id).await {
        Ok(workflow) => {
            let discovery_service = state.tool_discovery.read().await;
            let compatibility = discovery_service.get_tool_compatibility(&workflow).await
                .map_err(|e| format!("Failed to check compatibility: {}", e))?;
            drop(discovery_service);

            // Convert workflow steps to a serializable format
            let steps_json: Vec<serde_json::Value> = workflow.steps.iter().map(|step| {
                serde_json::json!({
                    "id": step.id,
                    "name": step.name,
                    "description": step.description,
                    "run": step.run,
                    "needs": step.needs,
                    "timeout": step.timeout,
                })
            }).collect();

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

#[tauri::command]
pub async fn execute_workflow(
    state: tauri::State<'_, AppState>,
    request: WorkflowExecuteRequest,
) -> Result<WorkflowExecuteResponse, String> {
    let execution_id = state.workflow_engine.execute_workflow(
        request.workflow_id,
        request.inputs,
        request.working_directory.unwrap_or_else(|| "./results".to_string()),
    ).await
    .map_err(|e| format!("Failed to execute workflow: {}", e))?;

    Ok(WorkflowExecuteResponse {
        execution_id,
        status: "running".to_string(),
        message: "Workflow execution started".to_string(),
    })
}

#[tauri::command]
pub async fn get_workflow_status(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] executionId: String,
) -> Result<WorkflowStatusResponse, String> {
    let execution = state.workflow_engine.get_execution_status(&executionId).await
        .map_err(|e| format!("Failed to get execution status: {}", e))?
        .ok_or_else(|| format!("Execution '{}' not found", executionId))?;

    Ok(WorkflowStatusResponse {
        execution_id: execution.id,
        status: format!("{:?}", execution.status),
        progress: execution.progress,
        current_step: execution.current_step,
        logs: execution.logs.iter().map(|log| log.message.clone()).collect(),
    })
}

#[tauri::command]
pub async fn stop_workflow_execution(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] executionId: String,
) -> Result<String, String> {
    state.workflow_engine.stop_execution(&executionId).await
        .map_err(|e| format!("Failed to stop execution: {}", e))?;

    Ok("Execution stopped".to_string())
}

// Commands for tool management
#[tauri::command]
pub async fn list_tools(
    #[allow(non_snake_case)] forceRefresh: bool,
    state: tauri::State<'_, AppState>
) -> Result<Vec<crate::tools::discovery::ToolRecord>, String> {
    let discovery_service = state.tool_discovery.read().await;
    
    let tools = discovery_service.get_all_tool_records(forceRefresh).await;
    
    eprintln!("list_tools called: force_refresh={}, found {} tools", forceRefresh, tools.len());
    if tools.len() > 0 {
        eprintln!("First 5 tools: {:?}", tools.iter().take(5).map(|t| &t.name).collect::<Vec<_>>());
    }
    
    Ok(tools)
}

#[tauri::command]
pub async fn get_tool(
    #[allow(non_snake_case)] toolName: String,
    #[allow(non_snake_case)] forceRefresh: bool,
    state: tauri::State<'_, AppState>
) -> Result<Option<crate::tools::discovery::ToolRecord>, String> {
    let discovery_service = state.tool_discovery.read().await;
    
    let tool = discovery_service.get_tool_record(&toolName, forceRefresh).await;
    
    Ok(tool)
}

#[tauri::command]
pub async fn recheck_tool(
    #[allow(non_snake_case)] toolName: String,
    state: tauri::State<'_, AppState>
) -> Result<Option<crate::tools::discovery::ToolRecord>, String> {
    eprintln!("🔄 Rechecking tool: {}", toolName);
    let discovery_service = state.tool_discovery.read().await;
    
    // Get the current cached tool record WITHOUT forcing refresh (avoid cache save that triggers rebuild)
    let mut record = match discovery_service.get_tool_record(&toolName, false).await {
        Some(r) => r,
        None => return Ok(None),
    };
    
    // Manually check if tool is available without saving to cache
    let tool_path = discovery_service.get_tool_path(&toolName).await;
    let tool_available = tool_path.is_some();
    
    // Update the record in memory
    if tool_available {
        record.installed = true;
        record.status = "available".to_string();
        if let Some(path) = tool_path {
            eprintln!("✅ Tool {} found at: {}", toolName, path);
            record.path = Some(path);
        }
    } else {
        eprintln!("⚠️  Tool {} not found on system", toolName);
        record.installed = false;
        record.status = "missing".to_string();
        record.path = None;
    }
    
    record.last_checked = Some(chrono::Utc::now().to_rfc3339());
    
    // Return the updated record WITHOUT saving cache (to avoid triggering dev server reload)
    Ok(Some(record))
}

#[tauri::command]
pub async fn refresh_tools(
    state: tauri::State<'_, AppState>
) -> Result<HashMap<String, crate::tools::discovery::ToolRecord>, String> {
    let discovery_service = state.tool_discovery.read().await;
    
    let results = discovery_service.refresh_all_tools().await;
    
    Ok(results)
}

#[tauri::command]
pub async fn get_tool_categories(
    state: tauri::State<'_, AppState>
) -> Result<Vec<String>, String> {
    let discovery_service = state.tool_discovery.read().await;
    
    let categories = discovery_service.get_categories();
    
    Ok(categories)
}

#[tauri::command]
pub async fn get_tools_by_category(
    category: String,
    state: tauri::State<'_, AppState>
) -> Result<Vec<crate::tools::discovery::ToolRecord>, String> {
    let discovery_service = state.tool_discovery.read().await;
    
    let tools = discovery_service.get_tools_by_category(&category).await;
    
    Ok(tools)
}

#[tauri::command]
pub async fn add_manual_tool(
    #[allow(non_snake_case)] toolName: String,
    #[allow(non_snake_case)] toolPath: String,
    category: String,
    state: tauri::State<'_, AppState>
) -> Result<crate::tools::discovery::ToolRecord, String> {
    let discovery_service = state.tool_discovery.write().await;
    
    let tool = discovery_service.add_manual_tool(&toolName, &toolPath, &category).await
        .map_err(|e| format!("Failed to add manual tool: {}", e))?;
    
    Ok(tool)
}

#[tauri::command]
pub async fn remove_manual_tool(
    #[allow(non_snake_case)] toolName: String,
    state: tauri::State<'_, AppState>
) -> Result<bool, String> {
    let discovery_service = state.tool_discovery.write().await;
    
    let success = discovery_service.remove_manual_tool(&toolName).await
        .map_err(|e| format!("Failed to remove manual tool: {}", e))?;
    
    Ok(success)
}

#[tauri::command]
pub async fn list_manual_tools(
    state: tauri::State<'_, AppState>
) -> Result<Vec<String>, String> {
    let discovery_service = state.tool_discovery.read().await;
    
    let manual_tools = discovery_service.list_manual_tools();
    
    Ok(manual_tools)
}

#[tauri::command]
pub async fn get_available_tools_count(
    state: tauri::State<'_, AppState>
) -> Result<usize, String> {
    let discovery_service = state.tool_discovery.read().await;
    
    let count = discovery_service.get_available_count().await;
    
    Ok(count)
}

// Commands for scan management
#[tauri::command]
pub async fn list_scans(
    state: tauri::State<'_, AppState>
) -> Result<Vec<serde_json::Value>, String> {
    let scans = state.db.list_scans().await
        .map_err(|e| format!("Failed to list scans: {}", e))?;

    let mut scan_data = Vec::new();
    for scan in scans {
        scan_data.push(serde_json::to_value(&scan).unwrap_or_default());
    }

    Ok(scan_data)
}

#[tauri::command]
pub async fn create_scan(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    scan_data: HashMap<String, serde_json::Value>,
) -> Result<String, String> {
    // Extract required fields
    let name = scan_data.get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Unnamed Scan")
        .to_string();

    let target = scan_data.get("target")
        .and_then(|v| v.as_str())
        .ok_or("Target is required")?
        .to_string();

    let scan_type = scan_data.get("scan_type")
        .and_then(|v| v.as_str())
        .unwrap_or("Custom Scan")
        .to_string();

    let workflow_id = scan_data.get("workflow_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let description = scan_data.get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let working_directory = scan_data.get("working_directory")
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

    state.db.create_scan(&scan).await
        .map_err(|e| format!("Failed to create scan: {}", e))?;

    // Emit scan started event
    let event = EventEmitter::scan_started(&scan.id);
    let _ = app.emit_all(SCAN_STARTED, event);

    Ok(scan.id)
}

#[tauri::command]
pub async fn get_scan(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] scanId: String,
) -> Result<Option<serde_json::Value>, String> {
    let scan = state.db.get_scan(&scanId).await
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
    let old_scan = state.db.get_scan(&scan.id).await
        .map_err(|e| format!("Failed to get scan: {}", e))?;

    state.db.update_scan(&scan).await
        .map_err(|e| format!("Failed to update scan: {}", e))?;

    // Emit events based on status changes
    if let Some(old) = old_scan {
        if old.status != scan.status {
            match scan.status.as_str() {
                "completed" => {
                    let event = EventEmitter::scan_completed(&scan.id);
                    let _ = app.emit_all(SCAN_COMPLETED, event);
                }
                "failed" => {
                    let event = EventEmitter::scan_failed(&scan.id);
                    let _ = app.emit_all(SCAN_FAILED, event);
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
                &scan.status
            );
            let _ = app.emit_all(SCAN_PROGRESS_UPDATE, event);
        }
    }

    Ok(())
}

#[tauri::command]
pub async fn delete_scan(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] scanId: String,
) -> Result<(), String> {
    state.db.delete_scan(&scanId).await
        .map_err(|e| format!("Failed to delete scan: {}", e))?;

    Ok(())
}

// Commands for system information
#[tauri::command]
pub async fn get_system_info() -> Result<serde_json::Value, String> {
    use sysinfo::{System, SystemExt};

    let mut sys = System::new_all();
    sys.refresh_all();
    
    let info = serde_json::json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "total_memory_mb": sys.total_memory(),
        "available_memory_mb": sys.available_memory(),
        "cpu_cores": sys.cpus().len()
    });
    
    Ok(info)
}

// Commands for workflow artifacts and findings
#[tauri::command]
pub async fn get_workflow_artifacts(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] executionId: String,
) -> Result<Vec<serde_json::Value>, String> {
    let artifacts = state.db.get_workflow_artifacts(&executionId).await
        .map_err(|e| format!("Failed to get artifacts: {}", e))?;

    let mut artifact_data = Vec::new();
    for artifact in artifacts {
        artifact_data.push(serde_json::to_value(&artifact).unwrap_or_default());
    }

    Ok(artifact_data)
}

#[tauri::command]
pub async fn get_workflow_findings(
    state: tauri::State<'_, AppState>,
    #[allow(non_snake_case)] executionId: String,
) -> Result<Vec<serde_json::Value>, String> {
    let findings = state.db.get_workflow_findings(&executionId).await
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
    state: tauri::State<'_, AppState>
) -> Result<Vec<serde_json::Value>, String> {
    let vulns = state.db.list_vulnerabilities().await
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
    let vulns = state.db.get_vulnerabilities_by_scan(&scan_id).await
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
        scan_id: vuln_data.get("scan_id")
            .and_then(|v| v.as_str())
            .ok_or("scan_id is required")?
            .to_string(),
        title: vuln_data.get("title")
            .and_then(|v| v.as_str())
            .ok_or("title is required")?
            .to_string(),
        severity: vuln_data.get("severity")
            .and_then(|v| v.as_str())
            .ok_or("severity is required")?
            .to_string(),
        cvss: vuln_data.get("cvss")
            .and_then(|v| v.as_f64()),
        description: vuln_data.get("description")
            .and_then(|v| v.as_str())
            .ok_or("description is required")?
            .to_string(),
        url: vuln_data.get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        parameter: vuln_data.get("parameter")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        payload: vuln_data.get("payload")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        remediation: vuln_data.get("remediation")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        discovered_by: vuln_data.get("discovered_by")
            .and_then(|v| v.as_str())
            .ok_or("discovered_by is required")?
            .to_string(),
        timestamp: chrono::Utc::now(),
        false_positive: vuln_data.get("false_positive")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        confirmed: vuln_data.get("confirmed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        evidence: vuln_data.get("evidence")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    };

    state.db.create_vulnerability(&vuln).await
        .map_err(|e| format!("Failed to create vulnerability: {}", e))?;

    Ok(vuln.id)
}

#[tauri::command]
pub async fn delete_vulnerability(
    state: tauri::State<'_, AppState>,
    vuln_id: String,
) -> Result<(), String> {
    state.db.delete_vulnerability(&vuln_id).await
        .map_err(|e| format!("Failed to delete vulnerability: {}", e))?;

    Ok(())
}

// Commands for report management
#[tauri::command]
pub async fn list_reports(
    state: tauri::State<'_, AppState>
) -> Result<Vec<serde_json::Value>, String> {
    let reports = state.db.list_reports().await
        .map_err(|e| format!("Failed to list reports: {}", e))?;

    let mut report_data = Vec::new();
    for report in reports {
        report_data.push(serde_json::to_value(&report).unwrap_or_default());
    }

    Ok(report_data)
}

#[tauri::command]
pub async fn get_report(
    state: tauri::State<'_, AppState>,
    report_id: String,
) -> Result<Option<serde_json::Value>, String> {
    let report = state.db.get_report(&report_id).await
        .map_err(|e| format!("Failed to get report: {}", e))?;

    if let Some(report) = report {
        Ok(Some(serde_json::to_value(&report).unwrap_or_default()))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub async fn create_report(
    state: tauri::State<'_, AppState>,
    report_data: HashMap<String, serde_json::Value>,
) -> Result<String, String> {
    let report = crate::database::Report {
        id: uuid::Uuid::new_v4().to_string(),
        scan_id: report_data.get("scan_id")
            .and_then(|v| v.as_str())
            .ok_or("scan_id is required")?
            .to_string(),
        title: report_data.get("title")
            .and_then(|v| v.as_str())
            .ok_or("title is required")?
            .to_string(),
        content: report_data.get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        format: report_data.get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("html")
            .to_string(),
        created_at: chrono::Utc::now(),
    };

    state.db.create_report(&report).await
        .map_err(|e| format!("Failed to create report: {}", e))?;

    Ok(report.id)
}

#[tauri::command]
pub async fn delete_report(
    state: tauri::State<'_, AppState>,
    report_id: String,
) -> Result<(), String> {
    state.db.delete_report(&report_id).await
        .map_err(|e| format!("Failed to delete report: {}", e))?;

    Ok(())
}

// Commands for statistics
#[tauri::command]
pub async fn get_stats(
    state: tauri::State<'_, AppState>
) -> Result<serde_json::Value, String> {
    let scans = state.db.list_scans().await
        .map_err(|e| format!("Failed to get scans: {}", e))?;
    let vulns = state.db.list_vulnerabilities().await
        .map_err(|e| format!("Failed to get vulnerabilities: {}", e))?;
    
    let discovery_service = state.tool_discovery.read().await;
    let tools = discovery_service.get_all_tool_records(false).await;

    let active_scans = scans.iter().filter(|s| s.status == "running").count();
    let critical_vulns = vulns.iter().filter(|v| v.severity.to_lowercase() == "critical").count();
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
    state: tauri::State<'_, AppState>
) -> Result<serde_json::Value, String> {
    let scans = state.db.list_scans().await
        .map_err(|e| format!("Failed to get scans: {}", e))?;
    let vulns = state.db.list_vulnerabilities().await
        .map_err(|e| format!("Failed to get vulnerabilities: {}", e))?;
    
    let discovery_service = state.tool_discovery.read().await;
    let tools = discovery_service.get_all_tool_records(false).await;

    let total_scans = scans.len();
    let active_scans = scans.iter().filter(|s| s.status == "running").count();
    let completed_scans = scans.iter().filter(|s| s.status == "completed").count();
    let total_vulnerabilities = vulns.len();
    let critical_issues = vulns.iter().filter(|v| v.severity.to_lowercase() == "critical").count();
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
pub async fn detect_package_managers() -> Result<Vec<crate::tools::package_managers::PackageManagerInfo>, String> {
    eprintln!("🔍 Detecting available package managers...");
    
    let managers = crate::tools::package_managers::detect_all_managers().await;
    
    eprintln!("✅ Detection complete:");
    for manager in &managers {
        if manager.available {
            eprintln!("  ✓ {} - v{}", 
                manager.manager_type.display_name(),
                manager.version.as_ref().unwrap_or(&"unknown".to_string())
            );
        } else {
            eprintln!("  ✗ {} - {}", 
                manager.manager_type.display_name(),
                manager.error.as_ref().unwrap_or(&"not found".to_string())
            );
        }
    }
    
    Ok(managers)
}

#[tauri::command]
pub async fn check_package_manager(
    manager_name: String
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
        eprintln!("✅ {} is available (v{})", 
            info.manager_type.display_name(),
            info.version.as_ref().unwrap_or(&"unknown".to_string())
        );
    } else {
        eprintln!("❌ {} is not available: {}", 
            info.manager_type.display_name(),
            info.error.as_ref().unwrap_or(&"not found".to_string())
        );
    }
    
    Ok(info)
}

// Package Manager Installation Commands

#[tauri::command]
pub async fn install_package_manager_pipx() -> Result<crate::tools::package_managers::InstallationResult, String> {
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
pub async fn install_package_manager_go() -> Result<crate::tools::package_managers::InstallationResult, String> {
    eprintln!("📦 Installing Go...");
    
    #[cfg(target_os = "windows")]
    let result = crate::tools::package_managers::install_go_windows().await?;
    
    #[cfg(not(target_os = "windows"))]
    {
        return Err("Go installation on Linux should be done via APT. Use: sudo apt install golang-go".to_string());
    }
    
    if result.success {
        eprintln!("✅ Go installation completed");
    } else {
        eprintln!("❌ Go installation failed: {}", result.message);
    }
    
    Ok(result)
}

#[tauri::command]
pub async fn install_package_manager_apt(package_name: String) -> Result<crate::tools::package_managers::InstallationResult, String> {
    eprintln!("📦 Installing APT package: {}", package_name);
    
    #[cfg(not(target_os = "linux"))]
    {
        return Err("APT is only available on Linux systems".to_string());
    }
    
    #[cfg(target_os = "linux")]
    {
        let result = crate::tools::package_managers::install_apt_package(&package_name).await?;
        
        if result.success {
            eprintln!("✅ APT package installed");
        } else {
            eprintln!("❌ APT installation failed: {}", result.message);
        }
        
        Ok(result)
    }
}

#[tauri::command]
pub async fn install_package_manager_winget() -> Result<crate::tools::package_managers::InstallationResult, String> {
    eprintln!("📦 Opening WinGet installation page...");
    
    #[cfg(target_os = "windows")]
    let result = crate::tools::package_managers::install_winget_windows().await?;
    
    #[cfg(not(target_os = "windows"))]
    {
        return Err("WinGet is only available on Windows systems".to_string());
    }
    
    if result.success {
        eprintln!("✅ Microsoft Store opened");
    } else {
        eprintln!("❌ Failed to open Store: {}", result.message);
    }
    
    Ok(result)
}

// Tool Installation Commands (Phase 7)

#[tauri::command]
pub async fn install_tool(
    #[allow(non_snake_case)] toolName: String,
    state: tauri::State<'_, AppState>
) -> Result<InstallationResult, String> {
    eprintln!("📦 Installing tool: {}", toolName);
    
    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog.get(&toolName)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", toolName))?;
    
    eprintln!("   Installation method: {}", tool_def.install_method);
    
    // Route to appropriate installer based on install_method
    match tool_def.install_method.as_str() {
        "go" => {
            // Install via Go
            let go_module = tool_def.go_module.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no go_module defined", toolName))?;
            
            eprintln!("   Go module: {}", go_module);
            
            let manager = GoInstallManager::new();
            
            if !manager.is_go_available().await {
                return Err("Go is not installed. Please install Go first.".to_string());
            }
            
            let go_result = manager.install(go_module, &toolName).await?;
            
            if go_result.success {
                eprintln!("✅ Successfully installed {}", toolName);
                
                // Trigger tool recheck to update UI
                let _ = recheck_tool(toolName.clone(), state).await;
            } else {
                eprintln!("❌ Failed to install {}: {}", toolName, go_result.message);
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
            let pipx_package = tool_def.pipx_package.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no pipx_package defined", toolName))?;
            
            eprintln!("   Pipx package: {}", pipx_package);
            
            let manager = crate::tools::package_managers::PipxManager::new();
            
            if !manager.is_pipx_available().await {
                return Err("pipx is not installed. Please install pipx first.".to_string());
            }
            
            let pipx_result = manager.install(pipx_package, &toolName).await?;
            
            if pipx_result.success {
                eprintln!("✅ Successfully installed {}", toolName);
                let _ = recheck_tool(toolName.clone(), state).await;
            } else {
                eprintln!("❌ Failed to install {}: {}", toolName, pipx_result.message);
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
                .ok_or_else(|| format!("Tool '{}' has no apt_package defined", toolName))?;
            
            eprintln!("   APT package: {}", apt_package);
            
            let manager = crate::tools::package_managers::AptManager::new();
            
            if !manager.is_apt_available().await {
                return Err("apt is not available. This system is not Debian/Ubuntu-based.".to_string());
            }
            
            let apt_result = manager.install(apt_package, &toolName).await?;
            
            if apt_result.success {
                eprintln!("✅ Successfully installed {}", toolName);
                let _ = recheck_tool(toolName.clone(), state).await;
            } else {
                eprintln!("❌ Failed to install {}: {}", toolName, apt_result.message);
            }
            
            Ok(InstallationResult {
                success: apt_result.success,
                message: apt_result.message,
                steps: vec![],
                requires_restart: false,
            })
        },
        "winget" => {
            let winget_id = tool_def.winget_id.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no winget_id defined", toolName))?;
            
            eprintln!("   WinGet ID: {}", winget_id);
            
            let manager = crate::tools::package_managers::WingetManager::new();
            
            if !manager.is_winget_available().await {
                return Err("winget is not installed. Please install App Installer from Microsoft Store.".to_string());
            }
            
            let winget_result = manager.install(winget_id, &toolName).await?;
            
            if winget_result.success {
                eprintln!("✅ Successfully installed {}", toolName);
                let _ = recheck_tool(toolName.clone(), state).await;
            } else {
                eprintln!("❌ Failed to install {}: {}", toolName, winget_result.message);
            }
            
            Ok(InstallationResult {
                success: winget_result.success,
                message: winget_result.message,
                steps: vec![],
                requires_restart: false,
            })
        },
        "manual" => {
            Err(format!("Tool '{}' requires manual installation. Check documentation.", toolName))
        },
        "runtime" => {
            Err(format!("Tool '{}' is a runtime environment (e.g. Python, Node.js). Install via system package manager.", toolName))
        },
        _ => {
            Err(format!("Unknown installation method '{}' for tool '{}'", tool_def.install_method, toolName))
        }
    }
}

#[tauri::command]
pub async fn update_tool(
    #[allow(non_snake_case)] toolName: String,
    state: tauri::State<'_, AppState>
) -> Result<InstallationResult, String> {
    eprintln!("🔄 Updating tool: {}", toolName);
    
    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog.get(&toolName)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", toolName))?;
    
    eprintln!("   Installation method: {}", tool_def.install_method);
    
    // Route to appropriate installer
    match tool_def.install_method.as_str() {
        "go" => {
            let go_module = tool_def.go_module.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no go_module defined", toolName))?;
            
            let manager = GoInstallManager::new();
            
            if !manager.is_go_available().await {
                return Err("Go is not installed. Please install Go first.".to_string());
            }
            
            let go_result = manager.update(go_module, &toolName).await?;
            
            if go_result.success {
                eprintln!("✅ Successfully updated {}", toolName);
                
                // Trigger tool recheck
                let _ = recheck_tool(toolName.clone(), state).await;
            } else {
                eprintln!("❌ Failed to update {}: {}", toolName, go_result.message);
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
            let pipx_package = tool_def.pipx_package.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no pipx_package defined", toolName))?;
            
            let manager = crate::tools::package_managers::PipxManager::new();
            
            if !manager.is_pipx_available().await {
                return Err("pipx is not installed.".to_string());
            }
            
            let pipx_result = manager.update(pipx_package, &toolName).await?;
            
            if pipx_result.success {
                eprintln!("✅ Successfully updated {}", toolName);
                let _ = recheck_tool(toolName.clone(), state).await;
            } else {
                eprintln!("❌ Failed to update {}: {}", toolName, pipx_result.message);
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
                .ok_or_else(|| format!("Tool '{}' has no apt_package defined", toolName))?;
            
            let manager = crate::tools::package_managers::AptManager::new();
            
            if !manager.is_apt_available().await {
                return Err("apt is not available.".to_string());
            }
            
            let apt_result = manager.update(apt_package, &toolName).await?;
            
            if apt_result.success {
                eprintln!("✅ Successfully updated {}", toolName);
                let _ = recheck_tool(toolName.clone(), state).await;
            } else {
                eprintln!("❌ Failed to update {}: {}", toolName, apt_result.message);
            }
            
            Ok(InstallationResult {
                success: apt_result.success,
                message: apt_result.message,
                steps: vec![],
                requires_restart: false,
            })
        },
        "winget" => {
            let winget_id = tool_def.winget_id.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no winget_id defined", toolName))?;
            
            let manager = crate::tools::package_managers::WingetManager::new();
            
            if !manager.is_winget_available().await {
                return Err("winget is not installed.".to_string());
            }
            
            let winget_result = manager.update(winget_id, &toolName).await?;
            
            if winget_result.success {
                eprintln!("✅ Successfully updated {}", toolName);
                let _ = recheck_tool(toolName.clone(), state).await;
            } else {
                eprintln!("❌ Failed to update {}: {}", toolName, winget_result.message);
            }
            
            Ok(InstallationResult {
                success: winget_result.success,
                message: winget_result.message,
                steps: vec![],
                requires_restart: false,
            })
        },
        _ => {
            Err(format!("Cannot update tool '{}' with install method '{}'", toolName, tool_def.install_method))
        }
    }
}

#[tauri::command]
pub async fn uninstall_tool(
    #[allow(non_snake_case)] toolName: String,
    state: tauri::State<'_, AppState>
) -> Result<String, String> {
    eprintln!("🗑️  Uninstalling tool: {}", toolName);
    
    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog.get(&toolName)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", toolName))?;
    
    // Route to appropriate installer
    match tool_def.install_method.as_str() {
        "go" => {
            let manager = GoInstallManager::new();
            
            let message = manager.uninstall(&toolName).await?;
            
            eprintln!("✅ {}", message);
            
            // Trigger tool recheck
            let _ = recheck_tool(toolName.clone(), state).await;
            
            Ok(message)
        },
        "pipx" => {
            let pipx_package = tool_def.pipx_package.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no pipx_package defined", toolName))?;
            
            let manager = crate::tools::package_managers::PipxManager::new();
            
            let message = manager.uninstall(pipx_package, &toolName).await?;
            
            eprintln!("✅ {}", message);
            
            let _ = recheck_tool(toolName.clone(), state).await;
            
            Ok(message)
        },
        "apt" => {
            let apt_package = tool_def.apt_package.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no apt_package defined", toolName))?;
            
            let manager = crate::tools::package_managers::AptManager::new();
            
            let message = manager.uninstall(apt_package, &toolName).await?;
            
            eprintln!("✅ {}", message);
            
            let _ = recheck_tool(toolName.clone(), state).await;
            
            Ok(message)
        },
        "winget" => {
            let winget_id = tool_def.winget_id.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no winget_id defined", toolName))?;
            
            let manager = crate::tools::package_managers::WingetManager::new();
            
            let message = manager.uninstall(winget_id, &toolName).await?;
            
            eprintln!("✅ {}", message);
            
            let _ = recheck_tool(toolName.clone(), state).await;
            
            Ok(message)
        },
        _ => {
            Err(format!("Cannot uninstall tool '{}' with install method '{}'", toolName, tool_def.install_method))
        }
    }
}

#[tauri::command]
pub async fn check_tool_installed(
    #[allow(non_snake_case)] toolName: String,
    _state: tauri::State<'_, AppState>
) -> Result<bool, String> {
    eprintln!("🔍 Checking if tool is installed: {}", toolName);
    
    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog.get(&toolName)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", toolName))?;
    
    // Route to appropriate installer
    match tool_def.install_method.as_str() {
        "go" => {
            let manager = GoInstallManager::new();
            let installed = manager.is_installed(&toolName);
            
            eprintln!("   Installed: {}", installed);
            
            Ok(installed)
        },
        "pipx" => {
            Err(format!("pipx check not yet implemented for '{}'", toolName))
        },
        _ => {
            // For other methods, assume not installed via this command
            Ok(false)
        }
    }
}

#[tauri::command]
pub async fn get_tool_version(
    #[allow(non_snake_case)] toolName: String,
    _state: tauri::State<'_, AppState>
) -> Result<Option<String>, String> {
    eprintln!("🔍 Getting tool version: {}", toolName);
    
    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog.get(&toolName)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", toolName))?;
    
    // Route to appropriate installer
    match tool_def.install_method.as_str() {
        "go" => {
            let manager = GoInstallManager::new();
            let version = manager.get_version(&toolName).await;
            
            if let Some(ref v) = version {
                eprintln!("   Version: {}", v);
            } else {
                eprintln!("   Version: unknown");
            }
            
            Ok(version)
        },
        _ => {
            Ok(None)
        }
    }
}

#[tauri::command]
pub async fn check_tool_update(
    #[allow(non_snake_case)] toolName: String,
    _state: tauri::State<'_, AppState>
) -> Result<VersionCheckResult, String> {
    eprintln!("🔄 Checking for updates: {}", toolName);
    
    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog.get(&toolName)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", toolName))?;
    
    // Route to appropriate version checker based on install method
    match tool_def.install_method.as_str() {
        "go" => {
            let manager = GoInstallManager::new();
            
            // Get the binary path
            let binary_path = manager.get_tool_path(&toolName)
                .ok_or_else(|| format!("Tool '{}' is not installed", toolName))?;
            
            // Get the go module path
            let module_path = tool_def.go_module.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no go_module defined", toolName))?;
            
            // Check for updates using go version -m and go list -m -versions
            let result = crate::tools::package_managers::check_go_update(&binary_path, module_path).await?;
            
            if result.has_update {
                eprintln!("   ⬆️  Update available: {} -> {}", 
                    result.current_version.as_ref().unwrap_or(&"unknown".to_string()),
                    result.latest_version.as_ref().unwrap_or(&"unknown".to_string())
                );
            } else {
                eprintln!("   ✅ Up to date: {}", 
                    result.current_version.as_ref().unwrap_or(&"unknown".to_string())
                );
            }
            
            Ok(result)
        },
        "apt" => {
            let package_name = tool_def.apt_package.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no apt_package defined", toolName))?;
            
            let result = crate::tools::package_managers::check_apt_update(package_name).await?;
            
            if result.has_update {
                eprintln!("   ⬆️  Update available: {} -> {}", 
                    result.current_version.as_ref().unwrap_or(&"unknown".to_string()),
                    result.latest_version.as_ref().unwrap_or(&"unknown".to_string())
                );
            }
            
            Ok(result)
        },
        "winget" => {
            let winget_id = tool_def.winget_id.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no winget_id defined", toolName))?;
            
            let result = crate::tools::package_managers::check_winget_update(winget_id).await?;
            
            if result.has_update {
                eprintln!("   ⬆️  Update available: {} -> {}", 
                    result.current_version.as_ref().unwrap_or(&"unknown".to_string()),
                    result.latest_version.as_ref().unwrap_or(&"unknown".to_string())
                );
            }
            
            Ok(result)
        },
        "pipx" => {
            let package_name = tool_def.pipx_package.as_ref()
                .ok_or_else(|| format!("Tool '{}' has no pipx_package defined", toolName))?;
            
            let result = crate::tools::package_managers::check_pipx_update(package_name).await?;
            
            if result.has_update {
                eprintln!("   ⬆️  Update available: {} -> {}", 
                    result.current_version.as_ref().unwrap_or(&"unknown".to_string()),
                    result.latest_version.as_ref().unwrap_or(&"unknown".to_string())
                );
            }
            
            Ok(result)
        },
        _ => {
            Err(format!("Version check not supported for install method '{}'", tool_def.install_method))
        }
    }
}

#[tauri::command]
pub async fn get_tool_installation_info(
    #[allow(non_snake_case)] toolName: String,
    _state: tauri::State<'_, AppState>
) -> Result<serde_json::Value, String> {
    eprintln!("ℹ️  Getting installation info for: {}", toolName);
    
    // Look up tool in catalog
    let catalog = get_tool_catalog();
    let tool_def = catalog.get(&toolName)
        .ok_or_else(|| format!("Tool '{}' not found in catalog", toolName))?;
    
    let info = serde_json::json!({
        "name": tool_def.name,
        "install_method": tool_def.install_method,
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
pub async fn check_elevation_support() -> Result<crate::tools::package_managers::ElevationMethod, String> {
    eprintln!("🔐 Checking elevation support...");
    let method = crate::tools::package_managers::check_elevation_support().await;
    eprintln!("✓ Elevation method: {:?}", method);
    Ok(method)
}

#[tauri::command]
pub async fn execute_elevated_command(
    command: String,
    args: Vec<String>,
    timeout_secs: u64,
) -> Result<crate::tools::package_managers::ElevationResult, String> {
    eprintln!("🔐 Executing elevated command: {} {:?}", command, args);
    
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = crate::tools::package_managers::execute_elevated(
        &command,
        &args_refs,
        timeout_secs
    ).await?;
    
    if result.success {
        eprintln!("✅ Elevated command succeeded");
    } else {
        eprintln!("❌ Elevated command failed");
    }
    
    Ok(result)
}

#[tauri::command]
pub async fn try_command_with_elevation(
    command: String,
    args: Vec<String>,
    reason: String,
    timeout_secs: u64,
) -> Result<crate::tools::package_managers::ElevationResult, String> {
    eprintln!("🔐 Trying command with smart elevation: {} {:?}", command, args);
    eprintln!("   Reason: {}", reason);
    
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    
    match crate::tools::package_managers::execute_with_smart_elevation(
        &command,
        &args_refs,
        &reason,
        timeout_secs
    ).await {
        Ok(result) => Ok(result),
        Err(e) if e.starts_with("ELEVATION_REQUIRED:") => {
            // Return error to frontend so it can show dialog
            Err(e)
        },
        Err(e) => Err(e)
    }
}

