use super::types::*;
use crate::{workflow::*, tools::*};
use tauri::State;
use anyhow::{anyhow, Result};
use log::{info, warn};
use std::collections::HashMap;
use uuid::Uuid;

/// Get all workflow templates
#[tauri::command]
pub async fn get_workflow_templates(
    include_compatibility: bool,
    state: State<'_, WorkflowEngine>,
) -> Result<Vec<WorkflowTemplate>> {
    info!("Getting workflow templates (compatibility: {})", include_compatibility);

    let mut templates = state.load_workflow_templates().await?;

    if include_compatibility {
        // Check compatibility for each template
        let tool_registry = ToolRegistry::new();
        tool_registry.initialize().await?;

        for template in &mut templates {
            match state.get_loader().check_workflow_compatibility(template, &tool_registry).await {
                Ok(compatibility) => {
                    template.compatibility = Some(compatibility);
                }
                Err(e) => {
                    warn!("Failed to check compatibility for workflow {}: {}", template.id, e);
                }
            }
        }
    }

    Ok(templates)
}

/// Get workflow template by ID
#[tauri::command]
pub async fn get_workflow_template(
    id: String,
    state: State<'_, WorkflowEngine>,
) -> Result<Option<WorkflowTemplate>> {
    info!("Getting workflow template: {}", id);

    let templates = state.load_workflow_templates().await?;
    let template = templates.iter().find(|t| t.id == id).cloned();
    Ok(template)
}

/// Execute a workflow
#[tauri::command]
pub async fn execute_workflow(
    workflow_id: String,
    inputs: HashMap<String, String>,
    working_directory: Option<String>,
    state: State<'_, WorkflowEngine>,
) -> Result<String> {
    info!("Executing workflow: {} with inputs: {:?}", workflow_id, inputs);

    let workdir = working_directory.unwrap_or_else(|| {
        format!("./results/workflow_{}_{}",
            workflow_id,
            chrono::Utc::now().timestamp()
        )
    });

    // Ensure working directory exists
    std::fs::create_dir_all(&workdir)?;

    let execution_id = state.execute_workflow(workflow_id, inputs, workdir).await?;

    info!("Workflow execution started: {}", execution_id);
    Ok(execution_id.to_string())
}

/// Get workflow execution status
#[tauri::command]
pub async fn get_workflow_status(
    execution_id: String,
    state: State<'_, WorkflowEngine>,
) -> Result<Option<WorkflowExecution>> {
    info!("Getting workflow status for execution: {}", execution_id);

    let execution_uuid = Uuid::parse_str(&execution_id)
        .map_err(|_| anyhow!("Invalid execution ID format"))?;

    let status = state.get_execution_status(execution_uuid).await;
    Ok(status)
}

/// Cancel a workflow execution
#[tauri::command]
pub async fn cancel_workflow(
    execution_id: String,
    state: State<'_, WorkflowEngine>,
) -> Result<()> {
    info!("Cancelling workflow execution: {}", execution_id);

    let execution_uuid = Uuid::parse_str(&execution_id)
        .map_err(|_| anyhow!("Invalid execution ID format"))?;

    state.cancel_execution(execution_uuid).await?;
    info!("Workflow execution cancelled: {}", execution_id);
    Ok(())
}

/// Get workflow execution logs
#[tauri::command]
pub async fn get_workflow_logs(
    execution_id: String,
    state: State<'_, WorkflowEngine>,
) -> Result<Vec<String>> {
    info!("Getting workflow logs for execution: {}", execution_id);

    let execution_uuid = Uuid::parse_str(&execution_id)
        .map_err(|_| anyhow!("Invalid execution ID format"))?;

    if let Some(execution) = state.get_execution_status(execution_uuid).await {
        // Collect logs from all steps
        let mut all_logs = Vec::new();

        for (step_id, step_state) in execution.step_states {
            all_logs.extend(step_state.stdout_lines);
            all_logs.extend(step_state.stderr_lines);
        }

        Ok(all_logs)
    } else {
        Ok(Vec::new())
    }
}

/// Get workflow execution artifacts
#[tauri::command]
pub async fn get_workflow_artifacts(
    execution_id: String,
    state: State<'_, WorkflowEngine>,
) -> Result<Vec<ExecutionArtifact>> {
    info!("Getting workflow artifacts for execution: {}", execution_id);

    let execution_uuid = Uuid::parse_str(&execution_id)
        .map_err(|_| anyhow!("Invalid execution ID format"))?;

    if let Some(execution) = state.get_execution_status(execution_uuid).await {
        // Collect artifacts from all steps
        let mut all_artifacts = Vec::new();

        for step_state in execution.step_states.values() {
            all_artifacts.extend(step_state.artifacts.clone());
        }

        Ok(all_artifacts)
    } else {
        Ok(Vec::new())
    }
}

/// Get available workflow categories
#[tauri::command]
pub async fn get_workflow_categories() -> Result<Vec<String>> {
    let loader = WorkflowLoader::new().unwrap();
    let categories = loader.get_workflow_categories();
    Ok(categories.iter().map(|s| s.to_string()).collect())
}

/// Validate workflow inputs against template
#[tauri::command]
pub async fn validate_workflow_inputs(
    workflow_id: String,
    inputs: HashMap<String, String>,
    state: State<'_, WorkflowEngine>,
) -> Result<Vec<String>> {
    info!("Validating inputs for workflow: {}", workflow_id);

    let templates = state.load_workflow_templates().await?;
    let template = templates.iter().find(|t| t.id == workflow_id)
        .ok_or_else(|| anyhow!("Workflow template '{}' not found", workflow_id))?;

    let mut errors = Vec::new();

    // Check required inputs
    for (input_name, input_def) in &template.inputs {
        if input_def.required {
            if !inputs.contains_key(input_name) || inputs[input_name].is_empty() {
                errors.push(format!("Required input '{}' is missing or empty", input_name));
            }
        }

        // Validate input format if validation rules exist
        if let Some(validation) = &input_def.validation {
            if let Some(input_value) = inputs.get(input_name) {
                if let Some(pattern) = &validation.pattern {
                    if let Ok(regex) = regex::Regex::new(pattern) {
                        if !regex.is_match(input_value) {
                            errors.push(format!("Input '{}' does not match required pattern '{}'", input_name, pattern));
                        }
                    }
                }

                if let Some(max_length) = validation.max_length {
                    if input_value.len() > max_length {
                        errors.push(format!("Input '{}' exceeds maximum length of {}", input_name, max_length));
                    }
                }

                if let Some(allowed_values) = &validation.allowed_values {
                    if !allowed_values.contains(&input_value.as_str()) {
                        errors.push(format!("Input '{}' must be one of: {:?}", input_name, allowed_values));
                    }
                }
            }
        }
    }

    // Check for unknown inputs
    for input_name in inputs.keys() {
        if !template.inputs.contains_key(input_name) {
            errors.push(format!("Unknown input parameter: '{}'", input_name));
        }
    }

    Ok(errors)
}