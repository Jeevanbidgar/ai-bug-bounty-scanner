use anyhow::{anyhow, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::events::{
    EventEmitter, WORKFLOW_EXECUTION_COMPLETED, WORKFLOW_EXECUTION_FAILED,
    WORKFLOW_EXECUTION_STARTED, WORKFLOW_STATUS_UPDATE, WORKFLOW_STEP_COMPLETED,
    WORKFLOW_STEP_FAILED, WORKFLOW_STEP_STARTED,
};
use crate::runtime::executor::ProcessExecutor;
use crate::tools::discovery::ToolDiscoveryService;
use crate::workflow::artifacts::ArtifactManager;
use crate::workflow::types::{
    ExecutionLog, ExecutionStatus, LogLevel, StepExecution, StepStatus, WorkflowArtifact,
    WorkflowExecution, WorkflowTemplate,
};

#[derive(Clone)]
pub struct WorkflowEngine {
    app_handle: AppHandle,
    active_executions: Arc<RwLock<HashMap<String, WorkflowExecution>>>,
    executor: ProcessExecutor,
    artifact_manager: Arc<ArtifactManager>,
}

impl WorkflowEngine {
    pub fn new(
        app_handle: AppHandle,
        tool_discovery: Arc<RwLock<ToolDiscoveryService>>,
        artifacts_dir: PathBuf,
    ) -> Self {
        let artifact_manager = Arc::new(
            ArtifactManager::new(artifacts_dir)
                .with_max_age(30) // Keep artifacts for 30 days
                .with_max_size(100_000_000), // 100 MB per artifact
        );

        Self {
            app_handle: app_handle.clone(),
            active_executions: Arc::new(RwLock::new(HashMap::new())),
            executor: ProcessExecutor::new(app_handle, tool_discovery, artifact_manager.clone()),
            artifact_manager,
        }
    }

    pub async fn execute_workflow(
        &self,
        workflow_id: String,
        inputs: HashMap<String, String>,
        working_directory: String,
    ) -> Result<String> {
        // Load workflow template
        let workflow_loader = crate::workflow::loader::WorkflowLoader::new("app/workflows");
        let workflow = workflow_loader.load_workflow(&workflow_id).await?;

        // Create execution record
        let execution_id = Uuid::new_v4().to_string();
        let execution = WorkflowExecution {
            id: execution_id.clone(),
            scan_id: None,
            workflow_id: workflow.id.clone(),
            status: ExecutionStatus::Pending,
            started: Utc::now(),
            completed: None,
            current_step: None,
            progress: 0,
            inputs,
            working_directory: working_directory.clone(),
            logs: vec![],
            steps: HashMap::new(),
            updated_at: Utc::now(),
        };

        // Store in active executions
        let mut active_executions = self.active_executions.write().await;
        active_executions.insert(execution_id.clone(), execution.clone());
        drop(active_executions); // Release lock

        // Emit execution started event
        let event = EventEmitter::workflow_execution_started(
            &execution_id,
            &workflow.name,
            execution.inputs.clone(),
            &working_directory,
        );
        let _ = self.app_handle.emit(WORKFLOW_EXECUTION_STARTED, event);

        // Execute workflow in background
        let engine_clone = self.clone();
        let execution_id_clone = execution_id.clone();
        tokio::spawn(async move {
            if let Err(e) = engine_clone
                .execute_workflow_async(execution_id_clone, workflow, working_directory)
                .await
            {
                eprintln!("Workflow execution failed: {}", e);
            }
        });

        Ok(execution_id)
    }

    async fn execute_workflow_async(
        &self,
        execution_id: String,
        workflow: WorkflowTemplate,
        working_directory: String,
    ) -> Result<()> {
        // Update execution status to running
        self.update_execution_status(
            &execution_id,
            ExecutionStatus::Running,
            Some("Initializing"),
            0,
        )
        .await?;

        // Execute DAG
        let result = self
            .execute_dag(execution_id.clone(), workflow, working_directory)
            .await;

        match result {
            Ok(_) => {
                // Update execution status to completed
                self.update_execution_status(&execution_id, ExecutionStatus::Completed, None, 100)
                    .await?;

                // Emit completion event
                let event = crate::events::WorkflowEvent {
                    execution_id: execution_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                };
                let _ = self.app_handle.emit(WORKFLOW_EXECUTION_COMPLETED, event);
            }
            Err(e) => {
                // Update execution status to failed
                self.update_execution_status(
                    &execution_id,
                    ExecutionStatus::Failed,
                    Some(&e.to_string()),
                    0,
                )
                .await?;

                // Emit failure event
                let event = crate::events::WorkflowEvent {
                    execution_id: execution_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                };
                let _ = self.app_handle.emit(WORKFLOW_EXECUTION_FAILED, event);

                return Err(e);
            }
        }

        Ok(())
    }

    async fn execute_dag(
        &self,
        execution_id: String,
        workflow: WorkflowTemplate,
        working_directory: String,
    ) -> Result<()> {
        let mut completed_steps = std::collections::HashSet::new();
        let mut step_executions = HashMap::new();
        let total_steps = workflow.steps.len() as u32;

        loop {
            // Find ready steps
            let ready_steps = self.get_ready_steps(&workflow.steps, &completed_steps)?;

            if ready_steps.is_empty() {
                break; // All steps completed
            }

            // Execute ready steps concurrently
            let mut handles = Vec::new();
            for step_id in ready_steps {
                if let Some(step) = workflow.steps.iter().find(|s| s.id == step_id) {
                    let engine_clone = self.clone();
                    let execution_id_clone = execution_id.clone();
                    let step_clone = step.clone();
                    let working_directory_clone = working_directory.clone();
                    let inputs_clone = workflow.inputs.clone();

                    let handle = tokio::spawn(async move {
                        engine_clone
                            .execute_step(
                                &step_clone,
                                &execution_id_clone,
                                &working_directory_clone,
                                &inputs_clone,
                            )
                            .await
                    });

                    handles.push((step_id, handle));
                }
            }

            // Wait for all steps to complete
            for (step_id, handle) in handles {
                // Emit step started event
                let step_name = workflow
                    .steps
                    .iter()
                    .find(|s| s.id == step_id)
                    .map(|s| s.name.clone())
                    .unwrap_or_else(|| step_id.clone());

                let event =
                    EventEmitter::workflow_step_started(&execution_id, &step_id, &step_name);
                let _ = self.app_handle.emit(WORKFLOW_STEP_STARTED, event);

                match handle.await {
                    Ok(Ok(artifacts)) => {
                        completed_steps.insert(step_id.clone());

                        // Update step execution record
                        let step_execution = StepExecution {
                            step_id: step_id.clone(),
                            status: StepStatus::Completed,
                            started: Some(Utc::now()),
                            completed: Some(Utc::now()),
                            exit_code: Some(0),
                            stdout: vec![],
                            stderr: vec![],
                            artifacts: artifacts.clone(),
                        };
                        step_executions.insert(step_id.clone(), step_execution);

                        // Emit step completed event
                        let event = EventEmitter::workflow_step_completed(
                            &execution_id,
                            &step_id,
                            0,
                            artifacts.len(),
                        );
                        let _ = self.app_handle.emit(WORKFLOW_STEP_COMPLETED, event);

                        // Update progress
                        let progress = (completed_steps.len() as u32 * 100) / total_steps;
                        self.update_execution_progress(&execution_id, progress)
                            .await?;
                    }
                    Ok(Err(e)) => {
                        eprintln!("Step '{}' failed: {}", step_id, e);

                        // Mark step as failed
                        let step_execution = StepExecution {
                            step_id: step_id.clone(),
                            status: StepStatus::Failed,
                            started: Some(Utc::now()),
                            completed: Some(Utc::now()),
                            exit_code: Some(-1),
                            stdout: vec![],
                            stderr: vec![e.to_string()],
                            artifacts: vec![],
                        };
                        step_executions.insert(step_id.clone(), step_execution);

                        // Emit step failed event
                        let event = EventEmitter::workflow_step_started(
                            &execution_id,
                            &step_id,
                            &step_name,
                        );
                        let _ = self.app_handle.emit(WORKFLOW_STEP_FAILED, event);

                        // Update execution status to failed
                        self.update_execution_status(
                            &execution_id,
                            ExecutionStatus::Failed,
                            Some(&format!("Step '{}' failed", step_id)),
                            0,
                        )
                        .await?;
                        return Err(e);
                    }
                    Err(e) => {
                        eprintln!("Step '{}' task failed: {}", step_id, e);
                        return Err(anyhow!("Step execution task failed: {}", e));
                    }
                }
            }
        }

        // Update final execution state
        let mut active_executions = self.active_executions.write().await;
        if let Some(execution) = active_executions.get_mut(&execution_id) {
            execution.status = ExecutionStatus::Completed;
            execution.completed = Some(Utc::now());
            execution.steps = step_executions;
            execution.updated_at = Utc::now();
        }

        Ok(())
    }

    fn get_ready_steps(
        &self,
        steps: &[crate::workflow::types::WorkflowStep],
        completed: &std::collections::HashSet<String>,
    ) -> Result<Vec<String>> {
        let mut ready_steps = Vec::new();

        for step in steps {
            if completed.contains(&step.id) {
                continue; // Already completed
            }

            // Check if all dependencies are completed
            let all_deps_completed = step.needs.iter().all(|dep| completed.contains(dep));

            if all_deps_completed {
                ready_steps.push(step.id.clone());
            }
        }

        Ok(ready_steps)
    }

    async fn execute_step(
        &self,
        step: &crate::workflow::types::WorkflowStep,
        execution_id: &str,
        working_directory: &str,
        inputs: &HashMap<String, String>,
    ) -> Result<Vec<WorkflowArtifact>> {
        self.executor
            .execute_step(step, execution_id, working_directory, inputs)
            .await
    }

    async fn update_execution_status(
        &self,
        execution_id: &str,
        status: ExecutionStatus,
        current_step: Option<&str>,
        progress: u32,
    ) -> Result<()> {
        let mut active_executions = self.active_executions.write().await;
        if let Some(execution) = active_executions.get_mut(execution_id) {
            execution.status = status.clone();
            execution.current_step = current_step.map(|s| s.to_string());
            execution.progress = progress;
            execution.updated_at = Utc::now();

            // Add log entry
            execution.logs.push(ExecutionLog {
                timestamp: Utc::now(),
                level: LogLevel::Info,
                message: format!("Status updated to {:?}", status),
                step_id: current_step.map(|s| s.to_string()),
            });
        }
        drop(active_executions); // Release lock

        // Emit status update event
        let event = EventEmitter::workflow_status_update(
            execution_id,
            &format!("{:?}", status),
            progress,
            current_step.map(|s| s.to_string()),
        );
        let _ = self.app_handle.emit(WORKFLOW_STATUS_UPDATE, event);

        Ok(())
    }

    async fn update_execution_progress(&self, execution_id: &str, progress: u32) -> Result<()> {
        let mut active_executions = self.active_executions.write().await;
        if let Some(execution) = active_executions.get_mut(execution_id) {
            execution.progress = progress;
            execution.updated_at = Utc::now();
        }

        // Emit progress update event
        let _ = self.app_handle.emit(
            "workflow:progress_update",
            serde_json::json!({
                "execution_id": execution_id,
                "progress": progress,
                "timestamp": Utc::now().to_rfc3339()
            }),
        );

        Ok(())
    }

    pub async fn get_execution_status(
        &self,
        execution_id: &str,
    ) -> Result<Option<WorkflowExecution>> {
        let active_executions = self.active_executions.read().await;
        Ok(active_executions.get(execution_id).cloned())
    }

    pub async fn list_executions(&self) -> Result<Vec<WorkflowExecution>> {
        let active_executions = self.active_executions.read().await;
        Ok(active_executions.values().cloned().collect())
    }

    pub async fn stop_execution(&self, execution_id: &str) -> Result<()> {
        let mut active_executions = self.active_executions.write().await;
        if let Some(execution) = active_executions.get_mut(execution_id) {
            execution.status = ExecutionStatus::Cancelled;
            execution.completed = Some(Utc::now());
            execution.updated_at = Utc::now();

            // Add log entry
            execution.logs.push(ExecutionLog {
                timestamp: Utc::now(),
                level: LogLevel::Info,
                message: "Execution cancelled by user".to_string(),
                step_id: None,
            });
        }

        // Emit cancellation event
        let _ = self.app_handle.emit(
            "workflow:execution_cancelled",
            serde_json::json!({
                "execution_id": execution_id,
                "timestamp": Utc::now().to_rfc3339()
            }),
        );

        Ok(())
    }
}
