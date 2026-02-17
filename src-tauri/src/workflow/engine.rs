use super::{loader::WorkflowLoader, types::*};
use crate::{adapters::*, runtime::executor::*, tools::registry::*};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

/// Workflow execution engine implementing DAG scheduling and state management
pub struct WorkflowEngine {
    loader: WorkflowLoader,
    tool_registry: Arc<ToolRegistry>,
    active_executions: Arc<RwLock<HashMap<ExecutionId, WorkflowExecution>>>,
    execution_sender: broadcast::Sender<ExecutionEvent>,
    _execution_receiver: broadcast::Receiver<ExecutionEvent>,
}

impl WorkflowEngine {
    /// Create a new workflow engine
    pub fn new() -> Self {
        let (execution_sender, execution_receiver) = broadcast::channel(1000);
        let loader = WorkflowLoader::new().expect("Failed to create workflow loader");
        let tool_registry = Arc::new(ToolRegistry::new());

        Self {
            loader,
            tool_registry,
            active_executions: Arc::new(RwLock::new(HashMap::new())),
            execution_sender,
            _execution_receiver: execution_receiver,
        }
    }

    /// Get the execution event broadcaster
    pub fn get_event_sender(&self) -> broadcast::Sender<ExecutionEvent> {
        self.execution_sender.clone()
    }

    /// Load all workflow templates
    pub async fn load_workflow_templates(&self) -> Result<Vec<WorkflowTemplate>> {
        self.loader.load_workflow_templates().await
    }

    /// Execute a workflow with the given inputs
    pub async fn execute_workflow(
        &self,
        template_id: WorkflowId,
        inputs: HashMap<String, String>,
        working_directory: String,
    ) -> Result<ExecutionId> {
        // Load the workflow template
        let templates = self.load_workflow_templates().await?;
        let template = self.loader.get_workflow_template(&templates, &template_id)
            .ok_or_else(|| anyhow!("Workflow template '{}' not found", template_id))?
            .clone();

        // Check compatibility
        let compatibility = self.loader.check_workflow_compatibility(&template, &self.tool_registry).await?;
        if !compatibility.compatible {
            return Err(anyhow!("Workflow '{}' is not compatible: missing tools: {:?}",
                template_id, compatibility.missing_tools));
        }

        // Create execution instance
        let execution_id = Uuid::new_v4();
        let mut execution = WorkflowExecution {
            id: execution_id,
            template_id: template.id.clone(),
            name: template.name.clone(),
            status: ExecutionStatus::Pending,
            inputs,
            outputs: HashMap::new(),
            step_states: HashMap::new(),
            started_at: None,
            finished_at: None,
            error_message: None,
            working_directory: working_directory.clone(),
            current_step: None,
            progress: 0.0,
        };

        // Initialize step states
        for step in &template.steps {
            execution.step_states.insert(step.id.clone(), StepState {
                step_id: step.id.clone(),
                status: StepStatus::Pending,
                started_at: None,
                finished_at: None,
                exit_code: None,
                error_message: None,
                retry_count: 0,
                stdout_lines: Vec::new(),
                stderr_lines: Vec::new(),
                artifacts: Vec::new(),
            });
        }

        // Store execution
        self.active_executions.write().await.insert(execution_id, execution.clone());

        // Start execution in background
        let engine = Arc::new(unsafe { std::ptr::read(self as *const Self) });
        tokio::spawn(async move {
            engine.run_workflow(execution_id, template, working_directory).await;
        });

        info!("Started workflow execution: {} ({})", template.name, execution_id);
        Ok(execution_id)
    }

    /// Run the workflow execution (internal method)
    async fn run_workflow(
        self: Arc<Self>,
        execution_id: ExecutionId,
        template: WorkflowTemplate,
        working_directory: String,
    ) {
        info!("Running workflow: {} ({})", template.name, execution_id);

        // Update execution status to running
        self.update_execution_status(execution_id, ExecutionStatus::Running, None).await;

        // Build DAG and find ready steps
        let mut dag = self.build_dag(&template.steps);
        let mut ready_steps = self.find_ready_steps(&template.steps, &dag);

        let mut completed_steps = 0;
        let total_steps = template.steps.len();

        while !ready_steps.is_empty() {
            let step_id = ready_steps.pop_front().unwrap();
            let step = template.steps.iter().find(|s| s.id == step_id).unwrap();

            info!("Executing step: {} ({})", step.name, step.id);

            // Update current step
            self.update_current_step(execution_id, Some(step.id.clone())).await;

            // Execute the step
            let step_result = self.execute_step(&template, step, &working_directory).await;

            // Update step state
            self.update_step_state(execution_id, &step.id, step_result).await;

            // Check if step failed and should not continue
            if !step.continue_on_error {
                if let Some(step_state) = self.get_step_state(execution_id, &step.id).await {
                    if step_state.status == StepStatus::Failed {
                        error!("Step '{}' failed and continue_on_error is false, stopping workflow", step.id);
                        self.update_execution_status(execution_id, ExecutionStatus::Failed, Some("Step failed".to_string())).await;
                        return;
                    }
                }
            }

            completed_steps += 1;
            let progress = (completed_steps as f32 / total_steps as f32) * 100.0;
            self.update_progress(execution_id, progress).await;

            // Find next ready steps
            for other_step in &template.steps {
                if self.is_step_ready(other_step, &dag, &template.steps) && !ready_steps.contains(&other_step.id) {
                    ready_steps.push_back(other_step.id.clone());
                }
            }
        }

        // Workflow completed
        self.update_execution_status(execution_id, ExecutionStatus::Completed, None).await;
        info!("Workflow completed: {} ({})", template.name, execution_id);
    }

    /// Execute a single workflow step
    async fn execute_step(
        &self,
        template: &WorkflowTemplate,
        step: &WorkflowStep,
        working_directory: &str,
    ) -> StepResult {
        let start_time = Utc::now();

        // Get tool information
        let tool = match self.tool_registry.get_tool(&step.tool).await {
            Ok(tool) => tool,
            Err(_) => {
                return StepResult {
                    status: StepStatus::Failed,
                    exit_code: Some(1),
                    error_message: Some(format!("Tool '{}' not found", step.tool)),
                    stdout_lines: Vec::new(),
                    stderr_lines: Vec::new(),
                    artifacts: Vec::new(),
                };
            }
        };

        if !tool.available {
            return StepResult {
                status: StepStatus::Failed,
                exit_code: Some(1),
                error_message: Some(format!("Tool '{}' is not available", step.tool)),
                stdout_lines: Vec::new(),
                stderr_lines: Vec::new(),
                artifacts: Vec::new(),
            };
        }

        // Build command arguments
        let argv = self.build_step_argv(step, template, working_directory);

        // Create process executor
        let mut executor = ProcessExecutor::new()
            .with_command(&tool.path)
            .with_args(argv)
            .with_cwd(working_directory)
            .with_timeout_ms(step.timeout_ms.unwrap_or(300000)) // 5 minutes default
            .with_environment(step.environment.clone());

        // Execute the step
        match executor.execute().await {
            Ok(result) => {
                let duration = Utc::now().signed_duration_since(start_time).num_milliseconds() as u64;

                info!("Step '{}' completed successfully in {}ms", step.id, duration);

                StepResult {
                    status: StepStatus::Completed,
                    exit_code: Some(result.exit_code),
                    error_message: None,
                    stdout_lines: result.stdout_lines,
                    stderr_lines: result.stderr_lines,
                    artifacts: result.artifacts,
                }
            }
            Err(e) => {
                warn!("Step '{}' failed: {}", step.id, e);

                StepResult {
                    status: StepStatus::Failed,
                    exit_code: Some(1),
                    error_message: Some(e.to_string()),
                    stdout_lines: Vec::new(),
                    stderr_lines: Vec::new(),
                    artifacts: Vec::new(),
                }
            }
        }
    }

    /// Build command arguments for a step
    fn build_step_argv(
        &self,
        step: &WorkflowStep,
        template: &WorkflowTemplate,
        working_directory: &str,
    ) -> Vec<String> {
        let mut argv = Vec::new();

        // Add base arguments
        argv.extend(step.argv.iter().cloned());

        // Substitute input variables
        for arg in &mut argv {
            // Replace {{input.variable}} with actual input values
            if arg.starts_with("{{input.") && arg.ends_with("}}") {
                let var_name = &arg[8..arg.len()-2]; // Remove {{input. and }}
                if let Some(value) = template.inputs.get(var_name) {
                    if let Some(input_value) = template.inputs.get(var_name).and_then(|_| template.inputs.get(var_name)) {
                        // This is a simplified substitution - in reality you'd want more sophisticated templating
                        *arg = input_value.default.clone().unwrap_or_else(|| format!("${}", var_name));
                    }
                }
            }

            // Replace {{output.step_id.output_name}} with step outputs
            if arg.starts_with("{{output.") && arg.contains('.')} && arg.ends_with("}}") {
                // This would need more complex parsing for nested references
                *arg = arg.replace("{{output.", "${").replace("}}", "}");
            }
        }

        argv
    }

    /// Build DAG from workflow steps
    fn build_dag(&self, steps: &[WorkflowStep]) -> HashMap<String, Vec<String>> {
        let mut dag = HashMap::new();

        for step in steps {
            dag.entry(step.id.clone()).or_insert_with(Vec::new);
            for need in &step.needs {
                dag.entry(need.clone()).or_insert_with(Vec::new).push(step.id.clone());
            }
        }

        dag
    }

    /// Find steps that are ready to execute
    fn find_ready_steps(&self, steps: &[WorkflowStep], dag: &HashMap<String, Vec<String>>) -> VecDeque<String> {
        let mut ready = VecDeque::new();

        for step in steps {
            if step.needs.is_empty() {
                ready.push_back(step.id.clone());
            }
        }

        ready
    }

    /// Check if a step is ready to execute
    fn is_step_ready(&self, step: &WorkflowStep, dag: &HashMap<String, Vec<String>>, all_steps: &[WorkflowStep]) -> bool {
        for need in &step.needs {
            if let Some(step_state) = self.get_step_state_from_dag(need, dag, all_steps) {
                if step_state.status != StepStatus::Completed {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }

    /// Get step state from DAG (simplified - in reality would check execution state)
    fn get_step_state_from_dag(&self, step_id: &str, _dag: &HashMap<String, Vec<String>>, _all_steps: &[WorkflowStep]) -> Option<&StepState> {
        // This is a simplified version - in reality would check the execution state
        None
    }

    /// Update execution status
    async fn update_execution_status(&self, execution_id: ExecutionId, status: ExecutionStatus, error_message: Option<String>) {
        if let Some(execution) = self.active_executions.write().await.get_mut(&execution_id) {
            execution.status = status.clone();
            execution.error_message = error_message;

            if matches!(status, ExecutionStatus::Running) && execution.started_at.is_none() {
                execution.started_at = Some(Utc::now());
            }

            if matches!(status, ExecutionStatus::Completed | ExecutionStatus::Failed | ExecutionStatus::Cancelled) {
                execution.finished_at = Some(Utc::now());
            }

            // Emit event
            let _ = self.execution_sender.send(ExecutionEvent {
                execution_id,
                event_type: ExecutionEventType::StatusChanged,
                timestamp: Utc::now(),
                data: serde_json::json!({
                    "status": status,
                    "error_message": execution.error_message
                }),
            });
        }
    }

    /// Update current executing step
    async fn update_current_step(&self, execution_id: ExecutionId, step_id: Option<String>) {
        if let Some(execution) = self.active_executions.write().await.get_mut(&execution_id) {
            execution.current_step = step_id.clone();

            // Emit event
            let _ = self.execution_sender.send(ExecutionEvent {
                execution_id,
                event_type: ExecutionEventType::StepChanged,
                timestamp: Utc::now(),
                data: serde_json::json!({
                    "current_step": step_id
                }),
            });
        }
    }

    /// Update execution progress
    async fn update_progress(&self, execution_id: ExecutionId, progress: f32) {
        if let Some(execution) = self.active_executions.write().await.get_mut(&execution_id) {
            execution.progress = progress;

            // Emit event
            let _ = self.execution_sender.send(ExecutionEvent {
                execution_id,
                event_type: ExecutionEventType::ProgressUpdated,
                timestamp: Utc::now(),
                data: serde_json::json!({
                    "progress": progress
                }),
            });
        }
    }

    /// Update step state
    async fn update_step_state(&self, execution_id: ExecutionId, step_id: &str, result: StepResult) {
        if let Some(execution) = self.active_executions.write().await.get_mut(&execution_id) {
            if let Some(step_state) = execution.step_states.get_mut(step_id) {
                step_state.status = result.status.clone();
                step_state.exit_code = result.exit_code;
                step_state.error_message = result.error_message;
                step_state.stdout_lines = result.stdout_lines;
                step_state.stderr_lines = result.stderr_lines;
                step_state.artifacts = result.artifacts;

                if matches!(result.status, StepStatus::Running) && step_state.started_at.is_none() {
                    step_state.started_at = Some(Utc::now());
                }

                if matches!(result.status, StepStatus::Completed | StepStatus::Failed | StepStatus::Cancelled) {
                    step_state.finished_at = Some(Utc::now());
                }

                // Emit event
                let _ = self.execution_sender.send(ExecutionEvent {
                    execution_id,
                    event_type: ExecutionEventType::StepCompleted,
                    timestamp: Utc::now(),
                    data: serde_json::json!({
                        "step_id": step_id,
                        "status": result.status,
                        "exit_code": result.exit_code,
                        "stdout_lines_count": result.stdout_lines.len(),
                        "stderr_lines_count": result.stderr_lines.len(),
                        "artifacts_count": result.artifacts.len()
                    }),
                });
            }
        }
    }

    /// Get step state
    async fn get_step_state(&self, execution_id: ExecutionId, step_id: &str) -> Option<StepState> {
        self.active_executions.read().await
            .get(&execution_id)?
            .step_states
            .get(step_id)
            .cloned()
    }

    /// Get execution status
    pub async fn get_execution_status(&self, execution_id: ExecutionId) -> Option<WorkflowExecution> {
        self.active_executions.read().await.get(&execution_id).cloned()
    }

    /// Cancel a running execution
    pub async fn cancel_execution(&self, execution_id: ExecutionId) -> Result<()> {
        self.update_execution_status(execution_id, ExecutionStatus::Cancelled, Some("Cancelled by user".to_string())).await;
        Ok(())
    }
}

/// Step execution result
#[derive(Debug, Clone)]
struct StepResult {
    status: StepStatus,
    exit_code: Option<i32>,
    error_message: Option<String>,
    stdout_lines: Vec<String>,
    stderr_lines: Vec<String>,
    artifacts: Vec<ExecutionArtifact>,
}

/// Execution events for real-time updates
#[derive(Debug, Clone)]
pub struct ExecutionEvent {
    pub execution_id: ExecutionId,
    pub event_type: ExecutionEventType,
    pub timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
}

/// Types of execution events
#[derive(Debug, Clone)]
pub enum ExecutionEventType {
    StatusChanged,
    StepChanged,
    ProgressUpdated,
    StepCompleted,
    StepOutput,
    ExecutionCompleted,
    ExecutionFailed,
}

impl Default for WorkflowEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_workflow_engine_creation() {
        let engine = WorkflowEngine::new();
        assert!(engine.load_workflow_templates().await.is_ok());
    }
}