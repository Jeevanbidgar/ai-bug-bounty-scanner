use anyhow::{anyhow, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{watch, RwLock};
use uuid::Uuid;

const DEFAULT_WEB_WORDLIST: &str =
    include_str!("../../../app/resources/wordlists/common-web-paths.txt");

use crate::events::{
    EventEmitter, SharedEventSink, SCAN_CANCELLED, SCAN_COMPLETED, SCAN_ERROR, SCAN_FAILED,
    SCAN_PROGRESS_UPDATE, SCAN_STARTED, WORKFLOW_EXECUTION_CANCELLED, WORKFLOW_EXECUTION_COMPLETED,
    WORKFLOW_EXECUTION_FAILED, WORKFLOW_EXECUTION_STARTED, WORKFLOW_STATUS_UPDATE,
    WORKFLOW_STEP_COMPLETED, WORKFLOW_STEP_FAILED, WORKFLOW_STEP_STARTED,
};
use crate::runtime::executor::{ProcessExecutor, StepOutcome};
use crate::settings::AppSettings;
use crate::tools::discovery::ToolDiscoveryService;
use crate::workflow::artifacts::ArtifactManager;
use crate::workflow::types::{
    ExecutionLog, ExecutionStatus, LogLevel, StepExecution, StepStatus, WorkflowArtifact,
    WorkflowExecution, WorkflowTemplate,
};

use crate::database::Database;
use crate::database::WorkflowExecutionGovernance;
use crate::tools::parsers::ParsedFinding;
use crate::tools::parsers::ParserRegistry;

pub trait ExecutionGuard: Send + Sync {
    fn validate(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

#[derive(Clone)]
pub struct WorkflowEngine {
    events: SharedEventSink,
    active_executions: Arc<RwLock<HashMap<String, WorkflowExecution>>>,
    cancellations: Arc<RwLock<HashMap<String, watch::Sender<bool>>>>,
    workflows_dir: PathBuf,
    executor: ProcessExecutor,
    _artifact_manager: Arc<ArtifactManager>,
    db: Arc<Database>,
    parser_registry: Arc<ParserRegistry>,
    settings: Arc<RwLock<AppSettings>>,
}

impl WorkflowEngine {
    pub fn new(
        events: SharedEventSink,
        tool_discovery: Arc<RwLock<ToolDiscoveryService>>,
        artifacts_dir: PathBuf,
        workflows_dir: PathBuf,
        db: Arc<Database>,
        settings: Arc<RwLock<AppSettings>>,
    ) -> Self {
        let artifact_manager = Arc::new(
            ArtifactManager::new(artifacts_dir)
                .with_max_age(30) // Keep artifacts for 30 days
                .with_max_size(100_000_000), // 100 MB per artifact
        );

        Self {
            events: events.clone(),
            active_executions: Arc::new(RwLock::new(HashMap::new())),
            cancellations: Arc::new(RwLock::new(HashMap::new())),
            workflows_dir,
            executor: ProcessExecutor::new(
                events,
                tool_discovery,
                artifact_manager.clone(),
                settings.clone(),
            ),
            _artifact_manager: artifact_manager,
            db,
            parser_registry: Arc::new(ParserRegistry::new()),
            settings,
        }
    }

    pub async fn execute_workflow(
        &self,
        workflow_id: String,
        inputs: HashMap<String, String>,
        working_directory: String,
        scan_id: Option<String>,
    ) -> Result<String> {
        let workflow_loader =
            crate::workflow::loader::WorkflowLoader::new(self.workflows_dir.clone());
        let workflow = workflow_loader.load_workflow(&workflow_id).await?;

        let max_parallel_steps = self.settings.read().await.max_parallel_steps;
        self.start_workflow(
            Uuid::new_v4().to_string(),
            workflow,
            inputs,
            working_directory,
            scan_id,
            None,
            max_parallel_steps,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn execute_workflow_revision(
        &self,
        execution_id: String,
        workflow: WorkflowTemplate,
        inputs: HashMap<String, String>,
        working_directory: String,
        scan_id: Option<String>,
        governance: WorkflowExecutionGovernance,
        max_parallel_steps: usize,
        guard: Arc<dyn ExecutionGuard>,
    ) -> Result<String> {
        self.start_workflow(
            execution_id,
            workflow,
            inputs,
            working_directory,
            scan_id,
            Some(governance),
            max_parallel_steps,
            Some(guard),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_workflow(
        &self,
        execution_id: String,
        workflow: WorkflowTemplate,
        inputs: HashMap<String, String>,
        working_directory: String,
        scan_id: Option<String>,
        governance: Option<WorkflowExecutionGovernance>,
        max_parallel_steps: usize,
        guard: Option<Arc<dyn ExecutionGuard>>,
    ) -> Result<String> {
        if max_parallel_steps == 0 {
            return Err(anyhow!("Execution parallelism must be at least one"));
        }

        let requested_directory = PathBuf::from(working_directory);
        let absolute_directory = if requested_directory.is_absolute() {
            requested_directory
        } else {
            std::env::current_dir()?.join(requested_directory)
        };
        tokio::fs::create_dir_all(&absolute_directory).await?;
        let working_directory = tokio::fs::canonicalize(&absolute_directory)
            .await?
            .to_string_lossy()
            .to_string();

        // Request values override template defaults. Always expose the
        // canonical working directory so command output paths do not get
        // duplicated when the process also uses it as current_dir.
        let mut resolved_inputs = workflow.inputs.clone();
        resolved_inputs.extend(inputs);
        resolved_inputs.insert("workdir".to_string(), working_directory.clone());
        let support_dir = PathBuf::from(&working_directory).join(".unihack");
        tokio::fs::create_dir_all(&support_dir).await?;
        let wordlist_path = support_dir.join("common-web-paths.txt");
        tokio::fs::write(&wordlist_path, DEFAULT_WEB_WORDLIST).await?;
        resolved_inputs.insert(
            "wordlist".to_string(),
            wordlist_path.to_string_lossy().to_string(),
        );

        for variable in ["url", "domain", "host"] {
            if Self::workflow_uses_variable(&workflow, variable)
                && !resolved_inputs.contains_key(variable)
            {
                return Err(anyhow!(
                    "Workflow '{}' requires a {}-compatible target",
                    workflow.id,
                    variable
                ));
            }
        }

        // Create execution record
        let execution = WorkflowExecution {
            id: execution_id.clone(),
            scan_id,
            workflow_id: workflow.id.clone(),
            status: ExecutionStatus::Pending,
            started: Utc::now(),
            completed: None,
            current_step: None,
            progress: 0,
            inputs: resolved_inputs.clone(),
            working_directory: working_directory.clone(),
            logs: vec![],
            steps: HashMap::new(),
            updated_at: Utc::now(),
        };

        let database_execution = Self::database_execution(&execution)?;
        if let Some(governance) = &governance {
            self.db
                .create_governed_workflow_execution(&database_execution, governance)
                .await?;
        } else {
            self.db
                .create_workflow_execution(&database_execution)
                .await?;
        }

        self.active_executions
            .write()
            .await
            .insert(execution_id.clone(), execution.clone());

        let (cancellation_tx, cancellation_rx) = watch::channel(false);
        self.cancellations
            .write()
            .await
            .insert(execution_id.clone(), cancellation_tx);

        // Emit execution started event
        let event = EventEmitter::workflow_execution_started(
            &execution_id,
            &workflow.name,
            execution.inputs.clone(),
            &working_directory,
        );
        let _ = self.events.emit(WORKFLOW_EXECUTION_STARTED, event);
        if let Some(scan_id) = execution.scan_id.as_deref() {
            let _ = self
                .events
                .emit(SCAN_STARTED, EventEmitter::scan_started(scan_id));
        }

        // Execute workflow in background
        let engine_clone = self.clone();
        let execution_id_clone = execution_id.clone();
        let workflow_guard = guard.clone();
        tokio::spawn(async move {
            if let Err(e) = engine_clone
                .execute_workflow_async(
                    execution_id_clone,
                    workflow,
                    resolved_inputs,
                    working_directory,
                    cancellation_rx,
                    max_parallel_steps,
                    workflow_guard,
                )
                .await
            {
                eprintln!("Workflow execution failed: {}", e);
            }
        });

        if let Some(guard) = guard {
            let engine_clone = self.clone();
            let monitored_execution_id = execution_id.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    if !engine_clone
                        .cancellations
                        .read()
                        .await
                        .contains_key(&monitored_execution_id)
                    {
                        break;
                    }
                    if engine_clone
                        .enforce_execution_guard(&monitored_execution_id, &guard)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }

        Ok(execution_id)
    }

    fn workflow_uses_variable(
        workflow: &crate::workflow::types::WorkflowTemplate,
        variable: &str,
    ) -> bool {
        let token = format!("{{{{{}}}}}", variable);
        workflow.steps.iter().any(|step| {
            step.run.iter().any(|value| value.contains(&token))
                || step
                    .stdin
                    .as_ref()
                    .is_some_and(|value| value.contains(&token))
                || step
                    .env
                    .as_ref()
                    .is_some_and(|env| env.values().any(|value| value.contains(&token)))
                || step
                    .outputs
                    .iter()
                    .any(|output| output.path.contains(&token))
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_workflow_async(
        &self,
        execution_id: String,
        workflow: WorkflowTemplate,
        inputs: HashMap<String, String>,
        working_directory: String,
        cancellation: watch::Receiver<bool>,
        max_parallel_steps: usize,
        guard: Option<Arc<dyn ExecutionGuard>>,
    ) -> Result<()> {
        if let Some(guard) = &guard {
            self.enforce_execution_guard(&execution_id, guard).await?;
        }
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
            .execute_dag(
                execution_id.clone(),
                workflow,
                inputs,
                working_directory,
                cancellation.clone(),
                max_parallel_steps,
                guard,
            )
            .await;

        match result {
            Ok(_) => {
                if *cancellation.borrow() {
                    self.update_execution_status(
                        &execution_id,
                        ExecutionStatus::Cancelled,
                        None,
                        0,
                    )
                    .await?;
                    let event = crate::events::WorkflowEvent {
                        execution_id: execution_id.clone(),
                        timestamp: Utc::now().to_rfc3339(),
                    };
                    let _ = self.events.emit(WORKFLOW_EXECUTION_CANCELLED, event);
                    self.cancellations.write().await.remove(&execution_id);
                    return Ok(());
                }

                // Update execution status to completed
                self.update_execution_status(&execution_id, ExecutionStatus::Completed, None, 100)
                    .await?;

                // Emit completion event
                let event = crate::events::WorkflowEvent {
                    execution_id: execution_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                };
                let _ = self.events.emit(WORKFLOW_EXECUTION_COMPLETED, event);
            }
            Err(e) => {
                if *cancellation.borrow() {
                    self.update_execution_status(
                        &execution_id,
                        ExecutionStatus::Cancelled,
                        None,
                        0,
                    )
                    .await?;
                    let event = crate::events::WorkflowEvent {
                        execution_id: execution_id.clone(),
                        timestamp: Utc::now().to_rfc3339(),
                    };
                    let _ = self.events.emit(WORKFLOW_EXECUTION_CANCELLED, event);
                    self.cancellations.write().await.remove(&execution_id);
                    return Ok(());
                }

                self.append_execution_log(&execution_id, LogLevel::Error, e.to_string(), None)
                    .await?;

                // Update execution status to failed
                self.update_execution_status(&execution_id, ExecutionStatus::Failed, None, 0)
                    .await?;

                // Emit failure event
                let event = crate::events::WorkflowEvent {
                    execution_id: execution_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                };
                let _ = self.events.emit(WORKFLOW_EXECUTION_FAILED, event);

                self.cancellations.write().await.remove(&execution_id);
                return Err(e);
            }
        }

        self.cancellations.write().await.remove(&execution_id);

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_dag(
        &self,
        execution_id: String,
        workflow: WorkflowTemplate,
        inputs: HashMap<String, String>,
        working_directory: String,
        cancellation: watch::Receiver<bool>,
        max_parallel_steps: usize,
        guard: Option<Arc<dyn ExecutionGuard>>,
    ) -> Result<()> {
        let mut completed_steps = std::collections::HashSet::new();
        let mut step_executions = HashMap::new();
        let mut artifacts_by_step: HashMap<String, Vec<WorkflowArtifact>> = HashMap::new();
        let total_steps = workflow.steps.len() as u32;

        loop {
            if *cancellation.borrow() {
                return Err(anyhow!("Execution cancelled"));
            }
            if let Some(guard) = &guard {
                self.enforce_execution_guard(&execution_id, guard).await?;
            }

            // Find ready steps
            let ready_steps = self
                .get_ready_steps(&workflow.steps, &completed_steps)?
                .into_iter()
                .take(max_parallel_steps)
                .collect::<Vec<_>>();

            if ready_steps.is_empty() {
                if completed_steps.len() == workflow.steps.len() {
                    break;
                }
                return Err(anyhow!(
                    "Workflow cannot make progress because its dependency graph is invalid"
                ));
            }

            let current_steps = ready_steps
                .iter()
                .filter_map(|step_id| workflow.steps.iter().find(|step| step.id == *step_id))
                .map(|step| step.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let current_progress = (completed_steps.len() as u32 * 100) / total_steps;
            self.update_execution_status(
                &execution_id,
                ExecutionStatus::Running,
                Some(&current_steps),
                current_progress,
            )
            .await?;

            // Execute ready steps concurrently
            for step_id in &ready_steps {
                step_executions.insert(
                    step_id.clone(),
                    StepExecution {
                        step_id: step_id.clone(),
                        status: StepStatus::Running,
                        started: Some(Utc::now()),
                        completed: None,
                        exit_code: None,
                        stdout: vec![],
                        stderr: vec![],
                        artifacts: vec![],
                    },
                );
            }
            self.store_step_executions(&execution_id, &step_executions)
                .await?;

            let (layer_cancellation_tx, layer_cancellation_rx) = watch::channel(false);
            let mut handles = Vec::new();
            for step_id in ready_steps {
                if let Some(guard) = &guard {
                    self.enforce_execution_guard(&execution_id, guard).await?;
                }
                if let Some(step) = workflow.steps.iter().find(|s| s.id == step_id) {
                    let engine_clone = self.clone();
                    let execution_id_clone = execution_id.clone();
                    let step_clone = step.clone();
                    let working_directory_clone = working_directory.clone();
                    let inputs_clone = inputs.clone();
                    let artifacts_clone = artifacts_by_step.clone();
                    let cancellation_clone = Self::merge_cancellation(
                        cancellation.clone(),
                        layer_cancellation_rx.clone(),
                    );

                    let event =
                        EventEmitter::workflow_step_started(&execution_id, &step.id, &step.name);
                    let _ = self.events.emit(WORKFLOW_STEP_STARTED, event);

                    let handle = tokio::spawn(async move {
                        engine_clone
                            .execute_step(
                                &step_clone,
                                &execution_id_clone,
                                &working_directory_clone,
                                &inputs_clone,
                                &artifacts_clone,
                                cancellation_clone,
                            )
                            .await
                    });

                    handles.push((step_id, handle));
                }
            }

            // Wait for all steps to complete
            let mut layer_error = None;
            for (step_id, handle) in handles {
                let step_opt = workflow.steps.iter().find(|s| s.id == step_id);
                let step_name = step_opt
                    .map(|s| s.name.clone())
                    .unwrap_or_else(|| step_id.clone());

                match handle.await {
                    Ok(Ok(outcome)) => {
                        let StepOutcome {
                            artifacts,
                            exit_code,
                            stdout,
                            stderr,
                            started_at,
                            completed_at,
                        } = outcome;

                        for artifact in &artifacts {
                            self.save_artifact(artifact).await?;
                        }

                        let successful_exit =
                            step_opt.is_some_and(|step| step.is_success_exit_code(exit_code));
                        if !successful_exit {
                            let error_message =
                                format!("Step '{}' exited with code {}", step_id, exit_code);
                            let step_execution = StepExecution {
                                step_id: step_id.clone(),
                                status: StepStatus::Failed,
                                started: Some(started_at),
                                completed: Some(completed_at),
                                exit_code: Some(exit_code),
                                stdout,
                                stderr,
                                artifacts,
                            };
                            step_executions.insert(step_id.clone(), step_execution);
                            self.store_step_executions(&execution_id, &step_executions)
                                .await?;

                            let event = EventEmitter::workflow_step_failed(
                                &execution_id,
                                &step_id,
                                &step_name,
                                &error_message,
                            );
                            let _ = self.events.emit(WORKFLOW_STEP_FAILED, event);
                            if layer_error.is_none() {
                                layer_error = Some(anyhow!(error_message));
                                let _ = layer_cancellation_tx.send(true);
                            }
                            continue;
                        }

                        // Parse registered machine-readable artifacts before treating the step as
                        // complete. A schema or persistence failure must not become a false-clean
                        // scan; the raw artifact remains available for diagnosis.
                        let mut postprocess_error = None;
                        if let Some(step) = step_opt {
                            let tool_name = step.run.first().map(|s| s.as_str()).unwrap_or("");
                            if let Some(parser) = self.parser_registry.get_parser(tool_name) {
                                for artifact in &artifacts {
                                    if let Some(path_str) = &artifact.file_path {
                                        let path = std::path::Path::new(path_str);
                                        if parser.can_parse(path) {
                                            match parser.parse(path) {
                                                Ok(findings) => {
                                                    eprintln!(
                                                        "✅ Parsed {} findings from {}",
                                                        findings.len(),
                                                        path_str
                                                    );
                                                    if let Err(e) = self
                                                        .save_findings(
                                                            &execution_id,
                                                            &step_id,
                                                            tool_name,
                                                            findings,
                                                        )
                                                        .await
                                                    {
                                                        postprocess_error = Some(anyhow!(
                                                            "Failed to save findings from '{}': {}",
                                                            path_str,
                                                            e
                                                        ));
                                                        break;
                                                    }
                                                }
                                                Err(e) => {
                                                    postprocess_error = Some(anyhow!(
                                                        "Failed to parse artifact '{}': {}",
                                                        path_str,
                                                        e
                                                    ));
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if let Some(error) = postprocess_error {
                            let error_message = error.to_string();
                            let mut failed_stderr = stderr;
                            failed_stderr.push(error_message.clone());
                            let step_execution = StepExecution {
                                step_id: step_id.clone(),
                                status: StepStatus::Failed,
                                started: Some(started_at),
                                completed: Some(completed_at),
                                exit_code: Some(exit_code),
                                stdout,
                                stderr: failed_stderr,
                                artifacts,
                            };
                            step_executions.insert(step_id.clone(), step_execution);
                            self.store_step_executions(&execution_id, &step_executions)
                                .await?;

                            let event = EventEmitter::workflow_step_failed(
                                &execution_id,
                                &step_id,
                                &step_name,
                                &error_message,
                            );
                            let _ = self.events.emit(WORKFLOW_STEP_FAILED, event);
                            if layer_error.is_none() {
                                layer_error = Some(error);
                                let _ = layer_cancellation_tx.send(true);
                            }
                            continue;
                        }

                        completed_steps.insert(step_id.clone());

                        // Update step execution record
                        let step_execution = StepExecution {
                            step_id: step_id.clone(),
                            status: StepStatus::Completed,
                            started: Some(started_at),
                            completed: Some(completed_at),
                            exit_code: Some(exit_code),
                            stdout,
                            stderr,
                            artifacts: artifacts.clone(),
                        };
                        step_executions.insert(step_id.clone(), step_execution);
                        artifacts_by_step.insert(step_id.clone(), artifacts.clone());
                        self.store_step_executions(&execution_id, &step_executions)
                            .await?;

                        // Emit step completed event
                        let event = EventEmitter::workflow_step_completed(
                            &execution_id,
                            &step_id,
                            &step_name,
                            exit_code,
                            artifacts.len(),
                        );
                        let _ = self.events.emit(WORKFLOW_STEP_COMPLETED, event);

                        // Update progress
                        let progress = (completed_steps.len() as u32 * 100) / total_steps;
                        self.update_execution_progress(&execution_id, progress)
                            .await?;
                    }
                    Ok(Err(e)) => {
                        eprintln!("Step '{}' failed: {}", step_id, e);
                        let error_message = e.to_string();

                        // Mark step as failed
                        let step_execution = StepExecution {
                            step_id: step_id.clone(),
                            status: StepStatus::Failed,
                            started: Some(Utc::now()),
                            completed: Some(Utc::now()),
                            exit_code: Some(-1),
                            stdout: vec![],
                            stderr: vec![error_message.clone()],
                            artifacts: vec![],
                        };
                        step_executions.insert(step_id.clone(), step_execution);
                        self.store_step_executions(&execution_id, &step_executions)
                            .await?;

                        // Emit step failed event
                        let event = EventEmitter::workflow_step_failed(
                            &execution_id,
                            &step_id,
                            &step_name,
                            &error_message,
                        );
                        let _ = self.events.emit(WORKFLOW_STEP_FAILED, event);

                        if layer_error.is_none() {
                            layer_error = Some(e);
                            let _ = layer_cancellation_tx.send(true);
                        }
                    }
                    Err(e) => {
                        eprintln!("Step '{}' task failed: {}", step_id, e);
                        let error_message = format!("Step execution task failed: {}", e);
                        let step_execution = StepExecution {
                            step_id: step_id.clone(),
                            status: StepStatus::Failed,
                            started: Some(Utc::now()),
                            completed: Some(Utc::now()),
                            exit_code: Some(-1),
                            stdout: vec![],
                            stderr: vec![error_message.clone()],
                            artifacts: vec![],
                        };
                        step_executions.insert(step_id.clone(), step_execution);
                        self.store_step_executions(&execution_id, &step_executions)
                            .await?;

                        let event = EventEmitter::workflow_step_failed(
                            &execution_id,
                            &step_id,
                            &step_name,
                            &error_message,
                        );
                        let _ = self.events.emit(WORKFLOW_STEP_FAILED, event);
                        if layer_error.is_none() {
                            layer_error = Some(anyhow!(error_message));
                            let _ = layer_cancellation_tx.send(true);
                        }
                    }
                }
            }

            if let Some(error) = layer_error {
                return Err(error);
            }
        }

        // Update final execution state
        let mut active_executions = self.active_executions.write().await;
        if let Some(execution) = active_executions.get_mut(&execution_id) {
            execution.steps = step_executions;
            execution.updated_at = Utc::now();
        }

        Ok(())
    }

    async fn enforce_execution_guard(
        &self,
        execution_id: &str,
        guard: &Arc<dyn ExecutionGuard>,
    ) -> Result<()> {
        if let Err(error) = guard.validate().await {
            let message = format!("Execution authorization was withdrawn: {error}");
            let _ = self
                .append_execution_log(execution_id, LogLevel::Error, message.clone(), None)
                .await;
            if let Some(sender) = self.cancellations.read().await.get(execution_id).cloned() {
                let _ = sender.send(true);
            }
            return Err(anyhow!(message));
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
        artifacts: &HashMap<String, Vec<WorkflowArtifact>>,
        cancellation: watch::Receiver<bool>,
    ) -> Result<StepOutcome> {
        self.executor
            .execute_step(
                step,
                execution_id,
                working_directory,
                inputs,
                artifacts,
                cancellation,
            )
            .await
    }

    fn merge_cancellation(
        mut execution: watch::Receiver<bool>,
        mut layer: watch::Receiver<bool>,
    ) -> watch::Receiver<bool> {
        let (sender, receiver) = watch::channel(false);
        tokio::spawn(async move {
            loop {
                if *execution.borrow() || *layer.borrow() {
                    let _ = sender.send(true);
                    return;
                }

                tokio::select! {
                    changed = execution.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    changed = layer.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
            }
        });
        receiver
    }

    async fn update_execution_status(
        &self,
        execution_id: &str,
        status: ExecutionStatus,
        current_step: Option<&str>,
        progress: u32,
    ) -> Result<()> {
        let mut active_executions = self.active_executions.write().await;
        let execution = active_executions
            .get_mut(execution_id)
            .ok_or_else(|| anyhow!("Execution '{}' not found", execution_id))?;
        execution.status = status.clone();
        execution.current_step = current_step.map(|s| s.to_string());
        if progress > 0
            || !matches!(
                &status,
                ExecutionStatus::Failed | ExecutionStatus::Cancelled
            )
        {
            execution.progress = progress;
        }
        execution.updated_at = Utc::now();
        if matches!(
            &status,
            ExecutionStatus::Completed | ExecutionStatus::Failed | ExecutionStatus::Cancelled
        ) {
            execution.completed = Some(Utc::now());
        }

        execution.logs.push(ExecutionLog {
            timestamp: Utc::now(),
            level: LogLevel::Info,
            message: format!("Status updated to {:?}", status),
            step_id: current_step.map(|s| s.to_string()),
        });
        let snapshot = execution.clone();
        drop(active_executions);

        self.persist_execution(&snapshot).await?;
        self.sync_scan(&snapshot).await?;

        // Emit status update event
        let event = EventEmitter::workflow_status_update(
            execution_id,
            Self::status_name(&status),
            snapshot.progress,
            current_step.map(|s| s.to_string()),
        );
        let _ = self.events.emit(WORKFLOW_STATUS_UPDATE, event);

        if let Some(scan_id) = &snapshot.scan_id {
            let progress_event = EventEmitter::scan_progress_update(
                scan_id,
                snapshot.progress as i32,
                snapshot.current_step.clone(),
                Self::status_name(&snapshot.status),
            );
            let _ = self.events.emit(SCAN_PROGRESS_UPDATE, progress_event);

            match &snapshot.status {
                ExecutionStatus::Completed => {
                    let _ = self
                        .events
                        .emit(SCAN_COMPLETED, EventEmitter::scan_completed(scan_id));
                }
                ExecutionStatus::Failed => {
                    let _ = self
                        .events
                        .emit(SCAN_FAILED, EventEmitter::scan_failed(scan_id));
                    let _ = self.events.emit(
                        SCAN_ERROR,
                        EventEmitter::scan_error(scan_id, "Workflow execution failed"),
                    );
                }
                ExecutionStatus::Cancelled => {
                    let _ = self
                        .events
                        .emit(SCAN_CANCELLED, EventEmitter::scan_cancelled(scan_id));
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn append_execution_log(
        &self,
        execution_id: &str,
        level: LogLevel,
        message: String,
        step_id: Option<String>,
    ) -> Result<()> {
        let mut executions = self.active_executions.write().await;
        let execution = executions
            .get_mut(execution_id)
            .ok_or_else(|| anyhow!("Execution '{}' not found", execution_id))?;
        execution.logs.push(ExecutionLog {
            timestamp: Utc::now(),
            level,
            message,
            step_id,
        });
        execution.updated_at = Utc::now();
        let snapshot = execution.clone();
        drop(executions);
        self.persist_execution(&snapshot).await
    }

    async fn update_execution_progress(&self, execution_id: &str, progress: u32) -> Result<()> {
        let mut active_executions = self.active_executions.write().await;
        let execution = active_executions
            .get_mut(execution_id)
            .ok_or_else(|| anyhow!("Execution '{}' not found", execution_id))?;
        execution.progress = progress;
        execution.updated_at = Utc::now();
        let snapshot = execution.clone();
        drop(active_executions);

        self.persist_execution(&snapshot).await?;
        self.sync_scan(&snapshot).await?;

        if let Some(scan_id) = &snapshot.scan_id {
            let event = EventEmitter::scan_progress_update(
                scan_id,
                progress as i32,
                snapshot.current_step.clone(),
                Self::status_name(&snapshot.status),
            );
            let _ = self.events.emit(SCAN_PROGRESS_UPDATE, event);
        }

        // Emit progress update event
        let _ = self.events.emit(
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
        if let Some(execution) = active_executions.get(execution_id) {
            return Ok(Some(execution.clone()));
        }
        drop(active_executions);

        let Some(database_execution) = self.db.get_workflow_execution(execution_id).await? else {
            return Ok(None);
        };
        let mut execution = Self::workflow_execution_from_database(database_execution);
        execution.steps = self
            .db
            .get_workflow_step_executions(execution_id)
            .await?
            .into_iter()
            .map(|step| {
                let step_id = step.step_id.clone();
                (
                    step_id.clone(),
                    StepExecution {
                        step_id,
                        status: Self::parse_step_status(&step.status),
                        started: step.started,
                        completed: step.completed,
                        exit_code: step.exit_code,
                        stdout: serde_json::from_str(&step.stdout).unwrap_or_default(),
                        stderr: serde_json::from_str(&step.stderr).unwrap_or_default(),
                        artifacts: serde_json::from_str(&step.artifacts).unwrap_or_default(),
                    },
                )
            })
            .collect();
        Ok(Some(execution))
    }

    #[allow(dead_code)]
    pub async fn list_executions(&self) -> Result<Vec<WorkflowExecution>> {
        let active_executions = self.active_executions.read().await;
        Ok(active_executions.values().cloned().collect())
    }

    pub async fn stop_execution(&self, execution_id: &str) -> Result<()> {
        let sender = self
            .cancellations
            .read()
            .await
            .get(execution_id)
            .cloned()
            .ok_or_else(|| anyhow!("Execution '{}' is not running", execution_id))?;
        sender
            .send(true)
            .map_err(|_| anyhow!("Execution '{}' is no longer running", execution_id))?;

        self.update_execution_status(execution_id, ExecutionStatus::Cancelled, None, 0)
            .await?;

        // Emit cancellation event
        let _ = self.events.emit(
            "workflow:execution_cancelled",
            serde_json::json!({
                "execution_id": execution_id,
                "timestamp": Utc::now().to_rfc3339()
            }),
        );

        Ok(())
    }

    async fn save_findings(
        &self,
        execution_id: &str,
        step_id: &str,
        tool_name: &str,
        findings: Vec<ParsedFinding>,
    ) -> Result<()> {
        let scan_id = self
            .active_executions
            .read()
            .await
            .get(execution_id)
            .and_then(|execution| execution.scan_id.clone());

        for finding in findings {
            let finding_id = Uuid::new_v4().to_string();
            let workflow_finding = crate::database::WorkflowFinding {
                id: finding_id.clone(),
                execution_id: execution_id.to_string(),
                step_id: step_id.to_string(),
                title: finding.title.clone(),
                severity: finding.severity.clone(),
                description: finding.description.clone(),
                cvss: finding.cvss,
                url: finding.url.clone(),
                parameter: finding.parameter.clone(),
                payload: finding.payload.clone(),
                remediation: finding.remediation.clone(),
                discovered_by: Some(tool_name.to_string()),
                evidence: finding.evidence.clone(),
                false_positive: false,
                confirmed: false,
                created_at: Utc::now(),
            };
            self.db.create_workflow_finding(&workflow_finding).await?;

            if let Some(scan_id) = &scan_id {
                let vulnerability = crate::database::Vulnerability {
                    id: finding_id,
                    scan_id: scan_id.clone(),
                    title: finding.title,
                    severity: finding.severity.unwrap_or_else(|| "unknown".to_string()),
                    cvss: finding.cvss,
                    description: finding.description.unwrap_or_default(),
                    url: finding.url,
                    parameter: finding.parameter,
                    payload: finding.payload,
                    remediation: finding.remediation,
                    discovered_by: tool_name.to_string(),
                    timestamp: Utc::now(),
                    false_positive: false,
                    confirmed: false,
                    evidence: finding.evidence,
                };
                self.db.create_vulnerability(&vulnerability).await?;
            }
        }

        if let Some(scan_id) = scan_id {
            self.refresh_scan_finding_counts(&scan_id).await?;
        }
        Ok(())
    }

    async fn store_step_executions(
        &self,
        execution_id: &str,
        steps: &HashMap<String, StepExecution>,
    ) -> Result<()> {
        if let Some(execution) = self.active_executions.write().await.get_mut(execution_id) {
            execution.steps = steps.clone();
            execution.updated_at = Utc::now();
        }

        for step in steps.values() {
            self.db
                .upsert_workflow_step_execution(&crate::database::WorkflowStepExecution {
                    execution_id: execution_id.to_string(),
                    step_id: step.step_id.clone(),
                    status: Self::step_status_name(&step.status).to_string(),
                    started: step.started,
                    completed: step.completed,
                    exit_code: step.exit_code,
                    stdout: serde_json::to_string(&step.stdout)?,
                    stderr: serde_json::to_string(&step.stderr)?,
                    artifacts: serde_json::to_string(&step.artifacts)?,
                    updated_at: Utc::now(),
                })
                .await?;
        }
        Ok(())
    }

    async fn save_artifact(&self, artifact: &WorkflowArtifact) -> Result<()> {
        let mut metadata = artifact
            .metadata_
            .as_deref()
            .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        if let Some(object) = metadata.as_object_mut() {
            if let Some(size) = artifact.size {
                object.insert("size".to_string(), serde_json::json!(size));
            }
            if let Some(hash) = &artifact.hash {
                object.insert("sha256".to_string(), serde_json::json!(hash));
            }
        }

        self.db
            .create_workflow_artifact(&crate::database::WorkflowArtifact {
                id: artifact.id.clone(),
                execution_id: artifact.execution_id.clone(),
                step_id: artifact.step_id.clone(),
                name: artifact.name.clone(),
                artifact_type: artifact.artifact_type.clone(),
                file_path: artifact.file_path.clone(),
                content: artifact.content.clone(),
                metadata_: Some(metadata.to_string()),
                created_at: artifact.created_at,
            })
            .await?;
        Ok(())
    }

    fn database_execution(
        execution: &WorkflowExecution,
    ) -> Result<crate::database::WorkflowExecution> {
        Ok(crate::database::WorkflowExecution {
            id: execution.id.clone(),
            scan_id: execution.scan_id.clone(),
            workflow_id: execution.workflow_id.clone(),
            status: Self::status_name(&execution.status).to_string(),
            started: execution.started,
            completed: execution.completed,
            current_step: execution.current_step.clone(),
            progress: execution.progress as i32,
            inputs: serde_json::to_string(&execution.inputs)?,
            working_directory: Some(execution.working_directory.clone()),
            logs: serde_json::to_string(&execution.logs)?,
            created_at: execution.started,
            updated_at: execution.updated_at,
        })
    }

    fn workflow_execution_from_database(
        execution: crate::database::WorkflowExecution,
    ) -> WorkflowExecution {
        WorkflowExecution {
            id: execution.id,
            scan_id: execution.scan_id,
            workflow_id: execution.workflow_id,
            status: Self::parse_status(&execution.status),
            started: execution.started,
            completed: execution.completed,
            current_step: execution.current_step,
            progress: execution.progress.max(0) as u32,
            inputs: serde_json::from_str(&execution.inputs).unwrap_or_default(),
            working_directory: execution.working_directory.unwrap_or_default(),
            logs: serde_json::from_str(&execution.logs).unwrap_or_default(),
            steps: HashMap::new(),
            updated_at: execution.updated_at,
        }
    }

    async fn persist_execution(&self, execution: &WorkflowExecution) -> Result<()> {
        self.db
            .update_workflow_execution(&Self::database_execution(execution)?)
            .await?;
        Ok(())
    }

    async fn sync_scan(&self, execution: &WorkflowExecution) -> Result<()> {
        let Some(scan_id) = &execution.scan_id else {
            return Ok(());
        };
        let Some(mut scan) = self.db.get_scan(scan_id).await? else {
            return Ok(());
        };

        scan.status = Self::status_name(&execution.status).to_string();
        scan.progress = execution.progress as i32;
        scan.current_step = execution.current_step.clone();
        scan.current_test = execution.current_step.clone();
        scan.updated_at = Utc::now();
        if matches!(
            &execution.status,
            ExecutionStatus::Completed | ExecutionStatus::Failed | ExecutionStatus::Cancelled
        ) {
            scan.completed = execution.completed.or_else(|| Some(Utc::now()));
        }
        self.db.update_scan(&scan).await?;
        Ok(())
    }

    async fn refresh_scan_finding_counts(&self, scan_id: &str) -> Result<()> {
        let Some(mut scan) = self.db.get_scan(scan_id).await? else {
            return Ok(());
        };
        let findings = self.db.get_vulnerabilities_by_scan(scan_id).await?;
        scan.vulnerabilities = Some(findings.len() as i32);
        scan.critical = Some(
            findings
                .iter()
                .filter(|finding| finding.severity.eq_ignore_ascii_case("critical"))
                .count() as i32,
        );
        scan.high = Some(
            findings
                .iter()
                .filter(|finding| finding.severity.eq_ignore_ascii_case("high"))
                .count() as i32,
        );
        scan.medium = Some(
            findings
                .iter()
                .filter(|finding| finding.severity.eq_ignore_ascii_case("medium"))
                .count() as i32,
        );
        scan.low = Some(
            findings
                .iter()
                .filter(|finding| finding.severity.eq_ignore_ascii_case("low"))
                .count() as i32,
        );
        self.db.update_scan(&scan).await?;
        Ok(())
    }

    fn status_name(status: &ExecutionStatus) -> &'static str {
        match status {
            ExecutionStatus::Pending => "pending",
            ExecutionStatus::Running => "running",
            ExecutionStatus::Completed => "completed",
            ExecutionStatus::Failed => "failed",
            ExecutionStatus::Cancelled => "cancelled",
            ExecutionStatus::Interrupted => "interrupted",
        }
    }

    fn parse_status(status: &str) -> ExecutionStatus {
        match status.to_ascii_lowercase().as_str() {
            "running" => ExecutionStatus::Running,
            "completed" => ExecutionStatus::Completed,
            "failed" => ExecutionStatus::Failed,
            "cancelled" => ExecutionStatus::Cancelled,
            "interrupted" => ExecutionStatus::Interrupted,
            _ => ExecutionStatus::Pending,
        }
    }

    fn step_status_name(status: &StepStatus) -> &'static str {
        match status {
            StepStatus::Pending => "pending",
            StepStatus::Running => "running",
            StepStatus::Completed => "completed",
            StepStatus::Failed => "failed",
            StepStatus::Skipped => "skipped",
            StepStatus::Interrupted => "interrupted",
        }
    }

    fn parse_step_status(status: &str) -> StepStatus {
        match status.to_ascii_lowercase().as_str() {
            "running" => StepStatus::Running,
            "completed" => StepStatus::Completed,
            "failed" => StepStatus::Failed,
            "skipped" => StepStatus::Skipped,
            "interrupted" => StepStatus::Interrupted,
            _ => StepStatus::Pending,
        }
    }
}
