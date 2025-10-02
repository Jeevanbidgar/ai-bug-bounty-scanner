use std::collections::HashMap;
use std::path::Path;
use serde_yaml;
use anyhow::{Result, anyhow};
use crate::workflow::types::{WorkflowTemplate, WorkflowStep, WorkflowOutput, WorkflowRetry};

pub struct WorkflowLoader {
    workflows_dir: std::path::PathBuf,
}

impl WorkflowLoader {
    pub fn new<P: AsRef<Path>>(workflows_dir: P) -> Self {
        Self {
            workflows_dir: workflows_dir.as_ref().to_path_buf(),
        }
    }

    pub async fn load_workflow(&self, workflow_id: &str) -> Result<WorkflowTemplate> {
        let workflow_path = self.workflows_dir.join(format!("{}.yaml", workflow_id));
        
        if !workflow_path.exists() {
            return Err(anyhow!("Workflow '{}' not found", workflow_id));
        }

        let content = tokio::fs::read_to_string(&workflow_path).await?;
        let workflow_value: serde_yaml::Value = serde_yaml::from_str(&content)?;
        
        self.parse_workflow(workflow_id, workflow_value).await
    }

    pub async fn load_all_workflows(&self) -> Result<HashMap<String, WorkflowTemplate>> {
        let mut workflows = HashMap::new();

        if !self.workflows_dir.exists() {
            return Ok(workflows);
        }

        let mut entries = tokio::fs::read_dir(&self.workflows_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    match self.load_workflow(stem).await {
                        Ok(workflow) => {
                            workflows.insert(workflow.id.clone(), workflow);
                        }
                        Err(e) => {
                            eprintln!("Failed to load workflow '{}': {}", stem, e);
                        }
                    }
                }
            }
        }

        Ok(workflows)
    }

    async fn parse_workflow(&self, workflow_id: &str, workflow: serde_yaml::Value) -> Result<WorkflowTemplate> {
        let workflow_map = workflow.as_mapping()
            .ok_or_else(|| anyhow!("Workflow must be a YAML object"))?;

        let name = workflow_map.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(workflow_id)
            .to_string();

        let description = workflow_map.get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let category = workflow_map.get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("general")
            .to_string();

        let inputs = self.parse_inputs(workflow_map.get("inputs"))?;
        let steps = self.parse_steps(workflow_map.get("steps")).await?;

        // Validate DAG structure
        self.validate_dag(&steps)?;

        Ok(WorkflowTemplate {
            id: workflow_id.to_string(),
            name,
            description,
            category,
            inputs,
            steps,
        })
    }

    fn parse_inputs(&self, inputs_value: Option<&serde_yaml::Value>) -> Result<HashMap<String, String>> {
        let mut inputs = HashMap::new();

        if let Some(inputs_val) = inputs_value {
            if let Some(inputs_map) = inputs_val.as_mapping() {
                for (key, value) in inputs_map {
                    if let (Some(key_str), Some(value_str)) = (key.as_str(), value.as_str()) {
                        inputs.insert(key_str.to_string(), value_str.to_string());
                    }
                }
            }
        }

        Ok(inputs)
    }

    async fn parse_steps(&self, steps_value: Option<&serde_yaml::Value>) -> Result<Vec<WorkflowStep>> {
        let mut steps = Vec::new();

        if let Some(steps_val) = steps_value {
            if let Some(steps_seq) = steps_val.as_sequence() {
                for (index, step_val) in steps_seq.iter().enumerate() {
                    if let Some(step_map) = step_val.as_mapping() {
                        let step = self.parse_step(step_map, index).await?;
                        steps.push(step);
                    }
                }
            }
        }

        Ok(steps)
    }

    async fn parse_step(&self, step_map: &serde_yaml::Mapping, _index: usize) -> Result<WorkflowStep> {
        let id = step_map.get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Step must have an 'id' field"))?
            .to_string();

        let name = step_map.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(&id)
            .to_string();

        let description = step_map.get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let needs = step_map.get("needs")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        let run = step_map.get("run")
            .and_then(|v| v.as_sequence())
            .ok_or_else(|| anyhow!("Step '{}' must have a 'run' field", id))?
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect();

        let env = step_map.get("env")
            .and_then(|v| v.as_mapping())
            .map(|env_map| {
                env_map.iter()
                    .filter_map(|(k, v)| {
                        k.as_str().and_then(|k_str| {
                            v.as_str().map(|v_str| (k_str.to_string(), v_str.to_string()))
                        })
                    })
                    .collect()
            });

        let timeout = step_map.get("timeout")
            .and_then(|v| v.as_u64());

        let retry = self.parse_retry(step_map.get("retry"));

        let outputs = self.parse_step_outputs(step_map.get("outputs"))?;

        Ok(WorkflowStep {
            id,
            name,
            description,
            needs,
            run,
            env,
            timeout,
            retry,
            outputs,
        })
    }

    fn parse_retry(&self, retry_value: Option<&serde_yaml::Value>) -> Option<WorkflowRetry> {
        if let Some(retry_val) = retry_value {
            if let Some(retry_map) = retry_val.as_mapping() {
                // Parse max_attempts (backwards compatible with "count")
                let max_attempts = retry_map.get("max_attempts")
                    .or_else(|| retry_map.get("count"))  // Backwards compatibility
                    .and_then(|v| v.as_u64())
                    .unwrap_or(3) as u32;

                // Parse initial_delay_ms (backwards compatible with "delay")
                let initial_delay_ms = retry_map.get("initial_delay_ms")
                    .or_else(|| retry_map.get("delay"))  // Backwards compatibility
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1000);

                // Parse max_delay_ms (default 60 seconds)
                let max_delay_ms = retry_map.get("max_delay_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(60000);

                // Parse backoff_multiplier (default 2.0 for exponential backoff)
                let backoff_multiplier = retry_map.get("backoff_multiplier")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(2.0);

                return Some(WorkflowRetry {
                    max_attempts,
                    initial_delay_ms,
                    max_delay_ms,
                    backoff_multiplier,
                });
            }
        }
        None
    }

    fn parse_step_outputs(&self, outputs_value: Option<&serde_yaml::Value>) -> Result<Vec<WorkflowOutput>> {
        let mut outputs = Vec::new();

        if let Some(outputs_val) = outputs_value {
            if let Some(outputs_seq) = outputs_val.as_sequence() {
                for output_val in outputs_seq {
                    if let Some(output_map) = output_val.as_mapping() {
                        let name = output_map.get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("output")
                            .to_string();

                        let path = output_map.get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or("output.txt")
                            .to_string();

                        let artifact_type = output_map.get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("file")
                            .to_string();

                        outputs.push(WorkflowOutput {
                            name,
                            path,
                            artifact_type,
                        });
                    }
                }
            }
        }

        Ok(outputs)
    }

    fn validate_dag(&self, steps: &[WorkflowStep]) -> Result<()> {
        // Check that all step IDs are unique
        let mut step_ids = std::collections::HashSet::new();
        for step in steps {
            if !step_ids.insert(&step.id) {
                return Err(anyhow!("Duplicate step ID: {}", step.id));
            }
        }

        // Check that all dependencies exist
        for step in steps {
            for need in &step.needs {
                if !step_ids.contains(need) {
                    return Err(anyhow!("Step '{}' depends on non-existent step '{}'", step.id, need));
                }
            }
        }

        // Check for circular dependencies (simple DFS)
        let mut visited = std::collections::HashSet::new();
        let mut rec_stack = std::collections::HashSet::new();

        for step in steps {
            if !visited.contains(&step.id) {
                if self.has_cycle(step, steps, &mut visited, &mut rec_stack)? {
                    return Err(anyhow!("Circular dependency detected in workflow"));
                }
            }
        }

        Ok(())
    }

    fn has_cycle(
        &self,
        step: &WorkflowStep,
        all_steps: &[WorkflowStep],
        visited: &mut std::collections::HashSet<String>,
        rec_stack: &mut std::collections::HashSet<String>,
    ) -> Result<bool> {
        visited.insert(step.id.clone());
        rec_stack.insert(step.id.clone());

        for need in &step.needs {
            if let Some(dep_step) = all_steps.iter().find(|s| s.id == *need) {
                if !visited.contains(need) {
                    if self.has_cycle(dep_step, all_steps, visited, rec_stack)? {
                        return Ok(true);
                    }
                } else if rec_stack.contains(need) {
                    return Ok(true);
                }
            }
        }

        rec_stack.remove(&step.id);
        Ok(false)
    }
}