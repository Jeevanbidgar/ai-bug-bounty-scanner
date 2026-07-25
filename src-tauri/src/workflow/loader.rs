use crate::workflow::types::{WorkflowOutput, WorkflowRetry, WorkflowStep, WorkflowTemplate};
use anyhow::{anyhow, Result};
use serde_yaml;
use std::collections::HashMap;
use std::path::Path;

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
        if workflow_id.is_empty()
            || !workflow_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(anyhow!("Workflow ID contains invalid characters"));
        }

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
                    let workflow = self.load_workflow(stem).await.map_err(|error| {
                        anyhow!("Failed to load workflow '{}': {}", stem, error)
                    })?;
                    workflows.insert(workflow.id.clone(), workflow);
                }
            }
        }

        Ok(workflows)
    }

    async fn parse_workflow(
        &self,
        workflow_id: &str,
        workflow: serde_yaml::Value,
    ) -> Result<WorkflowTemplate> {
        let workflow_map = workflow
            .as_mapping()
            .ok_or_else(|| anyhow!("Workflow must be a YAML object"))?;

        let name = workflow_map
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(workflow_id)
            .to_string();

        let description = workflow_map
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let category = workflow_map
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("general")
            .to_string();

        let inputs = self.parse_inputs(workflow_map.get("inputs"))?;
        let steps = self.parse_steps(workflow_map.get("steps")).await?;

        if name.trim().is_empty() {
            return Err(anyhow!(
                "Workflow '{}' must have a non-empty name",
                workflow_id
            ));
        }
        if steps.is_empty() {
            return Err(anyhow!(
                "Workflow '{}' must contain at least one step",
                workflow_id
            ));
        }

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

    fn parse_inputs(
        &self,
        inputs_value: Option<&serde_yaml::Value>,
    ) -> Result<HashMap<String, String>> {
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

    async fn parse_steps(
        &self,
        steps_value: Option<&serde_yaml::Value>,
    ) -> Result<Vec<WorkflowStep>> {
        let mut steps = Vec::new();

        let steps_val = steps_value.ok_or_else(|| anyhow!("Workflow must have a 'steps' field"))?;
        let steps_seq = steps_val
            .as_sequence()
            .ok_or_else(|| anyhow!("Workflow 'steps' must be a list"))?;

        for (index, step_val) in steps_seq.iter().enumerate() {
            let step_map = step_val
                .as_mapping()
                .ok_or_else(|| anyhow!("Workflow step {} must be an object", index + 1))?;
            let step = self.parse_step(step_map, index).await?;
            steps.push(step);
        }

        Ok(steps)
    }

    async fn parse_step(
        &self,
        step_map: &serde_yaml::Mapping,
        _index: usize,
    ) -> Result<WorkflowStep> {
        let id = step_map
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Step must have an 'id' field"))?
            .to_string();

        let name = step_map
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(&id)
            .to_string();

        let description = step_map
            .get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let needs = step_map
            .get("needs")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        let run_values = step_map
            .get("run")
            .and_then(|v| v.as_sequence())
            .ok_or_else(|| anyhow!("Step '{}' must have a list-valued 'run' field", id))?;
        let run: Vec<String> = run_values
            .iter()
            .enumerate()
            .map(|(argument_index, value)| {
                value.as_str().map(str::to_string).ok_or_else(|| {
                    anyhow!(
                        "Step '{}' command argument {} must be a string",
                        id,
                        argument_index + 1
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if run.is_empty() || run[0].trim().is_empty() {
            return Err(anyhow!("Step '{}' must declare an executable", id));
        }
        if !run[0]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(anyhow!(
                "Step '{}' executable must be a registered tool name, not a path or template",
                id
            ));
        }

        for argument in &run {
            self.validate_template_variables(argument, &id)?;
        }

        let stdin = step_map
            .get("stdin")
            .and_then(|value| value.as_str())
            .map(str::to_string);
        if let Some(value) = &stdin {
            if value.len() > 65_536 {
                return Err(anyhow!("Step '{}' stdin template is too large", id));
            }
            self.validate_template_variables(value, &id)?;
        }

        let env: Option<HashMap<String, String>> = match step_map.get("env") {
            Some(value) => {
                let env_map = value
                    .as_mapping()
                    .ok_or_else(|| anyhow!("Step '{}' env must be an object", id))?;
                let mut parsed = HashMap::new();
                for (key, value) in env_map {
                    let key = key
                        .as_str()
                        .ok_or_else(|| anyhow!("Step '{}' env keys must be strings", id))?;
                    let value = value
                        .as_str()
                        .ok_or_else(|| anyhow!("Step '{}' env values must be strings", id))?;
                    parsed.insert(key.to_string(), value.to_string());
                }
                Some(parsed)
            }
            None => None,
        };
        if let Some(environment) = &env {
            for (key, value) in environment {
                if key.trim().is_empty() || key.contains('=') || key.contains('\0') {
                    return Err(anyhow!("Step '{}' has an invalid environment key", id));
                }
                self.validate_template_variables(value, &id)?;
            }
        }

        let timeout = step_map.get("timeout").and_then(|v| v.as_u64());
        if matches!(timeout, Some(0) | Some(86_401..)) {
            return Err(anyhow!(
                "Step '{}' timeout must be between 1 and 86400 seconds",
                id
            ));
        }

        let retry = self.parse_retry(step_map.get("retry"), &id)?;

        let success_exit_codes = match step_map.get("success_exit_codes") {
            Some(value) => {
                let codes = value
                    .as_sequence()
                    .ok_or_else(|| anyhow!("Step '{}' success_exit_codes must be a list", id))?;
                if codes.is_empty() {
                    return Err(anyhow!("Step '{}' success_exit_codes cannot be empty", id));
                }
                let mut parsed = Vec::with_capacity(codes.len());
                for code in codes {
                    let code = code
                        .as_i64()
                        .filter(|code| (0..=255).contains(code))
                        .ok_or_else(|| {
                            anyhow!("Step '{}' success exit codes must be between 0 and 255", id)
                        })? as i32;
                    if !parsed.contains(&code) {
                        parsed.push(code);
                    }
                }
                parsed
            }
            None => vec![0],
        };

        let outputs = self.parse_step_outputs(step_map.get("outputs"))?;

        Ok(WorkflowStep {
            id,
            name,
            description,
            needs,
            run,
            stdin,
            env,
            timeout,
            retry,
            success_exit_codes,
            outputs,
        })
    }

    fn parse_retry(
        &self,
        retry_value: Option<&serde_yaml::Value>,
        step_id: &str,
    ) -> Result<Option<WorkflowRetry>> {
        if let Some(retry_val) = retry_value {
            let retry_map = retry_val
                .as_mapping()
                .ok_or_else(|| anyhow!("Step '{}' retry must be an object", step_id))?;

            let max_attempts = retry_map
                .get("max_attempts")
                .or_else(|| retry_map.get("count"))
                .and_then(|v| v.as_u64())
                .unwrap_or(3);
            let initial_delay_ms = retry_map
                .get("initial_delay_ms")
                .or_else(|| retry_map.get("delay"))
                .and_then(|v| v.as_u64())
                .unwrap_or(1000);
            let max_delay_ms = retry_map
                .get("max_delay_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(60000);
            let backoff_multiplier = retry_map
                .get("backoff_multiplier")
                .and_then(|v| v.as_f64())
                .unwrap_or(2.0);

            if !(1..=10).contains(&max_attempts) {
                return Err(anyhow!(
                    "Step '{}' retry max_attempts must be between 1 and 10",
                    step_id
                ));
            }
            if initial_delay_ms > 300_000 || max_delay_ms > 300_000 {
                return Err(anyhow!(
                    "Step '{}' retry delays cannot exceed 300000 milliseconds",
                    step_id
                ));
            }
            if max_delay_ms < initial_delay_ms {
                return Err(anyhow!(
                    "Step '{}' retry max_delay_ms cannot be less than initial_delay_ms",
                    step_id
                ));
            }
            if !backoff_multiplier.is_finite() || !(1.0..=10.0).contains(&backoff_multiplier) {
                return Err(anyhow!(
                    "Step '{}' retry backoff_multiplier must be between 1 and 10",
                    step_id
                ));
            }

            return Ok(Some(WorkflowRetry {
                max_attempts: max_attempts as u32,
                initial_delay_ms,
                max_delay_ms,
                backoff_multiplier,
            }));
        }
        Ok(None)
    }

    fn parse_step_outputs(
        &self,
        outputs_value: Option<&serde_yaml::Value>,
    ) -> Result<Vec<WorkflowOutput>> {
        let mut outputs = Vec::new();

        if let Some(outputs_val) = outputs_value {
            if let Some(outputs_seq) = outputs_val.as_sequence() {
                for output_val in outputs_seq {
                    if let Some(output_map) = output_val.as_mapping() {
                        let name = output_map
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("output")
                            .to_string();

                        let path = output_map
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or("output.txt")
                            .to_string();

                        self.validate_output_path(&path, &name)?;

                        let artifact_type = output_map
                            .get("type")
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

    fn validate_output_path(&self, path: &str, output_name: &str) -> Result<()> {
        if path.trim().is_empty()
            || path.contains('\0')
            || path.split(['/', '\\']).any(|component| component == "..")
        {
            return Err(anyhow!(
                "Output '{}' has an unsafe artifact path",
                output_name
            ));
        }
        self.validate_template_variables(path, output_name)
    }

    fn validate_template_variables(&self, value: &str, owner: &str) -> Result<()> {
        let expression = regex::Regex::new(r"\{\{([^}]+)\}\}")?;
        for capture in expression.captures_iter(value) {
            let variable = capture.get(1).map(|item| item.as_str()).unwrap_or_default();
            if !matches!(
                variable,
                "target" | "workdir" | "url" | "domain" | "host" | "wordlist"
            ) && !variable.starts_with("artifacts.")
            {
                return Err(anyhow!(
                    "'{}' uses unsupported template variable '{{{{{}}}}}'",
                    owner,
                    variable
                ));
            }
        }

        if value.contains("{{") && !expression.is_match(value) {
            return Err(anyhow!(
                "'{}' contains a malformed template variable",
                owner
            ));
        }
        Ok(())
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
                    return Err(anyhow!(
                        "Step '{}' depends on non-existent step '{}'",
                        step.id,
                        need
                    ));
                }
            }
        }

        // Check for circular dependencies (simple DFS)
        let mut visited = std::collections::HashSet::new();
        let mut rec_stack = std::collections::HashSet::new();

        for step in steps {
            if !visited.contains(&step.id)
                && Self::has_cycle(step, steps, &mut visited, &mut rec_stack)?
            {
                return Err(anyhow!("Circular dependency detected in workflow"));
            }
        }

        Ok(())
    }

    fn has_cycle(
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
                    if Self::has_cycle(dep_step, all_steps, visited, rec_stack)? {
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

#[cfg(test)]
mod tests {
    use super::WorkflowLoader;
    use crate::tools::catalog::{get_tool_catalog, InstallPlatform};

    #[tokio::test]
    async fn loads_every_packaged_workflow() {
        let workflows_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("app/workflows");
        let workflows = WorkflowLoader::new(workflows_dir)
            .load_all_workflows()
            .await
            .unwrap();

        assert_eq!(workflows.len(), 15);
        assert!(workflows
            .values()
            .all(|workflow| !workflow.steps.is_empty()));
        let expected_ids = [
            "api-security-scan",
            "cloud-security-scan",
            "comprehensive-audit",
            "content-discovery",
            "discovery-only",
            "full-recon",
            "network-recon",
            "nikto-web-audit",
            "nuclei-only",
            "passive-url-discovery",
            "quick-bug-bounty",
            "subdomain-takeover",
            "web-application-scan",
            "wordpress-assessment",
            "xss-assessment",
        ]
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
        let actual_ids = workflows
            .keys()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(actual_ids, expected_ids);

        let packaged_tools = workflows
            .values()
            .flat_map(|workflow| workflow.steps.iter())
            .filter_map(|step| step.run.first().map(String::as_str))
            .collect::<std::collections::HashSet<_>>();
        for core_tool in [
            "nmap",
            "subfinder",
            "nuclei",
            "naabu",
            "amass",
            "httpx",
            "ffuf",
            "gobuster",
            "gau",
            "waybackurls",
            "sqlmap",
            "nikto",
            "wpscan",
            "feroxbuster",
            "dalfox",
        ] {
            assert!(
                packaged_tools.contains(core_tool),
                "core tool {core_tool} is not used by a packaged workflow"
            );
        }
    }

    #[tokio::test]
    async fn rejects_workflow_path_traversal() {
        let loader = WorkflowLoader::new(env!("CARGO_MANIFEST_DIR"));
        assert!(loader.load_workflow("../../not-a-workflow").await.is_err());
    }

    #[tokio::test]
    async fn packaged_workflows_only_use_supported_tools_and_declared_outputs() {
        let workflows_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("app/workflows");
        let workflows = WorkflowLoader::new(workflows_dir)
            .load_all_workflows()
            .await
            .unwrap();
        let catalog = get_tool_catalog();

        for workflow in workflows.values() {
            for step in &workflow.steps {
                let tool_name = step.run.first().expect("validated step has no executable");
                let definition = catalog.get(tool_name).unwrap_or_else(|| {
                    panic!(
                        "workflow '{}' step '{}' uses unregistered tool '{}'",
                        workflow.id, step.id, tool_name
                    )
                });

                for platform in [
                    InstallPlatform::Macos,
                    InstallPlatform::Windows,
                    InstallPlatform::Linux,
                ] {
                    assert!(
                        !definition
                            .install_methods_for(tool_name, platform)
                            .is_empty(),
                        "workflow '{}' tool '{}' is unsupported on {}",
                        workflow.id,
                        tool_name,
                        platform.as_str()
                    );
                }

                for output in &step.outputs {
                    if output.artifact_type == "stdout" {
                        continue;
                    }
                    assert!(
                        step.run.iter().any(|argument| argument.contains(&output.path)),
                        "workflow '{}' step '{}' declares output '{}' but never passes its path to the tool",
                        workflow.id,
                        step.id,
                        output.path
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn downstream_target_lists_are_emitted_as_plain_lines() {
        let workflows_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("app/workflows");
        let workflows = WorkflowLoader::new(workflows_dir)
            .load_all_workflows()
            .await
            .unwrap();

        for workflow in workflows.values() {
            let producers = workflow
                .steps
                .iter()
                .flat_map(|step| step.outputs.iter().map(move |output| (&output.path, step)))
                .collect::<std::collections::HashMap<_, _>>();

            for consumer in &workflow.steps {
                let consumer_tool = consumer.run.first().map(String::as_str).unwrap_or_default();
                let list_flags: &[&str] = match consumer_tool {
                    "httpx" | "nuclei" => &["-l", "-list"],
                    "katana" => &["-list"],
                    "nmap" => &["-iL"],
                    "sqlmap" => &["-m"],
                    _ => &[],
                };

                for arguments in consumer.run.windows(2) {
                    if !list_flags.contains(&arguments[0].as_str()) {
                        continue;
                    }
                    let Some(producer) = producers.get(&arguments[1]) else {
                        continue;
                    };
                    let producer_tool =
                        producer.run.first().map(String::as_str).unwrap_or_default();
                    let forbidden_flags: &[&str] = match producer_tool {
                        "naabu" => &["-json", "-j", "-csv"],
                        "httpx" => &[
                            "-json",
                            "-j",
                            "-csv",
                            "-title",
                            "-sc",
                            "-status-code",
                            "-cl",
                            "-content-length",
                            "-ct",
                            "-content-type",
                            "-location",
                            "-rt",
                            "-response-time",
                            "-td",
                            "-tech-detect",
                            "-web-server",
                            "-server",
                            "-cdn",
                            "-cname",
                            "-ip",
                            "-asn",
                            "-method",
                            "-probe",
                        ],
                        _ => &[],
                    };

                    for flag in forbidden_flags {
                        assert!(
                            !producer.run.iter().any(|argument| argument == flag),
                            "workflow '{}' step '{}' writes '{}' with '{}' but step '{}' consumes it as a plain target list",
                            workflow.id,
                            producer.id,
                            arguments[1],
                            flag,
                            consumer.id
                        );
                    }
                }
            }
        }
    }
}
