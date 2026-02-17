use super::types::*;
use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use serde_json::{json, Value};
use serde_yaml;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::fs as async_fs;

/// JSON Schema for workflow validation
const WORKFLOW_SCHEMA: &str = r#"
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9_-]+$"
    },
    "name": {
      "type": "string",
      "minLength": 1,
      "maxLength": 100
    },
    "description": {
      "type": "string",
      "maxLength": 500
    },
    "category": {
      "type": "string",
      "enum": ["reconnaissance", "vulnerability", "web-application", "network", "api", "comprehensive", "custom"]
    },
    "version": {
      "type": "string",
      "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"
    },
    "steps": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": {
            "type": "string",
            "pattern": "^[a-zA-Z0-9_-]+$"
          },
          "name": {
            "type": "string",
            "minLength": 1
          },
          "tool": {
            "type": "string",
            "minLength": 1
          },
          "argv": {
            "type": "array",
            "items": {"type": "string"}
          },
          "needs": {
            "type": "array",
            "items": {"type": "string"}
          },
          "outputs": {
            "type": "array",
            "items": {"type": "string"}
          },
          "timeout_ms": {
            "type": "integer",
            "minimum": 1000,
            "maximum": 3600000
          },
          "retry_count": {
            "type": "integer",
            "minimum": 0,
            "maximum": 10
          },
          "retry_delay_ms": {
            "type": "integer",
            "minimum": 100,
            "maximum": 30000
          },
          "environment": {
            "type": "object",
            "additionalProperties": {"type": "string"}
          },
          "cwd": {"type": "string"},
          "continue_on_error": {"type": "boolean"},
          "condition": {"type": "string"}
        },
        "required": ["id", "name", "tool", "argv"]
      }
    },
    "inputs": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "properties": {
          "description": {"type": "string"},
          "required": {"type": "boolean"},
          "default": {"type": "string"},
          "validation": {
            "type": "object",
            "properties": {
              "pattern": {"type": "string"},
              "min_length": {"type": "integer"},
              "max_length": {"type": "integer"},
              "allowed_values": {
                "type": "array",
                "items": {"type": "string"}
              }
            }
          }
        },
        "required": ["description", "required"]
      }
    },
    "outputs": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "properties": {
          "description": {"type": "string"},
          "format": {
            "type": "string",
            "enum": ["json", "jsonl", "xml", "csv", "txt", "binary"]
          },
          "required": {"type": "boolean"}
        },
        "required": ["description", "format", "required"]
      }
    }
  },
  "required": ["id", "name", "category", "version", "steps"]
}
"#;

/// Workflow loader for parsing and validating workflow templates
pub struct WorkflowLoader {
    plugin_dirs: Vec<PathBuf>,
    schema: Value,
}

impl WorkflowLoader {
    /// Create a new workflow loader
    pub fn new() -> Result<Self> {
        let schema: Value = serde_json::from_str(WORKFLOW_SCHEMA)
            .map_err(|e| anyhow!("Failed to parse workflow schema: {}", e))?;

        Ok(Self {
            plugin_dirs: vec![
                PathBuf::from("./plugins"),
                PathBuf::from("./backend/plugins"),
            ],
            schema,
        })
    }

    /// Load all workflow templates from plugin directories
    pub async fn load_workflow_templates(&self) -> Result<Vec<WorkflowTemplate>> {
        let mut templates = Vec::new();

        for plugin_dir in &self.plugin_dirs {
            if plugin_dir.exists() {
                let dir_templates = self.load_from_directory(plugin_dir).await?;
                templates.extend(dir_templates);
            }
        }

        info!("Loaded {} workflow templates", templates.len());
        Ok(templates)
    }

    /// Load workflow templates from a specific directory
    async fn load_from_directory(&self, dir: &Path) -> Result<Vec<WorkflowTemplate>> {
        let mut templates = Vec::new();

        if !dir.exists() {
            debug!("Plugin directory does not exist: {:?}", dir);
            return Ok(templates);
        }

        // Load from plugins/*.yaml files
        let plugins_pattern = dir.join("*.yaml");
        let plugins_glob = glob::glob(&plugins_pattern.to_string_lossy())?;

        for entry in plugins_glob {
            match entry {
                Ok(path) => {
                    match self.load_workflow_file(&path).await {
                        Ok(template) => templates.push(template),
                        Err(e) => {
                            error!("Failed to load workflow from {:?}: {}", path, e);
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading plugin file: {}", e);
                }
            }
        }

        // Load from plugins/workflows/ directory if it exists
        let workflows_dir = dir.join("workflows");
        if workflows_dir.exists() && workflows_dir.is_dir() {
            let workflows_pattern = workflows_dir.join("*.yaml");
            let workflows_glob = glob::glob(&workflows_pattern.to_string_lossy())?;

            for entry in workflows_glob {
                match entry {
                    Ok(path) => {
                        match self.load_workflow_file(&path).await {
                            Ok(template) => templates.push(template),
                            Err(e) => {
                                error!("Failed to load workflow from {:?}: {}", path, e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error reading workflow file: {}", e);
                    }
                }
            }
        }

        Ok(templates)
    }

    /// Load and validate a single workflow file
    async fn load_workflow_file(&self, path: &Path) -> Result<WorkflowTemplate> {
        debug!("Loading workflow from: {:?}", path);

        let content = async_fs::read_to_string(path).await?;
        let mut template: Value = serde_yaml::from_str(&content)?;

        // Validate against schema
        self.validate_workflow(&template)?;

        // Parse into strongly typed structure
        let workflow_template: WorkflowTemplate = serde_yaml::from_value(template)?;

        // Validate workflow logic
        self.validate_workflow_logic(&workflow_template)?;

        info!("Successfully loaded workflow: {} ({})", workflow_template.name, workflow_template.id);
        Ok(workflow_template)
    }

    /// Validate workflow against JSON schema
    fn validate_workflow(&self, template: &Value) -> Result<()> {
        use jsonschema::{Draft, JSONSchema, ValidationError};

        let schema = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&self.schema)
            .map_err(|e| anyhow!("Schema compilation error: {}", e))?;

        let validation_result = schema.validate(template);

        if let Err(validation_errors) = validation_result {
            let mut errors = Vec::new();
            for error in validation_errors {
                errors.push(format!("  - {}", error));
            }
            return Err(anyhow!("Workflow validation failed:\n{}", errors.join("\n")));
        }

        Ok(())
    }

    /// Validate workflow logic and dependencies
    fn validate_workflow_logic(&self, template: &WorkflowTemplate) -> Result<()> {
        // Check for duplicate step IDs
        let mut step_ids = std::collections::HashSet::new();
        for step in &template.steps {
            if !step_ids.insert(&step.id) {
                return Err(anyhow!("Duplicate step ID found: {}", step.id));
            }
        }

        // Validate step dependencies (needs)
        for step in &template.steps {
            for need in &step.needs {
                if !step_ids.contains(need) {
                    return Err(anyhow!("Step '{}' needs non-existent step '{}'", step.id, need));
                }
            }

            // Validate output references
            for output in &step.outputs {
                if !template.outputs.contains_key(output) {
                    return Err(anyhow!("Step '{}' outputs non-existent output '{}'", step.id, output));
                }
            }
        }

        // Check for circular dependencies in needs
        self.validate_dag(&template.steps)?;

        // Validate timeout values are reasonable
        for step in &template.steps {
            if let Some(timeout) = step.timeout_ms {
                if timeout < 1000 {
                    warn!("Step '{}' has very short timeout: {}ms", step.id, timeout);
                }
                if timeout > 3600000 {
                    warn!("Step '{}' has very long timeout: {}ms", step.id, timeout);
                }
            }
        }

        Ok(())
    }

    /// Validate DAG structure (no circular dependencies)
    fn validate_dag(&self, steps: &[WorkflowStep]) -> Result<()> {
        use std::collections::{HashSet, VecDeque};

        let mut visited = HashSet::new();
        let mut visiting = HashSet::new();

        // Build adjacency list
        let mut graph: HashMap<String, Vec<String>> = HashMap::new();
        for step in steps {
            graph.entry(step.id.clone()).or_insert_with(Vec::new);
            for need in &step.needs {
                graph.entry(need.clone()).or_insert_with(Vec::new).push(step.id.clone());
            }
        }

        // DFS to detect cycles
        fn has_cycle(
            node: &str,
            graph: &HashMap<String, Vec<String>>,
            visited: &mut HashSet<String>,
            visiting: &mut HashSet<String>,
        ) -> bool {
            if visiting.contains(node) {
                return true; // Cycle detected
            }
            if visited.contains(node) {
                return false; // Already processed
            }

            visiting.insert(node.to_string());

            if let Some(neighbors) = graph.get(node) {
                for neighbor in neighbors {
                    if has_cycle(neighbor, graph, visited, visiting) {
                        return true;
                    }
                }
            }

            visiting.remove(node);
            visited.insert(node.to_string());
            false
        }

        for step in steps {
            if !visited.contains(&step.id) {
                if has_cycle(&step.id, &graph, &mut visited, &mut visiting) {
                    return Err(anyhow!("Circular dependency detected in workflow steps"));
                }
            }
        }

        Ok(())
    }

    /// Check tool compatibility for a workflow
    pub async fn check_workflow_compatibility(
        &self,
        template: &WorkflowTemplate,
        tool_registry: &crate::tools::registry::ToolRegistry,
    ) -> Result<WorkflowCompatibility> {
        let mut missing_tools = Vec::new();
        let mut version_requirements = HashMap::new();
        let mut warnings = Vec::new();

        for step in &template.steps {
            if let Ok(tool) = tool_registry.get_tool(&step.tool).await {
                if !tool.available {
                    missing_tools.push(step.tool.clone());
                }
                if let Some(version) = &tool.version {
                    version_requirements.insert(step.tool.clone(), version.clone());
                }
            } else {
                missing_tools.push(step.tool.clone());
            }
        }

        let compatible = missing_tools.is_empty();

        if !compatible {
            warnings.push(format!("Missing {} required tools", missing_tools.len()));
        }

        Ok(WorkflowCompatibility {
            compatible,
            missing_tools,
            version_requirements,
            warnings,
        })
    }

    /// Get workflow template by ID
    pub fn get_workflow_template(&self, templates: &[WorkflowTemplate], id: &str) -> Option<&WorkflowTemplate> {
        templates.iter().find(|t| t.id == id)
    }

    /// List available workflow categories
    pub fn get_workflow_categories(&self) -> Vec<&'static str> {
        vec![
            "reconnaissance",
            "vulnerability",
            "web-application",
            "network",
            "api",
            "comprehensive",
            "custom",
        ]
    }
}

impl Default for WorkflowLoader {
    fn default() -> Self {
        Self::new().expect("Failed to create default WorkflowLoader")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_workflow_loading() {
        let loader = WorkflowLoader::new().unwrap();

        // Test with minimal workflow
        let test_workflow = r#"
id: test-workflow
name: Test Workflow
description: A test workflow
category: reconnaissance
version: 1.0.0
steps:
  - id: step1
    name: Test Step
    tool: echo
    argv: ["hello", "world"]
inputs: {}
outputs: {}
"#;

        let template: WorkflowTemplate = serde_yaml::from_str(test_workflow).unwrap();
        assert_eq!(template.id, "test-workflow");
        assert_eq!(template.steps.len(), 1);
    }

    #[test]
    fn test_circular_dependency_detection() {
        let loader = WorkflowLoader::new().unwrap();

        let steps = vec![
            WorkflowStep {
                id: "step1".to_string(),
                name: "Step 1".to_string(),
                description: None,
                tool: "echo".to_string(),
                argv: vec!["hello".to_string()],
                needs: vec!["step2".to_string()],
                outputs: vec![],
                timeout_ms: None,
                retry_count: None,
                retry_delay_ms: None,
                environment: HashMap::new(),
                cwd: None,
                continue_on_error: false,
                condition: None,
            },
            WorkflowStep {
                id: "step2".to_string(),
                name: "Step 2".to_string(),
                description: None,
                tool: "echo".to_string(),
                argv: vec!["world".to_string()],
                needs: vec!["step1".to_string()],
                outputs: vec![],
                timeout_ms: None,
                retry_count: None,
                retry_delay_ms: None,
                environment: HashMap::new(),
                cwd: None,
                continue_on_error: false,
                condition: None,
            },
        ];

        let result = loader.validate_dag(&steps);
        assert!(result.is_err()); // Should detect circular dependency
    }
}