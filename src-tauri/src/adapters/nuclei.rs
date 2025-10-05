use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiConfig {
    pub target: String,
    pub output_file: Option<String>,
    pub severity: Option<String>,
    pub passive: bool,
    pub templates: Option<Vec<String>>,
    pub silent: bool,
}

impl Default for NucleiConfig {
    fn default() -> Self {
        Self {
            target: "".to_string(),
            output_file: None,
            severity: Some("medium,high,critical".to_string()),
            passive: false,
            templates: None,
            silent: true,
        }
    }
}

pub struct NucleiAdapter;

impl NucleiAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn build_command(&self, config: &NucleiConfig) -> Vec<String> {
        let mut command = vec!["nuclei".to_string()];

        // Add target
        command.push("-target".to_string());
        command.push(config.target.clone());

        // Add JSON output format
        command.push("-json".to_string());

        // Add output file if specified
        if let Some(output_file) = &config.output_file {
            command.push("-o".to_string());
            command.push(output_file.clone());
        }

        // Add severity filter
        if let Some(severity) = &config.severity {
            command.push("-severity".to_string());
            command.push(severity.clone());
        }

        // Add mode flags
        if config.passive {
            command.push("-passive".to_string());
        }

        if config.silent {
            command.push("-silent".to_string());
        }

        // Add custom templates
        if let Some(templates) = &config.templates {
            for template in templates {
                command.push("-t".to_string());
                command.push(template.clone());
            }
        }

        command
    }

    pub fn build_command_with_defaults(&self, target: String, output_file: Option<String>) -> Vec<String> {
        let config = NucleiConfig {
            target,
            output_file,
            ..Default::default()
        };
        self.build_command(&config)
    }

    pub fn get_tool_name(&self) -> &'static str {
        "nuclei"
    }

    pub fn get_description(&self) -> &'static str {
        "Fast and customizable vulnerability scanner based on templates"
    }

    pub fn get_category(&self) -> &'static str {
        "vulnerability"
    }

    pub fn get_risk_level(&self) -> &'static str {
        "medium"
    }

    pub fn requires_authorization(&self) -> bool {
        true // Active scanning requires authorization
    }

    pub fn get_timeout(&self) -> u64 {
        1800 // 30 minutes (comprehensive scans take time)
    }

    pub fn get_expected_outputs(&self) -> Vec<String> {
        vec!["vulnerabilities.json".to_string()]
    }
}
