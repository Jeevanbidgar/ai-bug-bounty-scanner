use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubfinderConfig {
    pub target: String,
    pub output_file: Option<String>,
    pub passive: bool,
    pub all: bool,
    pub silent: bool,
}

impl Default for SubfinderConfig {
    fn default() -> Self {
        Self {
            target: "".to_string(),
            output_file: None,
            passive: true,
            all: false,
            silent: true,
        }
    }
}

#[derive(Default)]
pub struct SubfinderAdapter;

impl SubfinderAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn build_command(&self, config: &SubfinderConfig) -> Vec<String> {
        let mut command = vec!["subfinder".to_string()];

        // Add target
        command.push("-d".to_string());
        command.push(config.target.clone());

        // Add output file if specified
        if let Some(output_file) = &config.output_file {
            command.push("-o".to_string());
            command.push(output_file.clone());
        }

        // Add flags
        if config.passive {
            command.push("-passive".to_string());
        }

        if config.all {
            command.push("-all".to_string());
        }

        if config.silent {
            command.push("-silent".to_string());
        }

        command
    }

    pub fn build_command_with_defaults(
        &self,
        target: String,
        output_file: Option<String>,
    ) -> Vec<String> {
        let config = SubfinderConfig {
            target,
            output_file,
            ..Default::default()
        };
        self.build_command(&config)
    }

    pub fn get_tool_name(&self) -> &'static str {
        "subfinder"
    }

    pub fn get_description(&self) -> &'static str {
        "Fast passive subdomain discovery tool"
    }

    pub fn get_category(&self) -> &'static str {
        "recon"
    }

    pub fn get_risk_level(&self) -> &'static str {
        "low"
    }

    pub fn requires_authorization(&self) -> bool {
        false
    }

    pub fn get_timeout(&self) -> u64 {
        300 // 5 minutes
    }

    pub fn get_expected_outputs(&self) -> Vec<String> {
        vec!["subdomains.txt".to_string()]
    }
}
