use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NaabuConfig {
    pub target: String,
    pub output_file: Option<String>,
    pub ports: Option<String>,
    pub rate: Option<u32>,
    pub passive: bool,
    pub verbose: bool,
}

impl Default for NaabuConfig {
    fn default() -> Self {
        Self {
            target: "".to_string(),
            output_file: None,
            ports: None,
            rate: None,
            passive: false,
            verbose: false,
        }
    }
}

pub struct NaabuAdapter;

impl NaabuAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn build_command(&self, config: &NaabuConfig) -> Vec<String> {
        let mut command = vec!["naabu".to_string()];

        // Add target host
        command.push("-host".to_string());
        command.push(config.target.clone());

        // Add output file if specified
        if let Some(output_file) = &config.output_file {
            command.push("-o".to_string());
            command.push(output_file.clone());
        }

        // Add port specification
        if let Some(ports) = &config.ports {
            command.push("-p".to_string());
            command.push(ports.clone());
        }

        // Add rate limit
        if let Some(rate) = config.rate {
            command.push("-rate".to_string());
            command.push(rate.to_string());
        }

        // Add mode flags
        if config.passive {
            command.push("-passive".to_string());
        }

        if config.verbose {
            command.push("-v".to_string());
        }

        command
    }

    pub fn build_command_with_defaults(
        &self,
        target: String,
        output_file: Option<String>,
    ) -> Vec<String> {
        let config = NaabuConfig {
            target,
            output_file,
            ..Default::default()
        };
        self.build_command(&config)
    }

    pub fn get_tool_name(&self) -> &'static str {
        "naabu"
    }

    pub fn get_description(&self) -> &'static str {
        "Fast port scanner written in Go"
    }

    pub fn get_category(&self) -> &'static str {
        "port-scan"
    }

    pub fn get_risk_level(&self) -> &'static str {
        "medium"
    }

    pub fn requires_authorization(&self) -> bool {
        true // Port scanning requires authorization
    }

    pub fn get_timeout(&self) -> u64 {
        300 // 5 minutes
    }

    pub fn get_expected_outputs(&self) -> Vec<String> {
        vec!["open_ports.txt".to_string()]
    }
}
