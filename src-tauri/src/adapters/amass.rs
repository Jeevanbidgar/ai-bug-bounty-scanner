use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmassConfig {
    pub target: String,
    pub output_file: Option<String>,
    pub passive: bool,
    pub brute: bool,
    pub active: bool,
}

impl Default for AmassConfig {
    fn default() -> Self {
        Self {
            target: "".to_string(),
            output_file: None,
            passive: true,
            brute: false,
            active: false,
        }
    }
}

pub struct AmassAdapter;

impl AmassAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn build_command(&self, config: &AmassConfig) -> Vec<String> {
        let mut command = vec!["amass".to_string(), "enum".to_string()];

        // Add target domain
        command.push("-d".to_string());
        command.push(config.target.clone());

        // Add output file if specified
        if let Some(output_file) = &config.output_file {
            command.push("-o".to_string());
            command.push(output_file.clone());
        }

        // Add mode flags
        if config.passive {
            command.push("-passive".to_string());
        }

        if config.brute {
            command.push("-brute".to_string());
        }

        if config.active {
            command.push("-active".to_string());
        }

        command
    }

    pub fn build_command_with_defaults(
        &self,
        target: String,
        output_file: Option<String>,
    ) -> Vec<String> {
        let config = AmassConfig {
            target,
            output_file,
            ..Default::default()
        };
        self.build_command(&config)
    }

    pub fn get_tool_name(&self) -> &'static str {
        "amass"
    }

    pub fn get_description(&self) -> &'static str {
        "In-depth DNS enumeration and network mapping"
    }

    pub fn get_category(&self) -> &'static str {
        "recon"
    }

    pub fn get_risk_level(&self) -> &'static str {
        "medium"
    }

    pub fn requires_authorization(&self) -> bool {
        true // Active scanning requires authorization
    }

    pub fn get_timeout(&self) -> u64 {
        600 // 10 minutes (Amass can be slow)
    }

    pub fn get_expected_outputs(&self) -> Vec<String> {
        vec!["subdomains.txt".to_string()]
    }
}
