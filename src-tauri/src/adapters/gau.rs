use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GAUConfig {
    pub target: String,
    pub output_file: Option<String>,
    pub threads: Option<u32>,
    pub verbose: bool,
}

impl Default for GAUConfig {
    fn default() -> Self {
        Self {
            target: "".to_string(),
            output_file: None,
            threads: None,
            verbose: false,
        }
    }
}

pub struct GAUAdapter;

impl GAUAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn build_command(&self, config: &GAUConfig) -> Vec<String> {
        let mut command = vec!["gau".to_string()];

        // Add target domain
        command.push(config.target.clone());

        // Add output file if specified
        if let Some(output_file) = &config.output_file {
            command.push("--o".to_string());
            command.push(output_file.clone());
        }

        // Add threads
        if let Some(threads) = config.threads {
            command.push("--threads".to_string());
            command.push(threads.to_string());
        }

        // Add verbose flag
        if config.verbose {
            command.push("--verbose".to_string());
        }

        command
    }

    pub fn build_command_with_defaults(
        &self,
        target: String,
        output_file: Option<String>,
    ) -> Vec<String> {
        let config = GAUConfig {
            target,
            output_file,
            ..Default::default()
        };
        self.build_command(&config)
    }

    pub fn get_tool_name(&self) -> &'static str {
        "gau"
    }

    pub fn get_description(&self) -> &'static str {
        "Fetch known URLs from AlienVault's Open Threat Exchange, Wayback Machine, and Common Crawl"
    }

    pub fn get_category(&self) -> &'static str {
        "recon"
    }

    pub fn get_risk_level(&self) -> &'static str {
        "low"
    }

    pub fn requires_authorization(&self) -> bool {
        false // Passive URL discovery
    }

    pub fn get_timeout(&self) -> u64 {
        300 // 5 minutes
    }

    pub fn get_expected_outputs(&self) -> Vec<String> {
        vec!["urls.txt".to_string()]
    }
}
