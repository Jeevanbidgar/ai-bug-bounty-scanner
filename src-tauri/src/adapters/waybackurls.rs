use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaybackURLsConfig {
    pub target: String,
    pub output_file: Option<String>,
}

impl Default for WaybackURLsConfig {
    fn default() -> Self {
        Self {
            target: "".to_string(),
            output_file: None,
        }
    }
}

pub struct WaybackURLsAdapter;

impl WaybackURLsAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn build_command(&self, config: &WaybackURLsConfig) -> Vec<String> {
        let mut command = vec!["waybackurls".to_string()];

        // Add target domain
        command.push(config.target.clone());

        // Note: waybackurls outputs to stdout
        // Output redirection is handled by the executor

        command
    }

    pub fn build_command_with_defaults(
        &self,
        target: String,
        output_file: Option<String>,
    ) -> Vec<String> {
        let config = WaybackURLsConfig {
            target,
            output_file,
        };
        self.build_command(&config)
    }

    pub fn get_tool_name(&self) -> &'static str {
        "waybackurls"
    }

    pub fn get_description(&self) -> &'static str {
        "Fetch all URLs from the Wayback Machine for a given domain"
    }

    pub fn get_category(&self) -> &'static str {
        "recon"
    }

    pub fn get_risk_level(&self) -> &'static str {
        "low"
    }

    pub fn requires_authorization(&self) -> bool {
        false // Passive archive lookup
    }

    pub fn get_timeout(&self) -> u64 {
        300 // 5 minutes
    }

    pub fn get_expected_outputs(&self) -> Vec<String> {
        vec!["archive_urls.txt".to_string()]
    }
}
