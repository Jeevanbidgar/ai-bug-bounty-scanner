use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapConfig {
    pub target: String,
    pub output_file: Option<String>,
    pub xml_output_file: Option<String>,
    pub service_scan: bool,
    pub script_scan: bool,
    pub os_detection: bool,
    pub ports: Option<String>,
}

impl Default for NmapConfig {
    fn default() -> Self {
        Self {
            target: "".to_string(),
            output_file: None,
            xml_output_file: None,
            service_scan: true,
            script_scan: true,
            os_detection: false,
            ports: None,
        }
    }
}

#[derive(Default)]
pub struct NmapAdapter;

impl NmapAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn build_command(&self, config: &NmapConfig) -> Vec<String> {
        let mut command = vec!["nmap".to_string()];

        // Add output files
        if let Some(output_file) = &config.output_file {
            command.push("-oN".to_string());
            command.push(output_file.clone());
        }

        if let Some(xml_output_file) = &config.xml_output_file {
            command.push("-oX".to_string());
            command.push(xml_output_file.clone());
        }

        // Add scan options
        if config.service_scan {
            command.push("-sV".to_string());
        }

        if config.script_scan {
            command.push("-sC".to_string());
        }

        if config.os_detection {
            command.push("-O".to_string());
        }

        // Add port specification
        if let Some(ports) = &config.ports {
            command.push("-p".to_string());
            command.push(ports.clone());
        }

        // Add target (must be last)
        command.push(config.target.clone());

        command
    }

    pub fn build_command_with_defaults(
        &self,
        target: String,
        output_file: Option<String>,
    ) -> Vec<String> {
        let config = NmapConfig {
            target,
            output_file: output_file.clone(),
            xml_output_file: output_file.as_ref().map(|f| f.replace(".txt", ".xml")),
            ..Default::default()
        };
        self.build_command(&config)
    }

    pub fn get_tool_name(&self) -> &'static str {
        "nmap"
    }

    pub fn get_description(&self) -> &'static str {
        "Network exploration tool and security scanner"
    }

    pub fn get_category(&self) -> &'static str {
        "port-scan"
    }

    pub fn get_risk_level(&self) -> &'static str {
        "high"
    }

    pub fn requires_authorization(&self) -> bool {
        true // Nmap requires explicit authorization
    }

    pub fn get_timeout(&self) -> u64 {
        1800 // 30 minutes (deep scans take time)
    }

    pub fn get_expected_outputs(&self) -> Vec<String> {
        vec![
            "scan_results.txt".to_string(),
            "scan_results.xml".to_string(),
        ]
    }
}
