use super::types::*;
use std::collections::HashMap;

/// Naabu adapter for fast port scanning
pub struct NaabuAdapter;

impl NaabuAdapter {
    /// Create command arguments for naabu
    pub fn build_command(target: &str, output_file: Option<&str>, options: &HashMap<String, String>) -> Vec<String> {
        let mut args = Vec::new();

        // Add target (naabu can take multiple targets)
        args.push(target.to_string());

        // Add output file if specified
        if let Some(output) = output_file {
            args.push("-o".to_string());
            args.push(output.to_string());
        }

        // Add custom options
        for (key, value) in options {
            match key.as_str() {
                "ports" => {
                    args.push("-p".to_string());
                    args.push(value.clone());
                }
                "top_ports" => {
                    args.push("-tp".to_string());
                    args.push(value.clone());
                }
                "exclude_ports" => {
                    args.push("-ep".to_string());
                    args.push(value.clone());
                }
                "scan_type" => {
                    args.push("-s".to_string());
                    args.push(value.clone());
                }
                "rate" => {
                    args.push("-rate".to_string());
                    args.push(value.clone());
                }
                "timeout" => {
                    args.push("-timeout".to_string());
                    args.push(value.clone());
                }
                "retries" => {
                    args.push("-retries".to_string());
                    args.push(value.clone());
                }
                "warmup_time" => {
                    args.push("-warm-up-time".to_string());
                    args.push(value.clone());
                }
                "host_discovery" if value == "true" => args.push("-sn".to_string()),
                "skip_host_discovery" if value == "true" => args.push("-Pn".to_string()),
                "service_detection" if value == "true" => args.push("-sV".to_string()),
                "os_detection" if value == "true" => args.push("-O".to_string()),
                "script_scan" => {
                    args.push("-sC".to_string());
                    if value != "true" {
                        args.push(value.clone());
                    }
                }
                "verbose" if value == "true" => args.push("-v".to_string()),
                "debug" if value == "true" => args.push("-debug".to_string()),
                "json" if value == "true" => args.push("-json".to_string()),
                "csv" if value == "true" => args.push("-csv".to_string()),
                "nmap_cli" => {
                    args.push("-nmap-cli".to_string());
                    args.push(value.clone());
                }
                _ => {
                    // Unknown options are ignored for safety
                }
            }
        }

        args
    }

    /// Get environment variables for naabu
    pub fn get_environment(_options: &HashMap<String, String>) -> HashMap<String, String> {
        HashMap::new()
    }

    /// Get working directory for naabu (uses current directory)
    pub fn get_working_directory() -> Option<String> {
        None
    }

    /// Get timeout in milliseconds for naabu (depends on target size)
    pub fn get_timeout_ms(target: &str) -> u64 {
        // Estimate based on target - larger targets need more time
        let base_timeout = 120000; // 2 minutes base

        if target.contains('/') {
            // CIDR notation or range - could be large
            base_timeout * 3
        } else if target.parse::<std::net::Ipv4Addr>().is_ok() {
            // Single IP - fast
            base_timeout / 2
        } else {
            // Domain - moderate
            base_timeout
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_naabu_basic_command() {
        let args = NaabuAdapter::build_command("example.com", None, &HashMap::new());
        assert!(args.contains(&"example.com".to_string()));
    }

    #[test]
    fn test_naabu_with_ports() {
        let mut options = HashMap::new();
        options.insert("ports".to_string(), "80,443,8080".to_string());

        let args = NaabuAdapter::build_command("example.com", None, &options);
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"80,443,8080".to_string()));
    }

    #[test]
    fn test_naabu_with_output() {
        let args = NaabuAdapter::build_command("example.com", Some("output.txt"), &HashMap::new());
        assert!(args.contains(&"-o".to_string()));
        assert!(args.contains(&"output.txt".to_string()));
    }

    #[test]
    fn test_naabu_with_json_output() {
        let mut options = HashMap::new();
        options.insert("json".to_string(), "true".to_string());

        let args = NaabuAdapter::build_command("example.com", None, &options);
        assert!(args.contains(&"-json".to_string()));
    }
}