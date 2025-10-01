use super::types::*;
use std::collections::HashMap;

/// Nuclei adapter for template-based vulnerability scanning
pub struct NucleiAdapter;

impl NucleiAdapter {
    /// Create command arguments for nuclei
    pub fn build_command(target: &str, output_file: Option<&str>, options: &HashMap<String, String>) -> Vec<String> {
        let mut args = Vec::new();

        // Add target (nuclei can take multiple targets)
        args.push("-l".to_string()); // Read targets from stdin
        args.push(target.to_string());

        // Add output file if specified
        if let Some(output) = output_file {
            args.push("-o".to_string());
            args.push(output.to_string());
        }

        // Add JSON output for structured data
        args.push("-json".to_string());

        // Add custom options
        for (key, value) in options {
            match key.as_str() {
                "templates" => {
                    args.push("-t".to_string());
                    args.push(value.clone());
                }
                "template_filters" => {
                    args.push("-tf".to_string());
                    args.push(value.clone());
                }
                "tags" => {
                    args.push("-tags".to_string());
                    args.push(value.clone());
                }
                "exclude_tags" => {
                    args.push("-etags".to_string());
                    args.push(value.clone());
                }
                "severity" => {
                    args.push("-severity".to_string());
                    args.push(value.clone());
                }
                "author" => {
                    args.push("-author".to_string());
                    args.push(value.clone());
                }
                "template_types" => {
                    args.push("-type".to_string());
                    args.push(value.clone());
                }
                "threads" => {
                    args.push("-c".to_string());
                    args.push(value.clone());
                }
                "rate_limit" => {
                    args.push("-rl".to_string());
                    args.push(value.clone());
                }
                "bulk_size" => {
                    args.push("-bs".to_string());
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
                "max_hosts" => {
                    args.push("-mh".to_string());
                    args.push(value.clone());
                }
                "headless" if value == "true" => args.push("-headless".to_string()),
                "system_chrome" if value == "true" => args.push("-system-chrome".to_string()),
                "no_interaction" if value == "true" => args.push("-no-interaction".to_string()),
                "follow_redirects" if value == "true" => args.push("-follow-redirects".to_string()),
                "follow_host_redirects" if value == "true" => args.push("-follow-host-redirects".to_string()),
                "disable_redirects" if value == "true" => args.push("-disable-redirects".to_string()),
                "random_agent" if value == "true" => args.push("-random-agent".to_string()),
                "proxy" => {
                    args.push("-proxy".to_string());
                    args.push(value.clone());
                }
                "http_proxy" => {
                    args.push("-http-proxy".to_string());
                    args.push(value.clone());
                }
                "https_proxy" => {
                    args.push("-https-proxy".to_string());
                    args.push(value.clone());
                }
                "custom_headers" => {
                    for header in value.split(',') {
                        args.push("-H".to_string());
                        args.push(header.trim().to_string());
                    }
                }
                "stats" if value == "true" => args.push("-stats".to_string()),
                "stats_interval" => {
                    args.push("-stats-interval".to_string());
                    args.push(value.clone());
                }
                "metrics" if value == "true" => args.push("-metrics".to_string()),
                "debug" if value == "true" => args.push("-debug".to_string()),
                "verbose" if value == "true" => args.push("-v".to_string()),
                "silent" if value == "true" => args.push("-silent".to_string()),
                "no_color" if value == "true" => args.push("-nc".to_string()),
                "update_templates" if value == "true" => args.push("-update-templates".to_string()),
                "update_directory" => {
                    args.push("-update-directory".to_string());
                    args.push(value.clone());
                }
                "templates_directory" => {
                    args.push("-td".to_string());
                    args.push(value.clone());
                }
                "config" => {
                    args.push("-config".to_string());
                    args.push(value.clone());
                }
                "report_config" => {
                    args.push("-rc".to_string());
                    args.push(value.clone());
                }
                "markdown_export" => {
                    args.push("-markdown-export".to_string());
                    args.push(value.clone());
                }
                "sarif_export" => {
                    args.push("-sarif-export".to_string());
                    args.push(value.clone());
                }
                "jsonl_export" if value == "true" => args.push("-j".to_string()),
                "jsonl_export_file" => {
                    args.push("-j".to_string());
                    args.push(value.clone());
                }
                _ => {
                    // Unknown options are ignored for safety
                }
            }
        }

        args
    }

    /// Get environment variables for nuclei
    pub fn get_environment(options: &HashMap<String, String>) -> HashMap<String, String> {
        let mut env = HashMap::new();

        // Set proxy environment variables if specified
        if let Some(http_proxy) = options.get("http_proxy") {
            env.insert("HTTP_PROXY".to_string(), http_proxy.clone());
            env.insert("http_proxy".to_string(), http_proxy.clone());
        }

        if let Some(https_proxy) = options.get("https_proxy") {
            env.insert("HTTPS_PROXY".to_string(), https_proxy.clone());
            env.insert("https_proxy".to_string(), https_proxy.clone());
        }

        if let Some(proxy) = options.get("proxy") {
            env.insert("HTTP_PROXY".to_string(), proxy.clone());
            env.insert("HTTPS_PROXY".to_string(), proxy.clone());
            env.insert("http_proxy".to_string(), proxy.clone());
            env.insert("https_proxy".to_string(), proxy.clone());
        }

        env
    }

    /// Get working directory for nuclei (uses current directory)
    pub fn get_working_directory() -> Option<String> {
        None
    }

    /// Get timeout in milliseconds for nuclei (depends on template count and target size)
    pub fn get_timeout_ms(target: &str, options: &HashMap<String, String>) -> u64 {
        let base_timeout = 600000; // 10 minutes base

        // Adjust based on target size
        if target.contains('/') {
            // Multiple targets or file input - could be large
            base_timeout * 2
        } else {
            // Single target - standard timeout
            base_timeout
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nuclei_basic_command() {
        let args = NucleiAdapter::build_command("https://example.com", None, &HashMap::new());
        assert!(args.contains(&"-l".to_string()));
        assert!(args.contains(&"https://example.com".to_string()));
        assert!(args.contains(&"-json".to_string()));
    }

    #[test]
    fn test_nuclei_with_templates() {
        let mut options = HashMap::new();
        options.insert("templates".to_string(), "/path/to/templates".to_string());

        let args = NucleiAdapter::build_command("https://example.com", None, &options);
        assert!(args.contains(&"-t".to_string()));
        assert!(args.contains(&"/path/to/templates".to_string()));
    }

    #[test]
    fn test_nuclei_with_severity() {
        let mut options = HashMap::new();
        options.insert("severity".to_string(), "high,critical".to_string());

        let args = NucleiAdapter::build_command("https://example.com", None, &options);
        assert!(args.contains(&"-severity".to_string()));
        assert!(args.contains(&"high,critical".to_string()));
    }

    #[test]
    fn test_nuclei_with_jsonl_export() {
        let mut options = HashMap::new();
        options.insert("jsonl_export".to_string(), "true".to_string());

        let args = NucleiAdapter::build_command("https://example.com", None, &options);
        assert!(args.contains(&"-j".to_string()));
    }

    #[test]
    fn test_nuclei_environment_variables() {
        let mut options = HashMap::new();
        options.insert("http_proxy".to_string(), "http://proxy.example.com:8080".to_string());

        let env = NucleiAdapter::get_environment(&options);
        assert_eq!(env.get("HTTP_PROXY"), Some(&"http://proxy.example.com:8080".to_string()));
        assert_eq!(env.get("http_proxy"), Some(&"http://proxy.example.com:8080".to_string()));
    }
}