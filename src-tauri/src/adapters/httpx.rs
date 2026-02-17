use super::types::*;
use std::collections::HashMap;

/// Httpx adapter for HTTP toolkit operations
pub struct HttpxAdapter;

impl HttpxAdapter {
    /// Create command arguments for httpx
    pub fn build_command(target: &str, output_file: Option<&str>, options: &HashMap<String, String>) -> Vec<String> {
        let mut args = Vec::new();

        // Add target (httpx can take multiple targets)
        args.push("-l".to_string()); // Read targets from stdin
        args.push(target.to_string());

        // Add output file if specified
        if let Some(output) = output_file {
            args.push("-o".to_string());
            args.push(output.to_string());
        }

        // Add custom options
        for (key, value) in options {
            match key.as_str() {
                "threads" => {
                    args.push("-t".to_string());
                    args.push(value.clone());
                }
                "rate_limit" => {
                    args.push("-rl".to_string());
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
                "http_proxy" => {
                    args.push("-http-proxy".to_string());
                    args.push(value.clone());
                }
                "https_proxy" => {
                    args.push("-https-proxy".to_string());
                    args.push(value.clone());
                }
                "follow_redirects" if value == "true" => args.push("-follow-redirects".to_string()),
                "follow_host_redirects" if value == "true" => args.push("-follow-host-redirects".to_string()),
                "random_agent" if value == "true" => args.push("-random-agent".to_string()),
                "status_code" if value == "true" => args.push("-status-code".to_string()),
                "content_length" if value == "true" => args.push("-content-length".to_string()),
                "title" if value == "true" => args.push("-title".to_string()),
                "web_server" if value == "true" => args.push("-web-server".to_string()),
                "tech_detect" if value == "true" => args.push("-tech-detect".to_string()),
                "method" => {
                    args.push("-x".to_string());
                    args.push(value.clone());
                }
                "body" => {
                    args.push("-body".to_string());
                    args.push(value.clone());
                }
                "headers" => {
                    for header in value.split(',') {
                        args.push("-H".to_string());
                        args.push(header.trim().to_string());
                    }
                }
                "json" if value == "true" => args.push("-json".to_string()),
                "csv" if value == "true" => args.push("-csv".to_string()),
                "silent" if value == "true" => args.push("-silent".to_string()),
                "verbose" if value == "true" => args.push("-v".to_string()),
                "debug" if value == "true" => args.push("-debug".to_string()),
                "no_color" if value == "true" => args.push("-nc".to_string()),
                _ => {
                    // Unknown options are ignored for safety
                }
            }
        }

        args
    }

    /// Get environment variables for httpx
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

        env
    }

    /// Get working directory for httpx (uses current directory)
    pub fn get_working_directory() -> Option<String> {
        None
    }

    /// Get timeout in milliseconds for httpx (depends on target size)
    pub fn get_timeout_ms(target: &str) -> u64 {
        let base_timeout = 60000; // 1 minute base

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
    fn test_httpx_basic_command() {
        let args = HttpxAdapter::build_command("https://example.com", None, &HashMap::new());
        assert!(args.contains(&"-l".to_string()));
        assert!(args.contains(&"https://example.com".to_string()));
    }

    #[test]
    fn test_httpx_with_threads() {
        let mut options = HashMap::new();
        options.insert("threads".to_string(), "50".to_string());

        let args = HttpxAdapter::build_command("https://example.com", None, &options);
        assert!(args.contains(&"-t".to_string()));
        assert!(args.contains(&"50".to_string()));
    }

    #[test]
    fn test_httpx_with_json_output() {
        let mut options = HashMap::new();
        options.insert("json".to_string(), "true".to_string());

        let args = HttpxAdapter::build_command("https://example.com", None, &options);
        assert!(args.contains(&"-json".to_string()));
    }

    #[test]
    fn test_httpx_environment_variables() {
        let mut options = HashMap::new();
        options.insert("http_proxy".to_string(), "http://proxy.example.com:8080".to_string());

        let env = HttpxAdapter::get_environment(&options);
        assert_eq!(env.get("HTTP_PROXY"), Some(&"http://proxy.example.com:8080".to_string()));
        assert_eq!(env.get("http_proxy"), Some(&"http://proxy.example.com:8080".to_string()));
    }
}