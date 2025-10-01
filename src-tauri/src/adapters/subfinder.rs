use super::types::*;
use std::collections::HashMap;

/// Subfinder adapter for subdomain enumeration
pub struct SubfinderAdapter;

impl SubfinderAdapter {
    /// Create command arguments for subfinder
    pub fn build_command(target: &str, output_file: Option<&str>, options: &HashMap<String, String>) -> Vec<String> {
        let mut args = vec![
            "-d".to_string(),
            target.to_string(),
        ];

        // Add output file if specified
        if let Some(output) = output_file {
            args.push("-o".to_string());
            args.push(output.to_string());
        }

        // Add custom options
        for (key, value) in options {
            match key.as_str() {
                "silent" if value == "true" => args.push("-silent".to_string()),
                "all" if value == "true" => args.push("-all".to_string()),
                "recursive" if value == "true" => args.push("-recursive".to_string()),
                "resolvers" => {
                    args.push("-r".to_string());
                    args.push(value.clone());
                }
                "config" => {
                    args.push("-config".to_string());
                    args.push(value.clone());
                }
                "timeout" => {
                    args.push("-timeout".to_string());
                    args.push(value.clone());
                }
                _ => {
                    // Unknown options are ignored for safety
                }
            }
        }

        args
    }

    /// Get environment variables for subfinder
    pub fn get_environment(_options: &HashMap<String, String>) -> HashMap<String, String> {
        HashMap::new()
    }

    /// Get working directory for subfinder (uses current directory)
    pub fn get_working_directory() -> Option<String> {
        None
    }

    /// Get timeout in milliseconds for subfinder
    pub fn get_timeout_ms() -> u64 {
        60000 // 1 minute
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subfinder_basic_command() {
        let args = SubfinderAdapter::build_command("example.com", None, &HashMap::new());
        assert!(args.contains(&"-d".to_string()));
        assert!(args.contains(&"example.com".to_string()));
    }

    #[test]
    fn test_subfinder_with_options() {
        let mut options = HashMap::new();
        options.insert("silent".to_string(), "true".to_string());
        options.insert("recursive".to_string(), "true".to_string());

        let args = SubfinderAdapter::build_command("example.com", Some("output.txt"), &options);
        assert!(args.contains(&"-silent".to_string()));
        assert!(args.contains(&"-recursive".to_string()));
        assert!(args.contains(&"-o".to_string()));
        assert!(args.contains(&"output.txt".to_string()));
    }
}