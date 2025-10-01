use super::types::*;
use std::collections::HashMap;

/// Amass adapter for comprehensive network mapping
pub struct AmassAdapter;

impl AmassAdapter {
    /// Create command arguments for amass enum
    pub fn build_enum_command(target: &str, output_file: Option<&str>, options: &HashMap<String, String>) -> Vec<String> {
        let mut args = vec![
            "enum".to_string(),
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
                "passive" if value == "true" => args.push("-passive".to_string()),
                "active" if value == "true" => args.push("-active".to_string()),
                "brute" if value == "true" => args.push("-brute".to_string()),
                "alterations" if value == "true" => args.push("-alterations".to_string()),
                "min_for_recursive" => {
                    args.push("-min-for-recursive".to_string());
                    args.push(value.clone());
                }
                "config" => {
                    args.push("-config".to_string());
                    args.push(value.clone());
                }
                "resolvers" => {
                    args.push("-r".to_string());
                    args.push(value.clone());
                }
                "timeout" => {
                    args.push("-timeout".to_string());
                    args.push(value.clone());
                }
                "max_dns_queries" => {
                    args.push("-max-dns-queries".to_string());
                    args.push(value.clone());
                }
                _ => {
                    // Unknown options are ignored for safety
                }
            }
        }

        args
    }

    /// Create command arguments for amass intel
    pub fn build_intel_command(target: &str, output_file: Option<&str>, options: &HashMap<String, String>) -> Vec<String> {
        let mut args = vec![
            "intel".to_string(),
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
                "whois" if value == "true" => args.push("-whois".to_string()),
                "ip" if value == "true" => args.push("-ip".to_string()),
                "active" if value == "true" => args.push("-active".to_string()),
                _ => {
                    // Unknown options are ignored for safety
                }
            }
        }

        args
    }

    /// Get environment variables for amass
    pub fn get_environment(_options: &HashMap<String, String>) -> HashMap<String, String> {
        HashMap::new()
    }

    /// Get working directory for amass (uses current directory)
    pub fn get_working_directory() -> Option<String> {
        None
    }

    /// Get timeout in milliseconds for amass enum
    pub fn get_enum_timeout_ms() -> u64 {
        600000 // 10 minutes for enumeration
    }

    /// Get timeout in milliseconds for amass intel
    pub fn get_intel_timeout_ms() -> u64 {
        300000 // 5 minutes for intelligence gathering
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amass_enum_command() {
        let args = AmassAdapter::build_enum_command("example.com", None, &HashMap::new());
        assert!(args.contains(&"enum".to_string()));
        assert!(args.contains(&"-d".to_string()));
        assert!(args.contains(&"example.com".to_string()));
    }

    #[test]
    fn test_amass_enum_with_options() {
        let mut options = HashMap::new();
        options.insert("passive".to_string(), "true".to_string());
        options.insert("brute".to_string(), "true".to_string());

        let args = AmassAdapter::build_enum_command("example.com", Some("output.txt"), &options);
        assert!(args.contains(&"-passive".to_string()));
        assert!(args.contains(&"-brute".to_string()));
        assert!(args.contains(&"-o".to_string()));
        assert!(args.contains(&"output.txt".to_string()));
    }

    #[test]
    fn test_amass_intel_command() {
        let args = AmassAdapter::build_intel_command("example.com", None, &HashMap::new());
        assert!(args.contains(&"intel".to_string()));
        assert!(args.contains(&"-d".to_string()));
        assert!(args.contains(&"example.com".to_string()));
    }
}