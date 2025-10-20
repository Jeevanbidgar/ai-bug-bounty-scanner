#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Generic adapter that works for 80% of security tools
/// Instead of creating 57 custom adapters, this handles common patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericAdapter {
    pub tool_name: String,
    pub config: ToolConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    /// How to pass the target (e.g., "-d", "-target", "--domain", "-u")
    pub target_flag: String,

    /// How to specify output file (None = stdout redirect)
    pub output_flag: Option<String>,

    /// Common flags to always include
    pub default_flags: Vec<String>,

    /// Does this tool require the target to be a URL?
    pub requires_url: bool,

    /// Does this tool output JSON by default?
    pub outputs_json: bool,

    /// Tool category
    pub category: String,

    /// Execution timeout in seconds
    pub timeout: u64,

    /// Does this tool require authorization?
    pub requires_auth: bool,
}

impl GenericAdapter {
    /// Create a generic adapter for any tool
    pub fn new(tool_name: String, config: ToolConfig) -> Self {
        Self { tool_name, config }
    }

    /// Create adapter from predefined patterns
    pub fn from_preset(tool_name: &str) -> Result<Self, String> {
        let config = match tool_name.to_lowercase().as_str() {
            // Subdomain Discovery Tools
            "assetfinder" => ToolConfig {
                target_flag: "--subs-only".to_string(),
                output_flag: None, // Uses stdout
                default_flags: vec![],
                requires_url: false,
                outputs_json: false,
                category: "subdomain_discovery".to_string(),
                timeout: 300,
                requires_auth: false,
            },
            "crt.sh" => ToolConfig {
                target_flag: "".to_string(), // Just the domain
                output_flag: None,
                default_flags: vec![],
                requires_url: false,
                outputs_json: true,
                category: "subdomain_discovery".to_string(),
                timeout: 120,
                requires_auth: false,
            },

            // Web Crawlers
            "hakrawler" => ToolConfig {
                target_flag: "-url".to_string(),
                output_flag: None,
                default_flags: vec!["-depth".to_string(), "2".to_string()],
                requires_url: true,
                outputs_json: false,
                category: "crawler".to_string(),
                timeout: 600,
                requires_auth: false,
            },
            "gospider" => ToolConfig {
                target_flag: "-s".to_string(),
                output_flag: Some("-o".to_string()),
                default_flags: vec![
                    "-c".to_string(),
                    "10".to_string(),
                    "-d".to_string(),
                    "3".to_string(),
                ],
                requires_url: true,
                outputs_json: false,
                category: "crawler".to_string(),
                timeout: 600,
                requires_auth: false,
            },
            "katana" => ToolConfig {
                target_flag: "-u".to_string(),
                output_flag: Some("-o".to_string()),
                default_flags: vec!["-d".to_string(), "3".to_string(), "-jc".to_string()],
                requires_url: true,
                outputs_json: false,
                category: "crawler".to_string(),
                timeout: 600,
                requires_auth: false,
            },

            // HTTP Probing
            "httpx" => ToolConfig {
                target_flag: "-l".to_string(), // Takes file input
                output_flag: Some("-o".to_string()),
                default_flags: vec![
                    "-silent".to_string(),
                    "-json".to_string(),
                    "-status-code".to_string(),
                    "-title".to_string(),
                    "-tech-detect".to_string(),
                ],
                requires_url: false,
                outputs_json: true,
                category: "http_probe".to_string(),
                timeout: 300,
                requires_auth: false,
            },

            // Directory/File Fuzzing
            "ffuf" => ToolConfig {
                target_flag: "-u".to_string(),
                output_flag: Some("-o".to_string()),
                default_flags: vec![
                    "-w".to_string(),
                    "wordlist.txt".to_string(), // Would be replaced dynamically
                    "-of".to_string(),
                    "json".to_string(),
                ],
                requires_url: true,
                outputs_json: true,
                category: "fuzzer".to_string(),
                timeout: 1800,
                requires_auth: true,
            },
            "gobuster" => ToolConfig {
                target_flag: "-u".to_string(),
                output_flag: Some("-o".to_string()),
                default_flags: vec![
                    "-w".to_string(),
                    "wordlist.txt".to_string(),
                    "-t".to_string(),
                    "50".to_string(),
                ],
                requires_url: true,
                outputs_json: false,
                category: "fuzzer".to_string(),
                timeout: 1800,
                requires_auth: true,
            },
            "feroxbuster" => ToolConfig {
                target_flag: "-u".to_string(),
                output_flag: Some("-o".to_string()),
                default_flags: vec![
                    "-w".to_string(),
                    "wordlist.txt".to_string(),
                    "--json".to_string(),
                ],
                requires_url: true,
                outputs_json: true,
                category: "fuzzer".to_string(),
                timeout: 1800,
                requires_auth: true,
            },
            "dirsearch" => ToolConfig {
                target_flag: "-u".to_string(),
                output_flag: Some("-o".to_string()),
                default_flags: vec![
                    "-w".to_string(),
                    "wordlist.txt".to_string(),
                    "--format=json".to_string(),
                ],
                requires_url: true,
                outputs_json: true,
                category: "fuzzer".to_string(),
                timeout: 1800,
                requires_auth: true,
            },

            // DNS Tools
            "dnsx" => ToolConfig {
                target_flag: "-l".to_string(), // Takes file input
                output_flag: Some("-o".to_string()),
                default_flags: vec!["-silent".to_string(), "-json".to_string()],
                requires_url: false,
                outputs_json: true,
                category: "dns".to_string(),
                timeout: 300,
                requires_auth: false,
            },
            "shuffledns" => ToolConfig {
                target_flag: "-d".to_string(),
                output_flag: Some("-o".to_string()),
                default_flags: vec![
                    "-w".to_string(),
                    "wordlist.txt".to_string(),
                    "-r".to_string(),
                    "resolvers.txt".to_string(),
                ],
                requires_url: false,
                outputs_json: false,
                category: "dns".to_string(),
                timeout: 600,
                requires_auth: false,
            },
            "massdns" => ToolConfig {
                target_flag: "".to_string(), // Special: takes file as positional arg
                output_flag: Some("-o".to_string()),
                default_flags: vec!["-r".to_string(), "resolvers.txt".to_string()],
                requires_url: false,
                outputs_json: false,
                category: "dns".to_string(),
                timeout: 600,
                requires_auth: false,
            },

            // Parameter Discovery
            "arjun" => ToolConfig {
                target_flag: "-u".to_string(),
                output_flag: Some("-o".to_string()),
                default_flags: vec!["--json".to_string()],
                requires_url: true,
                outputs_json: true,
                category: "param_discovery".to_string(),
                timeout: 900,
                requires_auth: true,
            },
            "paramspider" => ToolConfig {
                target_flag: "-d".to_string(),
                output_flag: Some("-o".to_string()),
                default_flags: vec![],
                requires_url: false,
                outputs_json: false,
                category: "param_discovery".to_string(),
                timeout: 600,
                requires_auth: false,
            },

            // Technology Detection
            "wappalyzer" => ToolConfig {
                target_flag: "".to_string(), // Just URL
                output_flag: None,
                default_flags: vec![],
                requires_url: true,
                outputs_json: true,
                category: "tech_detection".to_string(),
                timeout: 120,
                requires_auth: false,
            },
            "whatweb" => ToolConfig {
                target_flag: "".to_string(), // Just URL
                output_flag: None,
                default_flags: vec!["--aggression=3".to_string(), "-a=3".to_string()],
                requires_url: true,
                outputs_json: false,
                category: "tech_detection".to_string(),
                timeout: 120,
                requires_auth: false,
            },

            // Screenshot Tools
            "gowitness" => ToolConfig {
                target_flag: "file".to_string(), // Special: uses 'file' subcommand
                output_flag: Some("-f".to_string()),
                default_flags: vec![],
                requires_url: false,
                outputs_json: false,
                category: "screenshot".to_string(),
                timeout: 1800,
                requires_auth: false,
            },
            "aquatone" => ToolConfig {
                target_flag: "".to_string(), // Reads from stdin
                output_flag: Some("-out".to_string()),
                default_flags: vec![],
                requires_url: false,
                outputs_json: false,
                category: "screenshot".to_string(),
                timeout: 1800,
                requires_auth: false,
            },

            // JavaScript Analysis
            "linkfinder" => ToolConfig {
                target_flag: "-i".to_string(),
                output_flag: Some("-o".to_string()),
                default_flags: vec![],
                requires_url: true,
                outputs_json: false,
                category: "js_analysis".to_string(),
                timeout: 300,
                requires_auth: false,
            },
            "getjs" => ToolConfig {
                target_flag: "--url".to_string(),
                output_flag: Some("--output".to_string()),
                default_flags: vec![],
                requires_url: true,
                outputs_json: false,
                category: "js_analysis".to_string(),
                timeout: 300,
                requires_auth: false,
            },

            // Git Tools
            "gitdumper" => ToolConfig {
                target_flag: "".to_string(), // <url> <output_dir>
                output_flag: None,
                default_flags: vec![],
                requires_url: true,
                outputs_json: false,
                category: "git_exposure".to_string(),
                timeout: 600,
                requires_auth: false,
            },
            "truffleHog" => ToolConfig {
                target_flag: "".to_string(),
                output_flag: None,
                default_flags: vec!["--json".to_string()],
                requires_url: false,
                outputs_json: true,
                category: "secret_scanning".to_string(),
                timeout: 900,
                requires_auth: false,
            },

            // CMS Scanners
            "wpscan" => ToolConfig {
                target_flag: "--url".to_string(),
                output_flag: Some("--output".to_string()),
                default_flags: vec![
                    "--format".to_string(),
                    "json".to_string(),
                    "--enumerate".to_string(),
                    "vp,vt,u".to_string(),
                ],
                requires_url: true,
                outputs_json: true,
                category: "cms_scanner".to_string(),
                timeout: 1800,
                requires_auth: true,
            },
            "joomscan" => ToolConfig {
                target_flag: "-u".to_string(),
                output_flag: None,
                default_flags: vec![],
                requires_url: true,
                outputs_json: false,
                category: "cms_scanner".to_string(),
                timeout: 1800,
                requires_auth: true,
            },
            "droopescan" => ToolConfig {
                target_flag: "scan".to_string(), // Subcommand
                output_flag: Some("-o".to_string()),
                default_flags: vec!["--url".to_string()],
                requires_url: true,
                outputs_json: false,
                category: "cms_scanner".to_string(),
                timeout: 1800,
                requires_auth: true,
            },

            // Vulnerability Scanners
            "nikto" => ToolConfig {
                target_flag: "-h".to_string(),
                output_flag: Some("-o".to_string()),
                default_flags: vec!["-Format".to_string(), "json".to_string()],
                requires_url: true,
                outputs_json: true,
                category: "vulnerability".to_string(),
                timeout: 3600,
                requires_auth: true,
            },

            // Miscellaneous
            "cloudflare-enum" => ToolConfig {
                target_flag: "-d".to_string(),
                output_flag: Some("-o".to_string()),
                default_flags: vec![],
                requires_url: false,
                outputs_json: false,
                category: "cloud".to_string(),
                timeout: 300,
                requires_auth: false,
            },
            "chaos" => ToolConfig {
                target_flag: "-d".to_string(),
                output_flag: Some("-o".to_string()),
                default_flags: vec!["-silent".to_string()],
                requires_url: false,
                outputs_json: false,
                category: "subdomain_discovery".to_string(),
                timeout: 300,
                requires_auth: false,
            },

            _ => return Err(format!("No preset configuration for tool: {}", tool_name)),
        };

        Ok(Self::new(tool_name.to_string(), config))
    }

    /// Build command for execution
    pub fn build_command(
        &self,
        target: &str,
        output_file: Option<&str>,
        extra_flags: Option<Vec<String>>,
    ) -> Vec<String> {
        let mut command = vec![self.tool_name.clone()];

        // Add target flag and target
        if !self.config.target_flag.is_empty() {
            command.push(self.config.target_flag.clone());
        }

        // Format target (URL if required)
        let formatted_target = if self.config.requires_url && !target.starts_with("http") {
            format!("https://{}", target)
        } else {
            target.to_string()
        };
        command.push(formatted_target);

        // Add output file if specified
        if let (Some(output_flag), Some(output_file)) = (&self.config.output_flag, output_file) {
            command.push(output_flag.clone());
            command.push(output_file.to_string());
        }

        // Add default flags
        command.extend(self.config.default_flags.clone());

        // Add extra flags if provided
        if let Some(extra) = extra_flags {
            command.extend(extra);
        }

        command
    }

    /// Get tool metadata
    pub fn get_info(&self) -> GenericAdapterInfo {
        GenericAdapterInfo {
            tool_name: self.tool_name.clone(),
            category: self.config.category.clone(),
            timeout: self.config.timeout,
            requires_auth: self.config.requires_auth,
            outputs_json: self.config.outputs_json,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericAdapterInfo {
    pub tool_name: String,
    pub category: String,
    pub timeout: u64,
    pub requires_auth: bool,
    pub outputs_json: bool,
}

/// Manager for all generic adapters
pub struct GenericAdapterManager {
    adapters: HashMap<String, GenericAdapter>,
}

impl GenericAdapterManager {
    pub fn new() -> Self {
        let mut adapters = HashMap::new();

        // Load all preset adapters
        let tool_names = vec![
            "assetfinder",
            "crt.sh",
            "hakrawler",
            "gospider",
            "katana",
            "httpx",
            "ffuf",
            "gobuster",
            "feroxbuster",
            "dirsearch",
            "dnsx",
            "shuffledns",
            "massdns",
            "arjun",
            "paramspider",
            "wappalyzer",
            "whatweb",
            "gowitness",
            "aquatone",
            "linkfinder",
            "getjs",
            "gitdumper",
            "truffleHog",
            "wpscan",
            "joomscan",
            "droopescan",
            "nikto",
            "cloudflare-enum",
            "chaos",
        ];

        for tool_name in tool_names {
            if let Ok(adapter) = GenericAdapter::from_preset(tool_name) {
                adapters.insert(tool_name.to_string(), adapter);
            }
        }

        Self { adapters }
    }

    /// Get adapter for a tool
    pub fn get_adapter(&self, tool_name: &str) -> Option<&GenericAdapter> {
        self.adapters.get(tool_name)
    }

    /// Check if adapter exists
    pub fn has_adapter(&self, tool_name: &str) -> bool {
        self.adapters.contains_key(tool_name)
    }

    /// List all available adapters
    pub fn list_adapters(&self) -> Vec<String> {
        self.adapters.keys().cloned().collect()
    }

    /// Get adapters by category
    pub fn get_by_category(&self, category: &str) -> Vec<&GenericAdapter> {
        self.adapters
            .values()
            .filter(|a| a.config.category == category)
            .collect()
    }

    /// Build command for any tool
    pub fn build_command(
        &self,
        tool_name: &str,
        target: &str,
        output_file: Option<&str>,
        extra_flags: Option<Vec<String>>,
    ) -> Result<Vec<String>, String> {
        let adapter = self
            .get_adapter(tool_name)
            .ok_or_else(|| format!("No adapter found for: {}", tool_name))?;

        Ok(adapter.build_command(target, output_file, extra_flags))
    }
}

impl Default for GenericAdapterManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_adapter_creation() {
        let adapter = GenericAdapter::from_preset("httpx").unwrap();
        assert_eq!(adapter.tool_name, "httpx");
        assert!(adapter.config.outputs_json);
    }

    #[test]
    fn test_command_building() {
        let adapter = GenericAdapter::from_preset("httpx").unwrap();
        let cmd = adapter.build_command("example.com", Some("/tmp/output.json"), None);

        assert!(cmd.contains(&"httpx".to_string()));
        assert!(cmd.contains(&"-l".to_string()));
        assert!(cmd.contains(&"-o".to_string()));
    }

    #[test]
    fn test_adapter_manager() {
        let manager = GenericAdapterManager::new();
        assert!(manager.has_adapter("httpx"));
        assert!(manager.has_adapter("ffuf"));
        assert!(manager.list_adapters().len() > 25);
    }

    #[test]
    fn test_category_filtering() {
        let manager = GenericAdapterManager::new();
        let fuzzers = manager.get_by_category("fuzzer");
        assert!(fuzzers.len() >= 4); // ffuf, gobuster, feroxbuster, dirsearch
    }

    #[test]
    fn test_url_formatting() {
        let adapter = GenericAdapter::from_preset("hakrawler").unwrap();
        let cmd = adapter.build_command("example.com", None, None);

        // Should add https:// prefix
        assert!(cmd.iter().any(|s| s.starts_with("https://")));
    }
}
