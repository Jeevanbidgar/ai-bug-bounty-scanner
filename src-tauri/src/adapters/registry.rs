// Central registry for all security tool adapters
//
// This module provides a unified interface for accessing and using all tool adapters,
// making it easy to build commands programmatically across the application.

use serde::{Deserialize, Serialize};

use super::{
    amass::{AmassAdapter, AmassConfig},
    gau::{GAUAdapter, GAUConfig},
    naabu::{NaabuAdapter, NaabuConfig},
    nmap::{NmapAdapter, NmapConfig},
    nuclei::{NucleiAdapter, NucleiConfig},
    profile::{AdapterProfile, CommandProfile, OutputPlacement, TargetPlacement, TargetTransform},
    subfinder::{SubfinderAdapter, SubfinderConfig},
    waybackurls::{WaybackURLsAdapter, WaybackURLsConfig},
};

/// Enumeration of all available adapter types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "config")]
pub enum AdapterType {
    Subfinder(SubfinderConfig),
    Amass(AmassConfig),
    Naabu(NaabuConfig),
    Nmap(NmapConfig),
    Nuclei(NucleiConfig),
    GAU(GAUConfig),
    WaybackURLs(WaybackURLsConfig),
}

/// Information about an adapter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterInfo {
    pub name: String,
    pub tool_name: String,
    pub description: String,
    pub category: String,
    pub risk_level: String,
    pub requires_authorization: bool,
    pub timeout: u64,
    pub expected_outputs: Vec<String>,
    pub origin: String,
    pub status: String,
    pub confidence: f64,
    pub generated_at: Option<String>,
    pub verified_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandPreview {
    pub argv: Vec<String>,
    pub stdin: Option<String>,
}

const CORE_ADAPTER_PROFILES: &[AdapterProfile] = &[
    AdapterProfile {
        name: "HTTPX",
        tool_name: "httpx",
        description: "Probe HTTP services and collect status, title, and technology metadata",
        category: "http probe",
        risk_level: "medium",
        requires_authorization: true,
        timeout: 600,
        expected_outputs: &["jsonl", "service metadata"],
        command: CommandProfile {
            executable: "httpx",
            prefix_args: &[],
            target: TargetPlacement::Flag("-u"),
            target_transform: TargetTransform::EnsureHttpUrl,
            suffix_args: &["-silent", "-json", "-status-code", "-title", "-tech-detect"],
            output: OutputPlacement::Flag {
                prelude: &[],
                flag: "-o",
            },
        },
    },
    AdapterProfile {
        name: "FFUF",
        tool_name: "ffuf",
        description: "Discover web content using a bounded FUZZ path and managed wordlist",
        category: "content discovery",
        risk_level: "high",
        requires_authorization: true,
        timeout: 1800,
        expected_outputs: &["json", "discovered paths"],
        command: CommandProfile {
            executable: "ffuf",
            prefix_args: &[],
            target: TargetPlacement::Flag("-u"),
            target_transform: TargetTransform::EnsureHttpUrlWithSuffix("/FUZZ"),
            suffix_args: &["-w", "<unihack-managed-web-wordlist>", "-of", "json"],
            output: OutputPlacement::Flag {
                prelude: &[],
                flag: "-o",
            },
        },
    },
    AdapterProfile {
        name: "Gobuster",
        tool_name: "gobuster",
        description: "Enumerate web directories with an explicit mode and managed wordlist",
        category: "content discovery",
        risk_level: "high",
        requires_authorization: true,
        timeout: 1800,
        expected_outputs: &["text", "discovered paths"],
        command: CommandProfile {
            executable: "gobuster",
            prefix_args: &["dir"],
            target: TargetPlacement::Flag("-u"),
            target_transform: TargetTransform::EnsureHttpUrl,
            suffix_args: &["-w", "<unihack-managed-web-wordlist>"],
            output: OutputPlacement::Flag {
                prelude: &[],
                flag: "-o",
            },
        },
    },
    AdapterProfile {
        name: "SQLMap",
        tool_name: "sqlmap",
        description: "Perform conservative, non-interactive SQL injection detection",
        category: "vulnerability",
        risk_level: "high",
        requires_authorization: true,
        timeout: 2400,
        expected_outputs: &["session directory", "detection log"],
        command: CommandProfile {
            executable: "sqlmap",
            prefix_args: &[],
            target: TargetPlacement::Flag("-u"),
            target_transform: TargetTransform::EnsureHttpUrl,
            suffix_args: &["--batch", "--level=1", "--risk=1", "--disable-coloring"],
            output: OutputPlacement::InlinePrefix("--output-dir="),
        },
    },
    AdapterProfile {
        name: "Nikto",
        tool_name: "nikto",
        description: "Audit a web server for known exposures and configuration weaknesses",
        category: "web audit",
        risk_level: "high",
        requires_authorization: true,
        timeout: 1800,
        expected_outputs: &["json", "web server findings"],
        command: CommandProfile {
            executable: "nikto",
            prefix_args: &[],
            target: TargetPlacement::Flag("-h"),
            target_transform: TargetTransform::EnsureHttpUrl,
            suffix_args: &["-nointeractive", "-nocheck"],
            output: OutputPlacement::Flag {
                prelude: &["-Format", "json"],
                flag: "-output",
            },
        },
    },
    AdapterProfile {
        name: "WPScan",
        tool_name: "wpscan",
        description: "Inspect an authorized WordPress deployment and its exposed components",
        category: "cms audit",
        risk_level: "high",
        requires_authorization: true,
        timeout: 1500,
        expected_outputs: &["json", "WordPress findings"],
        command: CommandProfile {
            executable: "wpscan",
            prefix_args: &[],
            target: TargetPlacement::Flag("--url"),
            target_transform: TargetTransform::EnsureHttpUrl,
            suffix_args: &["--format", "json", "--no-banner"],
            output: OutputPlacement::Flag {
                prelude: &[],
                flag: "--output",
            },
        },
    },
    AdapterProfile {
        name: "Feroxbuster",
        tool_name: "feroxbuster",
        description: "Recursively discover web content using a managed wordlist",
        category: "content discovery",
        risk_level: "high",
        requires_authorization: true,
        timeout: 1800,
        expected_outputs: &["jsonl", "discovered paths"],
        command: CommandProfile {
            executable: "feroxbuster",
            prefix_args: &[],
            target: TargetPlacement::Flag("-u"),
            target_transform: TargetTransform::EnsureHttpUrl,
            suffix_args: &[
                "-w",
                "<unihack-managed-web-wordlist>",
                "--json",
                "--no-state",
                "--quiet",
            ],
            output: OutputPlacement::Flag {
                prelude: &[],
                flag: "--output",
            },
        },
    },
    AdapterProfile {
        name: "Dalfox",
        tool_name: "dalfox",
        description: "Test an authorized endpoint for reflected and DOM cross-site scripting",
        category: "vulnerability",
        risk_level: "high",
        requires_authorization: true,
        timeout: 1800,
        expected_outputs: &["json", "XSS findings"],
        command: CommandProfile {
            executable: "dalfox",
            prefix_args: &["scan"],
            target: TargetPlacement::Positional,
            target_transform: TargetTransform::EnsureHttpUrl,
            suffix_args: &["--format", "json", "--no-color"],
            output: OutputPlacement::Flag {
                prelude: &[],
                flag: "--output",
            },
        },
    },
];

fn core_adapter_profile(tool_name: &str) -> Option<&'static AdapterProfile> {
    CORE_ADAPTER_PROFILES
        .iter()
        .find(|profile| profile.tool_name.eq_ignore_ascii_case(tool_name))
}

/// Central registry for all adapters
pub struct AdapterRegistry;

impl AdapterRegistry {
    /// Create a new adapter registry
    pub fn new() -> Self {
        Self
    }

    /// Build a command for a specific tool with custom configuration
    pub fn build_command(&self, adapter_type: &AdapterType) -> CommandPreview {
        let (argv, stdin) = match adapter_type {
            AdapterType::Subfinder(config) => (SubfinderAdapter::new().build_command(config), None),
            AdapterType::Amass(config) => (AmassAdapter::new().build_command(config), None),
            AdapterType::Naabu(config) => (NaabuAdapter::new().build_command(config), None),
            AdapterType::Nmap(config) => (NmapAdapter::new().build_command(config), None),
            AdapterType::Nuclei(config) => (NucleiAdapter::new().build_command(config), None),
            AdapterType::GAU(config) => (GAUAdapter::new().build_command(config), None),
            AdapterType::WaybackURLs(config) => (
                WaybackURLsAdapter::new().build_command(config),
                Some(config.target.clone()),
            ),
        };
        CommandPreview { argv, stdin }
    }

    /// Build a command with default configuration
    pub fn build_command_with_defaults(
        &self,
        tool_name: &str,
        target: String,
        output_file: Option<String>,
    ) -> Result<CommandPreview, String> {
        if let Some(profile) = core_adapter_profile(tool_name) {
            let command = profile.build_command(&target, output_file.as_deref())?;
            return Ok(CommandPreview {
                argv: command.argv,
                stdin: command.stdin,
            });
        }

        let (argv, stdin) = match tool_name.to_lowercase().as_str() {
            "subfinder" => (
                SubfinderAdapter::new().build_command_with_defaults(target, output_file),
                None,
            ),
            "amass" => (
                AmassAdapter::new().build_command_with_defaults(target, output_file),
                None,
            ),
            "naabu" => (
                NaabuAdapter::new().build_command_with_defaults(target, output_file),
                None,
            ),
            "nmap" => (
                NmapAdapter::new().build_command_with_defaults(target, output_file),
                None,
            ),
            "nuclei" => (
                NucleiAdapter::new().build_command_with_defaults(target, output_file),
                None,
            ),
            "gau" => (
                GAUAdapter::new().build_command_with_defaults(target, output_file),
                None,
            ),
            "waybackurls" => {
                let stdin = target.clone();
                (
                    WaybackURLsAdapter::new().build_command_with_defaults(target, output_file),
                    Some(stdin),
                )
            }
            _ => return Err(format!("Unknown tool: {}", tool_name)),
        };
        Ok(CommandPreview { argv, stdin })
    }

    /// Get information about a specific adapter
    pub fn get_adapter_info(&self, tool_name: &str) -> Result<AdapterInfo, String> {
        match tool_name.to_lowercase().as_str() {
            "subfinder" => {
                let adapter = SubfinderAdapter::new();
                Ok(AdapterInfo {
                    name: "Subfinder".to_string(),
                    tool_name: adapter.get_tool_name().to_string(),
                    description: adapter.get_description().to_string(),
                    category: adapter.get_category().to_string(),
                    risk_level: adapter.get_risk_level().to_string(),
                    requires_authorization: adapter.requires_authorization(),
                    timeout: adapter.get_timeout(),
                    expected_outputs: adapter.get_expected_outputs(),
                    origin: "specialized".to_string(),
                    status: "ready".to_string(),
                    confidence: 1.0,
                    generated_at: None,
                    verified_version: None,
                })
            }
            "amass" => {
                let adapter = AmassAdapter::new();
                Ok(AdapterInfo {
                    name: "Amass".to_string(),
                    tool_name: adapter.get_tool_name().to_string(),
                    description: adapter.get_description().to_string(),
                    category: adapter.get_category().to_string(),
                    risk_level: adapter.get_risk_level().to_string(),
                    requires_authorization: adapter.requires_authorization(),
                    timeout: adapter.get_timeout(),
                    expected_outputs: adapter.get_expected_outputs(),
                    origin: "specialized".to_string(),
                    status: "ready".to_string(),
                    confidence: 1.0,
                    generated_at: None,
                    verified_version: None,
                })
            }
            "naabu" => {
                let adapter = NaabuAdapter::new();
                Ok(AdapterInfo {
                    name: "Naabu".to_string(),
                    tool_name: adapter.get_tool_name().to_string(),
                    description: adapter.get_description().to_string(),
                    category: adapter.get_category().to_string(),
                    risk_level: adapter.get_risk_level().to_string(),
                    requires_authorization: adapter.requires_authorization(),
                    timeout: adapter.get_timeout(),
                    expected_outputs: adapter.get_expected_outputs(),
                    origin: "specialized".to_string(),
                    status: "ready".to_string(),
                    confidence: 1.0,
                    generated_at: None,
                    verified_version: None,
                })
            }
            "nmap" => {
                let adapter = NmapAdapter::new();
                Ok(AdapterInfo {
                    name: "Nmap".to_string(),
                    tool_name: adapter.get_tool_name().to_string(),
                    description: adapter.get_description().to_string(),
                    category: adapter.get_category().to_string(),
                    risk_level: adapter.get_risk_level().to_string(),
                    requires_authorization: adapter.requires_authorization(),
                    timeout: adapter.get_timeout(),
                    expected_outputs: adapter.get_expected_outputs(),
                    origin: "specialized".to_string(),
                    status: "ready".to_string(),
                    confidence: 1.0,
                    generated_at: None,
                    verified_version: None,
                })
            }
            "nuclei" => {
                let adapter = NucleiAdapter::new();
                Ok(AdapterInfo {
                    name: "Nuclei".to_string(),
                    tool_name: adapter.get_tool_name().to_string(),
                    description: adapter.get_description().to_string(),
                    category: adapter.get_category().to_string(),
                    risk_level: adapter.get_risk_level().to_string(),
                    requires_authorization: adapter.requires_authorization(),
                    timeout: adapter.get_timeout(),
                    expected_outputs: adapter.get_expected_outputs(),
                    origin: "specialized".to_string(),
                    status: "ready".to_string(),
                    confidence: 1.0,
                    generated_at: None,
                    verified_version: None,
                })
            }
            "gau" => {
                let adapter = GAUAdapter::new();
                Ok(AdapterInfo {
                    name: "GAU".to_string(),
                    tool_name: adapter.get_tool_name().to_string(),
                    description: adapter.get_description().to_string(),
                    category: adapter.get_category().to_string(),
                    risk_level: adapter.get_risk_level().to_string(),
                    requires_authorization: adapter.requires_authorization(),
                    timeout: adapter.get_timeout(),
                    expected_outputs: adapter.get_expected_outputs(),
                    origin: "specialized".to_string(),
                    status: "ready".to_string(),
                    confidence: 1.0,
                    generated_at: None,
                    verified_version: None,
                })
            }
            "waybackurls" => {
                let adapter = WaybackURLsAdapter::new();
                Ok(AdapterInfo {
                    name: "WaybackURLs".to_string(),
                    tool_name: adapter.get_tool_name().to_string(),
                    description: adapter.get_description().to_string(),
                    category: adapter.get_category().to_string(),
                    risk_level: adapter.get_risk_level().to_string(),
                    requires_authorization: adapter.requires_authorization(),
                    timeout: adapter.get_timeout(),
                    expected_outputs: adapter.get_expected_outputs(),
                    origin: "specialized".to_string(),
                    status: "ready".to_string(),
                    confidence: 1.0,
                    generated_at: None,
                    verified_version: None,
                })
            }
            _ => core_adapter_profile(tool_name)
                .map(|profile| AdapterInfo {
                    name: profile.name.to_string(),
                    tool_name: profile.tool_name.to_string(),
                    description: profile.description.to_string(),
                    category: profile.category.to_string(),
                    risk_level: profile.risk_level.to_string(),
                    requires_authorization: profile.requires_authorization,
                    timeout: profile.timeout,
                    expected_outputs: profile
                        .expected_outputs
                        .iter()
                        .map(|output| output.to_string())
                        .collect(),
                    origin: "bundled_profile".to_string(),
                    status: "ready".to_string(),
                    confidence: 1.0,
                    generated_at: None,
                    verified_version: None,
                })
                .ok_or_else(|| format!("Unknown tool: {}", tool_name)),
        }
    }

    /// List all available adapters
    pub fn list_adapters(&self) -> Vec<AdapterInfo> {
        let mut adapters = vec![
            self.get_adapter_info("subfinder").unwrap(),
            self.get_adapter_info("amass").unwrap(),
            self.get_adapter_info("naabu").unwrap(),
            self.get_adapter_info("nmap").unwrap(),
            self.get_adapter_info("nuclei").unwrap(),
            self.get_adapter_info("gau").unwrap(),
            self.get_adapter_info("waybackurls").unwrap(),
        ];
        adapters.extend(
            CORE_ADAPTER_PROFILES
                .iter()
                .filter_map(|profile| self.get_adapter_info(profile.tool_name).ok()),
        );
        adapters
    }

    /// Get all adapter names
    pub fn get_adapter_names(&self) -> Vec<String> {
        let mut names = vec![
            "subfinder".to_string(),
            "amass".to_string(),
            "naabu".to_string(),
            "nmap".to_string(),
            "nuclei".to_string(),
            "gau".to_string(),
            "waybackurls".to_string(),
        ];
        names.extend(
            CORE_ADAPTER_PROFILES
                .iter()
                .map(|profile| profile.tool_name.to_string()),
        );
        names
    }

    /// Get adapters by category
    pub fn get_adapters_by_category(&self, category: &str) -> Vec<AdapterInfo> {
        self.list_adapters()
            .into_iter()
            .filter(|info| info.category.to_lowercase() == category.to_lowercase())
            .collect()
    }

    /// Get adapters by risk level
    pub fn get_adapters_by_risk_level(&self, risk_level: &str) -> Vec<AdapterInfo> {
        self.list_adapters()
            .into_iter()
            .filter(|info| info.risk_level.to_lowercase() == risk_level.to_lowercase())
            .collect()
    }

    /// Check if an adapter exists for a tool
    pub fn has_adapter(&self, tool_name: &str) -> bool {
        self.get_adapter_names().contains(&tool_name.to_lowercase())
    }

    /// Return the canonical target shape expected by a bundled adapter.
    pub fn target_kind(&self, tool_name: &str) -> Option<&'static str> {
        match tool_name.to_ascii_lowercase().as_str() {
            "subfinder" | "amass" | "gau" | "waybackurls" => Some("domain"),
            "nmap" | "naabu" => Some("host"),
            "nuclei" => Some("url"),
            _ if core_adapter_profile(tool_name).is_some() => Some("url"),
            _ => None,
        }
    }

    /// Get all adapter categories
    pub fn get_categories(&self) -> Vec<String> {
        let mut categories: Vec<String> = self
            .list_adapters()
            .into_iter()
            .map(|info| info.category)
            .collect();
        categories.sort();
        categories.dedup();
        categories
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_registry_creation() {
        let registry = AdapterRegistry::new();
        assert!(!registry.list_adapters().is_empty());
    }

    #[test]
    fn test_build_command_with_defaults() {
        let registry = AdapterRegistry::new();
        let cmd = registry.build_command_with_defaults(
            "subfinder",
            "example.com".to_string(),
            Some("/tmp/output.txt".to_string()),
        );
        assert!(cmd.is_ok());
        let cmd = cmd.unwrap();
        assert_eq!(cmd.argv[0], "subfinder");
        assert!(cmd.argv.contains(&"-d".to_string()));
        assert!(cmd.argv.contains(&"example.com".to_string()));
        assert!(cmd.stdin.is_none());
    }

    #[test]
    fn waybackurls_uses_standard_input() {
        let preview = AdapterRegistry::new()
            .build_command_with_defaults("waybackurls", "example.com".to_string(), None)
            .unwrap();

        assert_eq!(preview.argv, vec!["waybackurls"]);
        assert_eq!(preview.stdin.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_get_adapter_info() {
        let registry = AdapterRegistry::new();
        let info = registry.get_adapter_info("subfinder");
        assert!(info.is_ok());
        let info = info.unwrap();
        assert_eq!(info.tool_name, "subfinder");
        assert_eq!(info.category, "recon");
    }

    #[test]
    fn test_list_adapters() {
        let registry = AdapterRegistry::new();
        let adapters = registry.list_adapters();
        assert_eq!(adapters.len(), 15);
    }

    #[test]
    fn declarative_profiles_are_valid_and_unique() {
        let mut tool_names = HashSet::new();
        for profile in CORE_ADAPTER_PROFILES {
            profile.validate().unwrap();
            assert!(
                tool_names.insert(profile.tool_name.to_lowercase()),
                "duplicate adapter profile for {}",
                profile.tool_name
            );
        }
    }

    #[test]
    fn declarative_profiles_preserve_core_command_contracts() {
        let cases = [
            (
                "httpx",
                vec![
                    "httpx",
                    "-u",
                    "https://example.com",
                    "-silent",
                    "-json",
                    "-status-code",
                    "-title",
                    "-tech-detect",
                    "-o",
                    "/tmp/output",
                ],
            ),
            (
                "ffuf",
                vec![
                    "ffuf",
                    "-u",
                    "https://example.com/FUZZ",
                    "-w",
                    "<unihack-managed-web-wordlist>",
                    "-of",
                    "json",
                    "-o",
                    "/tmp/output",
                ],
            ),
            (
                "gobuster",
                vec![
                    "gobuster",
                    "dir",
                    "-u",
                    "https://example.com",
                    "-w",
                    "<unihack-managed-web-wordlist>",
                    "-o",
                    "/tmp/output",
                ],
            ),
            (
                "sqlmap",
                vec![
                    "sqlmap",
                    "-u",
                    "https://example.com",
                    "--batch",
                    "--level=1",
                    "--risk=1",
                    "--disable-coloring",
                    "--output-dir=/tmp/output",
                ],
            ),
            (
                "nikto",
                vec![
                    "nikto",
                    "-h",
                    "https://example.com",
                    "-nointeractive",
                    "-nocheck",
                    "-Format",
                    "json",
                    "-output",
                    "/tmp/output",
                ],
            ),
            (
                "wpscan",
                vec![
                    "wpscan",
                    "--url",
                    "https://example.com",
                    "--format",
                    "json",
                    "--no-banner",
                    "--output",
                    "/tmp/output",
                ],
            ),
            (
                "feroxbuster",
                vec![
                    "feroxbuster",
                    "-u",
                    "https://example.com",
                    "-w",
                    "<unihack-managed-web-wordlist>",
                    "--json",
                    "--no-state",
                    "--quiet",
                    "--output",
                    "/tmp/output",
                ],
            ),
            (
                "dalfox",
                vec![
                    "dalfox",
                    "scan",
                    "https://example.com",
                    "--format",
                    "json",
                    "--no-color",
                    "--output",
                    "/tmp/output",
                ],
            ),
        ];

        for (tool_name, expected) in cases {
            let preview = AdapterRegistry::new()
                .build_command_with_defaults(
                    tool_name,
                    "example.com".to_string(),
                    Some("/tmp/output".to_string()),
                )
                .unwrap();
            assert_eq!(preview.argv, expected, "command changed for {tool_name}");
            assert!(preview.stdin.is_none());
        }
    }

    #[test]
    fn test_get_adapters_by_category() {
        let registry = AdapterRegistry::new();
        let adapters = registry.get_adapters_by_category("recon");
        assert!(!adapters.is_empty());
    }

    #[test]
    fn test_has_adapter() {
        let registry = AdapterRegistry::new();
        assert!(registry.has_adapter("subfinder"));
        assert!(registry.has_adapter("amass"));
        assert!(registry.has_adapter("httpx"));
        assert!(registry.has_adapter("dalfox"));
        assert!(!registry.has_adapter("nonexistent"));
    }

    #[test]
    fn core_web_adapters_use_safe_structured_defaults() {
        let registry = AdapterRegistry::new();
        let ffuf = registry
            .build_command_with_defaults("ffuf", "example.com".to_string(), None)
            .unwrap();
        assert_eq!(ffuf.argv[0], "ffuf");
        assert!(ffuf.argv.contains(&"https://example.com/FUZZ".to_string()));
        assert!(ffuf
            .argv
            .contains(&"<unihack-managed-web-wordlist>".to_string()));

        let sqlmap = registry
            .build_command_with_defaults("sqlmap", "https://example.com/?id=1".to_string(), None)
            .unwrap();
        assert!(sqlmap.argv.contains(&"--batch".to_string()));
        assert!(sqlmap.argv.contains(&"--risk=1".to_string()));
        assert!(!sqlmap.argv.iter().any(|arg| arg == "--dump"));

        let nikto = registry
            .build_command_with_defaults(
                "nikto",
                "example.com".to_string(),
                Some("/tmp/nikto.json".to_string()),
            )
            .unwrap();
        assert_eq!(
            nikto.argv,
            vec![
                "nikto",
                "-h",
                "https://example.com",
                "-nointeractive",
                "-nocheck",
                "-Format",
                "json",
                "-output",
                "/tmp/nikto.json",
            ]
        );
    }
}
