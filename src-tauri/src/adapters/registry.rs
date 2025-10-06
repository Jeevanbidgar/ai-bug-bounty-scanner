// Central registry for all security tool adapters
//
// This module provides a unified interface for accessing and using all tool adapters,
// making it easy to build commands programmatically across the application.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    amass::{AmassAdapter, AmassConfig},
    gau::{GAUAdapter, GAUConfig},
    naabu::{NaabuAdapter, NaabuConfig},
    nmap::{NmapAdapter, NmapConfig},
    nuclei::{NucleiAdapter, NucleiConfig},
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
}

/// Central registry for all adapters
pub struct AdapterRegistry;

impl AdapterRegistry {
    /// Create a new adapter registry
    pub fn new() -> Self {
        Self
    }

    /// Build a command for a specific tool with custom configuration
    pub fn build_command(&self, adapter_type: &AdapterType) -> Vec<String> {
        match adapter_type {
            AdapterType::Subfinder(config) => SubfinderAdapter::new().build_command(config),
            AdapterType::Amass(config) => AmassAdapter::new().build_command(config),
            AdapterType::Naabu(config) => NaabuAdapter::new().build_command(config),
            AdapterType::Nmap(config) => NmapAdapter::new().build_command(config),
            AdapterType::Nuclei(config) => NucleiAdapter::new().build_command(config),
            AdapterType::GAU(config) => GAUAdapter::new().build_command(config),
            AdapterType::WaybackURLs(config) => WaybackURLsAdapter::new().build_command(config),
        }
    }

    /// Build a command with default configuration
    pub fn build_command_with_defaults(
        &self,
        tool_name: &str,
        target: String,
        output_file: Option<String>,
    ) -> Result<Vec<String>, String> {
        match tool_name.to_lowercase().as_str() {
            "subfinder" => {
                Ok(SubfinderAdapter::new().build_command_with_defaults(target, output_file))
            }
            "amass" => Ok(AmassAdapter::new().build_command_with_defaults(target, output_file)),
            "naabu" => Ok(NaabuAdapter::new().build_command_with_defaults(target, output_file)),
            "nmap" => Ok(NmapAdapter::new().build_command_with_defaults(target, output_file)),
            "nuclei" => Ok(NucleiAdapter::new().build_command_with_defaults(target, output_file)),
            "gau" => Ok(GAUAdapter::new().build_command_with_defaults(target, output_file)),
            "waybackurls" => {
                Ok(WaybackURLsAdapter::new().build_command_with_defaults(target, output_file))
            }
            _ => Err(format!("Unknown tool: {}", tool_name)),
        }
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
                })
            }
            _ => Err(format!("Unknown tool: {}", tool_name)),
        }
    }

    /// List all available adapters
    pub fn list_adapters(&self) -> Vec<AdapterInfo> {
        vec![
            self.get_adapter_info("subfinder").unwrap(),
            self.get_adapter_info("amass").unwrap(),
            self.get_adapter_info("naabu").unwrap(),
            self.get_adapter_info("nmap").unwrap(),
            self.get_adapter_info("nuclei").unwrap(),
            self.get_adapter_info("gau").unwrap(),
            self.get_adapter_info("waybackurls").unwrap(),
        ]
    }

    /// Get all adapter names
    pub fn get_adapter_names(&self) -> Vec<String> {
        vec![
            "subfinder".to_string(),
            "amass".to_string(),
            "naabu".to_string(),
            "nmap".to_string(),
            "nuclei".to_string(),
            "gau".to_string(),
            "waybackurls".to_string(),
        ]
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

    #[test]
    fn test_registry_creation() {
        let registry = AdapterRegistry::new();
        assert!(registry.list_adapters().len() > 0);
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
        assert_eq!(cmd[0], "subfinder");
        assert!(cmd.contains(&"-d".to_string()));
        assert!(cmd.contains(&"example.com".to_string()));
    }

    #[test]
    fn test_get_adapter_info() {
        let registry = AdapterRegistry::new();
        let info = registry.get_adapter_info("subfinder");
        assert!(info.is_ok());
        let info = info.unwrap();
        assert_eq!(info.tool_name, "subfinder");
        assert_eq!(info.category, "subdomain_discovery");
    }

    #[test]
    fn test_list_adapters() {
        let registry = AdapterRegistry::new();
        let adapters = registry.list_adapters();
        assert_eq!(adapters.len(), 7);
    }

    #[test]
    fn test_get_adapters_by_category() {
        let registry = AdapterRegistry::new();
        let adapters = registry.get_adapters_by_category("subdomain_discovery");
        assert!(adapters.len() > 0);
    }

    #[test]
    fn test_has_adapter() {
        let registry = AdapterRegistry::new();
        assert!(registry.has_adapter("subfinder"));
        assert!(registry.has_adapter("amass"));
        assert!(!registry.has_adapter("nonexistent"));
    }
}
