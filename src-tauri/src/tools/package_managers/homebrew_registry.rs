// Homebrew package registry for security tools
//
// This module maintains mappings between tool names and their corresponding
// Homebrew formulas/casks, with verification dates and metadata.

use once_cell::sync::Lazy;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HomebrewMapping {
    pub brew_formula: Option<String>, // Official formula name
    pub brew_cask: Option<String>,    // Official cask name (GUI apps only)
    pub min_version: Option<String>,  // Cross-OS version parity
    #[allow(dead_code)]
    pub custom_tap: Option<String>, // Only if tool unavailable in official Formulae
    pub verified: bool,               // Verified via `brew info` (not just `brew search`)
    pub verified_date: Option<String>, // ISO date of last verification (e.g., "2025-10-16")
}

impl HomebrewMapping {
    pub fn new() -> Self {
        Self {
            brew_formula: None,
            brew_cask: None,
            min_version: None,
            custom_tap: None,
            verified: false,
            verified_date: None,
        }
    }

    pub fn with_formula(mut self, formula: &str) -> Self {
        self.brew_formula = Some(formula.to_string());
        self
    }

    pub fn with_cask(mut self, cask: &str) -> Self {
        self.brew_cask = Some(cask.to_string());
        self
    }

    pub fn with_min_version(mut self, version: &str) -> Self {
        self.min_version = Some(version.to_string());
        self
    }

    #[allow(dead_code)]
    pub fn with_custom_tap(mut self, tap: &str) -> Self {
        self.custom_tap = Some(tap.to_string());
        self
    }

    pub fn verified(mut self) -> Self {
        self.verified = true;
        self
    }

    pub fn with_verified_date(mut self, date: &str) -> Self {
        self.verified_date = Some(date.to_string());
        self
    }
}

pub static HOMEBREW_REGISTRY: Lazy<HashMap<&'static str, HomebrewMapping>> = Lazy::new(|| {
    let mut map = HashMap::new();

    // === Tier 1 - Critical Tools (Must verify ALL before adding) ===

    // Subdomain enumeration tools
    map.insert(
        "subfinder",
        HomebrewMapping::new()
            .with_formula("subfinder")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    map.insert(
        "amass",
        HomebrewMapping::new()
            .with_formula("amass")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    // Network scanning tools
    map.insert(
        "nmap",
        HomebrewMapping::new()
            .with_formula("nmap")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    map.insert(
        "naabu",
        HomebrewMapping::new()
            .with_formula("naabu")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    map.insert(
        "masscan",
        HomebrewMapping::new()
            .with_formula("masscan")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    // Web analysis tools
    map.insert(
        "httpx",
        HomebrewMapping::new()
            .with_formula("httpx")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    // Nuclei - Critical tool with version requirements
    map.insert(
        "nuclei",
        HomebrewMapping::new()
            .with_formula("nuclei")
            .with_min_version("3.0.0") // Cross-OS version parity
            .verified()
            .with_verified_date("2025-10-16"),
    );

    // Directory scanning tools
    map.insert(
        "gobuster",
        HomebrewMapping::new()
            .with_formula("gobuster")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    map.insert(
        "ffuf",
        HomebrewMapping::new()
            .with_formula("ffuf")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    map.insert(
        "wfuzz",
        HomebrewMapping::new()
            .with_formula("wfuzz")
            .verified()
            .with_verified_date("2025-10-20"),
    );

    // Vulnerability scanning
    map.insert(
        "sqlmap",
        HomebrewMapping::new()
            .with_formula("sqlmap")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    // === Tier 2 - High Priority Tools ===

    // Additional subdomain tools
    map.insert(
        "waybackurls",
        HomebrewMapping::new()
            .with_formula("waybackurls")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    map.insert(
        "gau",
        HomebrewMapping::new()
            .with_formula("gau")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    map.insert(
        "dnsx",
        HomebrewMapping::new()
            .with_formula("dnsx")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    map.insert(
        "shuffledns",
        HomebrewMapping::new()
            .with_formula("shuffledns")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    // Additional scanning tools
    map.insert(
        "rustscan",
        HomebrewMapping::new()
            .with_formula("rustscan")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    map.insert(
        "feroxbuster",
        HomebrewMapping::new()
            .with_formula("feroxbuster")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    // === Tier 3 - GUI Tools (Casks) ===

    // GUI applications use casks instead of formulas
    map.insert(
        "burp-suite",
        HomebrewMapping::new()
            .with_cask("burp-suite")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    map.insert(
        "wireshark",
        HomebrewMapping::new()
            .with_cask("wireshark")
            .verified()
            .with_verified_date("2025-10-16"),
    );

    // Note: Add more tools as they are verified with `brew info`
    // Each addition must be verified before including in registry

    map
});

/// Get Homebrew mapping for a tool
pub fn get_homebrew_mapping(tool_name: &str) -> Option<&HomebrewMapping> {
    HOMEBREW_REGISTRY.get(tool_name)
}

/// Get all registered tools
#[allow(dead_code)]
pub fn get_all_homebrew_tools() -> Vec<&'static str> {
    HOMEBREW_REGISTRY.keys().copied().collect()
}

/// Get tools by category (for UI organization)
#[allow(dead_code)]
pub fn get_homebrew_tools_by_category() -> HashMap<&'static str, Vec<&'static str>> {
    let mut categories = HashMap::new();

    for (tool_name, mapping) in &*HOMEBREW_REGISTRY {
        // Basic categorization - can be enhanced
        let category = if mapping.brew_cask.is_some() {
            "GUI Tools"
        } else {
            "CLI Tools"
        };

        categories
            .entry(category)
            .or_insert_with(Vec::new)
            .push(*tool_name);
    }

    categories
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_homebrew_mapping_creation() {
        let mapping = HomebrewMapping::new()
            .with_formula("test-tool")
            .with_min_version("1.0.0")
            .verified()
            .with_verified_date("2025-10-16");

        assert_eq!(mapping.brew_formula, Some("test-tool".to_string()));
        assert_eq!(mapping.min_version, Some("1.0.0".to_string()));
        assert_eq!(mapping.verified, true);
        assert_eq!(mapping.verified_date, Some("2025-10-16".to_string()));
    }

    #[test]
    fn test_registry_lookup() {
        let mapping = get_homebrew_mapping("nuclei");
        assert!(mapping.is_some());

        let mapping = mapping.unwrap();
        assert_eq!(mapping.brew_formula, Some("nuclei".to_string()));
        assert_eq!(mapping.min_version, Some("3.0.0".to_string()));
        assert_eq!(mapping.verified, true);
    }

    #[test]
    fn test_registry_completeness() {
        // Ensure critical tools are in registry
        assert!(get_homebrew_mapping("subfinder").is_some());
        assert!(get_homebrew_mapping("nuclei").is_some());
        assert!(get_homebrew_mapping("nmap").is_some());
        assert!(get_homebrew_mapping("httpx").is_some());
    }

    #[test]
    fn test_all_tools_list() {
        let tools = get_all_homebrew_tools();
        assert!(!tools.is_empty());
        assert!(tools.contains(&"nuclei"));
        assert!(tools.contains(&"subfinder"));
    }
}
