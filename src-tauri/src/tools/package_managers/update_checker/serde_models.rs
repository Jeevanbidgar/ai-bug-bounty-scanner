// Serde Models for Update Checker
//
// Defines serialization/deserialization models for various package manager outputs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// NPM package info from `npm list` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmPackageInfo {
    pub name: String,
    pub version: String,
    pub dependencies: Option<HashMap<String, NpmPackageInfo>>,
}

/// NPM outdated package info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmOutdatedPackage {
    pub current: String,
    pub wanted: String,
    pub latest: String,
    pub location: String,
}

/// Pipx outdated package info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipxOutdatedPackage {
    pub name: String,
    pub version: String,
    pub latest_version: String,
}

/// Homebrew formula info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomebrewFormula {
    pub name: String,
    pub full_name: String,
    pub desc: String,
    pub homepage: String,
    pub url: String,
    pub version: String,
    pub installed: Vec<HomebrewInstalledVersion>,
}

/// Homebrew installed version info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomebrewInstalledVersion {
    pub version: String,
    pub used_options: Vec<String>,
    pub built_as_bottle: bool,
    pub poured_from_bottle: bool,
    pub runtime_dependencies: Vec<HomebrewDependency>,
    pub installed_as_dependency: bool,
    pub installed_on_request: bool,
}

/// Homebrew dependency info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomebrewDependency {
    pub name: String,
    pub version: String,
}

/// Cargo search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CargoSearchResult {
    pub name: String,
    pub version: String,
    pub description: String,
    pub downloads: u64,
}

/// Gem info from `gem list`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GemInfo {
    pub name: String,
    pub version: String,
    pub platform: String,
    pub authors: Vec<String>,
    pub info: String,
    pub homepage: String,
    pub source_code_uri: String,
    pub changelog_uri: String,
    pub bug_tracker_uri: String,
    pub documentation_uri: String,
    pub mailing_list_uri: String,
    pub download_uri: String,
    pub yanked: bool,
}

/// APT policy info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AptPolicyInfo {
    pub package: String,
    pub installed: Option<String>,
    pub candidate: Option<String>,
    pub version_table: Vec<AptVersionInfo>,
}

/// APT version info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AptVersionInfo {
    pub version: String,
    pub priority: String,
    pub section: String,
    pub maintainer: String,
    pub architecture: String,
    pub size: String,
    pub description: String,
}

/// WinGet upgrade info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WingetUpgradeInfo {
    pub name: String,
    pub id: String,
    pub version: String,
    pub available: String,
    pub source: String,
}

/// Go module info from `go list -m`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoModuleInfo {
    pub path: String,
    pub version: String,
    pub sum: String,
    pub go_mod: String,
}

/// Go version info from `go version -m`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoVersionInfo {
    pub path: String,
    #[serde(rename = "mod")]
    pub r#mod: GoModuleInfo,
    pub dep: String,
    pub build: GoBuildInfo,
}

/// Go build info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoBuildInfo {
    pub go: String,
    pub path: String,
    #[serde(rename = "mod")]
    pub r#mod: String,
    pub sum: String,
    pub time: String,
    pub user: String,
    pub host: String,
    pub vcs: String,
    pub vcs_revision: String,
    pub vcs_time: String,
    pub vcs_modified: bool,
}

/// Generic package manager output parser
pub struct OutputParser;

impl OutputParser {
    /// Parse npm list output
    pub fn parse_npm_list(output: &str) -> Result<NpmPackageInfo, serde_json::Error> {
        serde_json::from_str(output)
    }

    /// Parse npm outdated output
    pub fn parse_npm_outdated(
        output: &str,
    ) -> Result<HashMap<String, NpmOutdatedPackage>, serde_json::Error> {
        serde_json::from_str(output)
    }

    /// Parse pipx outdated output
    pub fn parse_pipx_outdated(
        output: &str,
    ) -> Result<Vec<PipxOutdatedPackage>, serde_json::Error> {
        serde_json::from_str(output)
    }

    /// Parse homebrew info output
    pub fn parse_homebrew_info(output: &str) -> Result<Vec<HomebrewFormula>, serde_json::Error> {
        serde_json::from_str(output)
    }

    /// Parse cargo search output
    pub fn parse_cargo_search(output: &str) -> Result<Vec<CargoSearchResult>, serde_json::Error> {
        serde_json::from_str(output)
    }

    /// Parse gem list output
    pub fn parse_gem_list(output: &str) -> Result<Vec<GemInfo>, serde_json::Error> {
        serde_json::from_str(output)
    }

    /// Parse apt-cache policy output (custom format)
    pub fn parse_apt_policy(output: &str) -> AptPolicyInfo {
        let mut policy = AptPolicyInfo {
            package: String::new(),
            installed: None,
            candidate: None,
            version_table: Vec::new(),
        };

        for line in output.lines() {
            let line = line.trim();
            if line.starts_with("Installed:") {
                policy.installed = line
                    .split(':')
                    .nth(1)
                    .map(|s| s.trim().to_string())
                    .filter(|s| s != "(none)");
            } else if line.starts_with("Candidate:") {
                policy.candidate = line.split(':').nth(1).map(|s| s.trim().to_string());
            }
        }

        policy
    }

    /// Parse winget upgrade output (custom format)
    pub fn parse_winget_upgrade(output: &str) -> Vec<WingetUpgradeInfo> {
        let mut upgrades = Vec::new();

        for line in output.lines() {
            if line.contains("upgrades available") || line.contains("available") {
                // Try to parse versions from output
                // Format: Name  Id  Version  Available
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    upgrades.push(WingetUpgradeInfo {
                        name: parts[0].to_string(),
                        id: parts[1].to_string(),
                        version: parts[2].to_string(),
                        available: parts[3].to_string(),
                        source: "winget".to_string(),
                    });
                }
            }
        }

        upgrades
    }

    /// Parse go version -m output (custom format)
    pub fn parse_go_version_m(output: &str) -> Option<GoVersionInfo> {
        for line in output.lines() {
            if line.trim_start().starts_with("mod") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let version = parts[2].trim().trim_start_matches('v');
                    return Some(GoVersionInfo {
                        path: parts[1].to_string(),
                        r#mod: GoModuleInfo {
                            path: parts[1].to_string(),
                            version: version.to_string(),
                            sum: String::new(),
                            go_mod: String::new(),
                        },
                        dep: String::new(),
                        build: GoBuildInfo {
                            go: String::new(),
                            path: String::new(),
                            r#mod: String::new(),
                            sum: String::new(),
                            time: String::new(),
                            user: String::new(),
                            host: String::new(),
                            vcs: String::new(),
                            vcs_revision: String::new(),
                            vcs_time: String::new(),
                            vcs_modified: false,
                        },
                    });
                }
            }
        }
        None
    }

    /// Parse go list -m -versions output (custom format)
    pub fn parse_go_versions(output: &str) -> Vec<String> {
        let versions: Vec<&str> = output.split_whitespace().collect();
        versions
            .iter()
            .skip(1) // Skip the module name
            .map(|v| v.trim_start_matches('v').to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_npm_list() {
        let json = r#"{
            "name": "test-package",
            "version": "1.0.0",
            "dependencies": {
                "sub-package": {
                    "name": "sub-package",
                    "version": "2.0.0"
                }
            }
        }"#;

        let result = OutputParser::parse_npm_list(json);
        assert!(result.is_ok());
        let package = result.unwrap();
        assert_eq!(package.name, "test-package");
        assert_eq!(package.version, "1.0.0");
    }

    #[test]
    fn test_parse_pipx_outdated() {
        let json = r#"[{
            "name": "test-package",
            "version": "1.0.0",
            "latest_version": "1.1.0"
        }]"#;

        let result = OutputParser::parse_pipx_outdated(json);
        assert!(result.is_ok());
        let packages = result.unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "test-package");
    }

    #[test]
    fn test_parse_apt_policy() {
        let output = "Installed: 1.2.3\nCandidate: 1.2.4\n";
        let policy = OutputParser::parse_apt_policy(output);
        assert_eq!(policy.installed, Some("1.2.3".to_string()));
        assert_eq!(policy.candidate, Some("1.2.4".to_string()));
    }

    #[test]
    fn test_parse_go_versions() {
        let output = "module v1.0.0 v1.1.0 v1.2.0";
        let versions = OutputParser::parse_go_versions(output);
        assert_eq!(versions, vec!["1.0.0", "1.1.0", "1.2.0"]);
    }
}
