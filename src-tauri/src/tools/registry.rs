use super::types::*;
use crate::workflow::types::Tool;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::RwLock;

/// Tool registry for managing security tool discovery and availability
pub struct ToolRegistry {
    tools: Arc<RwLock<HashMap<String, Tool>>>,
    tool_paths: Arc<RwLock<HashMap<String, String>>>,
    last_refresh: Arc<RwLock<DateTime<Utc>>>,
}

impl ToolRegistry {
    /// Create a new tool registry
    pub fn new() -> Self {
        Self {
            tools: Arc::new(RwLock::new(HashMap::new())),
            tool_paths: Arc::new(RwLock::new(HashMap::new())),
            last_refresh: Arc::new(RwLock::new(Utc::now())),
        }
    }

    /// Initialize the registry with known tools
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing tool registry...");

        let mut tools = HashMap::new();

        // Define known security tools with their metadata
        let known_tools = vec![
            Tool {
                name: "subfinder".to_string(),
                path: "subfinder".to_string(),
                version: None,
                description: "Subdomain discovery tool".to_string(),
                category: ToolCategory::Reconnaissance,
                available: false,
                last_checked: Utc::now(),
            },
            Tool {
                name: "amass".to_string(),
                path: "amass".to_string(),
                version: None,
                description: "Network mapping and subdomain enumeration".to_string(),
                category: ToolCategory::Reconnaissance,
                available: false,
                last_checked: Utc::now(),
            },
            Tool {
                name: "naabu".to_string(),
                path: "naabu".to_string(),
                version: None,
                description: "Port scanning tool".to_string(),
                category: ToolCategory::Scanning,
                available: false,
                last_checked: Utc::now(),
            },
            Tool {
                name: "httpx".to_string(),
                path: "httpx".to_string(),
                version: None,
                description: "HTTP toolkit for running multiple probes".to_string(),
                category: ToolCategory::Scanning,
                available: false,
                last_checked: Utc::now(),
            },
            Tool {
                name: "nmap".to_string(),
                path: "nmap".to_string(),
                version: None,
                description: "Network mapper for network discovery and security auditing".to_string(),
                category: ToolCategory::Scanning,
                available: false,
                last_checked: Utc::now(),
            },
            Tool {
                name: "nuclei".to_string(),
                path: "nuclei".to_string(),
                version: None,
                description: "Template-based vulnerability scanner".to_string(),
                category: ToolCategory::Vulnerability,
                available: false,
                last_checked: Utc::now(),
            },
            Tool {
                name: "gau".to_string(),
                path: "gau".to_string(),
                version: None,
                description: "Get all URLs from various sources".to_string(),
                category: ToolCategory::Reconnaissance,
                available: false,
                last_checked: Utc::now(),
            },
            Tool {
                name: "waybackurls".to_string(),
                path: "waybackurls".to_string(),
                version: None,
                description: "Fetch URLs from Wayback Machine".to_string(),
                category: ToolCategory::Reconnaissance,
                available: false,
                last_checked: Utc::now(),
            },
            Tool {
                name: "ffuf".to_string(),
                path: "ffuf".to_string(),
                version: None,
                description: "Fast web fuzzer".to_string(),
                category: ToolCategory::Vulnerability,
                available: false,
                last_checked: Utc::now(),
            },
            Tool {
                name: "gobuster".to_string(),
                path: "gobuster".to_string(),
                version: None,
                description: "Directory/file and DNS busting tool".to_string(),
                category: ToolCategory::Vulnerability,
                available: false,
                last_checked: Utc::now(),
            },
            Tool {
                name: "sqlmap".to_string(),
                path: "sqlmap".to_string(),
                version: None,
                description: "SQL injection and database takeover tool".to_string(),
                category: ToolCategory::Exploitation,
                available: false,
                last_checked: Utc::now(),
            },
        ];

        for tool in known_tools {
            tools.insert(tool.name.clone(), tool);
        }

        *self.tools.write().await = tools;
        info!("Tool registry initialized with {} tools", self.tools.read().await.len());

        Ok(())
    }

    /// Refresh tool availability and versions
    pub async fn refresh(&self) -> Result<()> {
        info!("Refreshing tool registry...");

        let mut tools = self.tools.write().await;
        let mut available_count = 0;

        for tool in tools.values_mut() {
            match self.check_tool_availability(&tool.name).await {
                Ok((available, path, version)) => {
                    tool.available = available;
                    tool.path = path;
                    tool.version = version;
                    tool.last_checked = Utc::now();

                    if available {
                        available_count += 1;
                    }
                }
                Err(e) => {
                    warn!("Failed to check availability for tool '{}': {}", tool.name, e);
                    tool.available = false;
                    tool.last_checked = Utc::now();
                }
            }
        }

        *self.last_refresh.write().await = Utc::now();

        info!("Tool registry refreshed: {}/{} tools available", available_count, tools.len());
        Ok(())
    }

    /// Check if a tool is available and get its path and version
    async fn check_tool_availability(&self, tool_name: &str) -> Result<(bool, String, Option<String>)> {
        // First try to find the tool in PATH
        let which_output = Command::new("which")
            .arg(tool_name)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        if which_output.status.success() {
            let path = String::from_utf8_lossy(&which_output.stdout).trim().to_string();

            // Try to get version information
            let version = self.get_tool_version(tool_name, &path).await.ok();

            debug!("Tool '{}' found at: {} (version: {:?})", tool_name, path, version);
            return Ok((true, path, version));
        }

        // Tool not found in PATH
        debug!("Tool '{}' not found in PATH", tool_name);
        Ok((false, tool_name.to_string(), None))
    }

    /// Get tool version by running --version or -version
    async fn get_tool_version(&self, tool_name: &str, path: &str) -> Result<String> {
        // Try different version flags
        let version_flags = ["--version", "-version", "-V"];

        for flag in &version_flags {
            let output = Command::new(path)
                .arg(flag)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await;

            if let Ok(output) = output {
                if output.status.success() {
                    let version_output = String::from_utf8_lossy(&output.stdout);
                    let version = version_output
                        .lines()
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string();

                    if !version.is_empty() && version != tool_name {
                        return Ok(version);
                    }
                }
            }
        }

        // Fallback: try to parse from help output
        if let Ok(output) = Command::new(path)
            .arg("--help")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
        {
            if output.status.success() {
                let help_output = String::from_utf8_lossy(&output.stdout);
                if let Some(version_line) = help_output
                    .lines()
                    .find(|line| line.to_lowercase().contains("version"))
                {
                    return Ok(version_line.trim().to_string());
                }
            }
        }

        Err(anyhow!("Could not determine version for tool '{}'", tool_name))
    }

    /// Get tool information by name
    pub async fn get_tool(&self, name: &str) -> Result<Tool> {
        let tools = self.tools.read().await;
        tools.get(name)
            .cloned()
            .ok_or_else(|| anyhow!("Tool '{}' not found in registry", name))
    }

    /// Get all registered tools
    pub async fn get_all_tools(&self) -> Vec<Tool> {
        self.tools.read().await.values().cloned().collect()
    }

    /// Get tools by category
    pub async fn get_tools_by_category(&self, category: &ToolCategory) -> Vec<Tool> {
        self.tools.read().await
            .values()
            .filter(|tool| &tool.category == category)
            .cloned()
            .collect()
    }

    /// Get available tools only
    pub async fn get_available_tools(&self) -> Vec<Tool> {
        self.tools.read().await
            .values()
            .filter(|tool| tool.available)
            .cloned()
            .collect()
    }

    /// Check if a tool is available
    pub async fn is_tool_available(&self, name: &str) -> bool {
        if let Ok(tool) = self.get_tool(name).await {
            tool.available
        } else {
            false
        }
    }

    /// Register a custom tool
    pub async fn register_tool(&self, tool: Tool) -> Result<()> {
        let mut tools = self.tools.write().await;
        tools.insert(tool.name.clone(), tool);
        Ok(())
    }

    /// Get registry statistics
    pub async fn get_stats(&self) -> ToolRegistryStats {
        let tools = self.tools.read().await;
        let available = tools.values().filter(|t| t.available).count();
        let by_category = tools.values()
            .fold(HashMap::new(), |mut acc, tool| {
                *acc.entry(&tool.category).or_insert(0) += 1;
                acc
            });

        ToolRegistryStats {
            total_tools: tools.len(),
            available_tools: available,
            last_refresh: *self.last_refresh.read().await,
            tools_by_category: by_category,
        }
    }

    /// Auto-discover tools in common installation paths
    pub async fn auto_discover_tools(&self) -> Result<Vec<String>> {
        let mut discovered = Vec::new();

        // Common installation paths for security tools
        let search_paths = [
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/opt/homebrew/bin", // macOS Homebrew ARM
            "/usr/local/homebrew/bin", // macOS Homebrew Intel
            "/snap/bin", // Snap packages
            "/home/linuxbrew/.linuxbrew/bin", // Linuxbrew
            "C:\\Program Files\\", // Windows Program Files
            "C:\\Program Files (x86)\\", // Windows Program Files x86
        ];

        for path in &search_paths {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    if let Ok(name) = entry.file_name().into_string() {
                        // Check if this looks like a security tool
                        if self.is_security_tool_name(&name) {
                            if let Ok(tool) = self.get_tool(&name).await {
                                // Tool already registered, check if path is different
                                if tool.path != entry.path().to_string_lossy() {
                                    debug!("Found {} at different path: {}", name, entry.path().display());
                                }
                            } else {
                                // New tool discovered
                                debug!("Discovered new security tool: {}", name);
                                discovered.push(name);
                            }
                        }
                    }
                }
            }
        }

        Ok(discovered)
    }

    /// Check if a filename looks like a security tool
    fn is_security_tool_name(&self, name: &str) -> bool {
        let security_tools = [
            "subfinder", "amass", "naabu", "httpx", "nmap", "nuclei",
            "gau", "waybackurls", "ffuf", "gobuster", "sqlmap",
            "dirsearch", "dirb", "gobuster", "wfuzz", "masscan",
            "zmap", " eyewitness", "aquatone", "sublist3r",
        ];

        security_tools.iter().any(|tool| name.contains(tool))
    }
}

/// Tool registry statistics
#[derive(Debug, Clone)]
pub struct ToolRegistryStats {
    pub total_tools: usize,
    pub available_tools: usize,
    pub last_refresh: DateTime<Utc>,
    pub tools_by_category: HashMap<ToolCategory, usize>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tool_registry_creation() {
        let registry = ToolRegistry::new();
        assert_eq!(registry.get_all_tools().await.len(), 0);

        registry.initialize().await.unwrap();
        assert!(registry.get_all_tools().await.len() > 0);
    }

    #[test]
    fn test_security_tool_name_detection() {
        let registry = ToolRegistry::new();

        assert!(registry.is_security_tool_name("subfinder"));
        assert!(registry.is_security_tool_name("nmap"));
        assert!(registry.is_security_tool_name("nuclei"));
        assert!(!registry.is_security_tool_name("ls"));
        assert!(!registry.is_security_tool_name("cat"));
    }
}