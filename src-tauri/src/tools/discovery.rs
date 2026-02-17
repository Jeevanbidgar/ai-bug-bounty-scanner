use super::registry::ToolRegistry;
use super::types::*;
use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

/// Tool discovery service for finding and registering security tools
pub struct ToolDiscovery {
    registry: ToolRegistry,
    search_paths: Vec<PathBuf>,
}

impl ToolDiscovery {
    /// Create a new tool discovery service
    pub fn new() -> Self {
        Self {
            registry: ToolRegistry::new(),
            search_paths: Self::default_search_paths(),
        }
    }

    /// Get default search paths for different operating systems
    fn default_search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        if cfg!(target_os = "windows") {
            // Windows paths
            paths.push(PathBuf::from("C:\\Program Files"));
            paths.push(PathBuf::from("C:\\Program Files (x86)"));
            paths.push(PathBuf::from("C:\\Windows\\System32"));
            if let Ok(home) = std::env::var("USERPROFILE") {
                paths.push(PathBuf::from(home).join(".local\\bin"));
            }
        } else if cfg!(target_os = "macos") {
            // macOS paths
            paths.push(PathBuf::from("/usr/local/bin"));
            paths.push(PathBuf::from("/usr/bin"));
            paths.push(PathBuf::from("/bin"));
            paths.push(PathBuf::from("/opt/homebrew/bin"));
            paths.push(PathBuf::from("/usr/local/homebrew/bin"));
            if let Ok(home) = std::env::var("HOME") {
                paths.push(PathBuf::from(home).join(".local/bin"));
            }
        } else {
            // Linux/Unix paths
            paths.push(PathBuf::from("/usr/local/bin"));
            paths.push(PathBuf::from("/usr/bin"));
            paths.push(PathBuf::from("/bin"));
            paths.push(PathBuf::from("/snap/bin"));
            paths.push(PathBuf::from("/usr/local/sbin"));
            paths.push(PathBuf::from("/usr/sbin"));
            if let Ok(home) = std::env::var("HOME") {
                paths.push(PathBuf::from(home).join(".local/bin"));
                paths.push(PathBuf::from(home).join("bin"));
            }
        }

        paths
    }

    /// Discover all available security tools
    pub async fn discover_tools(&self) -> Result<Vec<Tool>> {
        info!("Starting comprehensive tool discovery...");

        let mut discovered_tools = Vec::new();

        // Discover from PATH
        let path_tools = self.discover_from_path().await?;
        discovered_tools.extend(path_tools);

        // Discover from common installation directories
        let directory_tools = self.discover_from_directories().await?;
        discovered_tools.extend(directory_tools);

        // Remove duplicates based on tool name
        let mut unique_tools = HashMap::new();
        for tool in discovered_tools {
            unique_tools.insert(tool.name.clone(), tool);
        }

        let final_tools: Vec<Tool> = unique_tools.into_values().collect();

        info!("Discovered {} unique security tools", final_tools.len());
        Ok(final_tools)
    }

    /// Discover tools from PATH environment variable
    async fn discover_from_path(&self) -> Result<Vec<Tool>> {
        let mut tools = Vec::new();

        if let Ok(path_var) = std::env::var("PATH") {
            for path_entry in std::env::split_paths(&path_var) {
                if let Ok(entries) = std::fs::read_dir(path_entry) {
                    for entry in entries.flatten() {
                        if let Ok(name) = entry.file_name().into_string() {
                            if self.is_security_tool_name(&name) {
                                if let Ok(tool) = self.create_tool_from_path(&name, &entry.path()).await {
                                    tools.push(tool);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(tools)
    }

    /// Discover tools from common installation directories
    async fn discover_from_directories(&self) -> Result<Vec<Tool>> {
        let mut tools = Vec::new();

        for search_path in &self.search_paths {
            if !search_path.exists() {
                continue;
            }

            if let Ok(entries) = std::fs::read_dir(search_path) {
                for entry in entries.flatten() {
                    if let Ok(name) = entry.file_name().into_string() {
                        if self.is_security_tool_name(&name) {
                            if let Ok(tool) = self.create_tool_from_path(&name, &entry.path()).await {
                                tools.push(tool);
                            }
                        }
                    }
                }
            }
        }

        Ok(tools)
    }

    /// Create a Tool struct from a discovered executable path
    async fn create_tool_from_path(&self, name: &str, path: &Path) -> Result<Tool> {
        let path_str = path.to_string_lossy().to_string();
        let available = path.exists() && self.is_executable(path).await;

        // Try to get version
        let version = if available {
            self.get_tool_version(name, &path_str).await.ok()
        } else {
            None
        };

        // Determine category based on tool name
        let category = self.categorize_tool(name);

        Ok(Tool {
            name: name.to_string(),
            path: path_str,
            version,
            description: self.get_tool_description(name),
            category,
            available,
            last_checked: chrono::Utc::now(),
        })
    }

    /// Check if a file is executable
    async fn is_executable(&self, path: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = tokio::fs::metadata(path).await {
                let permissions = metadata.permissions();
                permissions.readonly() == false
            } else {
                false
            }
        }

        #[cfg(windows)]
        {
            // On Windows, we check file extension
            if let Some(extension) = path.extension() {
                matches!(extension.to_string_lossy().to_lowercase().as_str(), "exe" | "bat" | "cmd")
            } else {
                false
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            true // Assume executable on other platforms
        }
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

    /// Check if a filename looks like a security tool
    fn is_security_tool_name(&self, name: &str) -> bool {
        let security_tools = [
            "subfinder", "amass", "naabu", "httpx", "nmap", "nuclei",
            "gau", "waybackurls", "ffuf", "gobuster", "sqlmap",
            "dirsearch", "dirb", "wfuzz", "masscan", "zmap",
            "eyewitness", "aquatone", "sublist3r", "assetfinder",
            "findomain", "dnsx", "tlsx", "dnsprobe", "shuffledns",
            "chaos", "github-subdomains", "crobat", "certspotter",
        ];

        security_tools.iter().any(|tool| name.contains(tool))
    }

    /// Categorize a tool based on its name
    fn categorize_tool(&self, name: &str) -> ToolCategory {
        let name_lower = name.to_lowercase();

        if name_lower.contains("subfinder") || name_lower.contains("amass") ||
           name_lower.contains("findomain") || name_lower.contains("sublist3r") ||
           name_lower.contains("assetfinder") || name_lower.contains("chaos") {
            ToolCategory::Reconnaissance
        } else if name_lower.contains("nmap") || name_lower.contains("naabu") ||
                  name_lower.contains("masscan") || name_lower.contains("zmap") {
            ToolCategory::Scanning
        } else if name_lower.contains("nuclei") || name_lower.contains("ffuf") ||
                  name_lower.contains("gobuster") || name_lower.contains("dirsearch") ||
                  name_lower.contains("dirb") || name_lower.contains("wfuzz") ||
                  name_lower.contains("sqlmap") {
            ToolCategory::Vulnerability
        } else if name_lower.contains("sqlmap") {
            ToolCategory::Exploitation
        } else {
            ToolCategory::Utility
        }
    }

    /// Get tool description based on name
    fn get_tool_description(&self, name: &str) -> String {
        let name_lower = name.to_lowercase();

        match name_lower.as_str() {
            s if s.contains("subfinder") => "Fast passive subdomain enumeration tool".to_string(),
            s if s.contains("amass") => "In-depth Attack Surface Mapping and Asset Discovery".to_string(),
            s if s.contains("naabu") => "Fast port scanner written in Go".to_string(),
            s if s.contains("httpx") => "Fast and multi-purpose HTTP toolkit".to_string(),
            s if s.contains("nmap") => "Network mapper for network discovery and security auditing".to_string(),
            s if s.contains("nuclei") => "Template based vulnerability scanner".to_string(),
            s if s.contains("gau") => "Get all URLs (fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl)".to_string(),
            s if s.contains("waybackurls") => "Accept line-delimited domains on stdin, fetch known URLs from the Wayback Machine for *.domain and output them on stdout".to_string(),
            s if s.contains("ffuf") => "Fast web fuzzer written in Go".to_string(),
            s if s.contains("gobuster") => "Directory/file and DNS busting tool written in Go".to_string(),
            s if s.contains("sqlmap") => "Automatic SQL injection and database takeover tool".to_string(),
            _ => format!("Security tool: {}", name),
        }
    }

    /// Get the tool registry (for registering discovered tools)
    pub fn get_registry(&self) -> &ToolRegistry {
        &self.registry
    }

    /// Run a comprehensive discovery and update the registry
    pub async fn run_full_discovery(&self) -> Result<usize> {
        info!("Running full tool discovery...");

        // Discover tools
        let discovered_tools = self.discover_tools().await?;

        // Register them in the registry
        let mut registered_count = 0;
        for tool in discovered_tools {
            if self.registry.register_tool(tool).await.is_ok() {
                registered_count += 1;
            }
        }

        // Refresh availability for all tools
        self.registry.refresh().await?;

        info!("Full discovery completed: {} tools discovered and registered", registered_count);
        Ok(registered_count)
    }
}

impl Default for ToolDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tool_discovery_creation() {
        let discovery = ToolDiscovery::new();
        assert!(discovery.discover_tools().await.is_ok());
    }

    #[test]
    fn test_tool_categorization() {
        let discovery = ToolDiscovery::new();

        assert!(matches!(discovery.categorize_tool("subfinder"), ToolCategory::Reconnaissance));
        assert!(matches!(discovery.categorize_tool("nmap"), ToolCategory::Scanning));
        assert!(matches!(discovery.categorize_tool("nuclei"), ToolCategory::Vulnerability));
        assert!(matches!(discovery.categorize_tool("sqlmap"), ToolCategory::Exploitation));
    }

    #[test]
    fn test_security_tool_name_detection() {
        let discovery = ToolDiscovery::new();

        assert!(discovery.is_security_tool_name("subfinder"));
        assert!(discovery.is_security_tool_name("nmap"));
        assert!(discovery.is_security_tool_name("nuclei"));
        assert!(!discovery.is_security_tool_name("ls"));
        assert!(!discovery.is_security_tool_name("cat"));
    }
}