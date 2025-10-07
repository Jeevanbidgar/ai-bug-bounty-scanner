use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use which::which;

#[derive(Debug, Clone)]
pub struct ToolInfo {
    pub name: String,
    pub path: String,
    pub version: Option<String>,
    pub category: String,
}

#[derive(Clone)]
pub struct ToolRegistry {
    tools: Arc<RwLock<HashMap<String, ToolInfo>>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn resolve_tool_path(&self, tool_name: &str) -> Option<String> {
        // Check cache first
        {
            let tools = self.tools.read().await;
            if let Some(tool_info) = tools.get(tool_name) {
                // Verify the tool still exists at the cached path
                if PathBuf::from(&tool_info.path).exists() {
                    return Some(tool_info.path.clone());
                }
            }
        }

        // Try to find the tool using the `which` crate (searches PATH)
        if let Ok(path) = which(tool_name) {
            let path_str = path.to_string_lossy().to_string();

            // Cache the result
            let mut tools = self.tools.write().await;
            tools.insert(
                tool_name.to_string(),
                ToolInfo {
                    name: tool_name.to_string(),
                    path: path_str.clone(),
                    version: None,
                    category: "unknown".to_string(),
                },
            );

            return Some(path_str);
        }

        // If not found in PATH, search additional common directories
        let additional_paths = self.get_additional_search_paths();
        for search_dir in additional_paths {
            let tool_path = search_dir.join(tool_name);
            
            // Check exact match
            if tool_path.exists() && tool_path.is_file() {
                let path_str = tool_path.to_string_lossy().to_string();
                
                // Cache the result
                let mut tools = self.tools.write().await;
                tools.insert(
                    tool_name.to_string(),
                    ToolInfo {
                        name: tool_name.to_string(),
                        path: path_str.clone(),
                        version: None,
                        category: "unknown".to_string(),
                    },
                );
                
                return Some(path_str);
            }
            
            // On Windows, try with .exe extension
            #[cfg(target_os = "windows")]
            {
                let tool_path_exe = search_dir.join(format!("{}.exe", tool_name));
                if tool_path_exe.exists() && tool_path_exe.is_file() {
                    let path_str = tool_path_exe.to_string_lossy().to_string();
                    
                    let mut tools = self.tools.write().await;
                    tools.insert(
                        tool_name.to_string(),
                        ToolInfo {
                            name: tool_name.to_string(),
                            path: path_str.clone(),
                            version: None,
                            category: "unknown".to_string(),
                        },
                    );
                    
                    return Some(path_str);
                }
            }
        }

        None
    }

    fn get_additional_search_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Ok(home) = std::env::var("USERPROFILE") {
                paths.push(PathBuf::from(&home).join("go\\bin"));
                paths.push(PathBuf::from(&home).join(".cargo\\bin"));
                paths.push(PathBuf::from(&home).join(".local\\bin"));
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            if let Ok(home) = std::env::var("HOME") {
                paths.push(PathBuf::from(&home).join("go/bin"));
                paths.push(PathBuf::from(&home).join(".cargo/bin"));
                paths.push(PathBuf::from(&home).join(".local/bin"));
            }
            
            // Also check /usr/local/bin and /usr/bin (common on Linux)
            paths.push(PathBuf::from("/usr/local/bin"));
            paths.push(PathBuf::from("/usr/bin"));
        }

        paths
    }

    pub async fn register_tool(&self, name: String, path: String, category: String) -> Result<()> {
        let mut tools = self.tools.write().await;
        tools.insert(
            name.clone(),
            ToolInfo {
                name,
                path,
                version: None,
                category,
            },
        );
        Ok(())
    }

    pub async fn get_tool_info(&self, tool_name: &str) -> Option<ToolInfo> {
        let tools = self.tools.read().await;
        tools.get(tool_name).cloned()
    }

    pub async fn list_tools(&self) -> Vec<ToolInfo> {
        let tools = self.tools.read().await;
        tools.values().cloned().collect()
    }

    pub async fn refresh_tools(&self) -> Result<()> {
        let mut tools = self.tools.write().await;
        tools.clear();

        // Common security tools to check for
        let common_tools = vec![
            "subfinder",
            "amass",
            "naabu",
            "nmap",
            "nuclei",
            "httpx",
            "gau",
            "waybackurls",
            "ffuf",
            "gobuster",
            "sqlmap",
            "arjun",
        ];

        for tool_name in common_tools {
            if let Ok(path) = which(tool_name) {
                let path_str = path.to_string_lossy().to_string();
                tools.insert(
                    tool_name.to_string(),
                    ToolInfo {
                        name: tool_name.to_string(),
                        path: path_str,
                        version: None,
                        category: self.categorize_tool(tool_name),
                    },
                );
            }
        }

        Ok(())
    }

    fn categorize_tool(&self, tool_name: &str) -> String {
        match tool_name {
            "subfinder" | "amass" => "recon".to_string(),
            "naabu" | "nmap" => "port_scanning".to_string(),
            "nuclei" => "vulnerability_scanning".to_string(),
            "httpx" => "http_probing".to_string(),
            "gau" | "waybackurls" => "url_discovery".to_string(),
            "ffuf" | "gobuster" => "directory_fuzzing".to_string(),
            "sqlmap" | "arjun" => "parameter_testing".to_string(),
            _ => "unknown".to_string(),
        }
    }
}
