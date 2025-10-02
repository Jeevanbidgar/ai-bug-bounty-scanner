use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
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

        // Try to find the tool using the `which` crate
        if let Ok(path) = which(tool_name) {
            let path_str = path.to_string_lossy().to_string();
            
            // Cache the result
            let mut tools = self.tools.write().await;
            tools.insert(tool_name.to_string(), ToolInfo {
                name: tool_name.to_string(),
                path: path_str.clone(),
                version: None,
                category: "unknown".to_string(),
            });

            return Some(path_str);
        }

        None
    }

    pub async fn register_tool(&self, name: String, path: String, category: String) -> Result<()> {
        let mut tools = self.tools.write().await;
        tools.insert(name.clone(), ToolInfo {
            name,
            path,
            version: None,
            category,
        });
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
            "subfinder", "amass", "naabu", "nmap", "nuclei", "httpx",
            "gau", "waybackurls", "ffuf", "gobuster", "sqlmap", "arjun"
        ];

        for tool_name in common_tools {
            if let Ok(path) = which(tool_name) {
                let path_str = path.to_string_lossy().to_string();
                tools.insert(tool_name.to_string(), ToolInfo {
                    name: tool_name.to_string(),
                    path: path_str,
                    version: None,
                    category: self.categorize_tool(tool_name),
                });
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