#![allow(dead_code)]
use super::catalog::{get_tool_catalog, ToolDefinition as CatalogToolDefinition};
use crate::runtime::process::configure_tokio_command;
use crate::tools::registry::ToolRegistry;
use crate::workflow::types::WorkflowTemplate;
use anyhow::Result;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

const REFRESH_TTL: u64 = 900; // 15 minutes in seconds
const VERSION_TIMEOUT: u64 = 5; // seconds

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub category: String,
    pub default_args: Vec<String>,
    pub version_command: Vec<String>,
    pub expected_outputs: Vec<String>,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRecord {
    pub name: String,
    pub description: String,
    pub category: String,
    pub status: String, // "available", "missing", "degraded", "error"
    pub installed: bool,
    pub command_template: Vec<String>,
    pub output_format: String,
    pub version: Option<String>,
    pub raw_version: Option<String>,
    pub path: Option<String>,
    pub os_dependencies: Vec<String>,
    pub missing_dependencies: Vec<String>,
    pub last_checked: Option<String>,
    pub last_seen: Option<String>,
    pub last_error: Option<String>,
    pub install_method: Option<String>, // Installation method: "go", "pipx", "git-pip", etc.
    pub alternative_install_methods: Option<Vec<String>>, // Alternative installation methods (e.g., ["pipx"] for git-pip tools)
    #[serde(default)]
    pub available_install_methods: Vec<String>,
}

impl ToolRecord {
    pub fn from_catalog_definition(def: &CatalogToolDefinition) -> Self {
        let platform = super::catalog::InstallPlatform::current();
        let methods = def.install_methods_for(&def.name, platform);
        let recommended = def.recommended_install_method(&def.name, platform);
        let alternatives = methods
            .iter()
            .filter(|method| Some(method.as_str()) != recommended.as_deref())
            .cloned()
            .collect::<Vec<_>>();
        Self {
            name: def.name.clone(),
            description: def.description.clone(),
            category: def.category.clone(),
            status: "unknown".to_string(),
            installed: false,
            command_template: def.command_candidates.clone(),
            output_format: def.output_format.clone(),
            version: None,
            raw_version: None,
            path: None,
            os_dependencies: def.os_dependencies.clone(),
            missing_dependencies: vec![],
            last_checked: None,
            last_seen: None,
            last_error: None,
            install_method: recommended,
            alternative_install_methods: if alternatives.is_empty() {
                None
            } else {
                Some(alternatives)
            },
            available_install_methods: methods,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolCache {
    tools: HashMap<String, ToolRecord>,
    manual_tools: Vec<String>,
    last_refresh: Option<String>,
}

pub struct ToolDiscoveryService {
    registry: ToolRegistry,
    definitions: Arc<RwLock<HashMap<String, ToolDefinition>>>,
    cache: Arc<RwLock<ToolCache>>,
    catalog: HashMap<String, CatalogToolDefinition>,
    additional_search_paths: Vec<PathBuf>,
    cache_file_path: PathBuf,
}

impl ToolDiscoveryService {
    pub fn new(cache_file_path: PathBuf) -> Self {
        let catalog = get_tool_catalog();
        let additional_paths = Self::build_additional_search_paths();

        let mut cache = ToolCache {
            tools: HashMap::new(),
            manual_tools: vec![],
            last_refresh: None,
        };

        // Initialize cache with placeholder entries from catalog
        for (name, def) in &catalog {
            cache
                .tools
                .insert(name.clone(), ToolRecord::from_catalog_definition(def));
        }

        Self {
            registry: ToolRegistry::new(),
            definitions: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(cache)),
            catalog,
            additional_search_paths: additional_paths,
            cache_file_path,
        }
    }

    /// Build additional search paths based on OS
    fn build_additional_search_paths() -> Vec<PathBuf> {
        let mut paths = vec![];

        // Add PATH directories
        if let Ok(path_var) = std::env::var("PATH") {
            for path_str in std::env::split_paths(&path_var) {
                if path_str.exists() {
                    paths.push(path_str);
                }
            }
        }

        // Add common installation directories
        #[cfg(target_os = "windows")]
        {
            if let Ok(program_files) = std::env::var("PROGRAMFILES") {
                paths.push(PathBuf::from(&program_files).join("Git\\usr\\bin"));
                paths.push(PathBuf::from(&program_files).join("Git\\bin"));
            }
            if let Ok(home) = std::env::var("USERPROFILE") {
                paths.push(PathBuf::from(&home).join("scoop\\shims"));
                paths.push(PathBuf::from(&home).join("AppData\\Local\\Microsoft\\WindowsApps"));

                // Add pipx bin directory (where pipx installs executables)
                paths.push(PathBuf::from(&home).join(".local\\bin"));

                // Add Go bin directory
                paths.push(PathBuf::from(&home).join("go\\bin"));
            }
            if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
                paths.push(PathBuf::from(local_app_data).join("Programs\\SecurityTools"));
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            paths.push(PathBuf::from("/usr/local/bin"));
            paths.push(PathBuf::from("/usr/bin"));
            paths.push(PathBuf::from("/bin"));

            if let Ok(home) = std::env::var("HOME") {
                paths.push(PathBuf::from(&home).join(".local/bin"));
                paths.push(PathBuf::from(&home).join("go/bin"));
                paths.push(PathBuf::from(&home).join(".cargo/bin"));
            }
        }

        paths
    }

    pub async fn initialize(&self) -> Result<()> {
        self.load_builtin_definitions().await?;
        self.registry.refresh_tools().await?;
        Ok(())
    }

    async fn load_builtin_definitions(&self) -> Result<()> {
        let mut definitions = self.definitions.write().await;

        let builtin_tools = self.get_builtin_tool_definitions();
        for tool in builtin_tools {
            definitions.insert(tool.name.clone(), tool);
        }

        Ok(())
    }

    fn get_builtin_tool_definitions(&self) -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "subfinder".to_string(),
                description: "Fast passive subdomain discovery tool".to_string(),
                category: "recon".to_string(),
                default_args: vec!["-silent".to_string(), "-passive".to_string()],
                version_command: vec!["subfinder".to_string(), "-version".to_string()],
                expected_outputs: vec!["subdomains.txt".to_string()],
                timeout: 300,
            },
            ToolDefinition {
                name: "amass".to_string(),
                description: "In-depth attack surface mapping and asset discovery".to_string(),
                category: "recon".to_string(),
                default_args: vec!["-passive".to_string(), "-silent".to_string()],
                version_command: vec!["amass".to_string(), "version".to_string()],
                expected_outputs: vec!["amass_output.txt".to_string()],
                timeout: 600,
            },
            ToolDefinition {
                name: "naabu".to_string(),
                description: "Fast port scanner written in Go".to_string(),
                category: "port_scanning".to_string(),
                default_args: vec!["-silent".to_string()],
                version_command: vec!["naabu".to_string(), "-version".to_string()],
                expected_outputs: vec!["ports.txt".to_string()],
                timeout: 300,
            },
            ToolDefinition {
                name: "nmap".to_string(),
                description: "Network exploration tool and security scanner".to_string(),
                category: "port_scanning".to_string(),
                default_args: vec!["-sS".to_string(), "-T4".to_string()],
                version_command: vec!["nmap".to_string(), "--version".to_string()],
                expected_outputs: vec!["nmap_output.xml".to_string()],
                timeout: 600,
            },
            ToolDefinition {
                name: "nuclei".to_string(),
                description: "Fast and customizable vulnerability scanner".to_string(),
                category: "vulnerability_scanning".to_string(),
                default_args: vec!["-silent".to_string(), "-j".to_string()],
                version_command: vec!["nuclei".to_string(), "-version".to_string()],
                expected_outputs: vec!["nuclei_output.jsonl".to_string()],
                timeout: 900,
            },
            ToolDefinition {
                name: "httpx".to_string(),
                description: "Fast and multi-purpose HTTP toolkit".to_string(),
                category: "http_probing".to_string(),
                default_args: vec!["-silent".to_string()],
                version_command: vec!["httpx".to_string(), "-version".to_string()],
                expected_outputs: vec!["httpx_output.txt".to_string()],
                timeout: 300,
            },
            ToolDefinition {
                name: "gau".to_string(),
                description: "Get All URLs from known services".to_string(),
                category: "url_discovery".to_string(),
                default_args: vec!["--subs".to_string()],
                version_command: vec!["gau".to_string(), "--version".to_string()],
                expected_outputs: vec!["gau_output.txt".to_string()],
                timeout: 300,
            },
            ToolDefinition {
                name: "waybackurls".to_string(),
                description: "Fetch all the URLs that the Wayback Machine has for the given domain"
                    .to_string(),
                category: "url_discovery".to_string(),
                default_args: vec![],
                version_command: vec!["waybackurls".to_string(), "-version".to_string()],
                expected_outputs: vec!["waybackurls_output.txt".to_string()],
                timeout: 300,
            },
            ToolDefinition {
                name: "ffuf".to_string(),
                description: "Fast web fuzzer written in Go".to_string(),
                category: "directory_fuzzing".to_string(),
                default_args: vec![
                    "-w".to_string(),
                    "/usr/share/wordlists/dirb/common.txt".to_string(),
                ],
                version_command: vec!["ffuf".to_string(), "-V".to_string()],
                expected_outputs: vec!["ffuf_output.json".to_string()],
                timeout: 600,
            },
            ToolDefinition {
                name: "gobuster".to_string(),
                description: "Directory/file & DNS busting tool written in Go".to_string(),
                category: "directory_fuzzing".to_string(),
                default_args: vec!["-q".to_string()],
                version_command: vec!["gobuster".to_string(), "version".to_string()],
                expected_outputs: vec!["gobuster_output.txt".to_string()],
                timeout: 600,
            },
            ToolDefinition {
                name: "sqlmap".to_string(),
                description: "Automatic SQL injection and database takeover tool".to_string(),
                category: "parameter_testing".to_string(),
                default_args: vec!["--batch".to_string(), "--silent".to_string()],
                version_command: vec!["sqlmap".to_string(), "--version".to_string()],
                expected_outputs: vec!["sqlmap_output.txt".to_string()],
                timeout: 1800,
            },
            ToolDefinition {
                name: "arjun".to_string(),
                description: "HTTP parameter discovery suite".to_string(),
                category: "parameter_testing".to_string(),
                default_args: vec!["--silent".to_string()],
                version_command: vec!["arjun".to_string(), "--version".to_string()],
                expected_outputs: vec!["arjun_output.txt".to_string()],
                timeout: 300,
            },
        ]
    }

    pub async fn get_tool_info(&self, tool_name: &str) -> Option<ToolDefinition> {
        let definitions = self.definitions.read().await;
        definitions.get(tool_name).cloned()
    }

    pub async fn list_tools(&self) -> Vec<ToolDefinition> {
        let definitions = self.definitions.read().await;
        definitions.values().cloned().collect()
    }

    pub async fn check_tool_availability(&self, tool_name: &str) -> Result<bool> {
        Ok(self.registry.resolve_tool_path(tool_name).await.is_some())
    }

    /// Get the path to a tool if it's available (public wrapper for registry method)
    pub async fn get_tool_path(&self, tool_name: &str) -> Option<String> {
        self.registry.resolve_tool_path(tool_name).await
    }

    pub async fn get_available_tools(&self) -> Result<Vec<String>> {
        let mut available_tools = Vec::new();
        let definitions = self.definitions.read().await;

        for (tool_name, _) in definitions.iter() {
            if self
                .check_tool_availability(tool_name)
                .await
                .unwrap_or(false)
            {
                available_tools.push(tool_name.clone());
            }
        }

        Ok(available_tools)
    }

    pub async fn get_tool_compatibility(
        &self,
        workflow_template: &WorkflowTemplate,
    ) -> Result<crate::workflow::types::WorkflowCompatibility> {
        let mut required_tools = Vec::new();
        let mut available_tools = Vec::new();
        let mut missing_tools = Vec::new();
        let mut warnings = Vec::new();

        // Extract tool names from workflow steps
        for step in &workflow_template.steps {
            if let Some(first_arg) = step.run.first() {
                let tool_name = first_arg.trim();
                if !required_tools.contains(&tool_name.to_string()) {
                    required_tools.push(tool_name.to_string());

                    if self
                        .check_tool_availability(tool_name)
                        .await
                        .unwrap_or(false)
                    {
                        available_tools.push(tool_name.to_string());
                    } else {
                        missing_tools.push(tool_name.to_string());
                    }
                }
            }
        }

        // Check if any tools are missing
        let compatible = missing_tools.is_empty();

        // Calculate compatibility percentage
        let compatibility_percentage = if required_tools.is_empty() {
            100.0
        } else {
            (available_tools.len() as f64 / required_tools.len() as f64) * 100.0
        };

        // Add warnings for potential issues
        if !compatible {
            warnings.push(format!("Missing {} required tools", missing_tools.len()));
        }

        Ok(crate::workflow::types::WorkflowCompatibility {
            compatible,
            required_tools,
            available_tools,
            missing_tools,
            compatibility_percentage,
            warnings,
        })
    }

    // New catalog-based methods for enhanced tool discovery

    /// Load cached tool records from disk
    pub async fn load_cache(&mut self) -> Result<()> {
        if self.cache_file_path.exists() {
            let contents = tokio::fs::read_to_string(&self.cache_file_path).await?;
            let cache: ToolCache = serde_json::from_str(&contents)?;
            *self.cache.write().await = cache;
            eprintln!("✅ Loaded cache from: {}", self.cache_file_path.display());
        } else {
            eprintln!(
                "ℹ️  No cache file found at: {}",
                self.cache_file_path.display()
            );
        }
        Ok(())
    }

    /// Save tool cache to disk
    pub async fn save_cache(&self) -> Result<()> {
        if let Some(parent) = self.cache_file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let cache = self.cache.read().await;
        let json = serde_json::to_string_pretty(&*cache)?;
        tokio::fs::write(&self.cache_file_path, json).await?;
        eprintln!("✅ Saved cache to: {}", self.cache_file_path.display());
        Ok(())
    }

    /// Check if cache is stale
    fn is_stale(&self, last_checked: Option<&String>) -> bool {
        if let Some(last_checked_str) = last_checked {
            if let Ok(last_checked_time) = last_checked_str.parse::<DateTime<Utc>>() {
                let now = Utc::now();
                let elapsed = now.signed_duration_since(last_checked_time);
                return elapsed.num_seconds() > REFRESH_TTL as i64;
            }
        }
        true
    }

    /// Get all tool records (new catalog-based implementation)
    pub async fn get_all_tool_records(&self, force_refresh: bool) -> Vec<ToolRecord> {
        let mut cache = self.cache.write().await;

        eprintln!(
            "get_all_tool_records: force_refresh={}, catalog size={}",
            force_refresh,
            self.catalog.len()
        );

        // Check if this is the first time (no cache exists)
        let is_first_load = cache.last_refresh.is_none() && cache.tools.is_empty();

        // Check if refresh needed - but SKIP auto-refresh on first load
        let needs_refresh = if is_first_load && !force_refresh {
            eprintln!("First load detected - skipping auto-refresh. Use force_refresh=true to discover tools.");
            false // Don't auto-refresh on first load unless explicitly requested
        } else {
            force_refresh || self.is_stale(cache.last_refresh.as_ref())
        };

        eprintln!(
            "needs_refresh={}, cache tools count={}",
            needs_refresh,
            cache.tools.len()
        );

        if needs_refresh {
            eprintln!("Refreshing tools from catalog...");
            let mut discovered_count = 0;
            let mut missing_count = 0;
            let total_tools = self.catalog.len();

            // Refresh all tools from catalog
            for (idx, (name, def)) in self.catalog.iter().enumerate() {
                let mut record = ToolRecord::from_catalog_definition(def);
                let progress = ((idx + 1) as f32 / total_tools as f32 * 100.0) as u32;

                // Emit progress event (we'll add window parameter later for Tauri events)
                eprintln!(
                    "🔄 Scanning {}/{}: {} ({}%)",
                    idx + 1,
                    total_tools,
                    name,
                    progress
                );

                // Try to resolve path
                if let Ok(Some(path)) = self.resolve_tool_path(&record.command_template).await {
                    record.installed = true;
                    record.status = "available".to_string();
                    record.path = Some(path.clone());
                    discovered_count += 1;
                    eprintln!("✅ {} is available", name);

                    // Try to get version
                    if !def.version_args.is_empty() {
                        if let Ok(version) =
                            self.capture_tool_version(&path, &def.version_args).await
                        {
                            record.version = Some(version.clone());
                            record.raw_version = Some(version);
                        }
                    }
                } else {
                    record.installed = false;
                    record.status = "missing".to_string();
                    missing_count += 1;
                    eprintln!("❌ {} not found", name);
                }

                record.last_checked = Some(Utc::now().to_rfc3339());
                cache.tools.insert(name.clone(), record);
            }

            eprintln!(
                "✅ Discovery complete: {} available, {} missing out of {} total",
                discovered_count, missing_count, total_tools
            );

            cache.last_refresh = Some(Utc::now().to_rfc3339());

            // Save cache
            drop(cache); // Release write lock before save
            let _ = self.save_cache().await;
            cache = self.cache.write().await;
        }

        let result: Vec<ToolRecord> = cache.tools.values().cloned().collect();
        eprintln!("Returning {} tool records", result.len());
        result
    }

    /// Get a specific tool record
    pub async fn get_tool_record(
        &self,
        tool_name: &str,
        force_refresh: bool,
    ) -> Option<ToolRecord> {
        let cache = self.cache.read().await;

        if let Some(record) = cache.tools.get(tool_name) {
            let needs_refresh = force_refresh || self.is_stale(record.last_checked.as_ref());

            if !needs_refresh {
                return Some(record.clone());
            }
        }

        drop(cache); // Release read lock

        // Refresh this specific tool
        if let Some(def) = self.catalog.get(tool_name) {
            let mut record = ToolRecord::from_catalog_definition(def);

            // Try to resolve path
            if let Ok(Some(path)) = self.resolve_tool_path(&record.command_template).await {
                record.installed = true;
                record.status = "available".to_string();
                record.path = Some(path.clone());

                // Try to get version
                if !def.version_args.is_empty() {
                    if let Ok(version) = self.capture_tool_version(&path, &def.version_args).await {
                        record.version = Some(version.clone());
                        record.raw_version = Some(version);
                    }
                }
            } else {
                record.installed = false;
                record.status = "missing".to_string();
            }

            record.last_checked = Some(Utc::now().to_rfc3339());

            // Update cache
            let mut cache = self.cache.write().await;
            cache.tools.insert(tool_name.to_string(), record.clone());
            drop(cache);

            let _ = self.save_cache().await;

            return Some(record);
        }

        None
    }

    /// Refresh all tools and return the updated records
    pub async fn refresh_all_tools(&self) -> HashMap<String, ToolRecord> {
        let records = self.get_all_tool_records(true).await;
        records.into_iter().map(|r| (r.name.clone(), r)).collect()
    }

    /// Get all unique categories from the catalog
    pub fn get_categories(&self) -> Vec<String> {
        let mut categories: Vec<String> = self
            .catalog
            .values()
            .map(|def| def.category.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        categories.sort();
        categories
    }

    /// Get tools filtered by category
    pub async fn get_tools_by_category(&self, category: &str) -> Vec<ToolRecord> {
        let cache = self.cache.read().await;
        cache
            .tools
            .values()
            .filter(|tool| tool.category == category)
            .cloned()
            .collect()
    }

    /// Add a manual tool
    pub async fn add_manual_tool(
        &self,
        name: &str,
        path: &str,
        category: &str,
    ) -> Result<ToolRecord> {
        let mut cache = self.cache.write().await;

        // Check if tool already exists
        if cache.tools.contains_key(name) {
            return Err(anyhow::anyhow!("Tool '{}' already exists", name));
        }

        // Verify path exists
        if !tokio::fs::try_exists(path).await? {
            return Err(anyhow::anyhow!("Tool path does not exist: {}", path));
        }

        // Create manual tool record
        let record = ToolRecord {
            name: name.to_string(),
            description: format!("Manual tool: {}", name),
            category: category.to_string(),
            status: "available".to_string(),
            installed: true,
            command_template: vec![path.to_string()],
            output_format: "text".to_string(),
            version: None,
            raw_version: None,
            path: Some(path.to_string()),
            os_dependencies: vec![],
            missing_dependencies: vec![],
            last_checked: Some(Utc::now().to_rfc3339()),
            last_seen: Some(Utc::now().to_rfc3339()),
            last_error: None,
            install_method: Some("manual".to_string()),
            alternative_install_methods: None, // Manual tools don't have alternatives
            available_install_methods: vec!["manual".to_string()],
        };

        cache.tools.insert(name.to_string(), record.clone());
        cache.manual_tools.push(name.to_string());

        drop(cache);
        let _ = self.save_cache().await;

        Ok(record)
    }

    /// Remove a manual tool
    pub async fn remove_manual_tool(&self, name: &str) -> Result<bool> {
        let mut cache = self.cache.write().await;

        // Check if it's a manual tool
        if !cache.manual_tools.contains(&name.to_string()) {
            return Ok(false);
        }

        cache.tools.remove(name);
        cache.manual_tools.retain(|t| t != name);

        drop(cache);
        let _ = self.save_cache().await;

        Ok(true)
    }

    /// Get list of manual tools
    pub fn list_manual_tools(&self) -> Vec<String> {
        // This needs to be sync, so we can't await here
        // Return empty for now, will need to refactor if needed
        vec![]
    }

    /// Get count of available tools
    pub async fn get_available_count(&self) -> usize {
        let cache = self.cache.read().await;
        cache.tools.values().filter(|t| t.installed).count()
    }

    /// Resolve tool path from command candidates
    async fn resolve_tool_path(&self, candidates: &[String]) -> Result<Option<String>> {
        eprintln!("🔎 Resolving tool path for candidates: {:?}", candidates);

        for candidate in candidates {
            if candidate.is_empty() {
                continue;
            }

            // Check if it's an absolute path
            if std::path::Path::new(candidate).is_absolute() {
                if tokio::fs::try_exists(candidate).await? {
                    eprintln!("✅ Found tool at absolute path: {}", candidate);
                    return Ok(Some(candidate.clone()));
                }
                continue;
            }

            // Try to find in PATH and OS-specific locations
            if let Some(path) = self.which_tool(candidate).await {
                return Ok(Some(path));
            }
        }

        eprintln!("❌ Could not resolve path for any candidate");
        Ok(None)
    }

    /// Find tool in PATH (cross-platform which) with fallback to OS-specific locations
    async fn which_tool(&self, tool_name: &str) -> Option<String> {
        eprintln!("🔍 Searching for tool: {}", tool_name);

        // First try: Use which crate for PATH lookup
        if let Ok(path) = which::which(tool_name) {
            if let Some(path_str) = path.to_str() {
                eprintln!("✅ Found {} in PATH: {}", tool_name, path_str);
                return Some(path_str.to_string());
            }
        }

        // Windows: honor the common executable and script launcher extensions.
        #[cfg(target_os = "windows")]
        {
            for extension in ["exe", "cmd", "bat", "ps1"] {
                let candidate = format!("{}.{}", tool_name, extension);
                if let Ok(path) = which::which(&candidate) {
                    if let Some(path_str) = path.to_str() {
                        eprintln!("✅ Found {} in PATH: {}", candidate, path_str);
                        return Some(path_str.to_string());
                    }
                }
            }
        }

        // Second try: Check OS-specific locations
        let search_paths = self.get_os_specific_search_paths();
        for search_dir in search_paths {
            let candidate = std::path::PathBuf::from(&search_dir).join(tool_name);

            #[cfg(target_os = "windows")]
            let candidates = vec![
                candidate.clone(),
                candidate.with_extension("exe"),
                candidate.with_extension("EXE"),
                candidate.with_extension("cmd"),
                candidate.with_extension("bat"),
                candidate.with_extension("ps1"),
            ];

            #[cfg(not(target_os = "windows"))]
            let candidates = vec![candidate];

            for candidate_path in candidates {
                if candidate_path.exists() {
                    if let Ok(metadata) = std::fs::metadata(&candidate_path) {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let permissions = metadata.permissions();
                            if permissions.mode() & 0o111 != 0 {
                                if let Some(path_str) = candidate_path.to_str() {
                                    eprintln!(
                                        "✅ Found {} in {}: {}",
                                        tool_name, search_dir, path_str
                                    );
                                    return Some(path_str.to_string());
                                }
                            }
                        }

                        #[cfg(windows)]
                        {
                            if let Some(path_str) = candidate_path.to_str() {
                                eprintln!("✅ Found {} in {}: {}", tool_name, search_dir, path_str);
                                return Some(path_str.to_string());
                            }
                        }
                    }
                }
            }
        }

        eprintln!("❌ Tool {} not found in PATH or known locations", tool_name);
        None
    }

    /// Get OS-specific search paths for tools
    fn get_os_specific_search_paths(&self) -> Vec<String> {
        let mut paths = Vec::new();

        #[cfg(target_os = "macos")]
        {
            // macOS: Check Homebrew locations
            // Apple Silicon (M1/M2) uses /opt/homebrew
            paths.push("/opt/homebrew/bin".to_string());
            paths.push("/opt/homebrew/sbin".to_string());

            // Intel Macs use /usr/local
            paths.push("/usr/local/bin".to_string());
            paths.push("/usr/local/sbin".to_string());

            // MacPorts
            paths.push("/opt/local/bin".to_string());
            paths.push("/opt/local/sbin".to_string());
        }

        #[cfg(target_os = "linux")]
        {
            // Linux: FHS-compliant directories
            paths.push("/usr/local/bin".to_string());
            paths.push("/usr/local/sbin".to_string());
            paths.push("/usr/bin".to_string());
            paths.push("/usr/sbin".to_string());
            paths.push("/bin".to_string());
            paths.push("/sbin".to_string());

            // Linuxbrew/Homebrew on Linux
            paths.push("/home/linuxbrew/.linuxbrew/bin".to_string());

            // Snap packages
            paths.push("/snap/bin".to_string());

            // User's local bin
            if let Ok(home) = std::env::var("HOME") {
                paths.push(format!("{}/.local/bin", home));
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Windows: Common installation directories
            if let Ok(program_files) = std::env::var("ProgramFiles") {
                paths.push(program_files.clone());
                paths.push(format!("{}\\Git\\cmd", program_files));
                paths.push(format!("{}\\Git\\usr\\bin", program_files));
            }

            if let Ok(program_files_x86) = std::env::var("ProgramFiles(x86)") {
                paths.push(program_files_x86.clone());
            }

            if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
                paths.push(format!("{}\\Programs", localappdata));
                paths.push(format!("{}\\Programs\\SecurityTools", localappdata));
            }

            // Chocolatey
            paths.push("C:\\ProgramData\\chocolatey\\bin".to_string());

            // Scoop
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                paths.push(format!("{}\\scoop\\shims", userprofile));
            }
        }

        for path in &self.additional_search_paths {
            let value = path.to_string_lossy().to_string();
            if !paths.contains(&value) {
                paths.push(value);
            }
        }

        paths
    }

    /// Capture tool version by running version command
    async fn capture_tool_version(
        &self,
        tool_path: &str,
        version_args: &[String],
    ) -> Result<String> {
        let mut cmd = tokio::process::Command::new(tool_path);
        cmd.args(version_args);
        configure_tokio_command(&mut cmd);

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(VERSION_TIMEOUT),
            cmd.output(),
        )
        .await??;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        // Try to extract version using common patterns
        let version_patterns = vec![
            r"v?(\d+\.\d+\.\d+)",
            r"version\s+v?(\d+\.\d+\.\d+)",
            r"(\d+\.\d+\.\d+)",
        ];

        for pattern in version_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(&combined) {
                    if let Some(version) = caps.get(1) {
                        return Ok(version.as_str().to_string());
                    }
                }
            }
        }

        Ok("unknown".to_string())
    }

    /// Enhanced recheck that looks in package-manager-specific locations
    pub async fn recheck_tool_enhanced(
        &self,
        tool_name: &str,
        install_method: Option<&str>,
    ) -> Option<ToolRecord> {
        let def = self.catalog.get(tool_name)?;

        // Get standard search paths
        let mut search_paths: Vec<PathBuf> = self
            .get_os_specific_search_paths()
            .into_iter()
            .map(PathBuf::from)
            .collect();

        // Add package-manager-specific paths
        if let Some(method) = install_method {
            search_paths.extend(self.get_pm_specific_paths(method).await);
        }

        eprintln!(
            "🔍 Enhanced search for {} in {} paths",
            tool_name,
            search_paths.len()
        );

        // Search in all paths
        for candidate in &def.command_candidates {
            for search_dir in &search_paths {
                // Try exact candidate name
                let tool_path = search_dir.join(candidate);
                if tool_path.exists() && tool_path.is_file() {
                    eprintln!("✅ Found {} at {}", tool_name, tool_path.display());
                    return self.check_tool_at_path_direct(tool_name, &tool_path).await;
                }

                // Try with common extensions on Windows
                #[cfg(target_os = "windows")]
                for ext in &[".exe", ".cmd", ".bat", ".ps1"] {
                    let tool_path_ext = search_dir.join(format!("{}{}", candidate, ext));
                    if tool_path_ext.exists() && tool_path_ext.is_file() {
                        eprintln!("✅ Found {} at {}", tool_name, tool_path_ext.display());
                        return self
                            .check_tool_at_path_direct(tool_name, &tool_path_ext)
                            .await;
                    }
                }
            }
        }

        eprintln!("❌ Could not find {} in enhanced search", tool_name);
        None
    }

    /// Check tool at specific path and update cache
    async fn check_tool_at_path_direct(
        &self,
        tool_name: &str,
        tool_path: &Path,
    ) -> Option<ToolRecord> {
        let def = self.catalog.get(tool_name)?;
        let mut record = ToolRecord::from_catalog_definition(def);

        record.installed = true;
        record.status = "available".to_string();
        record.path = Some(tool_path.to_string_lossy().to_string());

        // Try to get version
        if !def.version_args.is_empty() {
            if let Ok(version) = self
                .capture_tool_version(&tool_path.to_string_lossy(), &def.version_args)
                .await
            {
                record.version = Some(version.clone());
                record.raw_version = Some(version);
            }
        }

        record.last_checked = Some(Utc::now().to_rfc3339());

        // Update cache
        let mut cache = self.cache.write().await;
        cache.tools.insert(tool_name.to_string(), record.clone());
        drop(cache);

        let _ = self.save_cache().await;

        Some(record)
    }

    async fn get_pm_specific_paths(&self, install_method: &str) -> Vec<PathBuf> {
        match install_method {
            "npm" => self.get_npm_paths().await,
            "winget" => self.get_winget_paths().await,
            "cargo" => self.get_cargo_paths().await,
            _ => vec![],
        }
    }

    async fn get_npm_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![];

        eprintln!("🔍 Getting npm-specific paths...");

        // Try to get npm prefix
        let mut npm_cmd = tokio::process::Command::new("npm");
        npm_cmd.args(["prefix", "-g"]);
        configure_tokio_command(&mut npm_cmd);

        if let Ok(output) = npm_cmd.output().await {
            if output.status.success() {
                let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
                eprintln!("   npm prefix: {}", prefix);
                paths.push(PathBuf::from(format!("{}/node_modules/.bin", prefix)));
                paths.push(PathBuf::from(format!("{}\\node_modules\\.bin", prefix)));
            }
        }

        // Common npm global locations on Windows
        #[cfg(target_os = "windows")]
        {
            if let Ok(appdata) = std::env::var("APPDATA") {
                let npm_path = PathBuf::from(format!("{}\\npm", appdata));
                eprintln!("   Checking: {}", npm_path.display());
                paths.push(npm_path);
            }
            if let Ok(programfiles) = std::env::var("ProgramFiles") {
                paths.push(PathBuf::from(format!("{}\\nodejs", programfiles)));
            }
        }

        // Common npm global locations on Unix
        #[cfg(not(target_os = "windows"))]
        {
            if let Ok(home) = std::env::var("HOME") {
                paths.push(PathBuf::from(format!("{}/.npm-global/bin", home)));
                paths.push(PathBuf::from("/usr/local/bin"));
                paths.push(PathBuf::from("/usr/bin"));
            }
        }

        eprintln!("   Found {} npm paths", paths.len());
        paths
    }

    async fn get_winget_paths(&self) -> Vec<PathBuf> {
        let paths = vec![];

        eprintln!("🔍 Getting WinGet-specific paths...");

        #[cfg(target_os = "windows")]
        {
            // Common WinGet install locations
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                paths.push(PathBuf::from(format!(
                    "{}\\AppData\\Local\\Microsoft\\WinGet\\Packages",
                    userprofile
                )));
                paths.push(PathBuf::from(format!(
                    "{}\\AppData\\Local\\Microsoft\\WinGet\\Links",
                    userprofile
                )));
            }

            paths.push(PathBuf::from("C:\\Program Files"));
            paths.push(PathBuf::from("C:\\Program Files (x86)"));

            // Check ProgramFiles environment variables
            if let Ok(pf) = std::env::var("ProgramFiles") {
                paths.push(PathBuf::from(pf));
            }
            if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
                paths.push(PathBuf::from(pf86));
            }

            // Local bin directories
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                paths.push(PathBuf::from(format!(
                    "{}\\AppData\\Local\\Programs",
                    userprofile
                )));
            }
        }

        eprintln!("   Found {} WinGet paths", paths.len());
        paths
    }

    async fn get_cargo_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![];

        // Cargo bin directory
        if let Ok(home) = std::env::var("CARGO_HOME") {
            paths.push(PathBuf::from(format!("{}/bin", home)));
        } else if let Ok(home) = std::env::var("HOME") {
            paths.push(PathBuf::from(format!("{}/.cargo/bin", home)));
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                paths.push(PathBuf::from(format!("{}\\.cargo\\bin", userprofile)));
            }
        }

        paths
    }
}
