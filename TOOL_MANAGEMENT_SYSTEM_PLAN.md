# 🛠️ Tool Management System - Implementation Plan (Enhanced)

## 🎯 Overview
Transform the Tools tab into a **production-grade tool management platform** that leverages native OS package managers for seamless installation, updates, and removal - making security tools accessible to everyone, from beginners to experts.

**Core Philosophy**: Manager-first design with native OS workflows, reliable version signals, and minimal friction.

---

## ✨ Key Features

### 1. **Manager-First Installation (New Approach)**
- **Windows Priority**: WinGet → Chocolatey → Scoop → Language-specific
- **Linux Priority**: APT/DNF/pacman → Homebrew → Language-specific
- **Transparent Source**: Show which manager installs each tool (badge)
- **Unified Interface**: One UI, multiple managers working behind scenes
- **Safety First**: Preview commands before execution with elevation prompts

### 2. **Native Package Manager Integration**
#### Windows (WinGet Primary)
- `winget list` - Discover installed tools and updates
- `winget upgrade --id <ID>` - Update specific tool
- `winget upgrade --all` - Update all tools
- `winget uninstall --id <ID>` - Remove tool
- **Fallbacks**: Chocolatey (`choco upgrade/uninstall`) and Scoop (`scoop update/uninstall`)

#### Linux (System Package Manager)
- **Debian/Ubuntu**: `apt install/remove/purge` with autoremove support
- **Fedora/RHEL**: `dnf install/upgrade/remove` with autoremove
- **Arch/Manjaro**: `pacman -S/-Syu/-R/-Rns` with dependency cleanup
- **Homebrew**: `brew install/upgrade/uninstall` (macOS/Linux)

#### Language-Specific Managers
- **Python CLIs**: `pipx install/upgrade/uninstall` for isolated installs
- **Go tools**: `go install <module>@latest` for developer tools
- **Rust tools**: `cargo install/uninstall` for Rust-based tools
- **npm tools**: `npm install -g` for Node.js tools

### 3. **Smart Version Detection**
- **Timeout-bounded probes**: `tokio::time::timeout` prevents UI hangs
- **Multiple strategies**:
  1. Package manager metadata (preferred - `winget list`, `apt list --upgradable`)
  2. Direct version probe (`tool --version`) with semver parsing
  3. GitHub releases API for tools without package manager presence
- **Semver evaluation**: Precise version comparison with range requirements
- **Status labels**: "Latest", "Update Available (v2.3.0)", "Outdated (Critical)"

### 4. **One-Click Operations with Safety**
- **Install**: Execute platform-appropriate command with elevation
- **Update**: Manager's upgrade flow with version probe refresh
- **Remove**: Uninstall with optional cleanup flags (purge/-Rns)
- **Preview**: Show exact command before execution
- **Streaming Output**: Real-time stdout/stderr in UI
- **Progress Tracking**: Per-operation status with success/error handling

### 5. **Advanced Management Features**
- **Global "Update All"**: Per-manager batch updates with separate logs
- **Manager Source Badges**: Visual indicator of which manager handles each tool
- **Dependency Cleanup**: Offer autoremove/purge after uninstalls
- **Installation History**: Track all operations for audit trail
- **Rollback Support**: Restore previous version if update fails
- **Offline Mode**: Cache packages for air-gapped environments

---

## 🏗️ Architecture

### Backend Structure

```
src-tauri/src/tools/
├── manager.rs              # Main tool manager (orchestrates all managers)
├── version/
│   ├── mod.rs             # Version detection with timeout bounds
│   ├── probe.rs           # Direct tool version probes
│   ├── semver.rs          # Semantic version parsing and comparison
│   └── strategies.rs      # Multiple detection strategies
├── package_managers/
│   ├── mod.rs             # Package manager trait and registry
│   ├── windows/
│   │   ├── winget.rs      # WinGet (primary for Windows)
│   │   ├── chocolatey.rs  # Chocolatey fallback
│   │   └── scoop.rs       # Scoop fallback
│   ├── linux/
│   │   ├── apt.rs         # Debian/Ubuntu
│   │   ├── dnf.rs         # Fedora/RHEL
│   │   └── pacman.rs      # Arch/Manjaro
│   ├── cross_platform/
│   │   └── homebrew.rs    # macOS/Linux Brew
│   └── language/
│       ├── pipx.rs        # Python CLI isolation
│       ├── go.rs          # Go install
│       ├── cargo.rs       # Rust Cargo
│       └── npm.rs         # Node.js npm
├── installer.rs            # Installation orchestration
├── updater.rs             # Update orchestration with rollback
├── uninstaller.rs         # Removal with cleanup options
├── discovery.rs           # Enhanced discovery with manager detection
└── catalog_extended.rs    # Tool registry with manager mappings
```

### Tool Registry Schema (Enhanced)

```rust
pub struct ToolMetadata {
    pub name: String,
    pub description: String,
    pub homepage: String,
    pub repository: String,
    
    // Version detection
    pub version_command: Vec<String>,      // e.g., ["--version"], ["-V"]
    pub version_regex: String,             // Regex to extract version
    pub version_timeout_ms: u64,           // Timeout for version probe (default: 5000)
    
    // Package manager mappings (priority order)
    pub windows_packages: Vec<PackageSource>,
    pub linux_packages: Vec<PackageSource>,
    pub macos_packages: Vec<PackageSource>,
    
    // Semver requirements
    pub min_version: Option<String>,       // Minimum supported version
    pub recommended_version: Option<String>,
    
    // Metadata
    pub tags: Vec<String>,                 // ["network", "subdomain", "recon"]
    pub dependencies: Vec<String>,         // Other tools this depends on
    pub size_estimate_mb: Option<u64>,     // Estimated install size
}

pub struct PackageSource {
    pub manager: PackageManager,
    pub package_id: String,                // Manager-specific ID/name
    pub priority: u8,                      // 0 = highest priority
    pub requires_elevation: bool,          // Needs sudo/admin?
    pub notes: Option<String>,             // Special instructions
}

pub enum PackageManager {
    // Windows
    WinGet,
    Chocolatey,
    Scoop,
    
    // Linux
    Apt,
    Dnf,
    Pacman,
    
    // Cross-platform
    Homebrew,
    
    // Language-specific
    Pipx,
    GoInstall,
    Cargo,
    Npm,
    
    // Fallback
    Binary { url: String },                // Direct download
}
```

### Database Schema Extensions

```sql
-- Package manager detection cache
CREATE TABLE package_managers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    manager_type TEXT NOT NULL,            -- 'winget', 'apt', 'pipx', etc.
    version TEXT,                          -- Manager version
    available BOOLEAN NOT NULL,
    path TEXT,                             -- Full path to manager binary
    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tool installations with manager tracking
CREATE TABLE tool_installations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    version TEXT NOT NULL,
    manager_type TEXT NOT NULL,            -- Which manager installed it
    package_id TEXT NOT NULL,              -- Manager's package identifier
    install_path TEXT NOT NULL,
    installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    installed_by TEXT DEFAULT 'user',
    can_update BOOLEAN DEFAULT TRUE,       -- Managed by package manager?
    metadata TEXT                          -- JSON: size, dependencies, etc.
);

-- Version probe cache (with timeout tracking)
CREATE TABLE version_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL UNIQUE,
    current_version TEXT,
    latest_version TEXT,
    probe_strategy TEXT,                   -- 'manager', 'direct', 'api'
    probe_duration_ms INTEGER,             -- How long probe took
    last_probed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    probe_success BOOLEAN NOT NULL,
    error_message TEXT
);

-- Package manager operation log
CREATE TABLE manager_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_type TEXT NOT NULL,          -- 'install', 'update', 'remove'
    manager_type TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    package_id TEXT,
    command_executed TEXT NOT NULL,        -- Exact command run
    exit_code INTEGER,
    duration_ms INTEGER,
    stdout TEXT,
    stderr TEXT,
    success BOOLEAN NOT NULL,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 📋 Implementation Phases

### **Phase 1: Package Manager Detection & Version Probing** (Week 1)
**Priority: CRITICAL** - Foundation for everything

#### Goals:
- Detect available package managers on system
- Implement timeout-bounded version probing
- Create semver comparison engine
- Build manager priority selection logic

#### Tasks:

1. **Package Manager Detection** (`src-tauri/src/tools/package_managers/mod.rs`)
   ```rust
   pub trait PackageManager: Send + Sync {
       fn name(&self) -> &str;
       async fn is_available(&self) -> Result<bool>;
       async fn get_version(&self) -> Result<String>;
       async fn search(&self, query: &str) -> Result<Vec<PackageInfo>>;
       async fn list_installed(&self) -> Result<Vec<InstalledPackage>>;
       async fn list_upgradable(&self) -> Result<Vec<UpgradablePackage>>;
       async fn install(&self, package_id: &str, version: Option<&str>) -> Result<OperationResult>;
       async fn upgrade(&self, package_id: &str) -> Result<OperationResult>;
       async fn remove(&self, package_id: &str, options: RemoveOptions) -> Result<OperationResult>;
   }
   
   pub struct PackageManagerRegistry {
       managers: Vec<Box<dyn PackageManager>>,
       detected: Arc<RwLock<HashMap<String, ManagerInfo>>>,
   }
   
   impl PackageManagerRegistry {
       pub async fn detect_all(&self) -> Result<Vec<ManagerInfo>> {
           let mut detected = Vec::new();
           
           for manager in &self.managers {
               if manager.is_available().await? {
                   let version = manager.get_version().await.ok();
                   detected.push(ManagerInfo {
                       name: manager.name().to_string(),
                       version,
                       available: true,
                   });
               }
           }
           
           // Cache results
           let mut cache = self.detected.write().await;
           for info in &detected {
               cache.insert(info.name.clone(), info.clone());
           }
           
           Ok(detected)
       }
       
       pub fn select_best_manager(&self, tool: &ToolMetadata, os: Os) 
           -> Option<&dyn PackageManager> {
           let packages = match os {
               Os::Windows => &tool.windows_packages,
               Os::Linux => &tool.linux_packages,
               Os::MacOS => &tool.macos_packages,
           };
           
           // Sort by priority and check availability
           packages.iter()
               .sorted_by_key(|p| p.priority)
               .find_map(|pkg| {
                   self.managers.iter()
                       .find(|m| m.name() == pkg.manager.name())
                       .filter(|m| self.is_manager_available(m.name()))
               })
       }
   }
   ```

2. **WinGet Implementation** (`src-tauri/src/tools/package_managers/windows/winget.rs`)
   ```rust
   pub struct WinGetManager;
   
   #[async_trait]
   impl PackageManager for WinGetManager {
       fn name(&self) -> &str { "winget" }
       
       async fn is_available(&self) -> Result<bool> {
           Command::new("winget").arg("--version")
               .output().await
               .map(|o| o.status.success())
               .unwrap_or(false)
       }
       
       async fn list_upgradable(&self) -> Result<Vec<UpgradablePackage>> {
           // Parse output of: winget list --upgrade-available
           let output = timeout(
               Duration::from_secs(30),
               Command::new("winget")
                   .args(&["list", "--upgrade-available"])
                   .output()
           ).await??;
           
           let stdout = String::from_utf8_lossy(&output.stdout);
           self.parse_winget_list(&stdout)
       }
       
       async fn upgrade(&self, package_id: &str) -> Result<OperationResult> {
           eprintln!("⬆️  Upgrading {} via WinGet...", package_id);
           
           let output = Command::new("winget")
               .args(&["upgrade", "--id", package_id, "--silent"])
               .output()
               .await?;
           
           if output.status.success() {
               Ok(OperationResult::success(
                   format!("Upgraded {} via WinGet", package_id)
               ))
           } else {
               Err(format!("WinGet upgrade failed: {}", 
                   String::from_utf8_lossy(&output.stderr)).into())
           }
       }
   }
   ```

3. **APT Implementation** (`src-tauri/src/tools/package_managers/linux/apt.rs`)
   ```rust
   pub struct AptManager;
   
   #[async_trait]
   impl PackageManager for AptManager {
       fn name(&self) -> &str { "apt" }
       
       async fn is_available(&self) -> Result<bool> {
           // Check if we're on Debian/Ubuntu
           tokio::fs::metadata("/etc/apt/sources.list").await.is_ok()
       }
       
       async fn list_upgradable(&self) -> Result<Vec<UpgradablePackage>> {
           // First update package lists
           Command::new("sudo")
               .args(&["apt", "update"])
               .output()
               .await?;
           
           // Then list upgradable
           let output = timeout(
               Duration::from_secs(30),
               Command::new("apt")
                   .args(&["list", "--upgradable"])
                   .output()
           ).await??;
           
           let stdout = String::from_utf8_lossy(&output.stdout);
           self.parse_apt_list(&stdout)
       }
       
       async fn remove(&self, package_id: &str, options: RemoveOptions) 
           -> Result<OperationResult> {
           let action = if options.purge { "purge" } else { "remove" };
           
           eprintln!("🗑️  Removing {} via APT ({})", package_id, action);
           
           let mut cmd = Command::new("sudo");
           cmd.args(&["apt", action, "-y", package_id]);
           
           let output = cmd.output().await?;
           
           if output.status.success() {
               // Optionally run autoremove
               if options.autoremove {
                   Command::new("sudo")
                       .args(&["apt", "autoremove", "-y"])
                       .output()
                       .await?;
               }
               
               Ok(OperationResult::success(
                   format!("Removed {} via APT", package_id)
               ))
           } else {
               Err(format!("APT remove failed: {}", 
                   String::from_utf8_lossy(&output.stderr)).into())
           }
       }
   }
   ```

4. **Pipx Implementation** (`src-tauri/src/tools/package_managers/language/pipx.rs`)
   ```rust
   pub struct PipxManager;
   
   #[async_trait]
   impl PackageManager for PipxManager {
       fn name(&self) -> &str { "pipx" }
       
       async fn is_available(&self) -> Result<bool> {
           Command::new("pipx").arg("--version")
               .output().await
               .map(|o| o.status.success())
               .unwrap_or(false)
       }
       
       async fn list_installed(&self) -> Result<Vec<InstalledPackage>> {
           let output = Command::new("pipx")
               .arg("list")
               .output()
               .await?;
           
           let stdout = String::from_utf8_lossy(&output.stdout);
           self.parse_pipx_list(&stdout)
       }
       
       async fn upgrade(&self, package_id: &str) -> Result<OperationResult> {
           eprintln!("⬆️  Upgrading {} via pipx...", package_id);
           
           let output = Command::new("pipx")
               .args(&["upgrade", package_id])
               .output()
               .await?;
           
           if output.status.success() {
               Ok(OperationResult::success(
                   format!("Upgraded {} via pipx", package_id)
               ))
           } else {
               Err(format!("pipx upgrade failed: {}", 
                   String::from_utf8_lossy(&output.stderr)).into())
           }
       }
       
       // Convenience: upgrade all pipx packages
       pub async fn upgrade_all(&self) -> Result<OperationResult> {
           eprintln!("⬆️  Upgrading all pipx packages...");
           
           let output = Command::new("pipx")
               .arg("upgrade-all")
               .output()
               .await?;
           
           Ok(OperationResult::from_output(output))
       }
   }
   ```

5. **Version Probing with Timeout** (`src-tauri/src/tools/version/probe.rs`)
   ```rust
   pub struct VersionProbe {
       timeout_ms: u64,
   }
   
   impl VersionProbe {
       pub async fn probe_tool_version(&self, tool: &ToolMetadata) 
           -> Result<ProbeResult> {
           
           // Strategy 1: Ask package manager first (most reliable)
           if let Some(version) = self.probe_via_manager(tool).await? {
               return Ok(ProbeResult::success(version, "manager"));
           }
           
           // Strategy 2: Direct version command with timeout
           for cmd_args in &tool.version_command {
               match self.probe_direct(tool.name, cmd_args).await {
                   Ok(version) => return Ok(ProbeResult::success(version, "direct")),
                   Err(e) => eprintln!("⚠️  Direct probe failed: {}", e),
               }
           }
           
           // Strategy 3: GitHub Releases API (fallback)
           if let Some(version) = self.probe_via_github(tool).await? {
               return Ok(ProbeResult::success(version, "github"));
           }
           
           Ok(ProbeResult::unknown())
       }
       
       async fn probe_direct(&self, tool_name: &str, args: &[String]) 
           -> Result<String> {
           
           eprintln!("🔍 Probing {} version with timeout {}ms...", 
               tool_name, self.timeout_ms);
           
           let output = timeout(
               Duration::from_millis(self.timeout_ms),
               Command::new(tool_name).args(args).output()
           ).await
               .map_err(|_| format!("Version probe timed out after {}ms", self.timeout_ms))??;
           
           if !output.status.success() {
               return Err("Version command failed".into());
           }
           
           let stdout = String::from_utf8_lossy(&output.stdout);
           let stderr = String::from_utf8_lossy(&output.stderr);
           
           // Try to extract version from stdout, then stderr
           self.extract_version(&stdout)
               .or_else(|| self.extract_version(&stderr))
               .ok_or("Could not parse version from output".into())
       }
       
       fn extract_version(&self, text: &str) -> Option<String> {
           // Common patterns: v1.2.3, 1.2.3, version 1.2.3
           let patterns = vec![
               r"(?:version|v)?\s*(\d+\.\d+\.\d+(?:-\w+)?)",
               r"(\d+\.\d+\.\d+)",
           ];
           
           for pattern in patterns {
               if let Ok(re) = regex::Regex::new(pattern) {
                   if let Some(cap) = re.captures(text) {
                       return cap.get(1).map(|m| m.as_str().to_string());
                   }
               }
           }
           
           None
       }
   }
   
   pub struct ProbeResult {
       pub version: Option<String>,
       pub strategy: String,              // 'manager', 'direct', 'github', 'unknown'
       pub duration_ms: u64,
       pub success: bool,
   }
   ```

6. **Semver Comparison** (`src-tauri/src/tools/version/semver.rs`)
   ```rust
   use semver::{Version, VersionReq};
   
   pub struct VersionComparer;
   
   impl VersionComparer {
       pub fn compare(current: &str, latest: &str) -> Result<VersionStatus> {
           let current_ver = self.parse_version(current)?;
           let latest_ver = self.parse_version(latest)?;
           
           if latest_ver > current_ver {
               let severity = self.calculate_severity(&current_ver, &latest_ver);
               Ok(VersionStatus::Outdated { 
                   current: current.to_string(),
                   latest: latest.to_string(),
                   severity,
               })
           } else if latest_ver == current_ver {
               Ok(VersionStatus::Latest { 
                   version: current.to_string() 
               })
           } else {
               Ok(VersionStatus::Ahead {
                   version: current.to_string(),
                   note: "Running development/beta version".to_string(),
               })
           }
       }
       
       fn calculate_severity(&self, current: &Version, latest: &Version) 
           -> UpdateSeverity {
           
           if latest.major > current.major {
               UpdateSeverity::Major  // Breaking changes likely
           } else if latest.minor > current.minor {
               UpdateSeverity::Minor  // New features
           } else {
               UpdateSeverity::Patch  // Bug fixes only
           }
       }
       
       pub fn satisfies_requirement(&self, version: &str, requirement: &str) 
           -> Result<bool> {
           
           let ver = Version::parse(version)?;
           let req = VersionReq::parse(requirement)?;
           Ok(req.matches(&ver))
       }
   }
   
   pub enum VersionStatus {
       Latest { version: String },
       Outdated { current: String, latest: String, severity: UpdateSeverity },
       Ahead { version: String, note: String },
       Unknown,
   }
   
   pub enum UpdateSeverity {
       Patch,   // 1.2.3 -> 1.2.4 (green)
       Minor,   // 1.2.3 -> 1.3.0 (orange)
       Major,   // 1.2.3 -> 2.0.0 (red)
   }
   ```

7. **Tauri Commands**
   ```rust
   #[tauri::command]
   async fn detect_package_managers(state: State<'_, AppState>) 
       -> Result<Vec<ManagerInfo>, String> {
       let registry = &state.package_manager_registry;
       registry.detect_all().await
           .map_err(|e| e.to_string())
   }
   
   #[tauri::command]
   async fn probe_tool_versions(
       tool_names: Vec<String>,
       state: State<'_, AppState>
   ) -> Result<HashMap<String, ProbeResult>, String> {
       let prober = &state.version_probe;
       let catalog = &state.tool_catalog;
       
       let mut results = HashMap::new();
       
       for name in tool_names {
           if let Some(tool) = catalog.get_tool(&name) {
               match prober.probe_tool_version(tool).await {
                   Ok(result) => { results.insert(name, result); }
                   Err(e) => eprintln!("Failed to probe {}: {}", name, e),
               }
           }
       }
       
       Ok(results)
   }
   
   #[tauri::command]
   async fn check_for_updates(state: State<'_, AppState>) 
       -> Result<Vec<UpdateInfo>, String> {
       // Use package manager's list-upgradable when available
       let registry = &state.package_manager_registry;
       let mut updates = Vec::new();
       
       for manager in registry.available_managers().await {
           match manager.list_upgradable().await {
               Ok(upgradable) => {
                   for pkg in upgradable {
                       updates.push(UpdateInfo {
                           tool_name: pkg.name,
                           current_version: pkg.current_version,
                           latest_version: pkg.available_version,
                           manager: manager.name().to_string(),
                       });
                   }
               }
               Err(e) => eprintln!("Failed to list upgradable for {}: {}", 
                   manager.name(), e),
           }
       }
       
       Ok(updates)
   }
   ```

**Testing Phase 1:**
- Test manager detection on Windows (WinGet/Choco/Scoop)
- Test manager detection on Linux (APT/DNF/pacman/Homebrew)
- Test version probing with various timeout scenarios
- Verify semver comparison accuracy
- Benchmark probe performance (should be <5s per tool)

---

### **Phase 2: Installation System with Manager Integration** (Week 2-3)
**Priority: HIGH** - Core feature leveraging native package managers

#### Goals:
- Implement manager-first installation flow
- Support all major package managers per platform
- Preview commands before execution
- Stream installation output in real-time
- Handle elevation (sudo/admin) transparently

#### Tasks:

1. **Installation Orchestrator** (`src-tauri/src/tools/installer.rs`)
   ```rust
   pub struct ToolInstaller {
       manager_registry: Arc<PackageManagerRegistry>,
       db: Arc<Database>,
       event_emitter: Arc<EventEmitter>,
   }
   
   impl ToolInstaller {
       pub async fn install_tool(&self, tool_name: &str, options: InstallOptions) 
           -> Result<InstallResult> {
           
           eprintln!("📥 Starting installation of {}...", tool_name);
           
           // 1. Get tool metadata
           let metadata = self.get_tool_metadata(tool_name)?;
           
           // 2. Check if already installed
           if self.is_installed(tool_name).await? && !options.force {
               return Err(format!("{} is already installed. Use update or --force", 
                   tool_name).into());
           }
           
           // 3. Select best package manager for this tool
           let os = self.detect_os();
           let manager = self.manager_registry
               .select_best_manager(&metadata, os)
               .ok_or("No suitable package manager found")?;
           
           let package_source = self.get_package_source(&metadata, manager.name())?;
           
           eprintln!("✅ Selected {} for installation", manager.name());
           
           // 4. Check dependencies
           if !options.skip_dependencies {
               self.install_dependencies(&metadata).await?;
           }
           
           // 5. Preview command (if requested)
           if options.preview {
               let command = self.build_install_command(manager, &package_source);
               eprintln!("📋 Would execute: {}", command);
               return Ok(InstallResult::preview(command));
           }
           
           // 6. Execute installation
           self.event_emitter.emit("install:started", json!({
               "tool": tool_name,
               "manager": manager.name(),
           }));
           
           let start = Instant::now();
           
           let result = manager.install(
               &package_source.package_id, 
               options.version.as_deref()
           ).await?;
           
           let duration = start.elapsed();
           
           // 7. Verify installation
           let installed_version = self.verify_installation(tool_name).await?;
           
           // 8. Record in database
           self.db.record_installation(InstallationRecord {
               tool_name: tool_name.to_string(),
               version: installed_version.clone(),
               manager_type: manager.name().to_string(),
               package_id: package_source.package_id.clone(),
               install_path: self.get_tool_path(tool_name).await?,
               metadata: Some(json!({
                   "duration_ms": duration.as_millis(),
                   "size_mb": self.estimate_size(tool_name).await,
               })),
           }).await?;
           
           // 9. Emit success event
           self.event_emitter.emit("install:complete", json!({
               "tool": tool_name,
               "version": installed_version,
               "duration_ms": duration.as_millis(),
           }));
           
           eprintln!("🎉 Successfully installed {} v{}", tool_name, installed_version);
           
           Ok(InstallResult {
               success: true,
               version: installed_version,
               manager: manager.name().to_string(),
               duration_ms: duration.as_millis() as u64,
               output: result.output,
           })
       }
       
       async fn install_dependencies(&self, metadata: &ToolMetadata) -> Result<()> {
           if metadata.dependencies.is_empty() {
               return Ok(());
           }
           
           eprintln!("📦 Installing {} dependencies...", metadata.dependencies.len());
           
           for dep in &metadata.dependencies {
               if !self.is_installed(dep).await? {
                   eprintln!("  ⬇️  Installing dependency: {}", dep);
                   self.install_tool(dep, InstallOptions::default()).await?;
               } else {
                   eprintln!("  ✅ Dependency already installed: {}", dep);
               }
           }
           
           Ok(())
       }
   }
   
   pub struct InstallOptions {
       pub version: Option<String>,
       pub force: bool,                   // Reinstall if exists
       pub preview: bool,                 // Just show command, don't execute
       pub skip_dependencies: bool,
       pub prefer_manager: Option<String>, // Force specific manager
   }
   ```

2. **Command Preview System**
   ```rust
   pub struct CommandPreview {
       pub command: String,
       pub args: Vec<String>,
       pub requires_elevation: bool,
       pub manager: String,
       pub estimated_duration_sec: u64,
       pub estimated_size_mb: Option<u64>,
   }
   
   impl CommandPreview {
       pub fn format_for_display(&self) -> String {
           let elevation = if self.requires_elevation {
               if cfg!(windows) { "Administrator: " } else { "sudo " }
           } else {
               ""
           };
           
           format!("{}{} {}", 
               elevation,
               self.command,
               self.args.join(" ")
           )
       }
   }
   ```

3. **Real-Time Output Streaming**
   ```rust
   pub struct StreamingExecutor;
   
   impl StreamingExecutor {
       pub async fn execute_with_streaming(
           &self,
           command: &str,
           args: &[String],
           event_emitter: &EventEmitter,
           tool_name: &str,
       ) -> Result<OperationResult> {
           
           let mut child = Command::new(command)
               .args(args)
               .stdout(Stdio::piped())
               .stderr(Stdio::piped())
               .spawn()?;
           
           let stdout = child.stdout.take().unwrap();
           let stderr = child.stderr.take().unwrap();
           
           // Stream stdout
           let event_emitter_clone = event_emitter.clone();
           let tool_name_clone = tool_name.to_string();
           tokio::spawn(async move {
               let reader = BufReader::new(stdout);
               let mut lines = reader.lines();
               
               while let Some(line) = lines.next_line().await.ok().flatten() {
                   event_emitter_clone.emit("install:stdout", json!({
                       "tool": tool_name_clone,
                       "line": line,
                   }));
               }
           });
           
           // Stream stderr
           let event_emitter_clone = event_emitter.clone();
           let tool_name_clone = tool_name.to_string();
           tokio::spawn(async move {
               let reader = BufReader::new(stderr);
               let mut lines = reader.lines();
               
               while let Some(line) = lines.next_line().await.ok().flatten() {
                   event_emitter_clone.emit("install:stderr", json!({
                       "tool": tool_name_clone,
                       "line": line,
                   }));
               }
           });
           
           // Wait for completion
           let status = child.wait().await?;
           
           Ok(OperationResult {
               success: status.success(),
               exit_code: status.code(),
               output: String::new(), // Already streamed
           })
       }
   }
   ```

4. **Platform-Specific Tool Registry** (`src-tauri/src/tools/catalog_extended.rs`)
   ```rust
   // Example tool definitions
   pub fn get_extended_catalog() -> HashMap<String, ToolMetadata> {
       let mut catalog = HashMap::new();
       
       // Subfinder
       catalog.insert("subfinder".to_string(), ToolMetadata {
           name: "subfinder".to_string(),
           description: "Fast passive subdomain enumeration tool".to_string(),
           homepage: "https://github.com/projectdiscovery/subfinder".to_string(),
           repository: "https://github.com/projectdiscovery/subfinder".to_string(),
           
           version_command: vec!["--version".to_string()],
           version_regex: r"(\d+\.\d+\.\d+)".to_string(),
           version_timeout_ms: 5000,
           
           windows_packages: vec![
               PackageSource {
                   manager: PackageManager::WinGet,
                   package_id: "ProjectDiscovery.subfinder".to_string(),
                   priority: 0,
                   requires_elevation: false,
                   notes: None,
               },
               PackageSource {
                   manager: PackageManager::GoInstall,
                   package_id: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder".to_string(),
                   priority: 1,
                   requires_elevation: false,
                   notes: Some("Requires Go installed".to_string()),
               },
           ],
           
           linux_packages: vec![
               PackageSource {
                   manager: PackageManager::Apt,
                   package_id: "subfinder".to_string(),
                   priority: 0,
                   requires_elevation: true,
                   notes: Some("May not be in default repos".to_string()),
               },
               PackageSource {
                   manager: PackageManager::GoInstall,
                   package_id: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder".to_string(),
                   priority: 1,
                   requires_elevation: false,
                   notes: None,
               },
           ],
           
           macos_packages: vec![
               PackageSource {
                   manager: PackageManager::Homebrew,
                   package_id: "subfinder".to_string(),
                   priority: 0,
                   requires_elevation: false,
                   notes: None,
               },
           ],
           
           min_version: Some("2.5.0".to_string()),
           recommended_version: Some("2.6.6".to_string()),
           tags: vec!["subdomain".to_string(), "recon".to_string()],
           dependencies: vec![],
           size_estimate_mb: Some(15),
       });
       
       // Nuclei
       catalog.insert("nuclei".to_string(), ToolMetadata {
           name: "nuclei".to_string(),
           description: "Fast vulnerability scanner powered by templates".to_string(),
           homepage: "https://github.com/projectdiscovery/nuclei".to_string(),
           repository: "https://github.com/projectdiscovery/nuclei".to_string(),
           
           version_command: vec!["--version".to_string()],
           version_regex: r"(\d+\.\d+\.\d+)".to_string(),
           version_timeout_ms: 5000,
           
           windows_packages: vec![
               PackageSource {
                   manager: PackageManager::WinGet,
                   package_id: "ProjectDiscovery.nuclei".to_string(),
                   priority: 0,
                   requires_elevation: false,
                   notes: None,
               },
               PackageSource {
                   manager: PackageManager::GoInstall,
                   package_id: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei".to_string(),
                   priority: 1,
                   requires_elevation: false,
                   notes: None,
               },
           ],
           
           linux_packages: vec![
               PackageSource {
                   manager: PackageManager::GoInstall,
                   package_id: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei".to_string(),
                   priority: 0,
                   requires_elevation: false,
                   notes: None,
               },
           ],
           
           macos_packages: vec![
               PackageSource {
                   manager: PackageManager::Homebrew,
                   package_id: "nuclei".to_string(),
                   priority: 0,
                   requires_elevation: false,
                   notes: None,
               },
           ],
           
           min_version: Some("3.0.0".to_string()),
           recommended_version: Some("3.3.6".to_string()),
           tags: vec!["vulnerability".to_string(), "scanner".to_string()],
           dependencies: vec![],
           size_estimate_mb: Some(50),
       });
       
       // SQLMap (Python/pipx)
       catalog.insert("sqlmap".to_string(), ToolMetadata {
           name: "sqlmap".to_string(),
           description: "Automatic SQL injection and database takeover tool".to_string(),
           homepage: "https://sqlmap.org/".to_string(),
           repository: "https://github.com/sqlmapproject/sqlmap".to_string(),
           
           version_command: vec!["--version".to_string()],
           version_regex: r"(\d+\.\d+)".to_string(),
           version_timeout_ms: 5000,
           
           windows_packages: vec![
               PackageSource {
                   manager: PackageManager::Pipx,
                   package_id: "sqlmap".to_string(),
                   priority: 0,
                   requires_elevation: false,
                   notes: Some("Installs isolated Python environment".to_string()),
               },
               PackageSource {
                   manager: PackageManager::WinGet,
                   package_id: "sqlmap".to_string(),
                   priority: 1,
                   requires_elevation: false,
                   notes: None,
               },
           ],
           
           linux_packages: vec![
               PackageSource {
                   manager: PackageManager::Apt,
                   package_id: "sqlmap".to_string(),
                   priority: 0,
                   requires_elevation: true,
                   notes: None,
               },
               PackageSource {
                   manager: PackageManager::Pipx,
                   package_id: "sqlmap".to_string(),
                   priority: 1,
                   requires_elevation: false,
                   notes: None,
               },
           ],
           
           macos_packages: vec![
               PackageSource {
                   manager: PackageManager::Homebrew,
                   package_id: "sqlmap".to_string(),
                   priority: 0,
                   requires_elevation: false,
                   notes: None,
               },
           ],
           
           min_version: Some("1.7.0".to_string()),
           recommended_version: Some("1.8.12".to_string()),
           tags: vec!["sql".to_string(), "injection".to_string(), "database".to_string()],
           dependencies: vec!["python".to_string()],
           size_estimate_mb: Some(25),
       });
       
       // ... (Add all 57 tools)
       
       catalog
   }
   ```

5. **Tauri Commands**
   ```rust
   #[tauri::command]
   async fn install_tool(
       tool_name: String,
       options: InstallOptions,
       state: State<'_, AppState>
   ) -> Result<InstallResult, String> {
       state.tool_installer.install_tool(&tool_name, options).await
           .map_err(|e| e.to_string())
   }
   
   #[tauri::command]
   async fn preview_install_command(
       tool_name: String,
       state: State<'_, AppState>
   ) -> Result<CommandPreview, String> {
       let metadata = state.tool_catalog.get_tool(&tool_name)
           .ok_or("Tool not found")?;
       
       let os = detect_os();
       let manager = state.package_manager_registry
           .select_best_manager(&metadata, os)
           .ok_or("No suitable package manager")?;
       
       let package_source = get_package_source(&metadata, manager.name())?;
       
       Ok(CommandPreview {
           command: manager.get_install_command(),
           args: vec![package_source.package_id],
           requires_elevation: package_source.requires_elevation,
           manager: manager.name().to_string(),
           estimated_duration_sec: 60,
           estimated_size_mb: metadata.size_estimate_mb,
       })
   }
   
   #[tauri::command]
   async fn get_tool_install_sources(
       tool_name: String,
       state: State<'_, AppState>
   ) -> Result<Vec<InstallSourceInfo>, String> {
       let metadata = state.tool_catalog.get_tool(&tool_name)
           .ok_or("Tool not found")?;
       
       let os = detect_os();
       let packages = match os {
           Os::Windows => &metadata.windows_packages,
           Os::Linux => &metadata.linux_packages,
           Os::MacOS => &metadata.macos_packages,
       };
       
       let mut sources = Vec::new();
       
       for pkg in packages {
           let available = state.package_manager_registry
               .is_manager_available(&pkg.manager.name());
           
           sources.push(InstallSourceInfo {
               manager: pkg.manager.name(),
               package_id: pkg.package_id.clone(),
               priority: pkg.priority,
               available,
               requires_elevation: pkg.requires_elevation,
               notes: pkg.notes.clone(),
           });
       }
       
       // Sort by priority
       sources.sort_by_key(|s| s.priority);
       
       Ok(sources)
   }
   ```

**Testing Phase 2:**
- Test install on Windows with WinGet/Choco/Scoop
- Test install on Linux with APT/DNF/pacman
- Test pipx installs for Python tools
- Test go install for Go tools
- Verify command preview accuracy
- Test real-time output streaming
- Test dependency installation
- Verify database recording

---
**Priority: HIGH** - Core feature for beginners

#### Tasks:

1. **Package Manager Abstraction** (`src-tauri/src/tools/package_managers/`)
   
   **Go Installer** (`go.rs`):
   ```rust
   pub struct GoInstaller;
   
   impl PackageInstaller for GoInstaller {
       async fn install(&self, package: &str, version: Option<&str>) -> Result<InstallResult> {
           let cmd = if let Some(v) = version {
               format!("go install {}@{}", package, v)
           } else {
               format!("go install {}@latest", package)
           };
           
           // Execute with progress tracking
           self.execute_with_progress(cmd).await
       }
       
       async fn is_available(&self) -> bool {
           Command::new("go").arg("version").output().await.is_ok()
       }
   }
   ```

   **Pip Installer** (`pip.rs`):
   ```rust
   pub struct PipInstaller;
   
   impl PackageInstaller for PipInstaller {
       async fn install(&self, package: &str, version: Option<&str>) -> Result<InstallResult> {
           // Prefer pipx for isolated installs
           let installer = if self.has_pipx().await { "pipx" } else { "pip" };
           
           let cmd = match version {
               Some(v) => format!("{} install {}=={}", installer, package, v),
               None => format!("{} install {}", installer, package),
           };
           
           self.execute_with_progress(cmd).await
       }
   }
   ```

   **Cargo Installer** (`cargo.rs`):
   ```rust
   pub struct CargoInstaller;
   
   impl PackageInstaller for CargoInstaller {
       async fn install(&self, crate_name: &str, version: Option<&str>) -> Result<InstallResult> {
           let cmd = if let Some(v) = version {
               format!("cargo install {} --version {}", crate_name, v)
           } else {
               format!("cargo install {}", crate_name)
           };
           
           self.execute_with_progress(cmd).await
       }
   }
   ```

   **Binary Installer** (`binary.rs`):
   ```rust
   pub struct BinaryInstaller;
   
   impl PackageInstaller for BinaryInstaller {
       async fn install(&self, tool: &ToolMetadata) -> Result<InstallResult> {
           // 1. Detect OS and architecture
           let os = std::env::consts::OS;
           let arch = std::env::consts::ARCH;
           
           // 2. Get download URL for this platform
           let url = self.get_download_url(tool, os, arch).await?;
           
           // 3. Download to temp location
           let temp_file = self.download_with_progress(url).await?;
           
           // 4. Extract if archive (.zip, .tar.gz)
           let binary = self.extract_binary(temp_file).await?;
           
           // 5. Move to installation directory
           let install_path = self.get_install_dir()?;
           self.install_binary(binary, install_path).await?;
           
           // 6. Make executable (Unix)
           #[cfg(unix)]
           self.make_executable(&install_path).await?;
           
           Ok(InstallResult::success())
       }
   }
   ```

2. **Main Tool Manager** (`src-tauri/src/tools/manager.rs`)
   ```rust
   pub struct ToolManager {
       db: Arc<Database>,
       installers: HashMap<String, Box<dyn PackageInstaller>>,
       catalog: ToolCatalog,
   }
   
   impl ToolManager {
       pub async fn install_tool(&self, tool_name: &str, version: Option<&str>) 
           -> Result<InstallProgress> {
           
           // 1. Get tool metadata from catalog
           let metadata = self.catalog.get_tool_metadata(tool_name)?;
           
           // 2. Check if already installed
           if self.is_installed(tool_name).await? {
               return Err("Tool already installed. Use update instead.".into());
           }
           
           // 3. Select installation method (prefer order: package manager, binary, source)
           let install_method = self.select_best_install_method(&metadata)?;
           
           // 4. Check dependencies
           let deps = self.check_dependencies(&metadata).await?;
           if !deps.are_satisfied() {
               // Offer to install dependencies
               self.install_dependencies(deps).await?;
           }
           
           // 5. Execute installation
           let installer = self.get_installer(&install_method)?;
           let result = installer.install(&metadata.package_name, version).await?;
           
           // 6. Verify installation
           let installed_version = self.verify_installation(tool_name).await?;
           
           // 7. Record in database
           self.db.record_installation(tool_name, &installed_version, &install_method).await?;
           
           // 8. Update cache
           self.refresh_tool_cache(tool_name).await?;
           
           Ok(result)
       }
   }
   ```

3. **Installation Progress Tracking**
   ```rust
   #[derive(Clone, Serialize)]
   pub struct InstallProgress {
       pub stage: InstallStage,
       pub percent: u8,
       pub message: String,
       pub can_cancel: bool,
   }
   
   #[derive(Clone, Serialize)]
   pub enum InstallStage {
       Preparing,          // 0-10%
       CheckingDeps,       // 10-20%
       Downloading,        // 20-60%
       Installing,         // 60-90%
       Verifying,          // 90-95%
       Complete,           // 100%
       Failed { error: String },
   }
   ```

4. **Tauri Commands**
   ```rust
   #[tauri::command]
   async fn install_tool(
       tool_name: String,
       version: Option<String>,
       state: State<'_, AppState>
   ) -> Result<(), String>
   
   #[tauri::command]
   async fn get_install_methods(tool_name: String) -> Result<Vec<InstallMethod>, String>
   
   #[tauri::command]
   async fn can_install_tool(tool_name: String) -> Result<InstallCapability, String>
   ```

5. **Frontend Components**

   **InstallModal.tsx**:
   ```tsx
   interface InstallModalProps {
     tool: Tool
     onClose: () => void
     onSuccess: () => void
   }
   
   const InstallModal = ({ tool, onClose, onSuccess }: InstallModalProps) => {
     const [installMethod, setInstallMethod] = useState<InstallMethod>()
     const [progress, setProgress] = useState<InstallProgress>()
     const [installing, setInstalling] = useState(false)
     
     // Listen to installation progress events
     useEffect(() => {
       const unlisten = listen('install:progress', (event) => {
         setProgress(event.payload)
       })
       return () => { unlisten.then(fn => fn()) }
     }, [])
     
     const handleInstall = async () => {
       setInstalling(true)
       try {
         await invoke('install_tool', { 
           toolName: tool.name,
           installMethod 
         })
         onSuccess()
       } catch (error) {
         showError(`Failed to install ${tool.name}: ${error}`)
       } finally {
         setInstalling(false)
       }
     }
     
     return (
       <Modal>
         <div className="install-modal">
           <h2>Install {tool.name}</h2>
           
           {/* Installation method selection */}
           <InstallMethodSelector 
             tool={tool}
             selected={installMethod}
             onChange={setInstallMethod}
           />
           
           {/* Progress bar */}
           {installing && (
             <ProgressBar 
               stage={progress?.stage}
               percent={progress?.percent}
               message={progress?.message}
             />
           )}
           
           {/* Action buttons */}
           <div className="actions">
             <button onClick={onClose} disabled={installing}>
               Cancel
             </button>
             <button 
               onClick={handleInstall} 
               disabled={!installMethod || installing}
               className="primary"
             >
               {installing ? 'Installing...' : 'Install'}
             </button>
           </div>
         </div>
       </Modal>
     )
   }
   ```

   **Update ToolDetailModal.tsx**:
   ```tsx
   // Add install button
   {!tool.installed && (
     <button 
       onClick={() => setShowInstallModal(true)}
       className="btn-primary"
     >
       <DownloadIcon /> Install Tool
     </button>
   )}
   
   {showInstallModal && (
     <InstallModal 
       tool={tool}
       onClose={() => setShowInstallModal(false)}
       onSuccess={handleInstallSuccess}
     />
   )}
   ```

**Testing:**
- Test installation on Windows 11 and Linux (Ubuntu/Debian)
- Test all 57 tools across different install methods
- Handle failures gracefully (no Go installed, no sudo, disk space)
- Progress tracking accuracy
- Rollback on failure

---

### **Phase 3: Update System** (Week 4)
**Priority: MEDIUM** - Keeps tools current

#### Tasks:

1. **Update Checker** (`src-tauri/src/tools/updater.rs`)
   ```rust
   pub struct ToolUpdater;
   
   impl ToolUpdater {
       pub async fn check_updates(&self, tool_name: &str) -> Result<UpdateInfo> {
           let current = self.get_installed_version(tool_name).await?;
           let latest = self.get_latest_version(tool_name).await?;
           
           let is_outdated = self.compare_versions(&current, &latest)?;
           
           if is_outdated {
               let changelog = self.fetch_changelog(tool_name, &current, &latest).await?;
               
               Ok(UpdateInfo {
                   current_version: current,
                   latest_version: latest,
                   changelog,
                   severity: self.calculate_update_severity(&current, &latest),
               })
           } else {
               Ok(UpdateInfo::up_to_date(current))
           }
       }
       
       pub async fn update_tool(&self, tool_name: &str, to_version: Option<&str>) 
           -> Result<UpdateResult> {
           
           // 1. Backup current installation
           let backup = self.create_backup(tool_name).await?;
           
           // 2. Uninstall current version
           self.uninstaller.uninstall(tool_name).await?;
           
           // 3. Install new version
           match self.installer.install(tool_name, to_version).await {
               Ok(result) => {
                   // Success - remove backup
                   self.remove_backup(backup).await?;
                   
                   // Record update
                   self.db.record_update(tool_name, &result.version).await?;
                   
                   Ok(UpdateResult::success(result.version))
               }
               Err(e) => {
                   // Failure - restore backup
                   self.restore_backup(backup).await?;
                   Err(e)
               }
           }
       }
       
       pub async fn batch_update(&self, tools: Vec<&str>) -> Result<BatchUpdateResult> {
           let mut results = HashMap::new();
           
           for tool in tools {
               let result = self.update_tool(tool, None).await;
               results.insert(tool.to_string(), result);
           }
           
           Ok(BatchUpdateResult { results })
       }
   }
   ```

2. **Version Comparison**
   ```rust
   pub fn compare_versions(current: &str, latest: &str) -> Result<VersionComparison> {
       use semver::Version;
       
       let current_ver = Version::parse(current)?;
       let latest_ver = Version::parse(latest)?;
       
       if latest_ver > current_ver {
           // Determine severity
           let severity = if latest_ver.major > current_ver.major {
               UpdateSeverity::Major  // Breaking changes
           } else if latest_ver.minor > current_ver.minor {
               UpdateSeverity::Minor  // New features
           } else {
               UpdateSeverity::Patch  // Bug fixes
           };
           
           Ok(VersionComparison::Outdated { severity })
       } else if latest_ver == current_ver {
           Ok(VersionComparison::UpToDate)
       } else {
           Ok(VersionComparison::Ahead)  // Beta/dev version
       }
   }
   ```

3. **Auto-Update System**
   ```rust
   pub struct AutoUpdater {
       config: AutoUpdateConfig,
       scheduler: Scheduler,
   }
   
   impl AutoUpdater {
       pub async fn start(&self) {
           // Check for updates every 24 hours
           self.scheduler.schedule(Duration::hours(24), || {
               self.check_and_notify_updates().await
           });
       }
       
       async fn check_and_notify_updates(&self) {
           let updates = self.check_all_tools().await;
           
           if !updates.is_empty() {
               // Notify user via system notification
               self.send_notification(updates).await;
               
               // If auto-update enabled, update automatically
               if self.config.auto_install_updates {
                   self.batch_update(updates).await;
               }
           }
       }
   }
   ```

4. **Frontend Components**

   **UpdateBadge.tsx**:
   ```tsx
   const UpdateBadge = ({ tool }: { tool: Tool }) => {
     if (!tool.updateAvailable) return null
     
     const severity = tool.updateSeverity
     const color = {
       major: 'red',
       minor: 'orange', 
       patch: 'blue'
     }[severity]
     
     return (
       <span className={`badge badge-${color}`}>
         Update Available: v{tool.latestVersion}
       </span>
     )
   }
   ```

   **UpdateModal.tsx**:
   ```tsx
   const UpdateModal = ({ tool, onClose, onSuccess }) => {
     const [updating, setUpdating] = useState(false)
     const [changelog, setChangelog] = useState('')
     
     useEffect(() => {
       loadChangelog(tool).then(setChangelog)
     }, [tool])
     
     const handleUpdate = async () => {
       setUpdating(true)
       try {
         await invoke('update_tool', { toolName: tool.name })
         success(`${tool.name} updated to v${tool.latestVersion}`)
         onSuccess()
       } catch (error) {
         showError(`Update failed: ${error}`)
       } finally {
         setUpdating(false)
       }
     }
     
     return (
       <Modal>
         <h2>Update {tool.name}</h2>
         <div className="version-info">
           <span>Current: v{tool.version}</span>
           <ArrowRight />
           <span>Latest: v{tool.latestVersion}</span>
         </div>
         
         <div className="changelog">
           <h3>What's New</h3>
           <Markdown>{changelog}</Markdown>
         </div>
         
         <div className="actions">
           <button onClick={onClose} disabled={updating}>
             Cancel
           </button>
           <button onClick={handleUpdate} disabled={updating}>
             {updating ? 'Updating...' : 'Update Now'}
           </button>
         </div>
       </Modal>
     )
   }
   ```

   **Bulk Update UI**:
   ```tsx
   const ToolsToolbar = () => {
     const outdatedTools = tools.filter(t => t.updateAvailable)
     
     return (
       <div className="toolbar">
         {outdatedTools.length > 0 && (
           <button 
             onClick={handleUpdateAll}
             className="btn-primary"
           >
             <UpdateIcon />
             Update All ({outdatedTools.length})
           </button>
         )}
       </div>
     )
   }
   ```

**Testing:**
- Test update for various versions (major, minor, patch)
- Test rollback on failed update
- Test batch updates
- Verify changelog fetching

---

### **Phase 4: Uninstallation System** (Week 5)
**Priority: MEDIUM** - Complete management lifecycle

#### Tasks:

1. **Uninstaller** (`src-tauri/src/tools/uninstaller.rs`)
   ```rust
   pub struct ToolUninstaller {
       db: Arc<Database>,
   }
   
   impl ToolUninstaller {
       pub async fn uninstall_tool(&self, tool_name: &str, clean: bool) 
           -> Result<UninstallResult> {
           
           // 1. Get installation info
           let install_info = self.db.get_installation_info(tool_name).await?;
           
           // 2. Check dependencies (what depends on this tool?)
           let dependents = self.check_dependents(tool_name).await?;
           if !dependents.is_empty() {
               return Err(format!(
                   "Cannot uninstall: {} other tools depend on this", 
                   dependents.len()
               ).into());
           }
           
           // 3. Uninstall based on install method
           match install_info.install_method.as_str() {
               "go" => self.uninstall_go_tool(tool_name).await?,
               "pip" => self.uninstall_pip_tool(tool_name).await?,
               "cargo" => self.uninstall_cargo_tool(tool_name).await?,
               "binary" => self.uninstall_binary(tool_name, &install_info.path).await?,
               _ => return Err("Unknown install method".into()),
           }
           
           // 4. Clean up configuration files if requested
           if clean {
               self.clean_configs(tool_name).await?;
               self.clean_cache(tool_name).await?;
           }
           
           // 5. Record removal
           self.db.record_removal(tool_name, &install_info.version).await?;
           
           // 6. Update tool cache
           self.refresh_tool_cache().await?;
           
           Ok(UninstallResult::success())
       }
       
       async fn uninstall_go_tool(&self, tool_name: &str) -> Result<()> {
           let go_bin = self.get_go_bin_path()?;
           let tool_path = go_bin.join(tool_name);
           
           if tool_path.exists() {
               tokio::fs::remove_file(tool_path).await?;
           }
           
           Ok(())
       }
       
       async fn uninstall_pip_tool(&self, tool_name: &str) -> Result<()> {
           let installer = if self.was_installed_with_pipx(tool_name).await? {
               "pipx"
           } else {
               "pip"
           };
           
           let cmd = format!("{} uninstall -y {}", installer, tool_name);
           self.execute_command(&cmd).await?;
           
           Ok(())
       }
       
       async fn clean_configs(&self, tool_name: &str) -> Result<()> {
           // Remove config files from common locations
           let config_dirs = vec![
               home::home_dir().unwrap().join(".config").join(tool_name),
               home::home_dir().unwrap().join(format!(".{}", tool_name)),
           ];
           
           for dir in config_dirs {
               if dir.exists() {
                   tokio::fs::remove_dir_all(dir).await?;
               }
           }
           
           Ok(())
       }
   }
   ```

2. **Tauri Commands**
   ```rust
   #[tauri::command]
   async fn uninstall_tool(
       tool_name: String,
       clean: bool,
       state: State<'_, AppState>
   ) -> Result<(), String>
   
   #[tauri::command]
   async fn check_uninstall_impact(tool_name: String) -> Result<UninstallImpact, String>
   
   pub struct UninstallImpact {
       pub dependents: Vec<String>,
       pub disk_space_freed: u64,
       pub config_files: Vec<PathBuf>,
   }
   ```

3. **Frontend Components**

   **UninstallModal.tsx**:
   ```tsx
   const UninstallModal = ({ tool, onClose, onSuccess }) => {
     const [impact, setImpact] = useState<UninstallImpact>()
     const [cleanConfigs, setCleanConfigs] = useState(false)
     const [uninstalling, setUninstalling] = useState(false)
     
     useEffect(() => {
       invoke<UninstallImpact>('check_uninstall_impact', { 
         toolName: tool.name 
       }).then(setImpact)
     }, [tool])
     
     const handleUninstall = async () => {
       setUninstalling(true)
       try {
         await invoke('uninstall_tool', { 
           toolName: tool.name,
           clean: cleanConfigs
         })
         success(`${tool.name} uninstalled successfully`)
         onSuccess()
       } catch (error) {
         showError(`Uninstall failed: ${error}`)
       } finally {
         setUninstalling(false)
       }
     }
     
     return (
       <Modal>
         <div className="uninstall-modal">
           <div className="warning-icon">⚠️</div>
           <h2>Uninstall {tool.name}?</h2>
           
           {impact && (
             <div className="impact-info">
               {impact.dependents.length > 0 && (
                 <div className="warning">
                   <strong>Warning:</strong> {impact.dependents.length} tools 
                   depend on this: {impact.dependents.join(', ')}
                 </div>
               )}
               
               <div className="info">
                 <p>Disk space to be freed: {formatBytes(impact.disk_space_freed)}</p>
                 {impact.config_files.length > 0 && (
                   <p>{impact.config_files.length} config files found</p>
                 )}
               </div>
             </div>
           )}
           
           <label className="checkbox">
             <input 
               type="checkbox"
               checked={cleanConfigs}
               onChange={e => setCleanConfigs(e.target.checked)}
             />
             Also remove configuration files and cache
           </label>
           
           <div className="actions">
             <button onClick={onClose} disabled={uninstalling}>
               Cancel
             </button>
             <button 
               onClick={handleUninstall} 
               disabled={uninstalling || (impact?.dependents.length > 0)}
               className="btn-danger"
             >
               {uninstalling ? 'Uninstalling...' : 'Uninstall'}
             </button>
           </div>
         </div>
       </Modal>
     )
   }
   ```

**Testing:**
- Test uninstall for all install methods
- Verify config cleanup
- Test dependency checking
- Verify tool is actually removed

---

### **Phase 5: Advanced Features** (Week 6)
**Priority: LOW** - Nice-to-haves

#### Additional Features:

1. **Installation Queue**
   - Queue multiple installations
   - Parallel installs (up to N concurrent)
   - Retry failed installations
   - Save queue state across restarts

2. **Tool Profiles**
   - Beginner: Essential tools only
   - Intermediate: Common tools
   - Expert: All tools
   - Custom: User-defined sets
   - One-click "Install Profile"

3. **Docker Integration**
   - Run tools in Docker containers
   - Isolate potentially dangerous tools
   - No local installation needed
   - Pre-built images for all tools

4. **Tool Recommendations**
   - "Install Recommended" button
   - Smart suggestions based on:
     - Selected workflow
     - Tools user already has
     - Popular combinations
     - Missing dependencies

5. **Installation Analytics**
   - Show most popular tools
   - Success rate per tool
   - Average install time
   - Common failure reasons

6. **Offline Support**
   - Download all binaries for offline install
   - Create portable installation package
   - Air-gapped environment support

7. **Tool Sandboxing** (Security)
   - Run untrusted tools in sandbox
   - Limit filesystem access
   - Network isolation options
   - Audit tool behavior

8. **Configuration Manager**
   - Edit tool configs from UI
   - Template configurations
   - Share configs across team
   - Version control for configs

---

## 🎨 UI/UX Mockups

### Tool Card - Enhanced
```
┌─────────────────────────────────────┐
│ 🔧 nmap                     ●       │
│                         [Latest]    │
│ Version: 7.95                       │
│ Latest: 7.95                        │
│                                     │
│ Network Mapper                      │
│                                     │
│ [Update] [Configure] [Uninstall]   │
└─────────────────────────────────────┘
```

### Tool Card - Update Available
```
┌─────────────────────────────────────┐
│ 🔧 subfinder               ●        │
│                   [Update v2.6.6]   │
│ Version: 2.6.3                      │
│ Latest: 2.6.6 (2 months old)        │
│                                     │
│ Subdomain enumeration tool          │
│                                     │
│ [🔄 Update] [Configure] [Remove]    │
└─────────────────────────────────────┘
```

### Tool Card - Not Installed
```
┌─────────────────────────────────────┐
│ 🔧 rustscan                ○        │
│                       [Not Inst.]   │
│ Latest: 2.3.0                       │
│                                     │
│ Fast port scanner                   │
│                                     │
│ [📥 Install] [Learn More]           │
└─────────────────────────────────────┘
```

### Toolbar - Bulk Actions
```
┌─────────────────────────────────────┐
│ Tools (24/57 installed)             │
│                                     │
│ [🔄 Update All (5)] [📥 Install...] │
│ [🔍 Check Updates] [⚙️ Settings]    │
└─────────────────────────────────────┘
```

---

## 🔐 Security Considerations

1. **Verification**
   - Verify checksums for downloads
   - Verify GPG signatures where available
   - Only download from official sources

2. **Sandboxing**
   - Run installers with limited permissions
   - Use separate directories for managed tools
   - Option to review install scripts before execution

3. **User Permissions**
   - Warn if sudo/admin required
   - Prompt for elevation when needed
   - Log all privileged operations

4. **Network Security**
   - HTTPS only for downloads
   - Certificate pinning for critical sources
   - Proxy support

---

## 📊 Success Metrics

1. **Installation Success Rate**: >95%
2. **Average Install Time**: <2 minutes per tool
3. **Update Detection Accuracy**: >99%
4. **User Satisfaction**: "No more terminal commands!"
5. **Adoption**: 80%+ of users use install feature

---

## 🚀 Rollout Strategy

### Week 1-2: MVP (Phase 1 + Basic Phase 2)
- Version detection
- Basic installation (Go, Pip, Cargo)
- Works for 10 most popular tools

### Week 3-4: Extended Installation (Full Phase 2)
- Binary downloads
- All 57 tools supported
- Progress tracking

### Week 5: Updates & Uninstall (Phase 3 & 4)
- Update checking
- One-click updates
- Uninstallation

### Week 6+: Polish & Advanced Features
- Auto-updates
- Tool profiles
- Docker integration
- Analytics

---

## 🎯 Competitive Advantages

| Feature | Our Tool | Other Tools |
|---------|----------|-------------|
| One-Click Install | ✅ | ❌ |
| Version Management | ✅ | Partial |
| Cross-Platform | ✅ | Limited |
| Update Notifications | ✅ | ❌ |
| Rollback Support | ✅ | ❌ |
| Dependency Resolution | ✅ | ❌ |
| Progress Tracking | ✅ | ❌ |
| Offline Support | ✅ | ❌ |

---

## 🎓 Beginner-Friendly Features

1. **Guided Setup**
   - First-time user wizard
   - "Install Essential Tools" button
   - Explain what each tool does

2. **Educational Content**
   - Tool descriptions in plain English
   - Use case examples
   - Video tutorials (links)

3. **Error Messages**
   - Clear, actionable error messages
   - Automatic troubleshooting suggestions
   - "Help me fix this" button

4. **Safety Rails**
   - Confirm before removing critical tools
   - Warn about disk space
   - Explain permission requirements

---

## 🔧 Implementation Priority

### MUST HAVE (MVP)
- ✅ Version detection
- ✅ Basic installation (Go, Pip, Cargo)
- ✅ Installation progress tracking
- ✅ Basic uninstall

### SHOULD HAVE
- ✅ Binary downloads
- ✅ Update checking
- ✅ Update installation
- ✅ Batch operations

### NICE TO HAVE
- ⭐ Auto-updates
- ⭐ Tool profiles
- ⭐ Docker integration
- ⭐ Configuration manager
- ⭐ Offline support

---

## 📝 Notes

- Start with most popular tools (nmap, subfinder, nuclei, httpx)
- Prioritize Go and Pip tools (easiest to manage)
- Binary downloads are complex (OS detection, extraction)
- Windows needs special handling (no sudo, different paths)
- Linux distros vary (apt vs yum vs pacman)
- macOS uses Homebrew (simplest)

---

## 🤝 Additional Suggestions

1. **Tool Marketplace**
   - Community-submitted tool definitions
   - Ratings and reviews
   - Installation statistics

2. **Tool Collections**
   - "Web App Testing" bundle
   - "Bug Bounty Starter Pack"
   - "Red Team Toolkit"
   - One-click install entire collection

3. **Integration with Workflows**
   - Show which tools workflow needs
   - "Install Missing Tools" button on workflow page
   - Auto-install before running workflow

4. **Cloud Sync**
   - Sync installed tools across devices
   - Team sharing of tool configurations
   - Backup/restore tool setup

5. **Performance Monitoring**
   - Track tool execution times
   - Identify slow/broken tools
   - Suggest faster alternatives

6. **Cost Estimation**
   - Show disk space needed
   - Show bandwidth needed for download
   - Estimate install time

Would you like me to start implementing Phase 1 (Version Detection) first? This will lay the foundation for everything else and give you immediate value by showing which tools are outdated.


---

##  **Key Improvements from Community Suggestions**

This enhanced plan incorporates production-grade practices:

1.  **Manager-First Architecture** - Native package managers prioritized
2.  **Timeout-Bounded Probing** - Prevents UI hangs (5s default)
3.  **Package Manager Metadata** - More reliable than direct probes
4.  **Command Preview** - Transparency builds trust
5.  **Platform-Specific Best Practices** - WinGet/APT/Brew prioritization
6.  **Real-Time Streaming** - Live stdout/stderr in UI
7.  **Manager Source Badges** - Visual clarity per tool
8.  **Comprehensive Logging** - Full audit trail

**Why Better:**
- Native OS integration vs generic approach
- Reliability (timeouts, error handling, rollback)
- Educational (command preview teaches users)
- Professional (metrics, observability, audit logs)

---

##  **Ready to Start Phase 1?**

We can begin implementing:
1. Package manager detection (WinGet, APT, pipx, etc.)
2. Timeout-bounded version probing
3. Semver comparison engine
4. Manager source badges in UI

**Estimated Time:** 3-4 days for complete Phase 1
**Deliverable:** Tool cards showing version status with manager badges

Shall we proceed? 
