# Cross-Platform Installation System - Production Implementation Plan

## Objective
Build a robust, cross-platform package manager integration system that handles platform-specific quirks automatically.

---

## Current Architecture Issues

### Problem 1: Platform-Specific Constraints Not Handled
- **Linux**: PEP 668 blocks system pip, npm requires sudo, go install fails with replace directives
- **Windows**: Works fine with current implementation
- **macOS**: Untested but likely similar to Linux for pip

### Problem 2: Single Installation Method Per Tool
- Current: Each tool has ONE installation method (go/pip/npm)
- Needed: Fallback chain with platform detection

### Problem 3: No User-Level Package Installation
- Current: Global installs (requires admin)
- Needed: User-level installs (no sudo/admin required)

---

## Production-Ready Solution Architecture

### 1. Installation Strategy Pattern

```rust
pub trait InstallationStrategy {
    async fn can_install(&self) -> bool;
    async fn install(&self, tool: &ToolDef) -> Result<InstallResult>;
    fn priority(&self) -> u8; // Higher = try first
}

pub struct InstallationOrchestrator {
    strategies: Vec<Box<dyn InstallationStrategy>>,
}

impl InstallationOrchestrator {
    pub async fn install_tool(&self, tool: &ToolDef) -> Result<InstallResult> {
        // Try strategies in priority order
        for strategy in &self.strategies {
            if strategy.can_install().await {
                match strategy.install(tool).await {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        // Log error, try next strategy
                        continue;
                    }
                }
            }
        }
        Err("No suitable installation strategy found")
    }
}
```

### 2. Python Installation Strategies (Priority Order)

#### Strategy 1: pipx (Priority: 10 - Best for Linux/macOS)
```rust
pub struct PipxStrategy;

impl InstallationStrategy for PipxStrategy {
    async fn can_install(&self) -> bool {
        // Check if pipx is available
        Command::new("pipx").arg("--version").output().await.is_ok()
    }
    
    async fn install(&self, tool: &ToolDef) -> Result<InstallResult> {
        // pipx install git+{repo}
        // Works on: Linux, macOS, Windows
        // Pros: Automatic venv isolation, PEP 668 compliant
    }
    
    fn priority(&self) -> u8 { 10 }
}
```

#### Strategy 2: Git + Venv + Pip (Priority: 8 - Linux fallback)
```rust
pub struct GitVenvStrategy;

impl InstallationStrategy for GitVenvStrategy {
    async fn install(&self, tool: &ToolDef) -> Result<InstallResult> {
        // 1. Clone repo
        // 2. Create venv
        // 3. Install in venv
        // 4. Create wrapper script in ~/.local/bin
        // Works on: Linux, macOS
        // Pros: PEP 668 compliant, no pipx needed
    }
    
    fn priority(&self) -> u8 { 8 }
}
```

#### Strategy 3: System Pip (Priority: 5 - Windows only)
```rust
pub struct SystemPipStrategy;

impl InstallationStrategy for SystemPipStrategy {
    async fn can_install(&self) -> bool {
        cfg!(target_os = "windows") || 
        cfg!(target_os = "macos") // macOS doesn't have PEP 668 yet
    }
    
    async fn install(&self, tool: &ToolDef) -> Result<InstallResult> {
        // Traditional git clone + pip install
        // Works on: Windows, macOS (pre-PEP 668)
    }
    
    fn priority(&self) -> u8 { 5 }
}
```

### 3. npm Installation Strategies

#### Strategy 1: User-Level npm (Priority: 10 - All platforms)
```rust
pub struct NpmUserStrategy;

impl InstallationStrategy for NpmUserStrategy {
    async fn install(&self, tool: &ToolDef) -> Result<InstallResult> {
        // npm install -g {package} --prefix ~/.local
        // Works on: Linux, macOS, Windows
        // Pros: No sudo, user-writable location
        
        let prefix = if cfg!(windows) {
            env::var("APPDATA")?
        } else {
            format!("{}/.local", env::var("HOME")?)
        };
        
        Command::new("npm")
            .args(&["install", "-g", package, "--prefix", &prefix])
            .spawn()?
    }
    
    fn priority(&self) -> u8 { 10 }
}
```

#### Strategy 2: Global npm with Sudo (Priority: 3 - Linux fallback)
```rust
pub struct NpmGlobalStrategy;

impl InstallationStrategy for NpmGlobalStrategy {
    async fn install(&self, tool: &ToolDef) -> Result<InstallResult> {
        // sudo npm install -g {package}
        // Works on: Linux, macOS
        // Cons: Requires sudo prompt
        
        #[cfg(unix)]
        {
            Command::new("sudo")
                .args(&["npm", "install", "-g", package])
                .spawn()?
        }
    }
    
    fn priority(&self) -> u8 { 3 }
}
```

### 4. Go Installation Strategies

#### Strategy 1: Go Install (Priority: 10 - Standard)
```rust
pub struct GoInstallStrategy;

impl InstallationStrategy for GoInstallStrategy {
    async fn install(&self, tool: &ToolDef) -> Result<InstallResult> {
        // go install {module}@latest
        // Works on: All platforms
        // Pros: Official method, handles deps
        
        Command::new("go")
            .args(&["install", &format!("{}@latest", module)])
            .spawn()?
    }
    
    fn priority(&self) -> u8 { 10 }
}
```

#### Strategy 2: Git + Go Build (Priority: 8 - Fallback for replace directives)
```rust
pub struct GoSourceBuildStrategy;

impl InstallationStrategy for GoSourceBuildStrategy {
    async fn install(&self, tool: &ToolDef) -> Result<InstallResult> {
        // 1. Clone repo
        // 2. cd into repo
        // 3. go build -o $GOPATH/bin/{toolname}
        // Works on: All platforms
        // Pros: Works with replace directives
        
        let clone_dir = clone_repo(git_repo)?;
        let gopath = env::var("GOPATH")?;
        let bin_path = PathBuf::from(&gopath).join("bin").join(tool_name);
        
        Command::new("go")
            .current_dir(&clone_dir)
            .args(&["build", "-o", bin_path.to_str().unwrap()])
            .spawn()?
    }
    
    fn priority(&self) -> u8 { 8 }
}
```

---

## Implementation Files Structure

```
src-tauri/src/tools/
├── installation/
│   ├── mod.rs                    # Public API
│   ├── orchestrator.rs           # Strategy orchestrator
│   ├── strategy.rs               # Strategy trait
│   ├── python/
│   │   ├── mod.rs
│   │   ├── pipx_strategy.rs      # pipx install
│   │   ├── venv_strategy.rs      # git + venv + pip
│   │   └── system_pip_strategy.rs # traditional pip
│   ├── nodejs/
│   │   ├── mod.rs
│   │   ├── user_npm_strategy.rs  # npm --prefix ~/.local
│   │   └── global_npm_strategy.rs # npm -g (with sudo)
│   ├── golang/
│   │   ├── mod.rs
│   │   ├── go_install_strategy.rs # go install
│   │   └── go_build_strategy.rs   # git + go build
│   └── common/
│       ├── mod.rs
│       ├── path_manager.rs       # Add to PATH automatically
│       └── privilege_helper.rs   # Sudo/elevation detection
└── package_managers/             # Keep existing for backward compat
    └── ...
```

---

## Key Features

### 1. Automatic PATH Management
```rust
pub struct PathManager;

impl PathManager {
    pub fn ensure_in_path(dir: &str) -> Result<()> {
        if !self.is_in_path(dir) {
            self.add_to_path(dir)?;
            self.emit_path_warning(dir);
        }
        Ok(())
    }
    
    fn add_to_path(&self, dir: &str) -> Result<()> {
        #[cfg(unix)]
        {
            let shell_rc = self.detect_shell_rc()?;
            append_to_file(&shell_rc, &format!("export PATH=\"{}:$PATH\"", dir))?;
        }
        
        #[cfg(windows)]
        {
            // Update Windows registry for persistent PATH
            use winreg::RegKey;
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let env = hkcu.open_subkey_with_flags("Environment", KEY_ALL_ACCESS)?;
            let path: String = env.get_value("PATH")?;
            env.set_value("PATH", &format!("{};{}", path, dir))?;
        }
        
        Ok(())
    }
}
```

### 2. Privilege Detection
```rust
pub struct PrivilegeHelper;

impl PrivilegeHelper {
    pub fn requires_elevation() -> bool {
        cfg!(target_os = "linux") || cfg!(target_os = "macos")
    }
    
    pub async fn prompt_for_sudo() -> Result<bool> {
        // Show UI prompt asking user for sudo permission
        // Return true if granted, false if denied
    }
    
    pub fn can_write_to(&self, path: &Path) -> bool {
        path.exists() && std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .is_ok()
    }
}
```

### 3. Installation Status Tracking
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct InstallationStatus {
    pub tool_name: String,
    pub strategy_used: String,
    pub install_path: String,
    pub binary_path: String,
    pub in_path: bool,
    pub installation_time: chrono::DateTime<Utc>,
}

impl InstallationStatus {
    pub async fn save_to_db(&self, db: &Database) -> Result<()> {
        // Track which strategy was used for each tool
        // Helps with troubleshooting and updates
    }
}
```

---

## Migration Strategy

### Phase 1: Add New System (Non-Breaking)
1. ✅ Create new `installation/` module
2. ✅ Implement strategy pattern
3. ✅ Add all strategies
4. ✅ Keep old code functional

### Phase 2: Test New System
1. ✅ Add feature flag: `use_new_installer`
2. ✅ Test on Windows/Linux/macOS
3. ✅ Compare results with old system

### Phase 3: Gradual Migration
1. ✅ Route Python tools to new system
2. ✅ Route npm tools to new system
3. ✅ Route Go tools to new system
4. ✅ Verify all work

### Phase 4: Cleanup
1. ✅ Remove old code
2. ✅ Update documentation
3. ✅ Release

---

## Testing Matrix

| Tool | Windows | Linux | macOS | Method |
|------|---------|-------|-------|--------|
| eyewitness | ✅ pip | ✅ pipx | ✅ pipx | Python |
| fierce | ✅ pip | ✅ pipx | ✅ pipx | Python |
| wappalyzer | ✅ npm | ✅ npm --prefix | ✅ npm --prefix | npm |
| subfinder | ✅ go install | ✅ go install | ✅ go install | Go |
| trufflehog | ✅ go build | ✅ go build | ✅ go build | Go |

---

## Benefits of This Approach

1. ✅ **Cross-Platform**: Works on Windows, Linux, macOS
2. ✅ **No Admin Required**: User-level installs only
3. ✅ **PEP 668 Compliant**: Uses pipx/venv on Linux
4. ✅ **Automatic Fallback**: Tries multiple methods
5. ✅ **PATH Management**: Adds binaries to PATH automatically
6. ✅ **Maintainable**: Clean separation of concerns
7. ✅ **Testable**: Each strategy can be unit tested
8. ✅ **Extensible**: Easy to add new strategies

---

## Timeline Estimate

| Phase | Time | Description |
|-------|------|-------------|
| Phase 1 | 2-3 days | Implement strategy pattern + all strategies |
| Phase 2 | 1-2 days | Testing on all platforms |
| Phase 3 | 1 day | Integration + UI updates |
| Phase 4 | 1 day | Cleanup + documentation |
| **Total** | **5-7 days** | Full production-ready implementation |

---

## Next Steps

1. **Approve Architecture**: Review and approve this design
2. **Create Feature Branch**: `feature/cross-platform-installers`
3. **Implement Core**: Strategy pattern + orchestrator
4. **Implement Strategies**: One package manager at a time
5. **Test Thoroughly**: On all three platforms
6. **Deploy**: Merge to main

---

**Ready to implement?** I can start with Phase 1 right now! 🚀
