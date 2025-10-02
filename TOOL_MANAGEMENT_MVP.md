# 🎯 Tool Management System - MVP Plan

## **Simplified Scope for Faster Delivery**

### **Target Platforms (MVP)**
- ✅ **Windows 10/11** only
- ✅ **Kali Linux** only
- ⏳ Other Linux (Ubuntu/Fedora/Arch) - Future
- ⏳ macOS - Future

**Why Kali Linux?**
- Primary platform for security researchers and pen testers
- Pre-installed security tools make it ideal test environment
- APT package manager is stable and well-documented
- Our target audience already uses Kali

---

## 🔧 **Package Manager Priority (MVP)**

### **1. go install (Primary - 80% of tools)**
**Why First:**
- Most security tools are Go-based (subfinder, nuclei, httpx, ffuf, gobuster, etc.)
- Works identically on Windows AND Kali Linux
- No package manager differences to handle
- Always installs latest version: `go install <module>@latest`
- Simple, reliable, consistent

**Command:**
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### **2. APT (Kali Linux system packages)**
**For:**
- System tools: nmap, curl, git, netcat
- Tools with complex dependencies
- Tools not available as Go packages

**Commands:**
```bash
sudo apt update
sudo apt install -y nmap
```

### **3. WinGet (Windows system packages)**
**For:**
- System tools: nmap, git, curl
- Tools with official Windows packages
- Tools not available via go install

**Commands:**
```powershell
winget install Nmap.Nmap
winget install Git.Git
```

### **4. pipx (Python CLI tools - Secondary)**
**For:**
- Python-based security tools: sqlmap, wpscan, sublist3r
- Isolated Python environments (no conflicts)

**Commands:**
```bash
pipx install sqlmap
pipx upgrade sqlmap
```

### **Deferred (Not in MVP):**
- ❌ Chocolatey (Windows fallback) - WinGet is enough for MVP
- ❌ Scoop (Windows alternative) - Too many options confuses MVP
- ❌ DNF/pacman (Other Linux) - Focus on Kali first
- ❌ Homebrew (macOS/Linux) - macOS not in MVP
- ❌ cargo (Rust tools) - Very few security tools use Rust
- ❌ npm (Node.js tools) - Very few security tools use Node

---

## 📦 **MVP Tool List (Top 20)**

### **Go Tools (Primary - 15 tools) ⭐**
These work on both Windows AND Kali with `go install`:

1. **subfinder** - `github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
2. **nuclei** - `github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
3. **httpx** - `github.com/projectdiscovery/httpx/cmd/httpx@latest`
4. **ffuf** - `github.com/ffuf/ffuf/v2@latest`
5. **gobuster** - `github.com/OJ/gobuster/v3@latest`
6. **waybackurls** - `github.com/tomnomnom/waybackurls@latest`
7. **gau** - `github.com/lc/gau/v2/cmd/gau@latest`
8. **assetfinder** - `github.com/tomnomnom/assetfinder@latest`
9. **amass** - `github.com/owasp-amass/amass/v4/...@latest`
10. **katana** - `github.com/projectdiscovery/katana/cmd/katana@latest`
11. **naabu** - `github.com/projectdiscovery/naabu/v2/cmd/naabu@latest`
12. **interactsh-client** - `github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest`
13. **gowitness** - `github.com/sensepost/gowitness@latest`
14. **hakrawler** - `github.com/hakluke/hakrawler@latest`
15. **trufflehog** - `github.com/trufflesecurity/trufflehog/v3@latest`

### **System Tools (APT/WinGet - 3 tools) 🔧**
Different commands per platform:

16. **nmap** 
    - Windows: `winget install Nmap.Nmap`
    - Kali: `sudo apt install -y nmap`

17. **curl**
    - Windows: Pre-installed (Windows 10+)
    - Kali: Pre-installed

18. **git**
    - Windows: `winget install Git.Git`
    - Kali: Pre-installed

### **Python Tools (pipx - 2 tools) 🐍**
Same on both platforms:

19. **sqlmap** - `pipx install sqlmap`
20. **sublist3r** - `pipx install sublist3r`

---

## 🏗️ **Simplified Architecture (MVP)**

```
Frontend (React)
  ↓
Tauri Commands
  ↓
Tool Manager
  ├→ Go Install Manager (primary)
  ├→ APT Manager (Kali only)
  ├→ WinGet Manager (Windows only)
  └→ Pipx Manager (both)
    ↓
Install/Update/Remove
```

### **Key Simplifications:**
- ✅ Only 4 package managers instead of 10+
- ✅ Most tools use `go install` (same command everywhere)
- ✅ No manager priority logic needed (go install first, always)
- ✅ Fewer platform-specific branches
- ✅ Faster to implement and test

---

## 📋 **Phase 1: Detection & Probing (Week 1)**

### **Tasks:**

1. **Detect Package Managers**
   ```rust
   // Check if Go is installed
   async fn detect_go_install() -> bool {
       Command::new("go").arg("version").output().await.is_ok()
   }
   
   // Check if WinGet is installed (Windows)
   async fn detect_winget() -> bool {
       #[cfg(windows)]
       Command::new("winget").arg("--version").output().await.is_ok()
       #[cfg(not(windows))]
       false
   }
   
   // Check if APT is available (Kali/Debian)
   async fn detect_apt() -> bool {
       #[cfg(unix)]
       Path::new("/usr/bin/apt").exists()
       #[cfg(not(unix))]
       false
   }
   
   // Check if pipx is installed
   async fn detect_pipx() -> bool {
       Command::new("pipx").arg("--version").output().await.is_ok()
   }
   ```

2. **Version Probing (Timeout: 5s)**
   ```rust
   pub async fn probe_version(tool_name: &str) -> Result<String> {
       let output = timeout(
           Duration::from_secs(5),
           Command::new(tool_name).arg("--version").output()
       ).await??;
       
       let stdout = String::from_utf8_lossy(&output.stdout);
       extract_version(&stdout)
   }
   ```

3. **Manager Source Badges**
   - "Go" (green) - Most tools
   - "APT" (blue) - Kali system tools
   - "WinGet" (blue) - Windows system tools
   - "pipx" (yellow) - Python tools

**Deliverable:** Tool cards showing version status and manager badge

---

## 📋 **Phase 2: Installation (Week 2-3)**

### **Go Install Implementation (Priority 1)**

```rust
pub struct GoInstallManager;

impl GoInstallManager {
    pub async fn install(&self, module_path: &str) -> Result<()> {
        eprintln!("📥 Installing via go install: {}", module_path);
        
        let command = format!("go install {}@latest", module_path);
        
        let output = Command::new("go")
            .args(&["install", &format!("{}@latest", module_path)])
            .output()
            .await?;
        
        if output.status.success() {
            eprintln!("✅ Successfully installed via go install");
            Ok(())
        } else {
            Err(format!("go install failed: {}", 
                String::from_utf8_lossy(&output.stderr)).into())
        }
    }
    
    pub async fn is_go_tool_installed(&self, tool_name: &str) -> bool {
        // Check if binary exists in $GOPATH/bin
        let go_bin = self.get_go_bin_path().unwrap_or_default();
        let tool_path = go_bin.join(tool_name);
        
        #[cfg(windows)]
        let tool_path = tool_path.with_extension("exe");
        
        tool_path.exists()
    }
}
```

### **Tool Registry (Simplified)**

```rust
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    
    // Installation
    pub go_module: Option<String>,      // Primary: go install path
    pub apt_package: Option<String>,    // Kali: apt package name
    pub winget_id: Option<String>,      // Windows: winget package ID
    pub pipx_package: Option<String>,   // Python: pipx package name
    
    // Version detection
    pub version_args: Vec<String>,      // ["--version"] or ["-v"]
    pub version_regex: String,          // r"(\d+\.\d+\.\d+)"
}

// Example: subfinder
ToolDefinition {
    name: "subfinder".to_string(),
    description: "Fast subdomain enumeration tool".to_string(),
    
    go_module: Some("github.com/projectdiscovery/subfinder/v2/cmd/subfinder".to_string()),
    apt_package: None,  // Not in Kali repos
    winget_id: None,    // Not in WinGet (use go install)
    pipx_package: None, // Not a Python tool
    
    version_args: vec!["--version".to_string()],
    version_regex: r"(\d+\.\d+\.\d+)".to_string(),
}

// Example: nmap
ToolDefinition {
    name: "nmap".to_string(),
    description: "Network mapper and port scanner".to_string(),
    
    go_module: None,                    // Not a Go tool
    apt_package: Some("nmap".to_string()),
    winget_id: Some("Nmap.Nmap".to_string()),
    pipx_package: None,
    
    version_args: vec!["--version".to_string()],
    version_regex: r"(\d+\.\d+)".to_string(),
}
```

### **Installation Logic (Simplified)**

```rust
pub async fn install_tool(&self, tool: &ToolDefinition) -> Result<()> {
    // Strategy 1: Try go install first (works on both platforms)
    if let Some(go_module) = &tool.go_module {
        if self.go_manager.is_available().await {
            return self.go_manager.install(go_module).await;
        }
    }
    
    // Strategy 2: Use platform-specific package manager
    #[cfg(windows)]
    if let Some(winget_id) = &tool.winget_id {
        if self.winget_manager.is_available().await {
            return self.winget_manager.install(winget_id).await;
        }
    }
    
    #[cfg(unix)]
    if let Some(apt_pkg) = &tool.apt_package {
        if self.apt_manager.is_available().await {
            return self.apt_manager.install(apt_pkg).await;
        }
    }
    
    // Strategy 3: Try pipx for Python tools
    if let Some(pipx_pkg) = &tool.pipx_package {
        if self.pipx_manager.is_available().await {
            return self.pipx_manager.install(pipx_pkg).await;
        }
    }
    
    Err("No suitable installation method available".into())
}
```

**Deliverable:** One-click install for all 20 tools

---

## 📋 **Phase 3: Updates (Week 4)**

### **Go Tools: Always Latest**
```rust
// Go install always installs @latest, so update = reinstall
pub async fn update_go_tool(&self, module_path: &str) -> Result<()> {
    eprintln!("🔄 Updating via go install (reinstall latest)...");
    self.install(module_path).await  // Same as install!
}
```

### **System Packages**
```rust
// Windows: winget upgrade
winget upgrade --id Nmap.Nmap

// Kali: apt upgrade
sudo apt update && sudo apt upgrade -y nmap
```

### **Python Tools: pipx upgrade**
```rust
pipx upgrade sqlmap
```

**Deliverable:** One-click updates with "Update All" button

---

## 📋 **Phase 4: Uninstall (Week 5)**

### **Go Tools**
```rust
pub async fn uninstall_go_tool(&self, tool_name: &str) -> Result<()> {
    let go_bin = self.get_go_bin_path()?;
    let tool_path = go_bin.join(tool_name);
    
    #[cfg(windows)]
    let tool_path = tool_path.with_extension("exe");
    
    if tool_path.exists() {
        tokio::fs::remove_file(tool_path).await?;
        eprintln!("✅ Removed {} from $GOPATH/bin", tool_name);
        Ok(())
    } else {
        Err("Tool not found".into())
    }
}
```

### **System Packages**
```bash
# Windows
winget uninstall --id Nmap.Nmap

# Kali
sudo apt remove -y nmap
# Optional: sudo apt purge -y nmap  (remove configs too)
```

### **Python Tools**
```bash
pipx uninstall sqlmap
```

**Deliverable:** Safe uninstall with optional config cleanup

---

## 🎨 **UI Components (Simplified)**

### **Tool Card Enhancement**
```tsx
<div className="tool-card">
  <div className="tool-header">
    <h3>{tool.name}</h3>
    <span className="manager-badge">{tool.manager}</span>
  </div>
  
  <div className="tool-status">
    {tool.installed ? (
      <>
        <span className="version">v{tool.version}</span>
        {tool.updateAvailable && (
          <span className="update-badge">v{tool.latestVersion} available</span>
        )}
      </>
    ) : (
      <span className="not-installed">Not Installed</span>
    )}
  </div>
  
  <div className="tool-actions">
    {!tool.installed && (
      <button onClick={handleInstall}>
        <DownloadIcon /> Install
      </button>
    )}
    
    {tool.installed && tool.updateAvailable && (
      <button onClick={handleUpdate}>
        <UpdateIcon /> Update
      </button>
    )}
    
    {tool.installed && (
      <button onClick={handleUninstall}>
        <TrashIcon /> Remove
      </button>
    )}
  </div>
</div>
```

### **Manager Badges**
- 🟢 **Go** - Green (most common)
- 🔵 **APT** - Blue (Kali system)
- 🔵 **WinGet** - Blue (Windows system)
- 🟡 **pipx** - Yellow (Python tools)

---

## ✅ **MVP Success Criteria**

### **Must Have:**
- ✅ Detect if Go, WinGet (Windows), APT (Kali), pipx are installed
- ✅ Show version status for all 20 tools
- ✅ One-click install for all 20 tools
- ✅ One-click update for outdated tools
- ✅ One-click uninstall
- ✅ Real-time installation progress
- ✅ Works on Windows 10/11
- ✅ Works on Kali Linux

### **Nice to Have (Defer):**
- ⏳ Command preview (show exact command)
- ⏳ Installation history log
- ⏳ Batch "Update All" button
- ⏳ Rollback on failed update
- ⏳ Offline installation cache

---

## 📊 **Estimated Timeline**

- **Week 1**: Detection + Version Probing (Phase 1)
- **Week 2-3**: Installation System (Phase 2)
- **Week 4**: Update System (Phase 3)
- **Week 5**: Uninstall System (Phase 4)
- **Week 6**: Testing + Bug Fixes

**Total: 6 weeks for complete MVP**

---

## 🚀 **Why This MVP is Better**

### **Simplified:**
- ✅ Only 2 platforms (Windows + Kali)
- ✅ Only 4 package managers (go/WinGet/APT/pipx)
- ✅ 80% of tools use `go install` (same everywhere)
- ✅ Less code, fewer bugs

### **Faster to Ship:**
- ✅ 6 weeks vs 12+ weeks for full plan
- ✅ Users get value immediately
- ✅ Can expand to other platforms later

### **Lower Risk:**
- ✅ Focus on most-used platform (Kali)
- ✅ Test with smaller surface area
- ✅ Learn from real usage before expanding

### **Still Powerful:**
- ✅ Covers 90% of user needs
- ✅ 20 most essential tools
- ✅ Full install/update/uninstall cycle
- ✅ Professional UX

---

**Ready to start Phase 1?** 🎯
