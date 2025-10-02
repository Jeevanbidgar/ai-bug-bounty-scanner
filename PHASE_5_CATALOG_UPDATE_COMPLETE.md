# Phase 5: Catalog Update Complete ✅

## Summary
Successfully updated `catalog.rs` with installation metadata for all 57 security tools in preparation for one-click tool installation.

## Changes Made

### 1. ToolDefinition Struct Enhanced
Added 5 new fields to support installation metadata:

```rust
pub struct ToolDefinition {
    // Existing fields
    pub name: String,
    pub description: String,
    pub category: String,
    pub command_candidates: Vec<String>,
    pub version_args: Vec<String>,
    pub output_format: String,
    pub os_dependencies: Vec<String>,
    
    // NEW: Installation metadata
    pub go_module: Option<String>,        // e.g. "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    pub pipx_package: Option<String>,     // e.g. "sqlmap"
    pub apt_package: Option<String>,      // e.g. "nmap"
    pub winget_id: Option<String>,        // e.g. "Nmap.Nmap"
    pub install_method: String,           // "go", "pipx", "apt", "winget", "manual", "runtime"
}
```

### 2. Builder Methods Added
Added 5 chainable builder methods for setting installation metadata:

```rust
impl ToolDefinition {
    pub fn with_go_module(mut self, module: &str) -> Self
    pub fn with_pipx_package(mut self, package: &str) -> Self
    pub fn with_apt_package(mut self, package: &str) -> Self
    pub fn with_winget_id(mut self, id: &str) -> Self
    pub fn with_install_method(mut self, method: &str) -> Self
}
```

### 3. All 57 Tools Updated
Updated every tool definition in `get_tool_catalog()` with installation paths:

#### Go Install Tools (24 tools) - ⭐ MVP Focus
- **Subdomain Enumeration (5):**
  - `subfinder` → `github.com/projectdiscovery/subfinder/v2/cmd/subfinder`
  - `amass` → `github.com/owasp-amass/amass/v4/...`
  - `assetfinder` → `github.com/tomnomnom/assetfinder`
  - `naabu` → `github.com/projectdiscovery/naabu/v2/cmd/naabu`

- **HTTP Probing (3):**
  - `httpx` → `github.com/projectdiscovery/httpx/cmd/httpx`
  - `httprobe` → `github.com/tomnomnom/httprobe`
  - `meg` → `github.com/tomnomnom/meg`

- **Web Crawling (3):**
  - `katana` → `github.com/projectdiscovery/katana/cmd/katana`
  - `gospider` → `github.com/jaeles-project/gospider`
  - `hakrawler` → `github.com/hakluke/hakrawler`

- **URL Discovery (3):**
  - `gau` → `github.com/lc/gau/v2/cmd/gau`
  - `waybackurls` → `github.com/tomnomnom/waybackurls`
  - `gauplus` → `github.com/bp0lr/gauplus`

- **Vulnerability Scanning (1):**
  - `nuclei` → `github.com/projectdiscovery/nuclei/v3/cmd/nuclei`

- **Directory Fuzzing (2):**
  - `ffuf` → `github.com/ffuf/ffuf/v2`
  - `gobuster` → `github.com/OJ/gobuster/v3`

- **XSS Detection (1):**
  - `dalfox` → `github.com/hahwul/dalfox/v2`

- **Screenshots (2):**
  - `gowitness` → `github.com/sensepost/gowitness`
  - `aquatone` → `github.com/michenriksen/aquatone`

- **JavaScript Analysis (1):**
  - `subjs` → `github.com/lc/subjs`

- **SSRF Testing (1):**
  - `interactsh-client` → `github.com/projectdiscovery/interactsh/cmd/interactsh-client`

- **Secret Scanning (2):**
  - `trufflehog` → `github.com/trufflesecurity/trufflehog/v3`
  - `gitleaks` → `github.com/gitleaks/gitleaks/v8`

- **Cloud Security (1):**
  - `s3scanner` → `github.com/sa7mon/s3scanner`

#### Pipx Tools (10 tools)
- **Subdomain Enumeration:**
  - `knockpy` → `git+https://github.com/guelfoweb/knock.git`
  - `sublist3r` → `sublist3r`
  - `dnsrecon` → `dnsrecon`
  - `fierce` → `fierce`

- **Parameter Discovery:**
  - `arjun` → `arjun`

- **SQL Injection:**
  - `sqlmap` → `sqlmap`

- **XSS Detection:**
  - `xsstrike` → `git+https://github.com/s0md3v/XSStrike.git`

- **JavaScript Analysis:**
  - `linkfinder` → `linkfinder`

- **Screenshots:**
  - `eyewitness` → `git+https://github.com/FortyNorthSecurity/EyeWitness.git`

- **Cloud Security:**
  - `cloudfail` → `git+https://github.com/m0rtem/CloudFail.git`

#### APT/WinGet System Tools (10 tools)
- **Port Scanning:**
  - `nmap` → APT: `nmap`, WinGet: `Nmap.Nmap`
  - `masscan` → APT: `masscan`, manual on Windows
  - `dnsenum` → APT: `dnsenum`, manual on Windows

- **Network Tools:**
  - `netcat` → APT: `netcat-openbsd`, WinGet: `nmap.ncat`
  - `socat` → APT: `socat`, manual on Windows
  - `git` → WinGet: `Git.Git`, pre-installed on Linux
  - `curl` → Pre-installed (runtime)
  - `wget` → WinGet: `GnuWin32.Wget`, pre-installed on Linux
  - `jq` → APT: `jq`, WinGet: `jqlang.jq`

- **Runtime Prerequisites:**
  - `python` → WinGet: `Python.Python.3.12`, pre-installed on Linux
  - `go` → APT: `golang-go`, WinGet: `GoLang.Go`

#### Manual Installation Tools (13 tools)
- **Exploitation:**
  - `metasploit` → APT: `metasploit-framework`, manual installer on Windows
  - `searchsploit` → APT: `exploitdb`, manual on Windows

- **Vulnerability Scanning:**
  - `nikto` → APT: `nikto`, manual Perl install on Windows
  - `wpscan` → APT: `wpscan`, Ruby gem on Windows
  - `joomscan` → Git clone (Perl-based)

- **Directory Fuzzing:**
  - `dirbuster` → APT: `dirbuster`, manual JAR on Windows
  - `feroxbuster` → Cargo or GitHub releases
  - `wfuzz` → APT: `wfuzz`, pip on Windows

- **Technology Detection:**
  - `wappalyzer` → npm package (requires Node.js)
  - `whatweb` → APT: `whatweb`, manual Ruby install

- **Port Scanning:**
  - `rustscan` → Cargo or GitHub releases

- **Parameter Discovery:**
  - `param-miner` → Burp Suite extension (not CLI)

## Example Usage

### Before (Without Installation Metadata):
```rust
catalog.insert("subfinder".to_string(), 
    ToolDefinition::new(
        "subfinder",
        "Fast passive subdomain discovery tool",
        "recon",
        vec!["subfinder"]
    ).with_output_format("json")
);
```

### After (With Installation Metadata):
```rust
catalog.insert("subfinder".to_string(), 
    ToolDefinition::new(
        "subfinder",
        "Fast passive subdomain discovery tool",
        "recon",
        vec!["subfinder"]
    )
    .with_output_format("json")
    .with_go_module("github.com/projectdiscovery/subfinder/v2/cmd/subfinder")
);
```

## Compilation Status
✅ **Successfully compiles** with `cargo check`
- 0 errors
- 28 warnings (all dead code/unused variables, not related to catalog changes)

## Installation Method Distribution

| Method | Count | Notes |
|--------|-------|-------|
| 🟢 **go install** | **24** | Primary method, works everywhere |
| 🟡 **pipx** | **10** | Python isolated environments |
| 🔵 **apt/winget** | **10** | System packages |
| 🔴 **manual** | **13** | Requires special handling |
| **Total** | **57** | All tools from catalog |

## Next Steps (Phase 6)

### 1. Implement GoInstallManager ⭐ **QUICK WIN**
This will enable one-click installation of 24 tools immediately!

**File:** `src-tauri/src/tools/package_managers/go_install.rs`

**Methods to implement:**
```rust
pub struct GoInstallManager;

impl GoInstallManager {
    pub fn new() -> Self;
    
    // Install a tool via go install
    pub async fn install(&self, module_path: &str) -> Result<InstallationResult>;
    
    // Update a tool (same as install for Go)
    pub async fn update(&self, module_path: &str) -> Result<InstallationResult>;
    
    // Remove a tool binary
    pub async fn uninstall(&self, tool_name: &str) -> Result<()>;
    
    // Check if tool is installed
    pub async fn is_installed(&self, tool_name: &str) -> bool;
    
    // Get tool version
    pub async fn get_version(&self, tool_name: &str) -> Option<String>;
}
```

**Key Implementation Details:**
- Use `Command::new("go").arg("install").arg(module_path + "@latest")`
- Resolve `$GOPATH/bin` (default: `~/go/bin` on Linux, `%USERPROFILE%\go\bin` on Windows)
- For uninstall: Remove binary from `$GOPATH/bin`
- For is_installed: Check if binary exists in `$GOPATH/bin`
- Use elevation system if needed (usually not required for go install)

### 2. Add Tauri Commands
**File:** `src-tauri/src/commands/tools.rs`

```rust
#[tauri::command]
pub async fn install_tool(tool_name: String) -> Result<InstallationResult, String>;

#[tauri::command]
pub async fn update_tool(tool_name: String) -> Result<InstallationResult, String>;

#[tauri::command]
pub async fn uninstall_tool(tool_name: String) -> Result<(), String>;

#[tauri::command]
pub async fn check_tool_installed(tool_name: String) -> Result<bool, String>;
```

### 3. Update Frontend
- Connect Install buttons to new commands
- Show progress during installation
- Use ElevationDialog if needed
- Refresh tool status after install

### 4. Test End-to-End
- Test installing subfinder, nuclei, httpx
- Verify binaries appear in $GOPATH/bin
- Test tool detection after install
- Test uninstall removes binary

## Benefits of This Update

### 1. **Structured Installation Data**
- Every tool now has installation metadata
- Clear mapping of tool → installation method → command

### 2. **Cross-Platform Support**
- Windows: WinGet IDs specified
- Linux: APT package names specified
- Both: Go modules, pipx packages work everywhere

### 3. **Ready for Automation**
- Installation methods clearly defined
- Can now implement automatic tool installation
- Can show "Install" buttons with confidence

### 4. **MVP Focus**
- Top 20 MVP tools prioritized with Go install method
- Quick win: 24 Go tools can be installed immediately
- User-friendly: One-click installation coming soon

### 5. **Maintainability**
- Installation paths centralized in catalog
- Easy to add new tools
- Easy to update installation methods

## Files Modified

### `src-tauri/src/tools/catalog.rs`
- **Lines changed:** ~150 additions
- **Tools updated:** All 57 tools
- **New fields:** 5 (go_module, pipx_package, apt_package, winget_id, install_method)
- **New methods:** 5 builder methods
- **Status:** ✅ Compiles successfully

## Testing Performed
✅ **Compilation:** `cargo check` passes
✅ **Struct validation:** All fields properly initialized
✅ **Builder pattern:** Methods chain correctly
✅ **Installation paths:** Verified against TOOL_INSTALLATION_MAPPING.md

## References
- **TOOL_INSTALLATION_MAPPING.md:** Source of all installation paths
- **Phase 4 (Elevation System):** Ready to use for privileged operations
- **Phase 1 (Detection):** Package managers already detected

---

**Phase 5 Status:** ✅ **COMPLETE**  
**Next Phase:** Phase 6 - GoInstallManager Implementation (Quick Win!)  
**Impact:** Foundation laid for one-click tool installation of 57 security tools  
**Estimated Time to Phase 6 Complete:** 2-3 hours  
**Immediate Benefit After Phase 6:** 24 Go-based tools installable with one click!
