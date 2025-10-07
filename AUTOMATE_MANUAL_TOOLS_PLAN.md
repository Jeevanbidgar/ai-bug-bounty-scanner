# Automation Plan for Manual Tools

## Overview

This document outlines the strategy to automate installation of tools currently marked as "manual" in the catalog. We'll use appropriate installation methods based on each tool's technology stack.

## Installation Method Categories

### 1. ✅ **git-pip** (Python Tools)
**Method**: `git clone` + `pip install`  
**Status**: ✅ Already implemented in `GitPipInstaller`

#### Candidates to Convert:
1. **xsstrike** - XSS detection suite
   - Repo: `https://github.com/s0md3v/XSStrike.git`
   - Installation: `git clone` + `pip install -r requirements.txt`
   
2. **wfuzz** - Web application fuzzer
   - Repo: `https://github.com/xmendez/wfuzz.git`
   - Installation: `git clone` + `pip install -e .`
   
3. **cloudfail** - Find origin servers behind CDN
   - Repo: `https://github.com/m0rtem/CloudFail.git`
   - Installation: `git clone` + `pip install -r requirements.txt`

### 2. 🔧 **Cargo** (Rust Tools)
**Method**: `cargo install` or pre-built binaries  
**Status**: ⏳ To be implemented

#### Candidates:
1. **rustscan** - Modern port scanner
   - Repo: `https://github.com/RustScan/RustScan.git`
   - Options:
     - Cargo: `cargo install rustscan`
     - Binary: Download from GitHub releases
   
2. **feroxbuster** - Fast content discovery
   - Repo: `https://github.com/epi052/feroxbuster.git`
   - Options:
     - Cargo: `cargo install feroxbuster`
     - Binary: Download from GitHub releases

### 3. 💎 **Ruby Gems** (Ruby Tools)
**Method**: `gem install` or git + bundle  
**Status**: ⏳ To be implemented

#### Candidates:
1. **wpscan** - WordPress vulnerability scanner
   - Gem: `wpscan`
   - Installation: `gem install wpscan`

### 4. 📦 **NPM** (Node.js Tools)
**Method**: `npm install -g` or git + npm  
**Status**: ⏳ To be implemented

#### Candidates:
1. **wappalyzer** - Technology detection
   - NPM: `@wappalyzer/cli`
   - Installation: `npm install -g @wappalyzer/cli`

### 5. ⚙️ **Compiled Binaries** (C/C++ Tools)
**Method**: Download pre-built binaries or compile from source  
**Status**: ⏳ Requires manual installer recipes

#### Candidates:
1. **masscan** - TCP port scanner
   - Repo: `https://github.com/robertdavidgraham/masscan.git`
   - Windows: Download pre-built binary
   - Linux: Compile from source (`make` + `make install`)

### 6. 🐚 **Script-Based Tools** (Perl/Shell)
**Method**: git clone + PATH configuration  
**Status**: ⏳ Requires manual installer recipes

#### Candidates:
1. **nikto** - Web server scanner (Perl)
   - Repo: `https://github.com/sullo/nikto.git`
   - Installation: Clone + add to PATH
   
2. **dnsenum** - DNS enumeration (Perl)
   - Repo: `https://github.com/fwaeytens/dnsenum.git`
   - Installation: Clone + install dependencies
   
3. **joomscan** - Joomla scanner (Perl)
   - Repo: `https://github.com/OWASP/joomscan.git`
   - Installation: Clone + add to PATH

### 7. 🚫 **Not Suitable for Automation**
These tools require complex setup or are better installed manually:

1. **metasploit** - Complex framework (manual or system package)
2. **searchsploit** - Part of exploitdb package
3. **param-miner** - Burp Suite extension
4. **netcat/socat** - System utilities (APT/WinGet only)
5. **dirbuster** - Java tool (deprecated, use gobuster/ffuf instead)

## Implementation Plan

### Phase 1: Convert Python Tools to git-pip ✅ COMPLETE
- [x] fierce
- [x] linkfinder
- [x] arjun
- [x] sqlmap
- [x] dnsrecon
- [x] sublist3r
- [x] knockpy
- [x] eyewitness

**Next Python tools to add:**
- [ ] xsstrike
- [ ] wfuzz
- [ ] cloudfail

### Phase 2: Implement Cargo Installer (Rust Tools)
Create `CargoInstaller` similar to `GitPipInstaller`:

```rust
pub struct CargoInstaller {
    install_base_dir: PathBuf,
}

impl CargoInstaller {
    pub async fn install(
        &self,
        package_name: &str,  // e.g., "rustscan"
        tool_name: &str,
        app_handle: Option<&tauri::AppHandle>
    ) -> Result<InstallationResult, String>
    
    // Alternative: install from binary
    pub async fn install_from_binary(
        &self,
        github_repo: &str,  // e.g., "RustScan/RustScan"
        tool_name: &str,
        app_handle: Option<&tauri::AppHandle>
    ) -> Result<InstallationResult, String>
}
```

**Tools to add:**
- rustscan
- feroxbuster

### Phase 3: Implement Ruby Gem Installer
Create `GemInstaller`:

```rust
pub struct GemInstaller;

impl GemInstaller {
    pub async fn install(
        &self,
        gem_name: &str,  // e.g., "wpscan"
        tool_name: &str,
        app_handle: Option<&tauri::AppHandle>
    ) -> Result<InstallationResult, String>
}
```

**Tools to add:**
- wpscan

### Phase 4: Implement NPM Installer
Create `NpmInstaller`:

```rust
pub struct NpmInstaller;

impl NpmInstaller {
    pub async fn install_global(
        &self,
        package_name: &str,  // e.g., "@wappalyzer/cli"
        tool_name: &str,
        app_handle: Option<&tauri::AppHandle>
    ) -> Result<InstallationResult, String>
}
```

**Tools to add:**
- wappalyzer

### Phase 5: Enhance ManualInstaller with Recipes
Add installation recipes for script-based tools:

```rust
// In src-tauri/src/tools/install_recipes/
pub mod nikto_recipe;
pub mod dnsenum_recipe;
pub mod masscan_recipe;
pub mod joomscan_recipe;

// Each recipe implements:
pub trait InstallRecipe {
    async fn can_install(&self) -> bool;
    async fn install(&self, app_handle: Option<&tauri::AppHandle>) -> Result<InstallationResult, String>;
    fn get_steps(&self) -> Vec<InstallStep>;
}
```

**Tools to add:**
- nikto
- dnsenum
- joomscan
- masscan (with binary download option)

## Quick Wins: Convert Python Tools Now

Let's immediately convert these 3 Python tools to git-pip:

### 1. xsstrike
```rust
catalog.insert("xsstrike".to_string(),
    ToolDefinition::new(
        "xsstrike",
        "XSS detection suite",
        "web",
        vec!["xsstrike"]
    )
    .with_git_repo("https://github.com/s0md3v/XSStrike.git")
);
```

### 2. wfuzz
```rust
catalog.insert("wfuzz".to_string(),
    ToolDefinition::new(
        "wfuzz",
        "Web application fuzzer",
        "web",
        vec!["wfuzz"]
    )
    .with_git_repo("https://github.com/xmendez/wfuzz.git")
);
```

### 3. cloudfail
```rust
catalog.insert("cloudfail".to_string(),
    ToolDefinition::new(
        "cloudfail",
        "Find origin servers behind CDN",
        "cloud",
        vec!["cloudfail"]
    )
    .with_git_repo("https://github.com/m0rtem/CloudFail.git")
);
```

## Timeline

### Immediate (Today)
- ✅ git-pip foundation complete
- ⏳ Convert 3 more Python tools (xsstrike, wfuzz, cloudfail)

### Short-term (This Week)
- Implement CargoInstaller for Rust tools
- Add rustscan and feroxbuster

### Medium-term (Next Week)
- Implement GemInstaller for Ruby tools
- Implement NpmInstaller for Node.js tools
- Add wpscan and wappalyzer

### Long-term (Future)
- Create installation recipes for Perl/shell tools
- Binary downloader for compiled tools
- Advanced dependency management

## Benefits by Installation Method

| Method | Tools Covered | Reliability | Speed | User Experience |
|--------|--------------|-------------|-------|-----------------|
| git-pip | 11 tools | ⭐⭐⭐⭐⭐ | Fast | Excellent |
| cargo | 2 tools | ⭐⭐⭐⭐ | Medium | Good |
| gem | 1 tool | ⭐⭐⭐⭐ | Fast | Good |
| npm | 1 tool | ⭐⭐⭐⭐ | Fast | Good |
| recipes | 4-5 tools | ⭐⭐⭐ | Medium | Fair |
| manual | 5-6 tools | ⭐⭐ | N/A | Poor |

## Success Metrics

- **Coverage**: Automate 80%+ of currently manual tools
- **Reliability**: 95%+ success rate on fresh installations
- **Speed**: Average install time < 2 minutes per tool
- **UX**: Live output streaming + clear error messages

---

**Next Action**: Convert xsstrike, wfuzz, and cloudfail to git-pip method (5 minutes)
