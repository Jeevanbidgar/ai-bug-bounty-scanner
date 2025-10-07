# 🐛 Tool Detection Issues After Installation

## 📋 Problems Identified

### Issue 1: npm tools (wappalyzer)
- ✅ **Installed successfully** via `npm install -g wappalyzer`
- ❌ **Not detected** after installation
- ❌ **Recheck Status** doesn't find it

**Root Cause:** npm global tools installed to `npm prefix -g` location not in standard PATH search

### Issue 2: WinGet tools (netcat, jq)
- ❌ **netcat** - Installation failed (package not found)
- ✅ **jq** - Installed successfully
- ❌ **Not showing as installed** after installation

**Root Cause:** 
1. WinGet installs to various locations (depends on package)
2. PATH not refreshed after installation
3. Tool discovery doesn't check WinGet-specific install locations

---

## 🔍 Root Cause Analysis

### Problem 1: PATH Not Refreshed
After installing a tool, the application doesn't refresh the PATH environment variable. New PATH entries added by installers (npm, winget) aren't visible until app restart.

### Problem 2: Limited Search Paths
Tool discovery only checks:
- Standard PATH locations
- Some hardcoded common locations
- But NOT:
  - npm global bin directory
  - WinGet install locations (varied)
  - User-specific install directories

### Problem 3: No Post-Installation Verification
After successful installation, the verification logic (`recheck_tool`) uses the same discovery method that didn't find it before, so it still won't find it.

---

## 🛠️ Solutions

### Solution 1: Refresh PATH After Installation ✅
Add environment variable refresh after tool installation:

```rust
// After successful installation, refresh environment
#[cfg(target_os = "windows")]
fn refresh_environment() {
    unsafe {
        use winapi::um::winuser::{SendMessageTimeoutW, HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG};
        use std::ptr;
        
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            b"Environment\0".as_ptr() as _,
            SMTO_ABORTIFHUNG,
            5000,
            ptr::null_mut(),
        );
    }
}
```

### Solution 2: Check Package-Manager-Specific Locations ✅
Add dedicated search paths for each package manager:

```rust
async fn get_additional_search_paths(install_method: &str) -> Vec<PathBuf> {
    match install_method {
        "npm" => get_npm_bin_paths().await,
        "winget" => get_winget_install_paths().await,
        "cargo" => get_cargo_bin_paths().await,
        _ => vec![]
    }
}

async fn get_npm_bin_paths() -> Vec<PathBuf> {
    // Get npm prefix (where global packages are installed)
    let output = Command::new("npm")
        .args(&["prefix", "-g"])
        .output()
        .await;
        
    if let Ok(output) = output {
        let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
        vec![
            PathBuf::from(format!("{}/node_modules/.bin", prefix)),
            PathBuf::from(format!("{}\\node_modules\\.bin", prefix)), // Windows
        ]
    } else {
        vec![]
    }
}

async fn get_winget_install_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("C:\\Program Files"),
        PathBuf::from("C:\\Program Files (x86)"),
        PathBuf::from(format!("{}\\AppData\\Local\\Microsoft\\WinGet\\Packages", 
            std::env::var("USERPROFILE").unwrap_or_default())),
        // WinGet can install to various locations
    ]
}
```

### Solution 3: Enhanced Post-Installation Verification ✅
After installation, use a smarter verification strategy:

```rust
async fn verify_tool_after_installation(
    tool_name: &str,
    install_method: &str,
    command_candidates: &[String]
) -> Option<String> {
    // Step 1: Check additional package-manager-specific paths
    let extra_paths = get_additional_search_paths(install_method).await;
    
    for path_dir in extra_paths {
        for candidate in command_candidates {
            let tool_path = path_dir.join(candidate);
            if tool_path.exists() {
                return Some(tool_path.to_string_lossy().to_string());
            }
            
            // Try with .exe extension on Windows
            #[cfg(target_os = "windows")]
            {
                let tool_path_exe = path_dir.join(format!("{}.exe", candidate));
                if tool_path_exe.exists() {
                    return Some(tool_path_exe.to_string_lossy().to_string());
                }
            }
        }
    }
    
    // Step 2: Try running the command directly
    for candidate in command_candidates {
        if let Ok(_) = Command::new(candidate)
            .arg("--version")
            .output()
            .await
        {
            return Some(candidate.clone());
        }
    }
    
    None
}
```

### Solution 4: Force Full Rediscovery After Installation ✅
Instead of just rechecking one tool, force a full tool discovery cycle:

```rust
pub async fn install_tool(...) -> Result<InstallationResult, String> {
    // ... installation code ...
    
    if installation_successful {
        eprintln!("✅ Successfully installed {}", toolName);
        
        // BEFORE: Just recheck the one tool
        // let _ = recheck_tool(toolName.clone(), state).await;
        
        // AFTER: Force full rediscovery to pick up PATH changes
        let discovery_service = state.tool_discovery.write().await;
        discovery_service.force_refresh_all().await;
        drop(discovery_service);
        
        // Then specifically recheck this tool with enhanced search
        let _ = recheck_tool_enhanced(toolName.clone(), state).await;
    }
}
```

---

## 📝 Implementation Plan

### Phase 1: Quick Fix (Immediate) ⚡
1. Add enhanced tool search for npm-specific locations
2. Add enhanced tool search for WinGet-specific locations
3. Force full rediscovery after installation

### Phase 2: Comprehensive Fix (Better) 🎯
1. Implement PATH refresh mechanism
2. Add package-manager-specific search paths
3. Enhanced post-installation verification
4. Show "restart required" message when PATH changes

### Phase 3: UI Improvements (Polish) ✨
1. Show installation progress with PATH check
2. Display "Verifying installation..." step
3. Show "Restart recommended" notification
4. Auto-refresh tools list after installation

---

## 🚀 Quick Fix Implementation

Let me implement the immediate fix that will solve your issues:

### File 1: Enhanced Tool Discovery After Installation

```rust
// src-tauri/src/tools/discovery.rs

impl ToolDiscoveryService {
    /// Enhanced recheck that looks in package-manager-specific locations
    pub async fn recheck_tool_enhanced(
        &self,
        tool_name: &str,
        install_method: Option<&str>
    ) -> Option<ToolRecord> {
        let def = self.catalog.get(tool_name)?;
        
        // Get standard search paths
        let mut search_paths = self.get_search_paths();
        
        // Add package-manager-specific paths
        if let Some(method) = install_method {
            search_paths.extend(self.get_pm_specific_paths(method).await);
        }
        
        // Search in all paths
        for candidate in &def.command_candidates {
            for search_dir in &search_paths {
                let tool_path = search_dir.join(candidate);
                if tool_path.exists() && tool_path.is_file() {
                    // Found it! Update and return
                    return self.check_tool_at_path(tool_name, &tool_path).await;
                }
                
                // Try with common extensions
                #[cfg(target_os = "windows")]
                for ext in &[".exe", ".cmd", ".bat", ".ps1"] {
                    let tool_path_ext = search_dir.join(format!("{}{}", candidate, ext));
                    if tool_path_ext.exists() && tool_path_ext.is_file() {
                        return self.check_tool_at_path(tool_name, &tool_path_ext).await;
                    }
                }
            }
        }
        
        None
    }
    
    async fn get_pm_specific_paths(&self, install_method: &str) -> Vec<PathBuf> {
        match install_method {
            "npm" => self.get_npm_paths().await,
            "winget" => self.get_winget_paths().await,
            "cargo" => self.get_cargo_paths().await,
            _ => vec![]
        }
    }
    
    async fn get_npm_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![];
        
        // Try to get npm prefix
        if let Ok(output) = tokio::process::Command::new("npm")
            .args(&["prefix", "-g"])
            .output()
            .await
        {
            if output.status.success() {
                let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
                paths.push(PathBuf::from(format!("{}/node_modules/.bin", prefix)));
                paths.push(PathBuf::from(format!("{}\\node_modules\\.bin", prefix)));
            }
        }
        
        // Common npm global locations
        #[cfg(target_os = "windows")]
        {
            if let Ok(appdata) = std::env::var("APPDATA") {
                paths.push(PathBuf::from(format!("{}\\npm", appdata)));
            }
            if let Ok(programfiles) = std::env::var("ProgramFiles") {
                paths.push(PathBuf::from(format!("{}\\nodejs", programfiles)));
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            if let Ok(home) = std::env::var("HOME") {
                paths.push(PathBuf::from(format!("{}/.npm-global/bin", home)));
                paths.push(PathBuf::from("/usr/local/bin"));
                paths.push(PathBuf::from("/usr/bin"));
            }
        }
        
        paths
    }
    
    async fn get_winget_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![];
        
        #[cfg(target_os = "windows")]
        {
            // Common WinGet install locations
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                paths.push(PathBuf::from(format!("{}\\AppData\\Local\\Microsoft\\WinGet\\Packages", userprofile)));
                paths.push(PathBuf::from(format!("{}\\AppData\\Local\\Microsoft\\WinGet\\Links", userprofile)));
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
        }
        
        paths
    }
}
```

### File 2: Update install_tool Command

```rust
// src-tauri/src/commands/mod.rs

pub async fn install_tool(...) -> Result<InstallationResult, String> {
    // ... existing installation code ...
    
    if installation_successful {
        eprintln!("✅ Successfully installed {}", toolName);
        
        // Enhanced recheck with package-manager-specific paths
        let discovery_service = state.tool_discovery.write().await;
        let install_method = Some(tool_def.install_method.as_str());
        let updated_record = discovery_service
            .recheck_tool_enhanced(&toolName, install_method)
            .await;
        drop(discovery_service);
        
        if let Some(record) = updated_record {
            if record.installed {
                eprintln!("✅ Verified installation: {} at {}", 
                    toolName, 
                    record.path.as_deref().unwrap_or("unknown")
                );
            } else {
                eprintln!("⚠️  Installation reported success but tool not found in PATH");
                eprintln!("   You may need to restart the application");
            }
        }
    }
}
```

---

## 🎯 Expected Results After Fix

### For npm tools (wappalyzer):
✅ Installation succeeds → Immediately shows as installed  
✅ Recheck Status → Finds tool in npm global bin  
✅ Shows correct path: `C:\Users\...\AppData\Roaming\npm\wappalyzer.cmd`

### For WinGet tools (jq):
✅ Installation succeeds → Immediately shows as installed  
✅ Recheck Status → Finds tool in WinGet install location  
✅ Shows correct path: `C:\Program Files\...\jq.exe`

### For WinGet tools (netcat):
❌ Installation fails → Shows clear error message  
💡 Suggests alternative: "Package not found. Try `ncat` or install from https://nmap.org/"

---

## 📊 Testing Checklist

- [ ] Install npm tool (wappalyzer)
- [ ] Verify shows as "Installed" immediately
- [ ] Check path is correct
- [ ] Recheck Status works
- [ ] Install WinGet tool (jq)
- [ ] Verify shows as "Installed"
- [ ] Install another tool via different package manager
- [ ] Verify all show correct status

---

**Status**: Ready to implement
**Priority**: HIGH (user-facing bug)
**Estimated Time**: 30 minutes
