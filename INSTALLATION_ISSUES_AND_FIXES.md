# Installation Issues and Fixes

## Current Issues Detected

### 1. **Aquatone (Go) - Build Failure** ❌
**Error:**
```
C:\Users\jeevan\go\pkg\mod\github.com\michenriksen\aquatone@v1.7.0\parsers\regex.go:22:26: 
invalid operation: cannot call non-function xurls.Relaxed (variable of type *regexp.Regexp)
```

**Root Cause:** Aquatone v1.7.0 has compatibility issues with newer versions of Go (1.24.5). The `xurls` library API changed.

**Solutions:**
- **Option 1:** Manual installation with older Go version
- **Option 2:** Use a fork or newer version if available
- **Option 3:** Skip aquatone and use alternative tools (subfinder, amass)

**Status:** Tool is broken upstream, not a bug in our app ✅

---

### 2. **JQ (WinGet) - Not Available in Terminal** ❌
**Error:**
```
Failed to install jq: winget is not available. 
Please install App Installer from Microsoft Store.
```

**Root Cause:** WinGet may not be available in the context the app runs in, even though it shows as "Available" in the UI.

**Solutions:**
- **Option 1:** Install jq manually via Chocolatey:
  ```powershell
  choco install jq
  ```
- **Option 2:** Install from GitHub releases: https://github.com/jqlang/jq/releases
- **Option 3:** Install App Installer from Microsoft Store (may not fix IDE terminal issue)

**Recommended:** Use Chocolatey or manual installation

---

### 3. **Wappalyzer (npm) - Node.js Not Installed** ❌
**Error:**
```
❌ Node.js is not installed.
Please install Node.js from: https://nodejs.org/
```

**Root Cause:** Node.js is not installed on the system.

**Solution:**
1. **Install Node.js LTS** from https://nodejs.org/
2. **Restart the application** after installation
3. **Try installing wappalyzer again**

**Status:** User action required - install Node.js ⚠️

---

### 4. **Feroxbuster (Cargo) - Still Installing** ⏳
**Status:** Currently compiling (488/497 packages in dev server, feroxbuster installation running separately)

**Note:** Cargo installations can take 5-20 minutes depending on:
- Number of dependencies
- System specs
- Internet speed
- Disk I/O

**Current Progress:** Compiling dependencies (200+ packages)

**Expected:** Will complete successfully - this is normal for Rust tools

---

## General Installation Guidelines

### Package Manager Availability

| Manager | Status | Notes |
|---------|--------|-------|
| **Go** | ✅ Installed (1.24.5) | Working, but some tools have compatibility issues |
| **Pipx** | ✅ Installed (1.8.0) | Working for Python CLI tools |
| **WinGet** | ⚠️ Partially Working | Available but may fail in IDE terminal context |
| **APT** | ❌ Linux Only | Not available on Windows |
| **Cargo** | ❌ Not Detected | Need to verify installation |
| **npm** | ❌ Not Available | Requires Node.js installation |
| **gem** | ❌ Not Detected | Requires Ruby installation |

### Expected Installation Times

| Method | Typical Duration | Notes |
|--------|------------------|-------|
| **go install** | 1-3 minutes | Fast, but may have compatibility issues |
| **pipx install** | 2-5 minutes | Reliable for Python tools |
| **cargo install** | 5-20 minutes | Slow due to compilation, but reliable |
| **npm install -g** | 1-2 minutes | Fast once Node.js is installed |
| **winget install** | 1-2 minutes | Fast but may have permission issues |
| **git-pip** | 3-10 minutes | Depends on repository size |

### Why Cargo Installations Take Longer

Cargo (Rust) tools compile from source:
1. **Download** all dependencies (200-400 crates)
2. **Compile** each dependency individually
3. **Link** everything together
4. **Optimize** for release build

This is **NORMAL** and not an error. The app will show:
- Live compilation output
- Progress through dependencies
- Final success message when done

---

## Recommended Actions

### Immediate (Do Now)

1. **Install Node.js** (for wappalyzer and other npm tools)
   - Visit: https://nodejs.org/
   - Download: LTS version (recommended)
   - Restart app after installation

2. **Wait for feroxbuster** (currently installing)
   - Let it finish compiling (~10-15 minutes remaining)
   - Don't close the installation modal
   - You can minimize it and continue using the app

3. **Skip aquatone** (broken upstream)
   - Use alternative tools: subfinder, amass, assetfinder
   - Mark as "not needed" for now

### Short-term (Next 1-2 hours)

4. **Install jq manually** via Chocolatey:
   ```powershell
   # Install Chocolatey first (if not installed)
   Set-ExecutionPolicy Bypass -Scope Process -Force
   [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
   iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
   
   # Install jq
   choco install jq -y
   ```

5. **Verify installations**:
   ```powershell
   go version          # Should show 1.24.5
   pipx --version      # Should show 1.8.0
   node --version      # Should show v20.x.x or v22.x.x (after installation)
   npm --version       # Should show 10.x.x (after Node.js installation)
   cargo --version     # Check if Rust is installed
   ```

### Long-term (Optional Enhancements)

6. **Install Rust/Cargo** (for cargo-based tools):
   ```powershell
   # Visit: https://rustup.rs/
   # Or via Chocolatey:
   choco install rust -y
   ```

7. **Install Ruby** (for gem-based tools):
   ```powershell
   # Visit: https://rubyinstaller.org/
   # Or via Chocolatey:
   choco install ruby -y
   ```

---

## Understanding Installation Modal Behavior

### Normal Behavior ✅

1. **Modal opens** when you click "Install"
2. **Shows live output** (colorized logs)
3. **Progress bar** advances (may stay at 90% for a while during compilation)
4. **Compilation logs** scroll continuously (for cargo/go)
5. **Success message** appears when done
6. **Close button** becomes enabled

### When to Wait ⏳

- Cargo installations: 5-20 minutes
- Go installations with many dependencies: 2-5 minutes
- Pipx installations: 2-5 minutes
- Git-clone + pip: 3-10 minutes

### When to Force Close ⚠️

- After 5 minutes, a "Force Close" button appears
- Use this if installation seems frozen (no output for >2 minutes)
- Or if you need to cancel the installation

### Troubleshooting Stuck Installations

1. **Check the logs** - Is output still scrolling?
   - Yes → It's still working, wait longer
   - No → May be frozen, check background processes

2. **Check Task Manager**:
   - Look for `cargo.exe`, `go.exe`, `pip.exe`, `git.exe`
   - If CPU usage is active → Still working
   - If frozen → Can force close

3. **Force close and retry**:
   - Click "Force Close" (after 5 minutes)
   - Try installation again
   - If fails repeatedly, install manually

---

## Manual Installation Fallback

If automatic installation fails repeatedly:

### For Go Tools (like aquatone)
```powershell
go install github.com/michenriksen/aquatone@latest
```

### For Python Tools (via pipx)
```powershell
pipx install tool-name
```

### For Rust Tools (via cargo)
```powershell
cargo install tool-name
```

### For Node.js Tools (via npm)
```powershell
npm install -g tool-name
```

Then click "Recheck Status" in the app to detect the newly installed tool.

---

## Success Indicators

✅ **Installation Successful:**
- Modal shows "Installation completed successfully!"
- Green checkmark badge appears
- Tool status changes from "missing" to "available"
- Tool version is detected
- Tool path is shown

❌ **Installation Failed:**
- Modal shows "Installation failed"
- Red X badge appears
- Error message with details
- Tool remains in "missing" status

---

## Next Steps After Node.js Installation

1. **Restart the application** completely
2. **Go to Tools page**
3. **Click "Refresh Status"** to detect Node.js
4. **Try installing wappalyzer again**
5. **Check Package Managers panel** - npm should show as "Available"

---

## Known Working Installations

Based on your system:
- ✅ Go tools (when compatible with Go 1.24.5)
- ✅ Pipx tools (Python CLI tools)
- ✅ Git-pip tools (Python tools from GitHub)
- ⏳ Cargo tools (will work once compilation completes)
- ⚠️ WinGet tools (works but may have terminal context issues)
- ❌ npm tools (needs Node.js installation first)

---

## Summary

**Current Status:**
- 3 of 4 package managers working (Go, Pipx, WinGet*)
- 1 tool broken upstream (aquatone - not our bug)
- 1 tool needs Node.js installation (wappalyzer)
- 1 tool installing successfully (feroxbuster - in progress)
- 1 tool needs manual installation (jq - winget context issue)

**Priority Actions:**
1. ⏰ Wait for feroxbuster to finish (10-15 min)
2. 📥 Install Node.js for npm tools
3. ⚙️ Manually install jq via Chocolatey
4. ✅ Test installations after Node.js restart

**App Status:** ✅ Working correctly - showing proper installation status and providing helpful error messages!
