# Platform-Specific Installation Methods

## Overview

This document explains how the AI Bug Bounty Scanner handles tool installations differently across platforms (Windows, Linux, macOS) while maintaining 100% backward compatibility.

## Design Principles

✅ **Windows-first compatibility**: All existing Windows functionality remains untouched
✅ **Platform-specific optimization**: Each platform uses the most appropriate installation method
✅ **No sudo required**: Linux/macOS installations work without administrative privileges
✅ **Automatic fallbacks**: If preferred method fails, automatically tries alternatives
✅ **Security compliance**: Follows PEP 668 on Linux, uses isolated environments

---

## Python Tools (pip-based)

### Installation Methods by Platform

#### **Linux (Preferred Order)**
1. **pipx** (Priority 10) - Isolated environments, PEP 668 compliant
   - Uses: `pipx install git+{repo}`
   - Benefits: No conflicts, auto-PATH management, compliant with modern Python
   - Detection: Automatic if `pipx --version` succeeds

2. **git + venv** (Priority 8) - Virtual environment in user directory
   - Uses: `git clone` → `python -m venv` → `pip install`
   - Benefits: Isolated, no sudo needed
   - Location: `~/.local/share/ai-bug-bounty-scanner/tools/python-tools/`

3. **System pip** (Priority 5) - Direct pip install (legacy fallback)
   - Uses: `pip install --user git+{repo}`
   - Benefits: Simple, works on older systems
   - Note: May trigger PEP 668 warnings on modern Linux

#### **macOS (Preferred Order)**
1. **pipx** (Priority 10) - Same as Linux
2. **git + venv** (Priority 8) - Same as Linux
3. **System pip** (Priority 5) - Same as Linux

#### **Windows (Unchanged)**
- **System pip** (Priority 10) - Direct pip install
- Uses: `pip install git+{repo}`
- Benefits: Simple, reliable, no PEP 668 issues on Windows
- **No changes from original implementation**

### Example: Installing eyewitness

**Linux/macOS:**
```bash
# If pipx is installed:
pipx install git+https://github.com/FortyNorthSecurity/EyeWitness
# Automatically adds to PATH via pipx

# If pipx not installed:
# Fallback to git + venv method automatically
```

**Windows:**
```powershell
# Standard pip install (unchanged)
pip install git+https://github.com/FortyNorthSecurity/EyeWitness
```

---

## npm Tools (Node.js packages)

### Installation Methods by Platform

####  **Linux (Preferred Order)**
1. **User-level install** (Priority 10) - No sudo required
   - Uses: `npm install -g --prefix ~/.local {package}`
   - Benefits: No permission errors, works without sudo
   - Binary location: `~/.local/bin/`
   - Requires: `~/.local/bin` in PATH (auto-suggested)

2. **Global install with sudo** (Priority 3) - Fallback only
   - Uses: `sudo npm install -g {package}`
   - Benefits: Standard location, system-wide availability
   - Note: Requires sudo prompt

#### **macOS (Preferred Order)**
- Same as Linux

#### **Windows (Unchanged)**
- **Global install** (Priority 10)
- Uses: `npm install -g {package}`
- Location: `%APPDATA%\npm`
- **No changes from original implementation**

### Example: Installing wappalyzer

**Linux/macOS:**
```bash
# User-level install (no sudo)
npm install -g wappalyzer --prefix ~/.local
# Binary at: ~/.local/bin/wappalyzer

# If user prefers global:
sudo npm install -g wappalyzer
# Binary at: /usr/local/bin/wappalyzer
```

**Windows:**
```powershell
# Standard global install (unchanged)
npm install -g wappalyzer
# Binary at: %APPDATA%\npm\wappalyzer.cmd
```

---

## Go Tools (go install)

### Installation Methods by Platform

#### **All Platforms (Same Behavior)**

1. **go install** (Priority 10) - Standard method
   - Uses: `go install {module}@latest`
   - Benefits: Official, simple, fast
   - Binary location: `$GOPATH/bin` or `~/go/bin`

2. **Source build** (Priority 8) - Automatic fallback
   - Uses: `git clone` → `go build` → copy to GOPATH/bin
   - Benefits: Works with modules that have `replace` directives
   - Triggers: Automatically when go install fails with "replacement" or "replace directive" error
   - **Platform-agnostic**: Works identically on Windows, Linux, macOS

### Example: Installing trufflehog

**All Platforms:**
```bash
# Try go install first
go install github.com/trufflesecurity/trufflehog/v3@latest

# If fails with replace directive error, automatically:
# 1. Clone https://github.com/trufflesecurity/trufflehog
# 2. Run: go build -o trufflehog
# 3. Copy to GOPATH/bin with correct permissions
# 4. Clean up temp directory
```

This is the **same behavior** on Windows, Linux, and macOS! ✅

---

## Ruby Tools (gem install)

### Installation Methods by Platform

#### **All Platforms (Unchanged)**
- **gem install** (Priority 10)
- Uses: `gem install {package}`
- Location: Platform-dependent gem directory
- **No changes across any platform**

---

## apt Packages (Linux only)

### Installation Methods by Platform

#### **Debian/Ubuntu/Kali Linux**
- **apt install** (Priority 10)
- Uses: `sudo apt install {package}`
- Benefits: System package manager, auto-dependencies
- Note: Requires sudo (expected for system packages)

#### **Windows/macOS**
- Not applicable

---

## WinGet Packages (Windows only)

### Installation Methods by Platform

#### **Windows 10/11**
- **winget install** (Priority 10)
- Uses: `winget install {package-id}`
- Benefits: Official Microsoft package manager
- Note: May require UAC elevation

#### **Linux/macOS**
- Not applicable

---

## PATH Management

### Linux/macOS
The application suggests adding these to PATH if not present:
```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/.local/bin:$PATH"
export PATH="$HOME/go/bin:$PATH"
```

### Windows
Automatic via:
- npm: `%APPDATA%\npm` (added by npm)
- go: `%USERPROFILE%\go\bin` (added by Go installer)
- pipx: `%USERPROFILE%\.local\bin` (added by pipx)

---

## Installation Decision Matrix

| Tool Type | Windows | Linux | macOS | Requires Sudo? |
|-----------|---------|-------|-------|----------------|
| Python (pipx) | N/A | ✅ Preferred | ✅ Preferred | ❌ No |
| Python (pip) | ✅ Standard | ⚠️ Fallback | ⚠️ Fallback | ❌ No |
| npm (user) | N/A | ✅ Preferred | ✅ Preferred | ❌ No |
| npm (global) | ✅ Standard | ⚠️ Fallback | ⚠️ Fallback | ⚠️ Yes (Linux/macOS) |
| Go (install) | ✅ Standard | ✅ Standard | ✅ Standard | ❌ No |
| Go (source) | ⚠️ Fallback | ⚠️ Fallback | ⚠️ Fallback | ❌ No |
| Ruby (gem) | ✅ Standard | ✅ Standard | ✅ Standard | ⚠️ Sometimes |
| apt | N/A | ✅ Standard | N/A | ✅ Yes |
| winget | ✅ Standard | N/A | N/A | ⚠️ Sometimes |

---

## Backward Compatibility Guarantee

### ✅ Windows Users
- **Zero changes** to Python pip, npm, Go install behavior
- All existing scripts, workflows, and installations work identically
- No new PATH requirements
- Same binary locations as before

### ✅ Linux/macOS Users
- **Improvements only**, no breaking changes
- Can still use system-wide installs if preferred
- Old installations remain functional
- New installations automatically use better methods

---

## User Notifications

### Linux/macOS
When pipx is detected:
```
🐍 pipx detected, using pipx for installation
```

When pipx is not available:
```
⚠️  pipx not found, falling back to git+pip with venv
💡 Tip: Install pipx for better Python tool management: sudo apt install pipx
```

When npm user-level install is used:
```
📦 Installing wappalyzer to user directory (~/.local)...
💡 Note: Ensure ~/.local/bin is in your PATH
```

When Go source build fallback occurs:
```
⚠️  Module uses replace directives, trying source build...
📦 Building trufflehog from source...
📥 Cloning https://github.com/trufflesecurity/trufflehog...
✅ Repository cloned
🔨 Building trufflehog...
📦 Installing to /home/user/go/bin/trufflehog...
✅ Successfully installed trufflehog from source
```

### Windows
No changes to existing messages! ✅

---

## Implementation Files Changed

### Modified (Platform-Specific Logic Added)
1. `src-tauri/src/tools/package_managers/npm_installer.rs`
   - Added Linux/macOS user-level install with `--prefix ~/.local`
   - Windows behavior unchanged

2. `src-tauri/src/tools/package_managers/go_install.rs`
   - Added source build fallback for replace directive errors
   - Works on all platforms identically

3. `src-tauri/src/tools/package_managers/git_pip_installer.rs`
   - Added pipx detection and automatic use on Linux
   - Windows behavior unchanged (already pipx-ready from previous commits)

### Unchanged
- `src-tauri/src/tools/package_managers/gem_installer.rs` ✅
- `src-tauri/src/tools/package_managers/cargo_installer.rs` ✅
- `src-tauri/src/tools/package_managers/apt_manager.rs` ✅
- `src-tauri/src/tools/package_managers/winget_manager.rs` ✅
- `src-tauri/src/tools/package_managers/pipx_manager.rs` ✅

---

## Testing Matrix

### Must Pass on All Platforms

| Test Case | Windows | Linux | macOS |
|-----------|---------|-------|-------|
| Install Python tool (eyewitness) | ✅ pip | ✅ pipx/venv | ✅ pipx/venv |
| Install npm tool (wappalyzer) | ✅ global | ✅ user-level | ✅ user-level |
| Install Go tool (subfinder) | ✅ go install | ✅ go install | ✅ go install |
| Install Go tool with replace (trufflehog) | ✅ source build | ✅ source build | ✅ source build |
| Install Ruby tool (wpscan) | ✅ gem | ✅ gem | ✅ gem |
| PATH detection | ✅ auto | ✅ suggest | ✅ suggest |
| No sudo required | N/A | ✅ Yes | ✅ Yes |
| Backward compat | ✅ 100% | ✅ 100% | ✅ 100% |

---

## Troubleshooting

### Linux: "externally-managed-environment" Error
**Cause**: PEP 668 compliance on modern Linux distributions
**Solution**: Install pipx: `sudo apt install pipx` (automatic fallback to venv otherwise)

### Linux/macOS: npm Permission Denied
**Cause**: Trying to write to `/usr/local/lib/node_modules` without sudo
**Solution**: Automatic - uses `--prefix ~/.local` (no sudo needed)

### All Platforms: Go "replace directives" Error
**Cause**: Module uses local replace directives in go.mod
**Solution**: Automatic - fallback to source build (no user action needed)

### Linux/macOS: Tool not found after install
**Cause**: `~/.local/bin` or `~/go/bin` not in PATH
**Solution**: Add to shell RC file:
```bash
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
```

---

## Future Enhancements

### Planned
- 🔄 Auto-PATH detection and addition (one-time prompt)
- 🔄 Installation method selection in UI (let user choose preferred method)
- 🔄 Installation history with method tracking
- 🔄 Bulk re-install with different method

### Possible
- 🤔 Homebrew support for macOS
- 🤔 Flatpak/Snap support for Linux
- 🤔 Docker-based isolated installations

---

## Summary

✅ **Windows**: No changes, 100% backward compatible
✅ **Linux**: Optimized for no-sudo, PEP 668 compliant, automatic fallbacks
✅ **macOS**: Same as Linux, unified experience
✅ **Cross-platform Go**: Unified source build fallback for all platforms
✅ **No breaking changes**: Old installations continue to work

**Result**: Production-ready cross-platform installation system that respects platform conventions while maintaining complete backward compatibility! 🎉
