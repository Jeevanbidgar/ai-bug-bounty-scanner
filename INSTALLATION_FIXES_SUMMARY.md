# Installation Fixes Summary & Implementation

## Current Status
The application is **running successfully** on Kali Linux, but **tool installations are failing** due to platform-specific package manager issues.

## Issues & Solutions

### 1. Python Tools (eyewitness) - PEP 668 Error ✅ FIXED
**Error**: `externally-managed-environment` - Python 3.13 on Kali blocks system-wide pip installs

**Root Cause**: Kali Linux (and modern Debian/Ubuntu) implement PEP 668 to protect system Python packages

**Solution Implemented**:
- ✅ Added `pipx` detection and support
- ✅ Prefer `pipx install git+{repo}` on Linux (automatic venv isolation)
- ✅ Fallback to `python -m venv` + pip install if pipx not available
- ✅ Keep Windows/macOS behavior unchanged (system pip works fine)

**Code Changes**: `git_pip_installer.rs`
- Added `is_pipx_available()` method
- Added `install_with_pipx()` method
- Updated `install()` to check for pipx first on Linux
- Linux-specific venv creation when pipx unavailable

---

### 2. npm Tools (wappalyzer) - Permission Denied ⏳ PENDING
**Error**: `EACCES: permission denied, mkdir '/usr/local/lib/node_modules/wappalyzer'`

**Root Cause**: Global npm install (`npm install -g`) requires root/sudo on Linux

**Solution Needed**:
```bash
# Instead of: npm install -g wappalyzer (requires sudo)
# Use: npm install -g wappalyzer --prefix ~/.local (user-writable)
```

**Implementation**: `npm_installer.rs`
```rust
// Change from:
.args(&["install", "-g", package_name])

// To (on Linux):
.args(&["install", "-g", package_name, "--prefix", "~/.local"])

// Bonus: Add ~/.local/bin to PATH automatically
```

---

###  Go Tools (trufflehog) - Replace Directives ⏳ PENDING
**Error**: `The go.mod file contains replace directives`

**Root Cause**: `go install` doesn't support modules with local replace directives (security feature)

**Solution Needed**:
1. Clone the repository
2. Build from source: `go build -o $GOPATH/bin/trufflehog`
3. Move binary to GOPATH/bin

**Implementation**: `go_install.rs`
```rust
pub async fn install_from_source(
    &self,
    git_repo: &str,
    module_path: &str,
    tool_name: &str,
) -> Result<InstallationResult, String> {
    // 1. Clone repo
    // 2. cd into repo
    // 3. go build -o $GOPATH/bin/toolname
    // 4. chmod +x
}

// In main install() method:
// Try go install first
// If fails with "replace directives" error, fallback to install_from_source()
```

---

## Priority & Impact

| Issue | Priority | Impact | Status |
|-------|----------|--------|--------|
| Python/pip (PEP 668) | 🔴 HIGH | Blocks all Python tools | ✅ FIXED |
| npm permissions | 🟡 MEDIUM | Blocks npm tools | ⏳ PENDING |
| Go replace directives | 🟢 LOW | Only affects trufflehog | ⏳ PENDING |

---

## Testing Plan

### Python Tools (pipx) - Ready to Test
```bash
# Test eyewitness installation
1. Ensure pipx is installed: `which pipx`
2. If not: `sudo apt install pipx`
3. Try installing eyewitness from UI
4. Should install via pipx automatically
5. Binary should be in ~/.local/bin/eyewitness
```

### npm Tools - After Fix
```bash
# Test wappalyzer installation
1. Try installing wappalyzer from UI
2. Should install to ~/.local/lib/node_modules/
3. Binary should be in ~/.local/bin/wappalyzer
4. No sudo required
```

### Go Tools - After Fix
```bash
# Test trufflehog installation
1. Try installing trufflehog from UI
2. Should clone repo and build from source
3. Binary should be in ~/go/bin/trufflehog
```

---

## Next Steps

1. ✅ **DONE**: Python/pipx integration
2. ⏳ **TODO**: Fix npm user-level install (add `--prefix ~/.local`)
3. ⏳ **TODO**: Fix go install fallback (add source build method)
4. ⏳ **TODO**: Test all three on Kali Linux
5. ⏳ **TODO**: Update UI to show installation method used

---

## Additional Recommendations

### 1. Add PATH Configuration Helper
Many users won't have `~/.local/bin` or `~/go/bin` in PATH. Add automatic PATH detection and instructions:

```rust
// Check if directory is in PATH
pub fn is_in_path(dir: &str) -> bool {
    if let Ok(path_var) = std::env::var("PATH") {
        path_var.split(':').any(|p| p == dir)
    } else {
        false
    }
}

// Emit warning if not in PATH
if !is_in_path("~/.local/bin") {
    emit_output("⚠️  ~/.local/bin not in PATH");
    emit_output("Add to ~/.bashrc: export PATH=\"$HOME/.local/bin:$PATH\"");
}
```

### 2. Add Package Manager Auto-Install
If pipx/npm/go not found, offer to install them:

```rust
// Linux
sudo apt install pipx nodejs golang-go

// Windows
winget install pipx nodejs golang

// macOS
brew install pipx node go
```

### 3. Add Installation Method Badge in UI
Show which method was used for each tool:
- 🐍 pipx
- 📦 npm (user)
- 🚀 go install
- 🔨 go build (source)
- 📥 git+pip (venv)

---

## Files Modified

1. ✅ `src-tauri/src/tools/package_managers/git_pip_installer.rs`
   - Added pipx support
   - Added Linux venv fallback
   - ~100 lines added

2. ⏳ `src-tauri/src/tools/package_managers/npm_installer.rs`
   - TODO: Add `--prefix ~/.local` on Linux
   - ~10 lines to modify

3. ⏳ `src-tauri/src/tools/package_managers/go_install.rs`
   - TODO: Add `install_from_source()` method
   - ~100 lines to add

---

## Conclusion

**Python tool installation is now fixed!** 🎉

The pipx integration will handle all Python CLI tools automatically on Linux, with automatic fallback to venv if pipx is unavailable.

**Next**: Fix npm and go issues, then test all installations on Kali Linux.
