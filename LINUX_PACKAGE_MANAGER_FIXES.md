# Linux Package Manager Fixes - Implementation Plan

## Issues Identified

### 1. Go Install - trufflehog
**Problem**: `replace directives` in go.mod causing `go install` to fail
**Error**: `The go.mod file for the module providing named packages contains one or more replace directives`

**Solution**: 
- Clone the repository first
- Build from source using `go build` instead of `go install`
- Install the binary to GOPATH/bin manually

### 2. Git+Pip - eyewitness  
**Problem**: PEP 668 - externally-managed-environment
**Error**: `error: externally-managed-environment` - can't install system-wide packages with pip

**Solution**:
- Switch to `pipx` for Python CLI tools on Linux
- pipx creates isolated virtual environments automatically
- Falls back to git+pip with `python3 -m venv` if pipx not available

### 3. npm - wappalyzer
**Problem**: Permission denied for global install  
**Error**: `EACCES: permission denied, mkdir '/usr/local/lib/node_modules/wappalyzer'`

**Solution**:
- Use npm user-level install with `--prefix ~/.local`
- Add ~/.local/bin to PATH automatically  
- No sudo required

---

## Implementation Changes

### File: `go_install.rs`
Add special handling for modules with replace directives:

```rust
pub async fn install_from_source(
    &self,
    git_repo: &str,
    module_path: &str,
    tool_name: &str,
) -> Result<InstallationResult, String> {
    // For tools with replace directives:
    // 1. Clone the repo
    // 2. cd into it
    // 3. go build -o $GOPATH/bin/toolname
    // 4. chmod +x
}
```

### File: `git_pip_installer.rs`  
Detect Linux and use pipx instead:

```rust
pub async fn install_with_pipx(
    &self,
    git_repo: &str,
    tool_name: &str,
) -> Result<InstallationResult, String> {
    // Linux-specific:
    // pipx install git+{git_repo}
    // Automatically creates venv, no system packages affected
}
```

### File: `npm_installer.rs`
Use user-level npm install:

```rust
async fn install_npm_package_user_level(
    &self,
    package_name: &str,
    tool_name: &str,
) -> Result<String> {
    // npm install -g {package} --prefix ~/.local
    // Installs to ~/.local/bin (user-writable)
}
```

---

## Priority Order

1. **HIGH**: Fix git+pip → pipx (most critical, affects Python tools)
2. **HIGH**: Fix npm permissions (easy fix, big impact)  
3. **MEDIUM**: Fix go install for replace directives (only affects a few tools)

---

## Testing Plan

1. Test on Kali Linux (already have environment)
2. Verify each installation method works:
   - trufflehog (go from source)
   - eyewitness (pipx)
   - wappalyzer (npm user-level)
3. Ensure PATH is updated automatically
4. Test rollback if installation fails

---

## Implementation Steps

### Step 1: Add pipx detection and installation
- Check if pipx is installed
- Offer to install pipx if missing (`apt install pipx`)
- Use pipx as primary Python tool installer on Linux

### Step 2: Update git_pip_installer.rs
- Add OS detection
- On Linux: use pipx
- On Windows: keep current git+pip method
- On macOS: use pipx if available, fallback to git+pip

### Step 3: Update npm_installer.rs  
- Change from `-g` (global) to `--prefix ~/.local` (user)
- Add ~/.local/bin to PATH instructions
- Detect if ~/.local/bin is already in PATH

### Step 4: Update go_install.rs
- Add `install_from_source()` method
- Detect if module uses replace directives (check go.mod after clone)
- Fallback to source build if `go install` fails

---

## Next Action
Implement fixes in order:
1. pipx integration
2. npm user-level install
3. go source build fallback
