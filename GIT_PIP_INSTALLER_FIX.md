# Git-Pip Installer File Watcher Fix

## Problem

When installing tools via `git-pip` method (git clone + pip install), the app was crashing because:

1. Tools were being cloned into `src-tauri/tools/python-tools/`
2. Tauri's dev mode file watcher detected these changes
3. Each file change triggered a rebuild
4. Hundreds of files from git clone caused continuous rebuilds
5. App crashed/restarted repeatedly

## Solution

### 1. **Moved Tool Installation Directory** ✅

Updated `GitPipInstaller::new()` to use different paths:

**Dev Mode (debug):**
- Old: `src-tauri/tools/python-tools/` ❌ (inside watched directory)
- New: `tools/python-tools/` ✅ (at workspace root, outside src-tauri)

**Production Mode (release):**
- Uses: `%LOCALAPPDATA%/ai-bug-bounty-scanner/tools/python-tools/` ✅ (user data directory)

### 2. **Added Dependencies** ✅

Added `dirs = "5.0"` to `Cargo.toml` for cross-platform path resolution.

### 3. **Updated .gitignore** ✅

Added patterns to ignore tool installations:
```
tools/
src-tauri/tools/
```

## Recovery Steps

If your app is currently stuck in a rebuild loop:

### Option 1: Quick Fix (Recommended)
1. **Stop the dev server** (Ctrl+C in terminal)
2. **Delete the problematic directory:**
   ```powershell
   Remove-Item -Recurse -Force src-tauri\tools\python-tools\
   ```
3. **Restart the dev server:**
   ```powershell
   npm run tauri dev
   ```

### Option 2: Clean Build
1. Stop the dev server
2. Delete both tool directories:
   ```powershell
   Remove-Item -Recurse -Force src-tauri\tools\
   Remove-Item -Recurse -Force tools\
   ```
3. Clean Cargo build cache:
   ```powershell
   cd src-tauri
   cargo clean
   cd ..
   ```
4. Restart:
   ```powershell
   npm run tauri dev
   ```

### Option 3: Fresh Start
1. Stop all processes
2. Delete node_modules and reinstall:
   ```powershell
   Remove-Item -Recurse -Force frontend\node_modules\
   cd frontend
   npm install
   cd ..
   ```
3. Follow Option 2 steps
4. Restart dev server

## Testing the Fix

After restarting the dev server with the fix:

1. Navigate to Tools page
2. Find a tool with `git-pip` install method (e.g., eyewitness, feroxbuster)
3. Click "Install"
4. **Expected behavior:**
   - Installation modal opens
   - Shows live output
   - App remains stable (no crashes)
   - Tools are installed to `tools/python-tools/` (not `src-tauri/tools/`)

5. **Verify installation location:**
   ```powershell
   # Should exist
   Test-Path tools\python-tools\eyewitness
   
   # Should NOT exist (or be empty)
   Test-Path src-tauri\tools\python-tools\
   ```

## Technical Details

### Code Changes

**File:** `src-tauri/src/tools/package_managers/git_pip_installer.rs`

```rust
impl GitPipInstaller {
    pub fn new() -> Self {
        let install_base_dir = if cfg!(debug_assertions) {
            // Dev mode: workspace root/tools/python-tools
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .parent() // Go up from src-tauri
                .unwrap_or_else(|| Path::new("."))
                .join("tools")
                .join("python-tools")
        } else {
            // Production: user data directory
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("ai-bug-bounty-scanner")
                .join("tools")
                .join("python-tools")
        };
        
        Self { install_base_dir }
    }
}
```

### Why This Works

1. **Dev Mode:** Tools install to workspace root, which Tauri doesn't watch
2. **Production:** Tools install to user's local data folder (standard practice)
3. **No More Rebuilds:** File watcher only monitors `src-tauri/src/` for code changes
4. **Stable Development:** Can install tools without crashing the app

## Benefits

✅ No more app crashes during tool installation  
✅ Stable dev environment  
✅ Proper separation of concerns (code vs. data)  
✅ Production-ready: Uses standard app data directory  
✅ Cross-platform compatible  
✅ Git-ignored: Tool installations won't clutter git status  

## Notes

- Old installations in `src-tauri/tools/` can be safely deleted
- The fix is backward compatible (doesn't break existing functionality)
- Tools will need to be reinstalled after the fix (they'll go to the new location)
- In production builds, tools will be in user's app data folder

## Related Files Modified

1. `src-tauri/src/tools/package_managers/git_pip_installer.rs` - Path logic
2. `src-tauri/Cargo.toml` - Added `dirs` dependency
3. `.gitignore` - Added tool directory patterns

---

**Status:** ✅ Fixed and Ready for Testing  
**Priority:** Critical (app stability)  
**Impact:** All git-pip tool installations (eyewitness, feroxbuster, etc.)
