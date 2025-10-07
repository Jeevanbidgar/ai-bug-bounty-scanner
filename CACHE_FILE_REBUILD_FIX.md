# Cache File Rebuild Fix

## Problem
The Tauri dev server was automatically restarting whenever tool discovery operations occurred because:

1. **File Watcher Trigger**: The file `src-tauri/data/tool_discovery_cache.json` was being updated during tool discovery and installation checks
2. **Rebuild Loop**: Tauri's file watcher monitors the `src-tauri` directory for changes and triggers a rebuild/restart whenever files change
3. **Disruptive Experience**: This caused the app to restart during normal operations like checking for tool updates or discovering tools

## Root Cause
```
Tool Discovery/Check → Writes to src-tauri/data/tool_discovery_cache.json
                    ↓
           Tauri File Watcher Detects Change
                    ↓
          Triggers Rust Backend Rebuild
                    ↓
           Application Restarts 🔄
```

## Solution
**Move all runtime-generated cache and data files outside the `src-tauri` directory.**

### Changes Made

#### 1. Updated `src-tauri/src/tools/discovery.rs`
- **Removed**: Hardcoded `CACHE_FILE` constant pointing to `data/tool_discovery_cache.json`
- **Added**: Dynamic cache path computation based on build mode:
  - **Development**: `<workspace-root>/data/tool_discovery_cache.json`
  - **Production**: `<app-data-dir>/ai-bug-bounty-scanner/data/tool_discovery_cache.json`

```rust
fn get_cache_file_path() -> PathBuf {
    #[cfg(debug_assertions)]
    {
        // Development: workspace root/data (outside src-tauri)
        let workspace_root = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."));
        
        let workspace_root = if workspace_root.ends_with("src-tauri") {
            workspace_root.parent().unwrap_or(&workspace_root).to_path_buf()
        } else {
            workspace_root
        };
        
        workspace_root.join("data").join("tool_discovery_cache.json")
    }
    
    #[cfg(not(debug_assertions))]
    {
        // Production: app data directory
        if let Some(data_dir) = dirs::data_dir() {
            data_dir
                .join("ai-bug-bounty-scanner")
                .join("data")
                .join("tool_discovery_cache.json")
        } else {
            PathBuf::from("data").join("tool_discovery_cache.json")
        }
    }
}
```

#### 2. Updated `.gitignore`
- Added `data/tool_discovery_cache.json` to ignore list
- Added `src-tauri/data/` to ignore list (deprecated location)

#### 3. Fixed Unused Import Warning
- Removed unused `std::time::Duration` import from `cargo_installer.rs`

#### 4. Cleanup
- Removed old cache file from `src-tauri/data/tool_discovery_cache.json`

## New Cache File Locations

### Development Mode
```
d:\ai-bug-bounty-scanner\
├── data\                           ← New cache location
│   └── tool_discovery_cache.json   ← Outside src-tauri!
├── src-tauri\
│   ├── data\                       ← Old location (removed)
│   └── ...
└── ...
```

### Production Mode
```
Windows: %APPDATA%\ai-bug-bounty-scanner\data\tool_discovery_cache.json
macOS:   ~/Library/Application Support/ai-bug-bounty-scanner/data/tool_discovery_cache.json
Linux:   ~/.local/share/ai-bug-bounty-scanner/data/tool_discovery_cache.json
```

## Benefits

✅ **No More Unwanted Restarts**: Tool discovery and checks no longer trigger rebuilds
✅ **Faster Development**: No rebuild delays during normal operations
✅ **Better Architecture**: Separation of code (`src-tauri`) and runtime data (`data`)
✅ **Production Ready**: Proper app data directory usage in production builds
✅ **Cross-Platform**: Uses OS-specific data directories via the `dirs` crate

## Testing

### Verify the Fix
1. Start the dev server: `npm run tauri dev`
2. Wait for the app to load
3. Perform tool discovery or check for updates
4. **Expected**: App continues running without restart
5. **Verify**: Cache file is created at `d:\ai-bug-bounty-scanner\data\tool_discovery_cache.json`

### Check Cache Location
```powershell
# Development mode cache
Get-Item "d:\ai-bug-bounty-scanner\data\tool_discovery_cache.json"

# Old location should NOT exist
Test-Path "src-tauri\data\tool_discovery_cache.json"  # Should be False
```

## Related Fixes
This fix follows the same pattern as the previous **Git-Pip Installer Fix** where tool installation directories were moved outside `src-tauri` to prevent rebuild loops.

### Similar Patterns Applied
- **Git-Pip Tools**: Moved from `src-tauri/tools/python-tools` → `tools/python-tools`
- **Cache Files**: Moved from `src-tauri/data` → `data/` (workspace root in dev)
- **Principle**: Keep `src-tauri` for **source code only**, not runtime-generated data

## Future Considerations

### Additional Files to Consider
If you encounter similar rebuild issues with other files, apply the same pattern:
- Log files
- Temporary files
- Downloaded files
- User-generated content
- Database files (if not already handled)

### General Rule
**Any file that is created, modified, or deleted at runtime should live OUTSIDE the `src-tauri` directory during development.**

## Troubleshooting

### If Rebuilds Still Occur
1. Check what file triggered the rebuild (Tauri output shows the changed file)
2. Move that file/directory outside `src-tauri`
3. Update code to use the new path
4. Add new path to `.gitignore` if needed

### Cache File Not Created
- Check file permissions on the `data` directory
- Ensure the directory exists: `New-Item -Path "data" -ItemType Directory -Force`
- Check console output for error messages about cache saving

### Old Cache Persists
- Manually remove: `Remove-Item "src-tauri\data" -Recurse -Force`
- Clear Cargo cache: `cargo clean` (from src-tauri directory)
- Restart dev server

## Summary
This fix ensures that tool discovery cache files are written to locations that don't trigger Tauri's file watcher, preventing unwanted application restarts during normal operations. The solution uses build-mode-aware paths and follows best practices for separating code and runtime data.
