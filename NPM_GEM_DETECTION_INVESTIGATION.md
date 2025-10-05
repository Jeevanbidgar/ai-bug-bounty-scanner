# 🔍 npm and gem Detection Investigation

## Problem Report

npm is showing as "not installed" in the application, but it's actually installed and accessible:

```powershell
PS> npm --version
11.1.0  # ✅ npm is installed!
```

Similarly, gem (Ruby) is also showing as not detected.

## Likely Root Cause

The detection is failing because:

1. **Windows PowerShell vs Command Execution Context**
   - npm might work in PowerShell but fail in `std::process::Command`
   - This can happen if npm is a PowerShell script or batch file
   
2. **PATH Environment Variable Differences**
   - The Tauri application may not have the same PATH as your terminal
   - npm/gem paths might not be inherited by the spawned process

3. **Async Command Execution**
   - The `execute_detection_command` uses `spawn_blocking` with a 5-second timeout
   - Commands might be timing out or failing to execute properly

## Detection Code Analysis

### Current Flow

```rust
async fn detect_npm() -> PackageManagerInfo {
    // Try command first
    match execute_detection_command("npm", &["--version"]).await {
        Ok((stdout, _stderr)) => {
            // ✅ Success: npm found in PATH
            let version = parse_simple_version(&stdout);
            return PackageManagerInfo::available(...);
        }
        Err(_) => {
            // ⚠️ Fallback: Dynamic search
            if let Some(path) = find_executable_in_path("npm").await {
                // Try with full path
                ...
            }
        }
    }
    
    // ❌ Not detected
    PackageManagerInfo::unavailable(...)
}
```

### execute_detection_command Implementation

```rust
async fn execute_detection_command(
    command: &str,
    args: &[&str],
) -> Result<(String, String), String> {
    let timeout_duration = Duration::from_secs(5);

    // Spawn in blocking thread
    let output_future = tokio::task::spawn_blocking({
        move || {
            Command::new(&command)  // ⚠️ Uses std::process::Command
                .args(&args)
                .output()
        }
    });

    // Wait with timeout
    match timeout(timeout_duration, output_future).await {
        Ok(Ok(Ok(output))) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            if output.status.success() || !stdout.is_empty() || !stderr.is_empty() {
                Ok((stdout, stderr))
            } else {
                Err(format!("{} command failed", command))
            }
        }
        ...
    }
}
```

## Debug Additions

Added diagnostic logging to trace execution:

```rust
async fn detect_npm() -> PackageManagerInfo {
    eprintln!("🔍 Detecting npm...");
    
    match execute_detection_command("npm", &["--version"]).await {
        Ok((stdout, _stderr)) => {
            eprintln!("✅ npm command succeeded: {}", stdout.trim());
            ...
        }
        Err(e) => {
            eprintln!("⚠️  npm direct command failed: {}", e);
            // Try dynamic search
            if let Some(path) = find_executable_in_path("npm").await {
                eprintln!("🔍 Trying npm at: {}", path);
                ...
            }
        }
    }
    
    eprintln!("❌ npm not detected");
    ...
}
```

## Diagnostic Output Expected

When running the app, you should see:

### If npm is in PATH and works:
```
🔍 Detecting npm...
✅ npm command succeeded: 11.1.0
```

### If npm direct command fails but dynamic search works:
```
🔍 Detecting npm...
⚠️  npm direct command failed: Failed to execute npm: [error]
🔍 Trying npm at: C:\Program Files\nodejs\npm.cmd
✅ Found npm at: C:\Program Files\nodejs\npm.cmd
```

### If npm is not detected at all:
```
🔍 Detecting npm...
⚠️  npm direct command failed: [error]
❌ npm not detected
```

## Potential Issues and Solutions

### Issue 1: npm.cmd vs npm.exe on Windows

**Problem:** npm on Windows is often `npm.cmd` (a batch file), not `npm.exe`

**Solution:** Update `find_executable_in_path` to check for `.cmd` and `.bat` extensions:

```rust
fn get_windows_executable_search_paths(exe_name: &str) -> Vec<String> {
    let mut paths = Vec::new();
    
    // Check multiple extensions
    for ext in ["", ".exe", ".cmd", ".bat", ".ps1"] {
        let exe_with_ext = if ext.is_empty() {
            exe_name.to_string()
        } else {
            format!("{}{}", exe_name, ext)
        };
        
        // Add search paths...
    }
    
    paths
}
```

### Issue 2: Environment Variables Not Inherited

**Problem:** The spawned process doesn't have the same environment as PowerShell

**Solution:** Explicitly pass environment variables:

```rust
Command::new(&command)
    .args(&args)
    .env("PATH", std::env::var("PATH").unwrap_or_default())
    .env("PATHEXT", std::env::var("PATHEXT").unwrap_or_default())
    .output()
```

### Issue 3: PowerShell-specific Commands

**Problem:** npm might require PowerShell to execute properly on Windows

**Solution:** Execute through PowerShell on Windows:

```rust
#[cfg(target_os = "windows")]
fn execute_command(command: &str, args: &[&str]) -> Result<Output, std::io::Error> {
    Command::new("powershell.exe")
        .args(&["-NoProfile", "-Command", &format!("{} {}", command, args.join(" "))])
        .output()
}
```

## Next Steps

1. **Run the app with debug output** to see what's failing
2. **Check the exact error message** from `execute_detection_command`
3. **Verify npm location:**
   ```powershell
   where.exe npm
   Get-Command npm | Select-Object -ExpandProperty Source
   ```
4. **Apply appropriate fix** based on diagnostic output

## Files Modified

- `src-tauri/src/tools/package_managers/detection.rs`
  - Added debug logging to `detect_npm()`
  - Added debug logging to `detect_gem()`

## Testing Instructions

1. Rebuild the application:
   ```powershell
   cd src-tauri
   cargo build --release
   ```

2. Run the application:
   ```powershell
   cd ..
   npm run tauri dev
   ```

3. Watch console output for npm detection messages:
   - Look for "🔍 Detecting npm..."
   - Check if direct command succeeds or fails
   - See what path (if any) is found

4. Compare with manual check:
   ```powershell
   where.exe npm
   npm --version
   ```

## Status

**🔍 INVESTIGATING** - Debug logging added, waiting for diagnostic output to identify root cause

---

## Additional Notes

### Windows npm Installation Paths

Common locations:
- `C:\Program Files\nodejs\npm.cmd`
- `C:\Program Files (x86)\nodejs\npm.cmd`
- `%APPDATA%\npm\npm.cmd`
- `%LOCALAPPDATA%\Programs\nodejs\npm.cmd`
- Scoop: `%USERPROFILE%\scoop\shims\npm.cmd`
- Chocolatey: `C:\ProgramData\chocolatey\bin\npm.cmd`

### Ruby gem Installation Paths

Common locations:
- `C:\Ruby32-x64\bin\gem.bat`
- `C:\Ruby27-x64\bin\gem.bat`
- `%USERPROFILE%\.gem\ruby\[version]\bin\gem`
- RubyInstaller paths

---

*Investigation in progress... 🔬*
