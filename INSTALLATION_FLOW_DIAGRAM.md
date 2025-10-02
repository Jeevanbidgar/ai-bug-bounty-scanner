# Installation Flow Architecture

## User Journey Flowchart

```
┌─────────────────────────────────────────────────────────────────┐
│                     Settings Page Opens                         │
│                  (PackageManagerTest Component)                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ Click "Detect        │
                  │ Package Managers"    │
                  └──────────┬───────────┘
                             │
                             ▼
        ┌────────────────────────────────────────┐
        │  Tauri Command: detect_package_managers│
        │  Detects: Go, pipx, APT, WinGet        │
        └────────────┬───────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────────────────┐
        │         Display Results:                │
        │  🟢 Go v1.24.5         ✓ Available     │
        │  🟡 pipx              ✗ Not Found       │
        │  🔵 APT               ✗ Linux Only      │
        │  🔵 WinGet            ✗ Not Found       │
        └────────────┬───────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────────────────┐
        │  User Clicks "Install" on pipx Card    │
        └────────────┬───────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────────────────┐
        │  Button → "Installing..." (disabled)   │
        │  Invoke: install_package_manager_pipx  │
        └────────────┬───────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────────────────┐
        │         Backend Execution:              │
        │  Step 1: Run pip install --user pipx   │
        │         (60s timeout)                   │
        │  Step 2: Run pipx ensurepath           │
        │         (30s timeout)                   │
        └────────────┬───────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────────────────┐
        │       Return InstallationResult:        │
        │  success: true                          │
        │  message: "pipx installed successfully!"│
        │  steps: [                               │
        │    {step: "Installing pipx", ✓}        │
        │    {step: "Adding to PATH", ✓}         │
        │  ]                                      │
        │  requires_restart: true                 │
        └────────────┬───────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────────────────┐
        │      Display Installation Result:       │
        │  ✓ Installation Complete                │
        │  ⚠ Please restart your terminal         │
        │                                         │
        │  Installation Steps:                    │
        │    ✓ Installing pipx                   │
        │       python -m pip install...          │
        │    ✓ Adding pipx to PATH               │
        │       pipx ensurepath                   │
        │                                         │
        │  [ Refresh Detection ]  (blue button)   │
        └────────────┬───────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────────────────┐
        │  User Restarts Terminal & Clicks       │
        │         "Refresh Detection"             │
        └────────────┬───────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────────────────┐
        │  Tauri Command: detect_package_managers│
        │  Re-detects all managers                │
        └────────────┬───────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────────────────┐
        │         Updated Results:                │
        │  🟢 Go v1.24.5         ✓ Available     │
        │  🟡 pipx v1.2.0       ✓ Available ←NEW │
        │  🔵 APT               ✗ Linux Only      │
        │  🔵 WinGet            ✗ Not Found       │
        └─────────────────────────────────────────┘
```

## Elevation Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Package Manager Types                        │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────┐
│      pipx           │
│  🟡 User-Scope      │
└──────────┬──────────┘
           │
           ├─→ pip install --user pipx    (No elevation ✓)
           │   └─→ Installs to ~/.local/
           │
           └─→ pipx ensurepath            (No elevation ✓)
               └─→ Modifies user PATH only

┌─────────────────────┐
│      Go             │
│  🟢 Mixed Scope     │
└──────────┬──────────┘
           │
           ├─→ Check: Is WinGet available?
           │      │
           │      ├─→ Yes: winget install GoLang.Go
           │      │         └─→ May trigger UAC ⚠
           │      │             (depends on package)
           │      │
           │      └─→ No:  Open https://go.dev/dl/
           │                └─→ User manually installs
           │                    (User-scope installer available ✓)

┌─────────────────────┐
│      APT            │
│  🔵 System-Scope    │
└──────────┬──────────┘
           │
           ├─→ sudo apt update             (Requires sudo ⚠)
           │   └─→ User enters password
           │
           └─→ sudo apt install -y pkg     (Requires sudo ⚠)
               └─→ System-wide installation
               
               ⚠ Warning: "Requires sudo on Linux" shown upfront

┌─────────────────────┐
│     WinGet          │
│  🔵 User-Scope      │
└──────────┬──────────┘
           │
           └─→ Open Microsoft Store App Installer page
               └─→ User installs from Store (No elevation ✓)
               
               ℹ Info: "May trigger UAC if required" (rare)
```

## State Machine Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                   Frontend State Machine                        │
└─────────────────────────────────────────────────────────────────┘

    [Initial State]
         │
         ▼
    ┌─────────┐
    │  Idle   │ ←──────────────────┐
    └────┬────┘                    │
         │ Click "Detect"          │
         ▼                         │
    ┌─────────────┐                │
    │  Detecting  │                │
    │ loading=true│                │
    └────┬────────┘                │
         │                         │
         ▼                         │
    ┌─────────────────┐            │
    │  Results Shown  │            │
    │ managers=[...]  │────────────┘ Click "Clear Results"
    └────┬────────────┘
         │ Click "Install"
         ▼
    ┌──────────────────┐
    │   Installing     │
    │installing="pipx" │
    └────┬─────────────┘
         │ Backend completes
         ▼
    ┌────────────────────┐
    │ Install Result     │
    │installResult={...} │
    └────┬───────────────┘
         │ Click "Refresh Detection"
         ▼
    ┌─────────────┐
    │  Detecting  │ (loops back)
    └─────────────┘
```

## Backend Command Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                  Backend Command Pipeline                       │
└─────────────────────────────────────────────────────────────────┘

[Frontend invokes Tauri command]
         │
         ▼
┌────────────────────────┐
│  #[tauri::command]     │
│  install_package_*()   │
└────────┬───────────────┘
         │
         ▼
┌────────────────────────┐
│  Platform Check        │
│  #[cfg(target_os=...)] │
└────────┬───────────────┘
         │
         ▼
┌────────────────────────┐
│  Installation Module   │
│  install_pipx()        │
│  install_go_windows()  │
│  install_apt_package() │
└────────┬───────────────┘
         │
         ▼
┌────────────────────────────┐
│  execute_command_with_     │
│  output()                  │
│  - Spawn tokio::Command    │
│  - Capture stdout/stderr   │
│  - Enforce timeout         │
│  - Return Result<String>   │
└────────┬───────────────────┘
         │
         ▼
┌────────────────────────────┐
│  Build InstallationResult  │
│  - Collect steps           │
│  - Mark success/failure    │
│  - Set requires_restart    │
└────────┬───────────────────┘
         │
         ▼
[Return to Frontend as JSON]
```

## Error Handling Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     Error Handling Path                         │
└─────────────────────────────────────────────────────────────────┘

    [Command Execution]
         │
         ├─→ Success (exit code 0)
         │      │
         │      └─→ Return Ok(output)
         │            │
         │            └─→ Display success UI
         │
         └─→ Failure (non-zero exit)
                │
                ├─→ Network Timeout (5-180s)
                │      │
                │      └─→ Return Err("Command timed out after X seconds")
                │            │
                │            └─→ Display timeout error
                │
                ├─→ Command Not Found
                │      │
                │      └─→ Return Err("Failed to execute X: No such file")
                │            │
                │            └─→ Display installation guide
                │
                └─→ Permission Denied
                       │
                       └─→ Return Err("Permission denied")
                             │
                             └─→ Display elevation instructions
```

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        Data Flow                                │
└─────────────────────────────────────────────────────────────────┘

Frontend                       Backend                   System
   │                              │                         │
   │  invoke("install_*")         │                         │
   ├─────────────────────────────>│                         │
   │                              │                         │
   │                              │  spawn Command("pip")   │
   │                              ├────────────────────────>│
   │                              │                         │
   │                              │  ← stdout/stderr        │
   │                              │<────────────────────────┤
   │                              │                         │
   │                              │  Package installed ✓    │
   │                              │                         │
   │  ← InstallationResult {      │                         │
   │      success: true,          │                         │
   │      steps: [...]            │                         │
   │    }                         │                         │
   │<─────────────────────────────┤                         │
   │                              │                         │
   │  Display progress UI         │                         │
   │                              │                         │
   │  User clicks "Refresh"       │                         │
   │  invoke("detect_*")          │                         │
   ├─────────────────────────────>│                         │
   │                              │                         │
   │                              │  which pipx             │
   │                              ├────────────────────────>│
   │                              │                         │
   │                              │  ← /path/to/pipx        │
   │                              │<────────────────────────┤
   │                              │                         │
   │  ← PackageManagerInfo {      │                         │
   │      available: true,        │                         │
   │      version: "1.2.0"        │                         │
   │    }                         │                         │
   │<─────────────────────────────┤                         │
   │                              │                         │
   │  Update UI: pipx ✓ v1.2.0   │                         │
   │                              │                         │
```

---

## Key Design Decisions

### 1. **User-Scope by Default**
- Reduces elevation prompts
- Safer for multi-user systems
- Aligns with modern security practices

### 2. **Explicit Elevation Warnings**
- No surprise UAC/sudo prompts
- Clear warnings before user clicks Install
- Per-step elevation requirements shown

### 3. **Progressive Disclosure**
- Install button only shows when manager unavailable
- Progress details expand during installation
- Refresh button appears only after success

### 4. **Timeout Protection**
- 5-60s for quick operations (version checks)
- 60-180s for downloads/installs
- Prevents indefinite hangs

### 5. **Platform-Specific Guards**
- Linux-only: APT functions
- Windows-only: WinGet/Go installer
- Compile-time checks prevent runtime errors
