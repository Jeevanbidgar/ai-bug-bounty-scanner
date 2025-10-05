# 🦀 Rust/Tauri Architecture Analysis & Enhancement Roadmap

> **Analysis Date**: October 5, 2025  
> **Application**: AI Bug Bounty Scanner v2.0.0  
> **Based on**: Security orchestrator best practices with Rust ownership, Tauri capabilities, and zero-cost abstractions

---

## 📊 Executive Summary

Your application **already implements** many Rust/Tauri best practices but has significant opportunities to enhance security boundaries, resource isolation, and performance. This document maps your current architecture against the best practices you've extracted and provides a concrete roadmap for improvements.

### Current State: Strong Foundation ✅
- ✅ Tauri + Rust core with capability-based security model
- ✅ Native process orchestration with `tokio::process::Command`
- ✅ Real-time IPC via Tauri events (no WebSocket overhead)
- ✅ Concurrent subprocess handling with `tokio::join!` pattern
- ✅ Error handling with stream error recovery and timeout protection
- ✅ Package manager orchestration (Gem, NPM, Cargo, Pipx, APT, Winget, Go)
- ✅ DAG-based workflow execution with parallel step execution
- ✅ Tool discovery and installation automation

### Gap Analysis: Opportunity Areas 🎯
- ⚠️ **No resource limits enforcement** (cgroups v2, Job Objects, sandbox profiles)
- ⚠️ **Broad shell allowlist** (18 tools with unrestricted args)
- ⚠️ **No sidecar packaging** for bundled tools
- ⚠️ **No PyO3 integration** for Python ecosystem access
- ⚠️ **Missing capability-scoped commands** (all windows have same permissions)
- ⚠️ **No platform-specific security boundaries** (macOS sandbox, Windows Job Objects, Linux cgroups)
- ⚠️ **Backend Python code still present** but unused (migration incomplete)

---

## 🏗️ Current Architecture Map

### 1. **Process Runner & Pool** (✅ Excellent)

**Current Implementation**:
```rust
// src-tauri/src/runtime/executor.rs
pub struct ProcessExecutor {
    app_handle: AppHandle,
    tool_discovery: Arc<RwLock<ToolDiscoveryService>>,
    artifact_manager: Arc<ArtifactManager>,
}

// Concurrent subprocess handling with proper stream drainage
let (status, _, _) = tokio::join!(
    child.wait(),
    stdout_task,  // Concurrent drainage prevents deadlock
    stderr_task
);
```

**Strengths**:
- ✅ `tokio::process::Command` with argv arrays (no shell injection)
- ✅ Concurrent stdout/stderr streaming prevents pipe buffer deadlocks
- ✅ Timeout enforcement with `tokio::time::timeout`
- ✅ Real-time IPC via `app_handle.emit_all()` for progress updates
- ✅ Graceful process termination with `child.kill()` fallback

**Missing**:
- ❌ Per-process CPU/memory limits
- ❌ cgroups v2 integration on Linux
- ❌ Windows Job Objects for resource constraints
- ❌ macOS sandbox profiles or entitlements

**Gap Rating**: 7/10 (excellent execution, missing resource isolation)

---

### 2. **Workflow Engine** (✅ Strong)

**Current Implementation**:
```rust
// src-tauri/src/workflow/engine.rs
pub struct WorkflowEngine {
    app_handle: AppHandle,
    active_executions: Arc<RwLock<HashMap<String, WorkflowExecution>>>,
    executor: ProcessExecutor,
    artifact_manager: Arc<ArtifactManager>,
}

// DAG execution with parallel step execution
async fn execute_dag(&self, execution_id: String, workflow: WorkflowTemplate, working_directory: String) -> Result<()> {
    let ready_steps = self.get_ready_steps(&workflow.steps, &completed_steps)?;
    
    // Execute ready steps concurrently
    let mut handles = Vec::new();
    for step_id in ready_steps {
        let handle = tokio::spawn(async move {
            engine_clone.execute_step(/* ... */).await
        });
        handles.push(handle);
    }
}
```

**Strengths**:
- ✅ DAG dependency resolution with parallel execution
- ✅ Send/Sync-safe data structures (`Arc<RwLock<>>`)
- ✅ Backpressure-aware with step completion tracking
- ✅ Event-driven progress updates
- ✅ Artifact management with retention policies

**Missing**:
- ❌ Channel-based message passing for more robust concurrency
- ❌ Resource pooling to prevent system overload
- ❌ Priority queue for workflow scheduling

**Gap Rating**: 8/10 (solid concurrency, could use channels)

---

### 3. **Tauri Command Surface** (⚠️ Needs Improvement)

**Current Implementation**:
```json
// src-tauri/tauri.conf.json
{
  "tauri": {
    "allowlist": {
      "shell": {
        "scope": [
          { "name": "subfinder", "cmd": "subfinder", "args": true },
          { "name": "naabu", "cmd": "naabu", "args": true },
          // ... 16 more tools with unrestricted args
        ]
      }
    }
  }
}
```

**Strengths**:
- ✅ Explicit allowlist (only approved tools can execute)
- ✅ No shell execution (`cmd /c` or `sh -c` prevented)
- ✅ Rust commands validate inputs before spawning

**Weaknesses**:
- ⚠️ `"args": true` allows **any arguments** to approved commands
- ⚠️ All windows have same capabilities (no per-window scoping)
- ⚠️ No validation of argument patterns (e.g., prevent `--exec`, file writes)
- ⚠️ Missing platform-specific capability files

**Current Commands** (32 Tauri commands):
```rust
// src-tauri/src/commands/mod.rs
- execute_workflow
- list_scans, create_scan, update_scan, delete_scan
- install_tool, recheck_tool, check_tool_installed
- install_package_manager_[pipx|go|apt|winget]
- execute_elevated_command, try_command_with_elevation
- check_pipx_path, fix_pipx_path, cleanup_old_pipx
```

**Gap Rating**: 5/10 (explicit allowlist good, but too broad and no capability scoping)

---

### 4. **Sidecar Manager** (❌ Not Implemented)

**Current State**: External tools are discovered via `which` crate and executed via system PATH.

**What's Missing**:
- ❌ No bundled sidecars in `externalBin` configuration
- ❌ No target-triple specific binaries (e.g., `sqlmap-x86_64-pc-windows-msvc.exe`)
- ❌ No embedded Python CLI helpers or scanners
- ❌ No explicit permission grants in Tauri config
- ❌ No deterministic pathing (relies on user's PATH)

**Opportunity**:
```json
// src-tauri/tauri.conf.json (potential)
{
  "bundle": {
    "externalBin": [
      "binaries/subfinder-x86_64-pc-windows-msvc",
      "binaries/subfinder-x86_64-unknown-linux-gnu",
      "binaries/subfinder-aarch64-apple-darwin"
    ]
  }
}
```

**Gap Rating**: 2/10 (system PATH reliance, no bundling)

---

### 5. **Parser & Normalizer** (⚠️ Partial)

**Current Implementation**:
- ✅ Rust adapters in `src-tauri/src/adapters/` (Subfinder example exists)
- ⚠️ Python adapters still present in `backend/adapters/` (7 adapters: Subfinder, Amass, Naabu, Nuclei, Nmap, GAU, Waybackurls)
- ❌ No zero-cost parsers for large tool outputs
- ❌ No streaming parsers (parse-as-you-read for 100MB+ outputs)

**Current Rust Adapter**:
```rust
// src-tauri/src/adapters/subfinder.rs
pub struct SubfinderAdapter;

impl SubfinderAdapter {
    pub fn build_command(&self, config: &SubfinderConfig) -> Vec<String> { /* ... */ }
    pub fn get_risk_level(&self) -> &'static str { "low" }
    pub fn get_timeout(&self) -> u64 { 300 }
}
```

**Python Adapters** (currently unused):
```python
# backend/adapters/subfinder_adapter.py
class SubfinderAdapter(BaseAdapter):
    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        # Regex parsing, JSON parsing for nuclei
```

**Gap Rating**: 4/10 (Rust adapters started, Python code abandoned mid-migration)

---

### 6. **Platform Guards** (❌ Not Implemented)

**Current State**: No platform-specific resource limits or security boundaries.

**What You Need**:

#### Linux (cgroups v2):
```rust
// Proposed: src-tauri/src/runtime/cgroups.rs
pub struct CgroupsManager {
    cgroup_path: PathBuf,
}

impl CgroupsManager {
    pub fn create_cgroup(&self, scan_id: &str) -> Result<()> {
        // Create /sys/fs/cgroup/ai-bug-bounty/{scan_id}
        let cgroup = self.cgroup_path.join(scan_id);
        fs::create_dir_all(&cgroup)?;
        
        // Set cpu.max: 100000 100000 (100% of 1 core)
        fs::write(cgroup.join("cpu.max"), "100000 100000")?;
        
        // Set memory.max: 1073741824 (1 GB)
        fs::write(cgroup.join("memory.max"), "1073741824")?;
        
        Ok(())
    }
    
    pub fn add_process(&self, scan_id: &str, pid: u32) -> Result<()> {
        let cgroup_procs = self.cgroup_path.join(scan_id).join("cgroup.procs");
        fs::write(cgroup_procs, pid.to_string())?;
        Ok(())
    }
}
```

#### Windows (Job Objects):
```rust
// Proposed: src-tauri/src/runtime/job_objects.rs
use windows::Win32::System::JobObjects::*;

pub struct JobObjectManager {
    job_handle: HANDLE,
}

impl JobObjectManager {
    pub fn new(scan_id: &str) -> Result<Self> {
        unsafe {
            let job_handle = CreateJobObjectW(None, PCWSTR::null())?;
            
            // Set memory limit (1 GB)
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            limits.JobMemoryLimit = 1 * 1024 * 1024 * 1024; // 1 GB
            
            SetInformationJobObject(job_handle, JobObjectExtendedLimitInformation, &limits, size_of_val(&limits) as u32)?;
            
            Ok(Self { job_handle })
        }
    }
    
    pub fn assign_process(&self, process_handle: HANDLE) -> Result<()> {
        unsafe {
            AssignProcessToJobObject(self.job_handle, process_handle)?;
        }
        Ok(())
    }
}
```

#### macOS (App Sandbox):
```xml
<!-- Proposed: src-tauri/entitlements.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.files.user-selected.read-write</key>
    <true/>
    <key>com.apple.security.files.downloads.read-write</key>
    <true/>
</dict>
</plist>
```

**Gap Rating**: 0/10 (not started)

---

## 🎯 Enhancement Roadmap

### **Priority 1: Security Boundaries (High Impact, Medium Effort)**

#### 1.1 Capability-Scoped Commands
**Goal**: Restrict Tauri commands per window/context instead of global permissions.

**Implementation**:
```rust
// src-tauri/src/main.rs
use tauri::command;

#[command]
async fn execute_tool(
    window: tauri::Window,
    tool_name: String,
    args: Vec<String>
) -> Result<String, String> {
    // Check window label for permissions
    let allowed_tools = match window.label() {
        "main" => vec!["subfinder", "naabu", "nuclei"],
        "admin" => vec!["subfinder", "naabu", "nuclei", "sqlmap", "nmap"],
        _ => vec![],
    };
    
    if !allowed_tools.contains(&tool_name.as_str()) {
        return Err(format!("Tool '{}' not allowed in this window", tool_name));
    }
    
    // Validate args against patterns
    validate_args(&tool_name, &args)?;
    
    // Execute
    execute_tool_internal(tool_name, args).await
}

fn validate_args(tool_name: &str, args: &[String]) -> Result<(), String> {
    // Prevent dangerous arguments
    for arg in args {
        if arg.contains("--exec") || arg.contains("$(") || arg.contains("`") {
            return Err(format!("Dangerous argument pattern detected: {}", arg));
        }
    }
    
    // Tool-specific validation
    match tool_name {
        "subfinder" => {
            // Only allow safe flags
            let allowed_flags = vec!["-d", "-o", "-silent", "-v", "-t"];
            for arg in args {
                if arg.starts_with("-") && !allowed_flags.contains(&arg.as_str()) {
                    return Err(format!("Unsafe subfinder flag: {}", arg));
                }
            }
        },
        _ => {}
    }
    
    Ok(())
}
```

**Files to Modify**:
- `src-tauri/src/commands/mod.rs` - Add validation to all tool commands
- `src-tauri/tauri.conf.json` - Remove `"args": true`, use stricter patterns

**Effort**: 2-3 days  
**Impact**: High (prevents command injection, limits blast radius)

---

#### 1.2 Argument Pattern Allowlisting
**Goal**: Replace `"args": true` with explicit allowed patterns.

**Current** (insecure):
```json
{ "name": "subfinder", "cmd": "subfinder", "args": true }
```

**Enhanced** (secure):
```json
{
  "name": "subfinder",
  "cmd": "subfinder",
  "args": [
    { "validator": "^-d$" },
    { "validator": "^[a-zA-Z0-9.-]+$" },  // Domain name
    { "validator": "^-o$" },
    { "validator": "^[a-zA-Z0-9/_.-]+$" },  // Output path
    { "validator": "^-silent$" },
    { "validator": "^-v$" }
  ]
}
```

**Effort**: 1-2 weeks (18 tools × validation patterns)  
**Impact**: Critical (prevents argument injection attacks)

---

### **Priority 2: Resource Limits (Critical Safety, High Effort)**

#### 2.1 Linux cgroups v2 Integration
**Goal**: Enforce per-scan CPU/memory limits on Linux.

**Implementation**:
```rust
// src-tauri/src/runtime/resource_limits.rs
#[cfg(target_os = "linux")]
pub mod linux {
    use std::fs;
    use std::path::PathBuf;
    
    pub struct CgroupController {
        base_path: PathBuf,
    }
    
    impl CgroupController {
        pub fn new() -> Result<Self> {
            let base_path = PathBuf::from("/sys/fs/cgroup/ai-bug-bounty");
            fs::create_dir_all(&base_path)?;
            Ok(Self { base_path })
        }
        
        pub fn create_scan_cgroup(&self, scan_id: &str, cpu_quota: u64, memory_bytes: u64) -> Result<PathBuf> {
            let cgroup_path = self.base_path.join(scan_id);
            fs::create_dir_all(&cgroup_path)?;
            
            // CPU limit: cpu.max = $quota_us $period_us
            // Example: 50000 100000 = 50% of 1 core
            fs::write(cgroup_path.join("cpu.max"), format!("{} 100000", cpu_quota))?;
            
            // Memory limit
            fs::write(cgroup_path.join("memory.max"), memory_bytes.to_string())?;
            
            // Enable memory.oom.group for clean kills
            fs::write(cgroup_path.join("memory.oom.group"), "1")?;
            
            Ok(cgroup_path)
        }
        
        pub fn add_process(&self, cgroup_path: &PathBuf, pid: u32) -> Result<()> {
            fs::write(cgroup_path.join("cgroup.procs"), pid.to_string())?;
            Ok(())
        }
        
        pub fn cleanup(&self, scan_id: &str) -> Result<()> {
            let cgroup_path = self.base_path.join(scan_id);
            fs::remove_dir(cgroup_path)?;
            Ok(())
        }
    }
}

// Usage in ProcessExecutor
#[cfg(target_os = "linux")]
pub async fn execute_with_limits(&self, step: &WorkflowStep, scan_id: &str) -> Result<()> {
    let cgroups = linux::CgroupController::new()?;
    let cgroup_path = cgroups.create_scan_cgroup(
        scan_id,
        50_000,         // 50% of 1 core
        1_073_741_824   // 1 GB
    )?;
    
    let mut child = Command::new(&step.run[0])
        .args(&step.run[1..])
        .spawn()?;
    
    // Add to cgroup
    cgroups.add_process(&cgroup_path, child.id().unwrap())?;
    
    // Wait for completion
    let status = child.wait().await?;
    
    // Cleanup
    cgroups.cleanup(scan_id)?;
    
    Ok(())
}
```

**Files to Create**:
- `src-tauri/src/runtime/resource_limits/linux.rs`
- `src-tauri/src/runtime/resource_limits/windows.rs`
- `src-tauri/src/runtime/resource_limits/macos.rs`
- `src-tauri/src/runtime/resource_limits/mod.rs`

**Dependencies**:
```toml
# Cargo.toml
[target.'cfg(target_os = "linux")'.dependencies]
nix = { version = "0.27", features = ["process"] }

[target.'cfg(target_os = "windows")'.dependencies]
windows = { version = "0.52", features = ["Win32_System_JobObjects"] }
```

**Effort**: 2-3 weeks  
**Impact**: Critical (prevents resource exhaustion, runaway processes)

---

#### 2.2 Windows Job Objects
**Goal**: Enforce per-scan resource limits on Windows.

**Implementation** (see earlier code sample)

**Effort**: 1 week  
**Impact**: Critical (Windows resource safety)

---

#### 2.3 macOS Sandbox Profiles
**Goal**: Apply App Sandbox entitlements for helper tools.

**Implementation**:
```xml
<!-- src-tauri/entitlements.macos.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Enable App Sandbox -->
    <key>com.apple.security.app-sandbox</key>
    <true/>
    
    <!-- Network access for tools -->
    <key>com.apple.security.network.client</key>
    <true/>
    
    <!-- File access -->
    <key>com.apple.security.files.user-selected.read-write</key>
    <true/>
    <key>com.apple.security.files.downloads.read-write</key>
    <true/>
    
    <!-- Temporary exception for external binaries -->
    <key>com.apple.security.temporary-exception.sbpl</key>
    <string>(allow process-exec (literal "/usr/local/bin/subfinder"))</string>
</dict>
</plist>
```

**Tauri Config**:
```json
// tauri.conf.json
{
  "tauri": {
    "bundle": {
      "macOS": {
        "entitlements": "entitlements.macos.plist"
      }
    }
  }
}
```

**Effort**: 3-5 days  
**Impact**: High (macOS distribution requirement for App Store, enhanced security)

---

### **Priority 3: Sidecar Packaging (Medium Impact, Medium Effort)**

#### 3.1 Bundle Core Tools as Sidecars
**Goal**: Embed critical security tools in app bundle for deterministic execution.

**Architecture**:
```
src-tauri/
├── binaries/
│   ├── subfinder-x86_64-pc-windows-msvc.exe
│   ├── subfinder-x86_64-unknown-linux-gnu
│   ├── subfinder-aarch64-apple-darwin
│   ├── nuclei-x86_64-pc-windows-msvc.exe
│   ├── nuclei-x86_64-unknown-linux-gnu
│   └── nuclei-aarch64-apple-darwin
└── Cargo.toml
```

**Tauri Configuration**:
```json
{
  "tauri": {
    "bundle": {
      "externalBin": [
        "binaries/subfinder",
        "binaries/nuclei"
      ]
    },
    "allowlist": {
      "shell": {
        "sidecar": true,
        "scope": [
          { "name": "binaries/subfinder", "sidecar": true, "args": ["subfinder_args_pattern"] },
          { "name": "binaries/nuclei", "sidecar": true, "args": ["nuclei_args_pattern"] }
        ]
      }
    }
  }
}
```

**Rust Code**:
```rust
use tauri::api::process::{Command, CommandEvent};

#[tauri::command]
async fn run_subfinder_sidecar(domain: String) -> Result<String, String> {
    let (mut rx, mut child) = Command::new_sidecar("subfinder")
        .map_err(|e| e.to_string())?
        .args(["-d", &domain, "-silent"])
        .spawn()
        .map_err(|e| e.to_string())?;
    
    let mut output = String::new();
    while let Some(event) = rx.recv().await {
        match event {
            CommandEvent::Stdout(line) => {
                output.push_str(&line);
            },
            CommandEvent::Stderr(line) => {
                eprintln!("Subfinder error: {}", line);
            },
            CommandEvent::Terminated(payload) => {
                if payload.code != Some(0) {
                    return Err(format!("Subfinder failed with code {:?}", payload.code));
                }
            },
            _ => {}
        }
    }
    
    Ok(output)
}
```

**Benefits**:
- ✅ Deterministic tool versions (no PATH dependency)
- ✅ Offline execution (tools bundled in app)
- ✅ Cross-platform binaries (target-triple suffixed)
- ✅ Explicit permission grants in Tauri config

**Effort**: 2 weeks (download binaries, configure, test across platforms)  
**Impact**: Medium-High (reliability, consistency, offline support)

---

### **Priority 4: PyO3 for Python Ecosystem (Medium Impact, High Effort)**

#### 4.1 Embed Python for Adapters
**Goal**: Use PyO3 to call Python-based security tools from Rust without subprocess overhead.

**Use Cases**:
- SQL injection testing (SQLMap)
- Web app scanning (WPScan)
- Custom Python parsers for tool outputs

**Architecture**:
```rust
// src-tauri/src/adapters/python_bridge.rs
use pyo3::prelude::*;
use pyo3::types::PyDict;

pub struct PythonAdapter {
    py_module: Py<PyModule>,
}

impl PythonAdapter {
    pub fn new(module_name: &str) -> Result<Self> {
        Python::with_gil(|py| {
            let sys = py.import("sys")?;
            let path = sys.getattr("path")?;
            path.call_method1("append", ("./adapters",))?;
            
            let module = py.import(module_name)?;
            Ok(Self {
                py_module: module.into(),
            })
        })
    }
    
    pub fn parse_nuclei_output(&self, json_output: &str) -> Result<Vec<Finding>> {
        Python::with_gil(|py| {
            let module = self.py_module.as_ref(py);
            let parse_fn = module.getattr("parse_nuclei_json")?;
            
            let result = parse_fn.call1((json_output,))?;
            let findings: Vec<Finding> = result.extract()?;
            
            Ok(findings)
        })
    }
}

#[pyclass]
#[derive(Clone)]
struct Finding {
    #[pyo3(get, set)]
    title: String,
    #[pyo3(get, set)]
    severity: String,
    #[pyo3(get, set)]
    cvss: f32,
}
```

**Python Adapter** (kept for complex parsing):
```python
# adapters/nuclei_parser.py
import json
from typing import List, Dict

def parse_nuclei_json(json_str: str) -> List[Dict]:
    findings = []
    for line in json_str.splitlines():
        data = json.loads(line)
        findings.append({
            'title': data['info']['name'],
            'severity': data['info']['severity'],
            'cvss': data['info'].get('classification', {}).get('cvss-score', 0.0)
        })
    return findings
```

**Cargo.toml**:
```toml
[dependencies]
pyo3 = { version = "0.20", features = ["auto-initialize"] }
```

**Benefits**:
- ✅ Access to Python security tool ecosystem
- ✅ Complex parsers in Python, orchestration in Rust
- ✅ No subprocess overhead for Python code
- ✅ Type-safe FFI between Rust and Python

**Effort**: 3-4 weeks (setup PyO3, port critical adapters, test)  
**Impact**: Medium (access to Python tools, but subprocess pattern already works)

---

### **Priority 5: Enhanced Parsers (Low-Medium Impact, Medium Effort)**

#### 5.1 Zero-Cost Streaming Parsers
**Goal**: Parse large tool outputs (100MB+ Nuclei scans) without loading into memory.

**Current Problem**:
```rust
// Current: Loads entire output into String
let output = String::from_utf8(stdout)?;
let findings = parse_nuclei_json(&output)?;  // Allocates entire output in memory
```

**Zero-Cost Solution**:
```rust
use serde_json::Deserializer;
use tokio::io::{AsyncBufReadExt, BufReader};

pub async fn parse_nuclei_stream(stdout: ChildStdout) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();
    
    while let Some(line) = lines.next_line().await? {
        // Parse line-by-line (JSONL format)
        if let Ok(finding) = serde_json::from_str::<Finding>(&line) {
            findings.push(finding);
            
            // Emit finding immediately to frontend
            app_handle.emit_all("finding:discovered", &finding)?;
        }
    }
    
    Ok(findings)
}
```

**Benefits**:
- ✅ Constant memory usage (no matter output size)
- ✅ Real-time finding discovery (emit as parsed)
- ✅ No GC pauses (zero-cost abstraction)

**Effort**: 1 week (implement for Nuclei, Nmap, Subfinder)  
**Impact**: Medium (performance improvement for large scans)

---

## 📋 Implementation Priority Matrix

| Feature | Impact | Effort | Priority | Timeline |
|---------|--------|--------|----------|----------|
| **Argument Pattern Allowlisting** | 🔴 Critical | Medium | 1 | Week 1-2 |
| **Capability-Scoped Commands** | 🔴 High | Medium | 1 | Week 1 |
| **Linux cgroups v2** | 🔴 Critical | High | 2 | Week 3-4 |
| **Windows Job Objects** | 🔴 Critical | Medium | 2 | Week 5 |
| **macOS Sandbox** | 🟡 High | Low | 3 | Week 6 |
| **Sidecar Packaging** | 🟡 Medium-High | Medium | 4 | Week 7-8 |
| **Zero-Cost Parsers** | 🟢 Medium | Medium | 5 | Week 9 |
| **PyO3 Integration** | 🟢 Medium | High | 6 | Week 10-13 |

---

## 🎯 Quick Wins (High Impact, Low Effort)

### 1. **Per-Process Timeout Enforcement** (Already Done ✅)
You already have this! `tokio::time::timeout` in `runtime/executor.rs`.

### 2. **Argument Validation Helpers** (2 days)
```rust
// src-tauri/src/validation/mod.rs
pub fn validate_domain(input: &str) -> Result<()> {
    let domain_regex = regex::Regex::new(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")?;
    if !domain_regex.is_match(input) {
        return Err(anyhow!("Invalid domain: {}", input));
    }
    Ok(())
}

pub fn validate_file_path(input: &str, allow_write: bool) -> Result<()> {
    let path = PathBuf::from(input);
    
    // Prevent directory traversal
    if input.contains("..") || input.contains("~") {
        return Err(anyhow!("Path traversal detected"));
    }
    
    // Ensure path is within allowed directories
    let allowed_dirs = vec![
        dirs::download_dir(),
        dirs::document_dir(),
        Some(PathBuf::from("./results")),
    ];
    
    let is_allowed = allowed_dirs.iter().any(|dir| {
        if let Some(dir) = dir {
            path.starts_with(dir)
        } else {
            false
        }
    });
    
    if !is_allowed {
        return Err(anyhow!("Path outside allowed directories"));
    }
    
    Ok(())
}
```

### 3. **Command Execution Event Logging** (1 day)
```rust
// src-tauri/src/audit/mod.rs
use chrono::Utc;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct AuditLog {
    timestamp: String,
    user: String,
    command: String,
    args: Vec<String>,
    working_dir: String,
    result: String,
}

pub fn log_command_execution(
    command: &str,
    args: &[String],
    working_dir: &str,
    result: &Result<()>
) -> Result<()> {
    let log = AuditLog {
        timestamp: Utc::now().to_rfc3339(),
        user: whoami::username(),
        command: command.to_string(),
        args: args.to_vec(),
        working_dir: working_dir.to_string(),
        result: match result {
            Ok(_) => "success".to_string(),
            Err(e) => format!("error: {}", e),
        },
    };
    
    // Append to audit log
    let log_path = dirs::data_dir()
        .unwrap()
        .join("ai-bug-bounty-scanner")
        .join("audit.jsonl");
    
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    
    writeln!(file, "{}", serde_json::to_string(&log)?)?;
    
    Ok(())
}
```

---

## 🚀 Migration Plan: Python Backend → Pure Rust

### Current Hybrid State:
- ✅ Tauri + Rust frontend/backend bridge
- ⚠️ Python backend code still exists but **unused**
- ⚠️ Python adapters exist but **unused** (Rust adapters partially implemented)

### Files to Remove:
```
backend/
├── adapters/           ❌ Remove (7 Python adapters)
├── middleware/         ❌ Remove (rate limiting, resource limiter)
├── services/           ❌ Remove (executor, workflow)
├── workers/            ❌ Remove (Dramatiq tasks)
├── main.py             ❌ Remove
├── config.py           ❌ Remove
└── requirements.txt    ❌ Remove
```

### Files to Keep (for reference):
- `backend/plugins/*.yaml` - Tool metadata (migrate to Rust)
- `app/workflows/*.yaml` - Workflow definitions (already used by Rust)

### Migration Checklist:
- [ ] Port Python adapters to Rust (7 remaining: Amass, Naabu, Nuclei, Nmap, GAU, Waybackurls, Httpx)
- [ ] Port rate limiting to Rust middleware
- [ ] Port resource monitoring to platform-specific Rust (cgroups/Job Objects)
- [ ] Remove Python backend entirely
- [ ] Update documentation to reflect Rust-only architecture

---

## 📚 Key Architectural Principles (Your Application Already Follows)

### ✅ You're Already Doing Well:

1. **No Shell Execution**: ✅ `tokio::process::Command` with argv arrays
2. **Concurrent Subprocess Handling**: ✅ `tokio::join!` pattern prevents deadlocks
3. **Real-Time IPC**: ✅ Tauri events instead of WebSockets
4. **Error Handling**: ✅ Stream error recovery, timeout protection
5. **DAG Execution**: ✅ Parallel step execution with dependencies
6. **Async/Await**: ✅ Tokio runtime throughout

### 🎯 Areas to Enhance:

1. **Resource Limits**: ❌ Add cgroups v2, Job Objects, sandbox profiles
2. **Security Boundaries**: ⚠️ Tighten argument validation, add capability scoping
3. **Sidecar Packaging**: ❌ Bundle tools for deterministic execution
4. **Zero-Cost Parsers**: ⚠️ Implement streaming parsers for large outputs
5. **Platform Guards**: ❌ Add platform-specific resource controls

---

## 🏁 Conclusion

Your application has a **solid foundation** in Rust/Tauri architecture. You've successfully migrated from Python/FastAPI to a native Rust backend with proper async subprocess handling, real-time IPC, and workflow orchestration.

### Next Steps (Recommended Order):
1. **Week 1-2**: Argument pattern allowlisting + capability scoping (security critical)
2. **Week 3-5**: Resource limits (cgroups/Job Objects) (safety critical)
3. **Week 6**: macOS sandbox entitlements (distribution requirement)
4. **Week 7-8**: Sidecar packaging for core tools (reliability)
5. **Week 9**: Zero-cost streaming parsers (performance)
6. **Week 10+**: PyO3 integration if Python ecosystem access needed

### Success Metrics:
- ✅ Zero command injection vulnerabilities (argument validation)
- ✅ Zero resource exhaustion incidents (cgroups/Job Objects)
- ✅ Offline tool execution (sidecar packaging)
- ✅ <50ms latency for finding discovery (streaming parsers)
- ✅ Cross-platform resource parity (Linux/Windows/macOS limits)

---

**Document Version**: 1.0  
**Last Updated**: October 5, 2025  
**Author**: GitHub Copilot  
**Status**: Ready for Implementation
