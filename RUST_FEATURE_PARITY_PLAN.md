# Rust Backend Feature Parity Implementation Plan

## Overview
This document outlines the complete implementation plan to achieve 100% feature parity between the Python backend and the Rust backend for the AI Bug Bounty Scanner.

---

## Current Status Analysis

### ✅ **Already Implemented (95%)**
- Database layer with all CRUD operations
- Basic Tauri commands (22 commands)
- Database models (Scan, Vulnerability, Report, WorkflowExecution, WorkflowArtifact, WorkflowFinding)
- Basic tool discovery
- Workflow template loading
- Frontend integration with Tauri commands
- Event system structure

### ❌ **Missing Critical Features (5%)**

---

## Implementation Roadmap

### **Phase 1: Tool Discovery Enhancement** (High Priority)

#### 1.1 Enhanced Tool Discovery Service
**Python Reference**: `backend/tool_discovery.py` (950+ lines)

**Required Features**:
- ✅ Basic tool resolution (partially done)
- ❌ Platform-specific tool resolution (Windows/Linux/macOS)
- ❌ Version detection with regex parsing
- ❌ OS dependency checking (libpcap, Npcap, WinPcap)
- ❌ Comprehensive tool catalog (70+ security tools)
- ❌ Tool cache persistence (JSON)
- ❌ Manual tool management (add/remove custom tools)
- ❌ Background refresh with TTL
- ❌ Tool verification before execution

**Tool Catalog to Support**:
```
Subdomain Enumeration: subfinder, amass, assetfinder, knockpy, sublist3r, dnsrecon, fierce, dnsenum
Port Scanning: nmap, naabu, masscan, rustscan
HTTP Probing: httpx, httprobe, meg
Web Crawling: katana, gospider, hakrawler
URL Discovery: gau, waybackurls, gauplus
Vulnerability Scanning: nuclei, nikto, wpscan, joomscan
Directory Bruteforce: ffuf, gobuster, dirbuster, feroxbuster, wfuzz
Parameter Discovery: arjun, param-miner
SQL Injection: sqlmap
XSS Detection: dalfox, xsstrike
Technology Detection: wappalyzer, whatweb
Screenshots: gowitness, aquatone, eyewitness
JS Analysis: linkfinder, subjs
Testing: interactsh-client
Exploitation: metasploit, searchsploit
Network: netcat, socat
Git: git, trufflehog, gitleaks
Cloud: s3scanner, cloudfail
Utilities: curl, wget, jq, python, go
```

**Files to Create**:
- `src-tauri/src/tools/discovery.rs` - Core discovery logic
- `src-tauri/src/tools/catalog.rs` - Tool definitions
- `src-tauri/src/tools/version_parser.rs` - Version extraction
- `src-tauri/src/tools/cache.rs` - Disk cache management

---

### **Phase 2: Workflow Execution Engine** (Critical Priority)

#### 2.1 DAG Executor Implementation
**Python Reference**: `backend/services/executor.py` (550+ lines)

**Required Features**:
- ❌ Dependency graph building
- ❌ Topological sort for step ordering
- ❌ Parallel step execution
- ❌ Retry logic with exponential backoff
- ❌ Timeout handling per step
- ❌ Environment variable injection
- ❌ Working directory management
- ❌ Output capture (stdout/stderr)
- ❌ Artifact processing
- ❌ Real-time progress events
- ❌ Error propagation and recovery

**Workflow Step Execution**:
```rust
pub struct StepExecution {
    step_id: String,
    step_name: String,
    command: Vec<String>,
    env: HashMap<String, String>,
    timeout: u64,
    retry_policy: RetryPolicy,
    status: StepStatus,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    artifacts: Vec<String>,
}
```

**Files to Create/Update**:
- `src-tauri/src/runtime/executor.rs` - DAG execution engine
- `src-tauri/src/runtime/process.rs` - Process management
- `src-tauri/src/workflow/step.rs` - Step execution logic
- `src-tauri/src/workflow/dependencies.rs` - Dependency resolution

---

### **Phase 3: Scan Service with Tool Execution** (Critical Priority)

#### 3.1 Scan Orchestration
**Python Reference**: `backend/services/scan_service.py` (200+ lines)

**Required Features**:
- ❌ Scan execution orchestration
- ❌ Agent/tool selection based on scan type
- ❌ Progress tracking (0-100%)
- ❌ Current test display
- ❌ Vulnerability creation from tool output
- ❌ Real-time scan events
- ❌ Scan cancellation
- ❌ Error handling and recovery
- ❌ Estimated completion time

**Scan Types**:
- Quick Scan: subfinder + nuclei
- Full Scan: subfinder + amass + nmap + nuclei + sqlmap
- Custom Scan: User-selected tools

**Files to Create**:
- `src-tauri/src/services/scan_service.rs` - Scan orchestration
- `src-tauri/src/services/agent_executor.rs` - Individual agent execution

---

### **Phase 4: Tool Adapters** (High Priority)

#### 4.1 Adapter System
**Python Reference**: `backend/adapters/` (multiple files)

**Required Adapters**:
```rust
trait ToolAdapter {
    fn build_command(&self, params: &HashMap<String, String>) -> Vec<String>;
    fn parse_output(&self, output: &str) -> Vec<Finding>;
    fn validate_requirements(&self) -> Result<(), Error>;
}
```

**Adapters to Implement**:
- SubfinderAdapter - Subdomain discovery
- AmassAdapter - Comprehensive recon
- NucleiAdapter - Vulnerability scanning
- NmapAdapter - Port scanning
- NaabuAdapter - Fast port scanning
- GauAdapter - URL collection
- WaybackurlsAdapter - Historical URLs
- HttpxAdapter - HTTP probing
- KatanaAdapter - Web crawling

**Files to Create**:
- `src-tauri/src/adapters/base.rs` - Base trait
- `src-tauri/src/adapters/subfinder.rs`
- `src-tauri/src/adapters/nuclei.rs`
- `src-tauri/src/adapters/nmap.rs`
- `src-tauri/src/adapters/amass.rs`
- `src-tauri/src/adapters/manager.rs` - Adapter registry

---

### **Phase 5: Output Parsers** (High Priority)

#### 5.1 Nuclei Parser
**Python Reference**: `backend/services/nuclei_parser.py`

**Required Features**:
- ❌ Parse JSONL output
- ❌ Extract severity (info, low, medium, high, critical)
- ❌ Extract CVSS scores
- ❌ Extract CWE identifiers
- ❌ Parse matched URLs
- ❌ Extract evidence
- ❌ Create WorkflowFinding records

**Files to Create**:
- `src-tauri/src/parsers/nuclei.rs` - Nuclei JSONL parser
- `src-tauri/src/parsers/nmap.rs` - Nmap XML parser
- `src-tauri/src/parsers/generic.rs` - Generic output parsers

---

### **Phase 6: Recon Planning Service** (Medium Priority)

#### 6.1 Recon Service
**Python Reference**: `backend/services/recon_service.py`

**Required Features**:
- ❌ Built-in recon templates
- ❌ Target type detection (domain, IP, CIDR, URL)
- ❌ Multi-phase recon workflows
- ❌ Tool compatibility checking
- ❌ Plan generation API
- ❌ Plan execution

**Built-in Templates**:
```rust
- SubdomainEnumeration
- PortScanning
- WebReconnaissance
- FullRecon (multi-phase)
```

**Files to Create**:
- `src-tauri/src/services/recon_service.rs` - Recon planning
- `src-tauri/src/services/recon_templates.rs` - Built-in templates

---

### **Phase 7: Report Generation** (Medium Priority)

#### 7.1 Report Service
**Python Reference**: Backend report generation logic

**Required Features**:
- ❌ HTML report generation
- ❌ JSON report export
- ❌ CSV report export
- ❌ PDF report generation (using wkhtmltopdf or similar)
- ❌ Executive summary generation
- ❌ Vulnerability aggregation
- ❌ Report download endpoint

**Report Structure**:
```rust
pub struct Report {
    title: String,
    generated: DateTime<Utc>,
    scan_id: String,
    vulnerabilities: Vec<Vulnerability>,
    summary: ReportSummary,
    charts: ReportCharts,
    recommendations: Vec<String>,
}
```

**Files to Create**:
- `src-tauri/src/services/report_service.rs` - Report generation
- `src-tauri/src/templates/report.html` - HTML template
- `src-tauri/src/services/pdf_generator.rs` - PDF conversion

---

### **Phase 8: Real-Time Events** (High Priority)

#### 8.1 Event Emission
**Python Reference**: WebSocket events in Python backend

**Required Events**:
- ❌ `scan:progress` - Scan progress updates
- ❌ `scan:completed` - Scan completion
- ❌ `scan:failed` - Scan failure
- ❌ `workflow:step_started` - Workflow step start
- ❌ `workflow:step_completed` - Workflow step completion
- ❌ `workflow:completed` - Workflow completion
- ❌ `tool:output` - Real-time tool output streaming
- ❌ `vulnerability:found` - New vulnerability discovered

**Files to Update**:
- `src-tauri/src/events.rs` - Add event emission functions
- `src-tauri/src/services/scan_service.rs` - Emit scan events
- `src-tauri/src/runtime/executor.rs` - Emit workflow events

---

### **Phase 9: Additional API Endpoints** (Medium Priority)

#### 9.1 Missing Endpoints

**Health & Metrics**:
- ❌ `GET /api/health` - Health check
- ❌ `GET /api/metrics` - System metrics
- ❌ `GET /api/stats` - Scan statistics

**Scan Management**:
- ❌ `POST /api/scans/{id}/start` - Start scan
- ❌ `POST /api/scans/{id}/stop` - Stop scan
- ❌ `GET /api/scans/{id}/progress` - Real-time progress

**Workflow Management**:
- ❌ `GET /api/workflows/{id}/status` - Execution status
- ❌ `POST /api/workflows/{id}/stop` - Stop execution
- ❌ `GET /api/workflows/{id}/artifacts` - Get artifacts
- ❌ `GET /api/workflows/{id}/findings` - Get findings

**Tool Management**:
- ❌ `POST /api/tools/refresh` - Refresh tool status
- ❌ `POST /api/tools/manual/add` - Manually add tool
- ❌ `DELETE /api/tools/manual/{name}` - Remove manual tool
- ❌ `GET /api/tools/available` - List available tools
- ❌ `GET /api/tools/categories` - Get categories

**Recon**:
- ❌ `GET /api/recon/plans` - List recon plans
- ❌ `POST /api/recon/plans/generate` - Generate plan
- ❌ `POST /api/recon/plans/{id}/execute` - Execute plan

**Files to Create**:
- `src-tauri/src/commands/health.rs` - Health endpoints
- `src-tauri/src/commands/metrics.rs` - Metrics endpoints
- `src-tauri/src/commands/recon.rs` - Recon endpoints

---

### **Phase 10: Background Services** (Low Priority)

#### 10.1 Background Tasks
**Python Reference**: FastAPI BackgroundTasks

**Required Features**:
- ❌ Tool cache refresh scheduler
- ❌ Scan cleanup scheduler
- ❌ Database vacuum/optimize
- ❌ Artifact cleanup (old files)

**Files to Create**:
- `src-tauri/src/services/scheduler.rs` - Task scheduler
- `src-tauri/src/services/cleanup.rs` - Cleanup tasks

---

## Database Schema Additions

### WorkflowStep Table (Missing)
```sql
CREATE TABLE IF NOT EXISTS workflow_steps (
    id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    step_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    started DATETIME,
    completed DATETIME,
    command TEXT,
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT,
    error_message TEXT,
    artifacts TEXT,
    FOREIGN KEY (execution_id) REFERENCES workflow_executions(id) ON DELETE CASCADE
);
```

### ReconPlan Table (Missing)
```sql
CREATE TABLE IF NOT EXISTS recon_plans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    target_type TEXT NOT NULL,
    phases TEXT NOT NULL,
    tools TEXT NOT NULL,
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

---

## Testing Strategy

### Unit Tests
- Tool discovery (mock commands)
- Version parsing
- Output parsing (nuclei, nmap)
- DAG dependency resolution
- Report generation

### Integration Tests
- End-to-end scan execution
- Workflow execution with mocked tools
- Database operations
- Event emission

### Manual Testing
- Install actual security tools
- Run quick scan on test target
- Verify vulnerability creation
- Check report generation
- Test real-time UI updates

---

## Implementation Priority

### **Week 1: Critical Foundation**
1. ✅ Enhanced tool discovery service
2. ✅ Tool catalog (70+ tools)
3. ✅ Tool cache persistence
4. ✅ Manual tool management

### **Week 2: Execution Engine**
1. ✅ Workflow DAG executor
2. ✅ Process management
3. ✅ Retry and timeout logic
4. ✅ Step tracking

### **Week 3: Scan Execution**
1. ✅ Scan service
2. ✅ Tool adapters (subfinder, nuclei, nmap)
3. ✅ Output parsers
4. ✅ Vulnerability creation

### **Week 4: Real-Time & Polish**
1. ✅ Event emission
2. ✅ Recon service
3. ✅ Report generation
4. ✅ Additional commands
5. ✅ Background services

---

## Success Criteria

- [ ] All 70+ security tools discovered automatically
- [ ] Workflows execute with parallel steps
- [ ] Scans run actual tools and create vulnerabilities
- [ ] Real-time progress updates in frontend
- [ ] Reports generated in multiple formats
- [ ] Manual tool management works
- [ ] Tool adapters for top 10 security tools
- [ ] Comprehensive error handling
- [ ] Event emission for all operations
- [ ] Performance: <50ms for database queries
- [ ] Memory: <100MB base usage
- [ ] Frontend shows no errors
- [ ] All Python backend features replicated

---

## Dependencies & Crates to Add

```toml
# Process execution
tokio-util = "0.7"
futures = "0.3"

# Command parsing
shellwords = "1.1"

# XML parsing (for nmap)
quick-xml = "0.31"

# HTML templating
tera = "1.19"

# PDF generation
wkhtmltopdf = "0.4"  # or headless_chrome

# Metrics
prometheus = "0.13"

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"
```

---

## Estimated Timeline

**Total Effort**: 4-6 weeks for complete feature parity

**Breakdown**:
- Tool Discovery: 1 week
- Workflow Engine: 1 week
- Scan Service + Adapters: 1.5 weeks
- Parsers + Reports: 1 week
- Events + Polish: 0.5-1.5 weeks

---

## Migration Verification Checklist

- [ ] Run `npm run tauri dev` without errors
- [ ] Create scan with target "example.com"
- [ ] Verify tools discovered (check console)
- [ ] Execute workflow and see progress
- [ ] Check vulnerabilities created
- [ ] Generate report
- [ ] Download report
- [ ] Verify real-time updates
- [ ] Test manual tool addition
- [ ] Test scan cancellation
- [ ] Check all dashboard metrics
- [ ] Verify no console errors
- [ ] Test on Windows/Linux/macOS

---

**Status**: Ready to implement  
**Last Updated**: 2025-01-01  
**Assignee**: AI Assistant  
**Priority**: P0 (Highest)
