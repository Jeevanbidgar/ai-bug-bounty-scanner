# Workflow Execution Engine Enhancement Plan - Phase 2

## Current Status Analysis

### ✅ Already Implemented
1. **Basic DAG Execution** (`engine.rs`)
   - Dependency graph resolution
   - Parallel step execution
   - Basic status tracking
   - Event emission

2. **Process Executor** (`executor.rs`)
   - Command execution with tokio
   - Timeout handling
   - Real-time stdout/stderr streaming
   - Basic artifact collection

3. **Type System** (`types.rs`)
   - WorkflowTemplate, WorkflowStep
   - WorkflowExecution with status tracking
   - StepExecution tracking
   - WorkflowArtifact structure

### ❌ Missing Features (To Implement)

1. **Retry Logic with Exponential Backoff**
   - Not implemented in ProcessExecutor
   - WorkflowRetry struct exists but unused
   - Need configurable retry policies

2. **Tool Integration**
   - ProcessExecutor doesn't use ToolDiscoveryService
   - No tool path resolution from discovered tools
   - No tool availability checking before execution

3. **Enhanced Artifact Management**
   - Basic artifact collection exists
   - Missing: artifact passing between steps
   - Missing: artifact metadata enrichment
   - Missing: cleanup policies

4. **Nuclei Output Parsing**
   - No nuclei JSONL parser
   - No vulnerability extraction
   - No CVSS parsing

5. **Execution State Persistence**
   - Active executions stored in memory only
   - Lost on application restart
   - Should persist to database

6. **Better Error Handling**
   - Basic error propagation
   - Need structured error types
   - Need error recovery strategies

---

## Implementation Plan

### Task 1: Integrate Tool Discovery with Workflow Executor ✅

**Goal**: Use discovered tools instead of assuming tools are in PATH

**Changes**:
1. Add `tool_discovery` field to `ProcessExecutor`
2. Update `execute_step` to resolve tool paths
3. Check tool availability before execution
4. Handle tool not found errors gracefully

**Files**:
- `src-tauri/src/runtime/executor.rs`
- `src-tauri/src/workflow/engine.rs`

---

### Task 2: Implement Retry Logic with Exponential Backoff ✅

**Goal**: Retry failed steps with configurable backoff

**Implementation**:
```rust
pub struct RetryPolicy {
    max_attempts: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    backoff_multiplier: f64,
}

async fn execute_with_retry(
    &self,
    step: &WorkflowStep,
    policy: &RetryPolicy,
) -> Result<Vec<WorkflowArtifact>> {
    let mut attempt = 0;
    let mut delay_ms = policy.initial_delay_ms;
    
    loop {
        attempt += 1;
        match self.execute_step_once(step).await {
            Ok(artifacts) => return Ok(artifacts),
            Err(e) if attempt < policy.max_attempts => {
                // Log retry
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                delay_ms = (delay_ms as f64 * policy.backoff_multiplier) as u64;
                delay_ms = delay_ms.min(policy.max_delay_ms);
            }
            Err(e) => return Err(e),
        }
    }
}
```

**Files**:
- `src-tauri/src/runtime/executor.rs`

---

### Task 3: Enhanced Artifact Management ✅

**Goal**: Better artifact handling and passing between steps

**Features**:
1. Artifact metadata enrichment (file size, hash, line count)
2. Artifact passing via template variables: `{{artifacts.step_id.artifact_name}}`
3. Artifact cleanup policies (age-based, size-based)

**Implementation**:
```rust
pub struct ArtifactManager {
    base_dir: PathBuf,
    max_age_days: u32,
    max_size_mb: u64,
}

impl ArtifactManager {
    async fn enrich_artifact(&self, artifact: &mut WorkflowArtifact) {
        // Add file size, hash, line count, etc.
    }
    
    async fn cleanup_old_artifacts(&self) {
        // Remove artifacts older than max_age_days
    }
    
    async fn resolve_artifact_reference(&self, template: &str, artifacts: &[WorkflowArtifact]) -> String {
        // Resolve {{artifacts.step_id.name}}
    }
}
```

**Files**:
- Create: `src-tauri/src/workflow/artifacts.rs`
- Update: `src-tauri/src/runtime/executor.rs`

---

### Task 4: Nuclei Output Parser ✅

**Goal**: Parse nuclei JSONL output and extract vulnerabilities

**Implementation**:
```rust
pub struct NucleiParser;

#[derive(Deserialize)]
pub struct NucleiVulnerability {
    template_id: String,
    template: String,
    info: NucleiInfo,
    matched_at: String,
    curl_command: Option<String>,
    matcher_name: Option<String>,
    #[serde(rename = "type")]
    vuln_type: String,
    host: String,
}

#[derive(Deserialize)]
pub struct NucleiInfo {
    name: String,
    severity: String,
    description: Option<String>,
    classification: Option<NucleiClassification>,
}

impl NucleiParser {
    pub fn parse_jsonl(content: &str) -> Result<Vec<NucleiVulnerability>> {
        // Parse each line as JSON
    }
    
    pub fn severity_to_score(severity: &str) -> i32 {
        match severity.to_lowercase().as_str() {
            "critical" => 9,
            "high" => 7,
            "medium" => 5,
            "low" => 3,
            "info" => 1,
            _ => 0,
        }
    }
}
```

**Files**:
- Create: `src-tauri/src/parsers/nuclei.rs`
- Create: `src-tauri/src/parsers/mod.rs`

---

### Task 5: Execution State Persistence ✅

**Goal**: Persist workflow executions to database

**Changes**:
1. Add database methods for workflow execution CRUD
2. Save execution state after each step
3. Load active executions on startup
4. Query execution history

**Files**:
- `src-tauri/src/database.rs` (methods already exist, need to use them)
- `src-tauri/src/workflow/engine.rs`

---

### Task 6: Better Error Types and Recovery ✅

**Goal**: Structured error handling with recovery strategies

**Implementation**:
```rust
#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    #[error("Tool not found: {0}")]
    ToolNotFound(String),
    
    #[error("Step timeout: {0}")]
    StepTimeout(String),
    
    #[error("Step failed with exit code {exit_code}: {message}")]
    StepFailed { exit_code: i32, message: String },
    
    #[error("Artifact not found: {0}")]
    ArtifactNotFound(String),
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

pub enum RecoveryStrategy {
    Retry { max_attempts: u32, backoff_ms: u64 },
    Skip,
    Fail,
    Fallback { alternative_step: String },
}
```

**Files**:
- Create: `src-tauri/src/workflow/errors.rs`
- Update: All workflow files to use new error types

---

## Detailed Implementation Order

### Week 1: Tool Integration + Retry Logic
1. **Day 1-2**: Tool discovery integration
   - Update ProcessExecutor to use ToolDiscoveryService
   - Resolve tool paths before execution
   - Add tool availability checks

2. **Day 3-4**: Retry logic implementation
   - Create RetryPolicy struct
   - Implement exponential backoff
   - Add retry configuration to WorkflowStep

3. **Day 5**: Testing and documentation

### Week 2: Artifacts + Parsers
1. **Day 1-2**: Artifact manager
   - Create ArtifactManager struct
   - Implement artifact enrichment
   - Add cleanup policies

2. **Day 3-4**: Nuclei parser
   - Create NucleiParser
   - Parse JSONL format
   - Extract vulnerabilities

3. **Day 5**: Testing and documentation

### Week 3: Persistence + Error Handling
1. **Day 1-2**: Database persistence
   - Use existing database methods
   - Save execution state
   - Load active executions on startup

2. **Day 3-4**: Better error handling
   - Create structured error types
   - Implement recovery strategies
   - Add error context

3. **Day 5**: Integration testing

---

## Success Criteria

### Must Have ✅
- [x] Tool discovery integration working
- [ ] Retry logic with exponential backoff
- [ ] Artifact passing between steps
- [ ] Nuclei output parsing
- [ ] Execution state persistence

### Should Have ✅
- [ ] Artifact metadata enrichment
- [ ] Artifact cleanup policies
- [ ] Structured error types
- [ ] Recovery strategies

### Nice to Have 🎁
- [ ] Parallel step optimization
- [ ] Step result caching
- [ ] Workflow metrics/analytics
- [ ] Step execution history

---

## Testing Strategy

### Unit Tests
- Retry logic with different policies
- Artifact resolution
- Nuclei parser with various inputs
- Error type conversions

### Integration Tests
- Full workflow execution
- Tool discovery → execution flow
- Artifact passing between steps
- Database persistence

### End-to-End Tests
- Run actual security workflows
- Verify nuclei vulnerabilities extracted
- Check artifact cleanup
- Test retry on transient failures

---

## Next Immediate Steps

1. **Start with Tool Integration** (Highest Priority)
   - ProcessExecutor currently assumes tools in PATH
   - Must use ToolDiscoveryService for reliability
   - Quick win with immediate impact

2. **Then Retry Logic** (High Priority)
   - Many security tools have transient failures
   - Retry with backoff improves reliability
   - Relatively straightforward to implement

3. **Follow with Artifact Manager** (Medium Priority)
   - Enables complex multi-step workflows
   - Required for artifact passing
   - Foundation for advanced features

4. **Nuclei Parser** (Medium Priority)
   - Core vulnerability scanning feature
   - Directly impacts product value
   - Well-defined scope

5. **Database Persistence** (Lower Priority)
   - Nice to have but not blocking
   - Methods already exist in database.rs
   - Can defer to polish phase

---

## Files to Create/Modify

### Create
- `src-tauri/src/workflow/artifacts.rs`
- `src-tauri/src/workflow/errors.rs`
- `src-tauri/src/parsers/mod.rs`
- `src-tauri/src/parsers/nuclei.rs`

### Modify
- `src-tauri/src/runtime/executor.rs` (major changes)
- `src-tauri/src/workflow/engine.rs` (tool discovery integration)
- `src-tauri/src/workflow/types.rs` (add retry policy fields)
- `src-tauri/src/workflow/mod.rs` (export new modules)

---

## Estimated Effort

- **Tool Integration**: 4-6 hours
- **Retry Logic**: 6-8 hours
- **Artifact Manager**: 8-12 hours
- **Nuclei Parser**: 4-6 hours
- **Database Persistence**: 4-6 hours
- **Error Handling**: 6-8 hours

**Total**: 32-46 hours (~1-1.5 weeks of focused development)

---

Let's start with **Task 1: Tool Integration** as it's the foundation for everything else!
