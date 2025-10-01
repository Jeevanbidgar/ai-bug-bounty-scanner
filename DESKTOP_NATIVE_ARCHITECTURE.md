# Desktop-Native Architecture Guide

## Overview

This document describes the desktop-native architecture of the AI Bug Bounty Scanner, which uses Tauri for workflow execution without web server or WebSocket dependencies for real-time updates.

## Architecture Principles

### 1. Desktop-Only Workflow Execution

All workflow orchestration runs within the Tauri/Rust runtime:

- **No FastAPI WebSockets** - Removed `backend/api/ws.py` WebSocket layer
- **Tauri Event System** - Real-time IPC using `emit_all` and `listen`
- **Native Process Control** - `tokio::process::Command` for child processes
- **Direct Tool Execution** - Security tools run as native system processes

### 2. Event-Driven Communication

#### Tauri Events (Frontend ← Rust Backend)

The following events are emitted from Rust to the React frontend:

```rust
// Workflow lifecycle events
workflow:step_started       // Step begins execution
workflow:step_completed     // Step finishes successfully
workflow:step_failed        // Step fails

// Real-time output streaming
workflow:stdout             // Tool stdout (line-by-line)
workflow:stderr             // Tool stderr (line-by-line)

// Execution completion
workflow:execution_completed  // All steps finished
workflow:execution_failed     // Workflow failed
```

#### Event Payload Structure

```typescript
// Step started
{
  execution_id: string
  step_id: string
  step_name: string
}

// Step completed
{
  execution_id: string
  step_id: string
  status: "completed" | "failed"
  exit_code: number
  artifacts: string[]
}

// Stdout/Stderr
{
  execution_id: string
  step_id: string
  line: string
}
```

### 3. Frontend Event Handling

Use the `useWorkflowEvents` hook for proper listener management:

```typescript
import { useWorkflowEvents } from "../hooks/useWorkflowEvents";

const MyComponent = () => {
  const [executionId, setExecutionId] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);

  // Setup event listeners with automatic cleanup
  useWorkflowEvents(executionId, {
    onStepStarted: (data) => {
      console.log(`Step started: ${data.step_name}`);
    },
    onStdout: (data) => {
      setLogs((prev) => [...prev, data.line]);
    },
    onExecutionCompleted: (data) => {
      console.log("Workflow completed!");
    },
  });

  // Listeners are automatically cleaned up on unmount
  return <div>{/* UI */}</div>;
};
```

**Important:** The hook automatically:

- Cleans up listeners on component unmount
- Filters events by `execution_id`
- Prevents duplicate handlers
- Handles reconnection scenarios

## Workflow Pipeline

### Full Reconnaissance Pipeline

The `full-recon.yaml` workflow implements the following DAG:

```
subfinder (subdomain discovery)
    ↓
naabu (port scanning)
    ↓
httpx (URL probing & HTTP detection)
    ↓
nuclei (vulnerability scanning)
```

**Critical:** The httpx step is essential because:

- Nuclei requires live URLs with schemes (`http://`, `https://`)
- Naabu outputs `host:port` which nuclei cannot consume directly
- httpx probes ports and produces scheme-aware URLs for nuclei

### Command Templates

Workflow steps use argv arrays (no shell):

```yaml
steps:
  - id: httpx
    run:
      - httpx
      - -l
      - "{{workdir}}/ports.txt"
      - -o
      - "{{workdir}}/urls.txt"
      - -title
      - -status-code
```

Variables like `{{workdir}}` and `{{target}}` are interpolated at runtime.

## Process Orchestration

### Tool Path Resolution

The Rust backend uses the `which` crate for cross-platform tool discovery:

```rust
use which::which;

fn resolve_tool_paths(command: Vec<String>) -> Result<Vec<String>, String> {
    let mut resolved = Vec::new();
    for arg in command {
        match which(&arg) {
            Ok(path) => resolved.push(path.to_string_lossy().to_string()),
            Err(_) => resolved.push(arg), // Keep flags/params as-is
        }
    }
    Ok(resolved)
}
```

**Benefits:**

- Caches tool paths for performance
- Cross-platform (Windows, Linux, macOS)
- Re-resolves on ENOENT errors
- Self-healing when tools are updated/moved

### Async Process Execution

Tools are spawned with `tokio::process::Command`:

```rust
let mut child = TokioCommand::new(&resolved_command[0])
    .args(&resolved_command[1..])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()?;

// Stream stdout line-by-line
let stdout = child.stdout.take().unwrap();
let reader = BufReader::new(stdout);
let mut lines = reader.lines();

while let Some(line) = lines.next_line().await? {
    // Emit to frontend via Tauri events
    app_handle.emit_all("workflow:stdout", json!({
        "execution_id": execution_id,
        "step_id": step_id,
        "line": line
    }))?;
}

// Enforce timeout
let timeout_duration = Duration::from_secs(step.timeout);
match timeout(timeout_duration, child.wait()).await {
    Ok(status) => { /* Handle completion */ },
    Err(_) => {
        child.kill().await?; // Force kill on timeout
        return Err("Step timed out");
    }
}
```

**Features:**

- Incremental stdout/stderr streaming (no buffering)
- Per-step timeout enforcement
- Graceful cancellation with `kill()`
- Proper exit code handling

### DAG Execution

Steps are executed in dependency order with concurrency:

```rust
async fn execute_dag(template: &WorkflowTemplate, execution: &mut WorkflowExecution) {
    let mut completed_steps = HashSet::new();

    while completed_steps.len() < template.steps.len() {
        // Find ready steps (dependencies satisfied)
        let ready_steps = get_ready_steps(&template.steps, &completed_steps);

        // Execute ready steps concurrently
        let tasks: Vec<_> = ready_steps.iter()
            .map(|step| execute_step(step, execution))
            .collect();

        let results = join_all(tasks).await;

        for (step_id, result) in results {
            if result.is_ok() {
                completed_steps.insert(step_id);
            } else {
                // Handle failure (fail fast or continue)
                return Err("Step failed");
            }
        }
    }
}
```

## Nuclei Integration

### Output Formats

Nuclei supports multiple structured output formats:

```yaml
- id: nuclei
  run:
    - nuclei
    - -l
    - "{{workdir}}/urls.txt"
    - -jsonl # JSONL output (one JSON per line)
    - -o
    - "{{workdir}}/nuclei.jsonl"
    - -je # JSON export (full structured JSON)
    - "{{workdir}}/nuclei-export.json"
```

### Parsing & Persistence

The `nuclei_parser` service handles both formats:

```python
from backend.services.nuclei_parser import nuclei_parser

# Auto-detect format
findings = nuclei_parser.parse_nuclei_output("nuclei.jsonl")

# Store in database
for finding in findings:
    workflow_finding = WorkflowFinding(
        execution_id=execution_id,
        step_id=step_id,
        finding_type=finding['finding_type'],
        severity=finding['severity'],
        title=finding['title'],
        url=finding['url'],
        cvss=finding['cvss'],
        cwe=finding['cwe'],
        tags=json.dumps(finding['tags']),
        evidence=json.dumps(finding['evidence']),
        raw_data=json.dumps(finding['raw_data'])
    )
    db.add(workflow_finding)
```

### Version Compatibility

The parser gracefully handles nuclei version differences:

- **v2.x**: `-j` (JSONL) and `-je` (JSON export)
- **v3.x**: `-jsonl` and `-json-export` (newer flags)

If older versions don't support certain flags, the parser logs a warning and suggests updating nuclei.

## Security Model

### Tauri Shell Allowlist

Only approved tools can be executed from the desktop app:

```json
{
  "tauri": {
    "allowlist": {
      "shell": {
        "all": false,
        "execute": true,
        "scope": [
          { "name": "subfinder", "cmd": "subfinder", "args": true },
          { "name": "naabu", "cmd": "naabu", "args": true },
          { "name": "httpx", "cmd": "httpx", "args": true },
          { "name": "nuclei", "cmd": "nuclei", "args": true },
          { "name": "amass", "cmd": "amass", "args": true },
          { "name": "sqlmap", "cmd": "sqlmap", "args": true }
        ]
      }
    }
  }
}
```

**Security Guarantees:**

- Only allowlisted commands can be executed
- Arguments must be explicitly allowed (`"args": true`)
- No shell execution (no `cmd /c` or `sh -c`)
- Arbitrary code execution is prevented

## Testing Strategy

### Unit Tests

Test individual components in isolation:

```python
# Test workflow template loading
def test_workflow_template_loading():
    templates = workflow_loader.list_workflows()
    assert len(templates) > 0

# Test DAG dependency resolution
def test_workflow_dag_dependencies():
    workflow = workflow_loader.get_workflow('full-recon')
    assert 'subfinder' in [s.id for s in workflow.steps]
```

### Integration Tests

Test end-to-end workflows:

```python
# Test workflow execution (mocked tools)
@pytest.mark.asyncio
async def test_workflow_execution():
    execution_id = await workflow_executor.execute_workflow(
        workflow_id='full-recon',
        inputs={'target': 'example.com'}
    )

    # Verify execution was created
    status = await workflow_executor.get_execution_status(execution_id)
    assert status['status'] in ['pending', 'running']
```

### Manual Testing

1. Start the desktop app: `npm run tauri dev`
2. Navigate to Workflows page
3. Select "Full Reconnaissance"
4. Enter target: `example.com`
5. Click "Execute Workflow"
6. Observe:
   - Step progress updates in real-time
   - Live stdout/stderr logs
   - Artifacts created in working directory
   - Findings persisted to database

## Troubleshooting

### Event Listeners Not Cleaning Up

**Symptom:** Duplicate log lines or events after navigation

**Solution:** Ensure `useWorkflowEvents` hook is used with proper dependencies:

```typescript
useEffect(() => {
  // Setup listeners
  return () => {
    // Cleanup is automatic
  };
}, [executionId]); // Re-setup if executionId changes
```

### Tools Not Found in PATH

**Symptom:** "Tool not found" errors during execution

**Solution:** Verify tools are installed and in PATH:

```bash
# Check tool availability
which subfinder
which naabu
which httpx
which nuclei

# Add to PATH if needed
export PATH=$PATH:/path/to/tools
```

### Nuclei Not Reading httpx Output

**Symptom:** Nuclei reports "no targets found"

**Solution:** Verify httpx step produces URLs with schemes:

```bash
# httpx should output:
http://example.com:80
https://example.com:443

# Not:
example.com:80
```

Ensure httpx step runs before nuclei in the DAG.

### Process Timeouts

**Symptom:** Steps killed mid-execution

**Solution:** Increase timeout in workflow YAML:

```yaml
- id: nuclei
  timeout: 3600 # 1 hour (default was 1800)
```

## References

- [Tauri Events](https://tauri.app/v1/guides/features/events/)
- [Tokio Async Process](https://docs.rs/tokio/latest/tokio/process/)
- [httpx Documentation](https://github.com/projectdiscovery/httpx)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [Which Crate](https://docs.rs/which/)
