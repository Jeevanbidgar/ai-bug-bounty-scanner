# 🗄️ AI Bug Bounty Scanner - Entity Relationship Diagram

## Overview
This ER diagram represents the data model for the AI Bug Bounty Scanner application, designed to orchestrate security tools and manage vulnerability scanning workflows.

## Entities & Relationships

### Core Entities

#### **Scan** (Primary Entity)
- **Purpose**: Represents a security scanning operation
- **Attributes**:
  - `id` (Primary Key) - UUID
  - `target` - Target URL/domain to scan
  - `scan_type` - Type (Quick, Full, Custom)
  - `status` - Current status (pending, running, completed, failed, cancelled)
  - `progress` - Completion percentage (0-100)
  - `started` - Start timestamp
  - `completed` - Completion timestamp
  - `agents` - JSON array of tools used
  - `current_test` - Currently executing test
  - `command_log` - JSON log of executed commands
  - `target_validated` - Boolean validation status

#### **Vulnerability** (Findings)
- **Purpose**: Stores discovered vulnerabilities
- **Attributes**:
  - `id` (Primary Key) - UUID
  - `scan_id` (Foreign Key → Scan.id)
  - `title` - Vulnerability title
  - `severity` - Risk level (Critical, High, Medium, Low)
  - `cvss` - CVSS score (optional)
  - `description` - Detailed description
  - `url` - Affected URL (optional)
  - `parameter` - Vulnerable parameter (optional)
  - `payload` - Exploit payload (optional)
  - `remediation` - Fix recommendation (optional)
  - `discovered_by` - Tool that found it
  - `timestamp` - Discovery timestamp
  - `false_positive` - Boolean flag
  - `confirmed` - Boolean confirmation flag
  - `evidence` - JSON evidence data

#### **Report** (Output Documents)
- **Purpose**: Generated security reports
- **Attributes**:
  - `id` (Primary Key) - UUID
  - `scan_id` (Foreign Key → Scan.id)
  - `title` - Report title
  - `format` - Output format (HTML, PDF, JSON, CSV)
  - `file_path` - File system path (optional)
  - `generated` - Creation timestamp
  - `summary` - Report summary (optional)
  - `severity_distribution` - JSON severity counts

#### **Tool** (Security Tools Registry)
- **Purpose**: Available security tools and their status
- **Attributes**:
  - `id` (Primary Key) - UUID
  - `name` - Tool name (e.g., "nmap", "nuclei")
  - `description` - Tool description
  - `category` - Tool category (recon, web, network, etc.)
  - `command_template` - JSON array of command templates
  - `installed` - Boolean installation status
  - `version` - Tool version (optional)
  - `path` - Installation path (optional)
  - `last_check` - Last status check timestamp
  - `os_dependencies` - JSON array of OS dependencies
  - `missing_dependencies` - JSON array of missing deps

### Supporting Entities

#### **SystemHealth** (Runtime Stats)
- **Purpose**: Real-time system monitoring
- **Attributes**:
  - `id` (Primary Key) - UUID
  - `timestamp` - Measurement timestamp
  - `active_scans` - Number of running scans
  - `total_scans` - Lifetime scan count
  - `tools_available` - Available tools count
  - `critical_issues` - Critical system issues
  - `memory_usage` - Memory utilization
  - `cpu_usage` - CPU utilization

#### **WorkflowExecution** (Tool Orchestration)
- **Purpose**: Track tool execution workflows
- **Attributes**:
  - `id` (Primary Key) - UUID
  - `scan_id` (Foreign Key → Scan.id)
  - `workflow_name` - Workflow identifier
  - `step_order` - Execution order
  - `tool_name` - Tool being executed
  - `command` - Executed command
  - `status` - Step status (pending, running, completed, failed)
  - `started` - Step start time
  - `completed` - Step completion time
  - `output` - Tool output (truncated)
  - `error_message` - Error details (if failed)

## Entity Relationships

### One-to-Many Relationships

```
Scan (1) ──── (Many) Vulnerability
Scan (1) ──── (Many) Report
Scan (1) ──── (Many) WorkflowExecution
```

### Many-to-One Relationships

```
Vulnerability (Many) ──── (1) Scan
Report (Many) ──── (1) Scan
WorkflowExecution (Many) ──── (1) Scan
```

### System-Level Relationships

```
SystemHealth (Many) ──── (1) System
Tool (Many) ──── (1) ToolCategory
```

## Data Flow Diagram

### Scan Lifecycle
1. **Scan Creation** → `Scan` record created with `status=pending`
2. **Tool Discovery** → Check available `Tool` records for execution
3. **Workflow Execution** → Create `WorkflowExecution` records for each tool
4. **Vulnerability Discovery** → Create `Vulnerability` records as findings are made
5. **Report Generation** → Create `Report` record with findings summary
6. **Status Updates** → Update `Scan` status throughout process

### Real-time Monitoring
- **SystemHealth** records updated every 10 seconds
- **WorkflowExecution** records updated during tool execution
- **Vulnerability** records created as tools find issues
- **Scan** status and progress updated in real-time

## Database Schema Considerations

### Indexes for Performance
```sql
-- Scan queries (most common)
CREATE INDEX idx_scan_status ON scans(status);
CREATE INDEX idx_scan_target ON scans(target);
CREATE INDEX idx_scan_started ON scans(started);

-- Vulnerability queries
CREATE INDEX idx_vulnerability_scan ON vulnerabilities(scan_id);
CREATE INDEX idx_vulnerability_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerability_confirmed ON vulnerabilities(confirmed);

-- Tool queries
CREATE INDEX idx_tool_installed ON tools(installed);
CREATE INDEX idx_tool_category ON tools(category);

-- Report queries
CREATE INDEX idx_report_scan ON reports(scan_id);
CREATE INDEX idx_report_generated ON reports(generated);
```

### JSON Fields (PostgreSQL)
- `agents` (Scan) - Array of tool names
- `command_template` (Tool) - Array of command strings
- `os_dependencies` (Tool) - Array of dependency names
- `missing_dependencies` (Tool) - Array of missing deps
- `command_log` (Scan) - JSONB for command execution logs
- `evidence` (Vulnerability) - JSONB for proof of findings

### Constraints
- `Scan.status` ∈ {pending, running, completed, failed, cancelled}
- `Vulnerability.severity` ∈ {Critical, High, Medium, Low}
- `Tool.category` ∈ {recon, web, network, fuzzing, injection, etc.}
- `Report.format` ∈ {HTML, PDF, JSON, CSV}

## Future Enhancements

### Additional Entities
- **User** (Authentication and authorization)
- **Project** (Multi-target organization)
- **Notification** (Alert management)
- **Template** (Reusable scan configurations)
- **Compliance** (Regulatory compliance tracking)

### Advanced Relationships
- Many-to-Many: Scans ↔ Templates (scan configurations)
- User permissions on Projects
- Notification subscriptions for scan events

## API Endpoints Mapping

### Scan Management
- `GET /api/scans/` → List scans with filtering
- `POST /api/scans/` → Create new scan
- `GET /api/scans/{id}` → Get scan details
- `POST /api/scans/{id}/start` → Start scan execution
- `DELETE /api/scans/{id}` → Delete scan

### Tool Management
- `GET /api/tools/` → List available tools
- `POST /api/tools/refresh` → Refresh tool status
- `GET /api/tools/{name}` → Get tool details

### Report Management
- `GET /api/reports/` → List reports
- `POST /api/reports/` → Generate new report
- `GET /api/reports/{id}` → Get report details
- `GET /api/reports/{id}/download` → Download report file

### Vulnerability Management
- `GET /api/scans/{id}/vulnerabilities` → Get scan vulnerabilities
- `PUT /api/vulnerabilities/{id}` → Update vulnerability status

## Data Retention Strategy

### Scan Data (90 days default)
- Completed scans: 90 days
- Failed scans: 30 days
- Running scans: Never (until completed)

### Vulnerability Data (1 year)
- All vulnerability records: 365 days minimum
- Critical/High severity: Permanent retention

### System Logs (30 days)
- Application logs: 30 days
- Audit logs: 1 year minimum

---

*This ER diagram provides the foundation for developing a robust, scalable security scanning platform with proper data relationships and performance optimization.*


