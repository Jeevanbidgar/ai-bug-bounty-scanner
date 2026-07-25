#![allow(dead_code)]
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::FromRow;
use sqlx::SqlitePool;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Scan {
    pub id: String,
    pub name: String,
    pub target: String,
    pub status: String,
    pub scan_type: String,
    pub workflow_id: Option<String>,
    pub started: DateTime<Utc>,
    pub completed: Option<DateTime<Utc>>,
    pub progress: i32,
    pub current_test: Option<String>,
    pub current_step: Option<String>,
    pub total_steps: Option<i32>,
    pub duration: Option<String>,
    pub estimated_time: Option<String>,
    pub description: Option<String>,
    pub tags: Option<String>,
    pub working_directory: Option<String>,
    pub agents: Option<String>,
    pub command_log: Option<String>,
    pub target_validated: bool,
    pub vulnerabilities: Option<i32>,
    pub critical: Option<i32>,
    pub high: Option<i32>,
    pub medium: Option<i32>,
    pub low: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WorkflowExecution {
    pub id: String,
    pub scan_id: Option<String>,
    pub workflow_id: String,
    pub status: String,
    pub started: DateTime<Utc>,
    pub completed: Option<DateTime<Utc>>,
    pub current_step: Option<String>,
    pub progress: i32,
    pub inputs: String,
    pub working_directory: Option<String>,
    pub logs: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WorkflowArtifact {
    pub id: String,
    pub execution_id: String,
    pub step_id: String,
    pub name: String,
    pub artifact_type: String,
    pub file_path: Option<String>,
    pub content: Option<String>,
    pub metadata_: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WorkflowStepExecution {
    pub execution_id: String,
    pub step_id: String,
    pub status: String,
    pub started: Option<DateTime<Utc>>,
    pub completed: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub artifacts: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WorkflowFinding {
    pub id: String,
    pub execution_id: String,
    pub step_id: String,
    pub title: String,
    pub severity: Option<String>,
    pub description: Option<String>,
    pub cvss: Option<f64>,
    pub url: Option<String>,
    pub parameter: Option<String>,
    pub payload: Option<String>,
    pub remediation: Option<String>,
    pub discovered_by: Option<String>,
    pub evidence: Option<String>,
    pub false_positive: bool,
    pub confirmed: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Vulnerability {
    pub id: String,
    pub scan_id: String,
    pub title: String,
    pub severity: String,
    pub cvss: Option<f64>,
    pub description: String,
    pub url: Option<String>,
    pub parameter: Option<String>,
    pub payload: Option<String>,
    pub remediation: Option<String>,
    pub discovered_by: String,
    pub timestamp: DateTime<Utc>,
    pub false_positive: bool,
    pub confirmed: bool,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Report {
    pub id: String,
    pub scan_id: String,
    pub title: String,
    pub content: String,
    pub format: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ReportExport {
    pub report_id: String,
    pub file_path: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct McpClientProfileRow {
    id: String,
    name: String,
    capabilities: String,
    created_at: DateTime<Utc>,
    last_seen_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct EngagementScopeRow {
    id: String,
    revision: i64,
    name: String,
    principal_id: String,
    targets: String,
    workflow_ids: String,
    allowed_risk_tier: String,
    budget: String,
    starts_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    signature: String,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct McpAuditEventRow {
    id: String,
    principal_id: String,
    capability: String,
    request_id: String,
    scope_id: Option<String>,
    sanitized_arguments: String,
    outcome: String,
    correlation_id: Option<String>,
    previous_hash: Option<String>,
    event_hash: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WorkflowExecutionGovernance {
    pub execution_id: String,
    pub revision_hash: String,
    pub scope_id: String,
    pub principal_id: String,
    pub request_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct WorkflowRevisionRow {
    id: String,
    workflow_id: String,
    revision_hash: String,
    document: String,
    immutable: bool,
    created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct WorkflowTrustRow {
    revision_hash: String,
    source: String,
    verifier_version: Option<String>,
    evidence_hash: Option<String>,
    trusted_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyReservation {
    Acquired,
    Replayed(String),
    InProgress,
    Conflict,
}

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(app_data_dir: PathBuf) -> Result<Self> {
        Self::open(app_data_dir, true).await
    }

    /// Open the UniHack database without claiming ownership of running child
    /// processes. Auxiliary clients such as the MCP bridge must use this until
    /// the dedicated daemon is the sole execution owner.
    pub async fn open_client(app_data_dir: PathBuf) -> Result<Self> {
        Self::open(app_data_dir, false).await
    }

    async fn open(app_data_dir: PathBuf, recover_incomplete: bool) -> Result<Self> {
        // Ensure data directory exists
        eprintln!("Creating app data directory: {}", app_data_dir.display());
        fs::create_dir_all(&app_data_dir).await?;

        // Verify directory was created
        if !app_data_dir.exists() {
            return Err(anyhow!("Failed to create app data directory"));
        }

        // Create database path
        let db_path = app_data_dir.join("scanner.db");

        // Debug: print the database path
        eprintln!("Database path: {}", db_path.display());
        eprintln!("Database path exists: {}", db_path.exists());

        // Try to create the database file explicitly
        if !db_path.exists() {
            eprintln!("Creating database file...");
            fs::File::create(&db_path).await?;
            eprintln!("Database file created successfully");
        }

        // SQLite PRAGMAs such as foreign_keys are connection-local. Configure
        // them through connect options so every pooled connection enforces the
        // same durability and referential-integrity policy.
        let connect_options = SqliteConnectOptions::new()
            .filename(&db_path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(10));
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(connect_options)
            .await?;

        let db = Self { pool };

        // Run migrations
        db.run_migrations().await?;
        if recover_incomplete {
            db.mark_incomplete_executions_interrupted().await?;
        }

        Ok(db)
    }

    async fn run_migrations(&self) -> Result<()> {
        // Create tables
        let migrations = vec![
            include_str!("migrations/001_initial.sql"),
            include_str!("migrations/002_workflow_executions.sql"),
            include_str!("migrations/003_workflow_artifacts.sql"),
            include_str!("migrations/004_workflow_findings.sql"),
            include_str!("migrations/005_workflow_step_executions.sql"),
            include_str!("migrations/006_reports_and_settings.sql"),
            include_str!("migrations/007_ai_mcp_governance.sql"),
        ];

        for migration in migrations {
            sqlx::query(migration).execute(&self.pool).await?;
        }

        Ok(())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    async fn mark_incomplete_executions_interrupted(&self) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            r#"
            UPDATE workflow_executions
            SET status = 'interrupted', completed = ?, updated_at = ?
            WHERE status IN ('pending', 'running')
            "#,
        )
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            UPDATE workflow_step_executions
            SET status = 'interrupted', completed = ?, updated_at = ?
            WHERE status IN ('pending', 'running')
            "#,
        )
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            UPDATE scans
            SET status = 'interrupted', completed = ?, updated_at = ?
            WHERE status IN ('pending', 'running')
            "#,
        )
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Scan operations
    pub async fn create_scan(&self, scan: &Scan) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO scans (
                id, name, target, status, scan_type, workflow_id, started, completed,
                progress, current_test, current_step, total_steps, duration, estimated_time,
                description, tags, working_directory, agents, command_log, target_validated,
                vulnerabilities, critical, high, medium, low, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&scan.id)
        .bind(&scan.name)
        .bind(&scan.target)
        .bind(&scan.status)
        .bind(&scan.scan_type)
        .bind(&scan.workflow_id)
        .bind(scan.started)
        .bind(scan.completed)
        .bind(scan.progress)
        .bind(&scan.current_test)
        .bind(&scan.current_step)
        .bind(scan.total_steps)
        .bind(&scan.duration)
        .bind(&scan.estimated_time)
        .bind(&scan.description)
        .bind(&scan.tags)
        .bind(&scan.working_directory)
        .bind(&scan.agents)
        .bind(&scan.command_log)
        .bind(scan.target_validated)
        .bind(scan.vulnerabilities)
        .bind(scan.critical)
        .bind(scan.high)
        .bind(scan.medium)
        .bind(scan.low)
        .bind(scan.created_at)
        .bind(scan.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_scan(&self, scan_id: &str) -> Result<Option<Scan>> {
        let scan = sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE id = ?")
            .bind(scan_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(scan)
    }

    pub async fn list_scans(&self) -> Result<Vec<Scan>> {
        let scans = sqlx::query_as::<_, Scan>("SELECT * FROM scans ORDER BY started DESC")
            .fetch_all(&self.pool)
            .await?;

        Ok(scans)
    }

    pub async fn update_scan(&self, scan: &Scan) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE scans SET
                name = ?, target = ?, status = ?, scan_type = ?, workflow_id = ?,
                completed = ?, progress = ?, current_test = ?, current_step = ?, total_steps = ?,
                duration = ?, estimated_time = ?, description = ?, tags = ?, working_directory = ?,
                agents = ?, command_log = ?, target_validated = ?, vulnerabilities = ?,
                critical = ?, high = ?, medium = ?, low = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&scan.name)
        .bind(&scan.target)
        .bind(&scan.status)
        .bind(&scan.scan_type)
        .bind(&scan.workflow_id)
        .bind(scan.completed)
        .bind(scan.progress)
        .bind(&scan.current_test)
        .bind(&scan.current_step)
        .bind(scan.total_steps)
        .bind(&scan.duration)
        .bind(&scan.estimated_time)
        .bind(&scan.description)
        .bind(&scan.tags)
        .bind(&scan.working_directory)
        .bind(&scan.agents)
        .bind(&scan.command_log)
        .bind(scan.target_validated)
        .bind(scan.vulnerabilities)
        .bind(scan.critical)
        .bind(scan.high)
        .bind(scan.medium)
        .bind(scan.low)
        .bind(Utc::now())
        .bind(&scan.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete_scan(&self, scan_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM scans WHERE id = ?")
            .bind(scan_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn create_workflow_execution(&self, execution: &WorkflowExecution) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO workflow_executions (
                id, scan_id, workflow_id, status, started, completed, current_step,
                progress, inputs, working_directory, logs, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&execution.id)
        .bind(&execution.scan_id)
        .bind(&execution.workflow_id)
        .bind(&execution.status)
        .bind(execution.started)
        .bind(execution.completed)
        .bind(&execution.current_step)
        .bind(execution.progress)
        .bind(&execution.inputs)
        .bind(&execution.working_directory)
        .bind(&execution.logs)
        .bind(execution.created_at)
        .bind(execution.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_governed_workflow_execution(
        &self,
        execution: &WorkflowExecution,
        governance: &WorkflowExecutionGovernance,
    ) -> Result<()> {
        if execution.id != governance.execution_id {
            return Err(anyhow!(
                "Execution governance must reference the exact execution ID"
            ));
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            r#"
            INSERT INTO workflow_executions (
                id, scan_id, workflow_id, status, started, completed, current_step,
                progress, inputs, working_directory, logs, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&execution.id)
        .bind(&execution.scan_id)
        .bind(&execution.workflow_id)
        .bind(&execution.status)
        .bind(execution.started)
        .bind(execution.completed)
        .bind(&execution.current_step)
        .bind(execution.progress)
        .bind(&execution.inputs)
        .bind(&execution.working_directory)
        .bind(&execution.logs)
        .bind(execution.created_at)
        .bind(execution.updated_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO workflow_execution_governance (
                execution_id, revision_hash, scope_id, principal_id, request_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&governance.execution_id)
        .bind(&governance.revision_hash)
        .bind(&governance.scope_id)
        .bind(&governance.principal_id)
        .bind(&governance.request_id)
        .bind(governance.created_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn get_workflow_execution(
        &self,
        execution_id: &str,
    ) -> Result<Option<WorkflowExecution>> {
        let execution = sqlx::query_as::<_, WorkflowExecution>(
            "SELECT * FROM workflow_executions WHERE id = ?",
        )
        .bind(execution_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(execution)
    }

    pub async fn get_running_workflow_execution_for_scan(
        &self,
        scan_id: &str,
    ) -> Result<Option<WorkflowExecution>> {
        let execution = sqlx::query_as::<_, WorkflowExecution>(
            r#"
            SELECT * FROM workflow_executions
            WHERE scan_id = ? AND status IN ('pending', 'running')
            ORDER BY started DESC
            LIMIT 1
            "#,
        )
        .bind(scan_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(execution)
    }

    pub async fn get_latest_workflow_execution_for_scan(
        &self,
        scan_id: &str,
    ) -> Result<Option<WorkflowExecution>> {
        let execution = sqlx::query_as::<_, WorkflowExecution>(
            r#"
            SELECT * FROM workflow_executions
            WHERE scan_id = ?
            ORDER BY started DESC
            LIMIT 1
            "#,
        )
        .bind(scan_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(execution)
    }

    pub async fn get_workflow_execution_governance(
        &self,
        execution_id: &str,
    ) -> Result<Option<WorkflowExecutionGovernance>> {
        Ok(sqlx::query_as::<_, WorkflowExecutionGovernance>(
            r#"
            SELECT execution_id, revision_hash, scope_id, principal_id, request_id, created_at
            FROM workflow_execution_governance
            WHERE execution_id = ?
            "#,
        )
        .bind(execution_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn count_scope_executions(&self, scope_id: &str) -> Result<u32> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflow_execution_governance WHERE scope_id = ?",
        )
        .bind(scope_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count.max(0) as u32)
    }

    pub async fn count_scope_active_executions(&self, scope_id: &str) -> Result<u32> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM workflow_execution_governance governance
            JOIN workflow_executions execution ON execution.id = governance.execution_id
            WHERE governance.scope_id = ? AND execution.status IN ('pending', 'running')
            "#,
        )
        .bind(scope_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count.max(0) as u32)
    }

    pub async fn count_active_workflow_executions(&self) -> Result<u32> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflow_executions WHERE status IN ('pending', 'running')",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count.max(0) as u32)
    }

    pub async fn list_scope_active_execution_ids(&self, scope_id: &str) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            r#"
            SELECT governance.execution_id
            FROM workflow_execution_governance governance
            JOIN workflow_executions execution ON execution.id = governance.execution_id
            WHERE governance.scope_id = ? AND execution.status IN ('pending', 'running')
            ORDER BY execution.started ASC
            "#,
        )
        .bind(scope_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn list_scope_working_directories(&self, scope_id: &str) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            r#"
            SELECT execution.working_directory
            FROM workflow_execution_governance governance
            JOIN workflow_executions execution ON execution.id = governance.execution_id
            WHERE governance.scope_id = ? AND execution.working_directory IS NOT NULL
            "#,
        )
        .bind(scope_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn update_workflow_execution(&self, execution: &WorkflowExecution) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE workflow_executions SET
                status = ?, completed = ?, current_step = ?, progress = ?,
                logs = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&execution.status)
        .bind(execution.completed)
        .bind(&execution.current_step)
        .bind(execution.progress)
        .bind(&execution.logs)
        .bind(Utc::now())
        .bind(&execution.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_workflow_artifact(&self, artifact: &WorkflowArtifact) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO workflow_artifacts (
                id, execution_id, step_id, name, artifact_type, file_path,
                content, metadata_, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&artifact.id)
        .bind(&artifact.execution_id)
        .bind(&artifact.step_id)
        .bind(&artifact.name)
        .bind(&artifact.artifact_type)
        .bind(&artifact.file_path)
        .bind(&artifact.content)
        .bind(&artifact.metadata_)
        .bind(artifact.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn upsert_workflow_step_execution(&self, step: &WorkflowStepExecution) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO workflow_step_executions (
                execution_id, step_id, status, started, completed, exit_code,
                stdout, stderr, artifacts, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(execution_id, step_id) DO UPDATE SET
                status = excluded.status,
                started = excluded.started,
                completed = excluded.completed,
                exit_code = excluded.exit_code,
                stdout = excluded.stdout,
                stderr = excluded.stderr,
                artifacts = excluded.artifacts,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&step.execution_id)
        .bind(&step.step_id)
        .bind(&step.status)
        .bind(step.started)
        .bind(step.completed)
        .bind(step.exit_code)
        .bind(&step.stdout)
        .bind(&step.stderr)
        .bind(&step.artifacts)
        .bind(step.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_workflow_step_executions(
        &self,
        execution_id: &str,
    ) -> Result<Vec<WorkflowStepExecution>> {
        let steps = sqlx::query_as::<_, WorkflowStepExecution>(
            r#"
            SELECT * FROM workflow_step_executions
            WHERE execution_id = ?
            ORDER BY started, step_id
            "#,
        )
        .bind(execution_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(steps)
    }

    pub async fn get_workflow_artifacts(
        &self,
        execution_id: &str,
    ) -> Result<Vec<WorkflowArtifact>> {
        let artifacts = sqlx::query_as::<_, WorkflowArtifact>(
            "SELECT * FROM workflow_artifacts WHERE execution_id = ? ORDER BY created_at",
        )
        .bind(execution_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(artifacts)
    }

    pub async fn create_workflow_finding(&self, finding: &WorkflowFinding) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO workflow_findings (
                id, execution_id, step_id, title, severity, description, cvss,
                url, parameter, payload, remediation, discovered_by, evidence,
                false_positive, confirmed, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&finding.id)
        .bind(&finding.execution_id)
        .bind(&finding.step_id)
        .bind(&finding.title)
        .bind(&finding.severity)
        .bind(&finding.description)
        .bind(finding.cvss)
        .bind(&finding.url)
        .bind(&finding.parameter)
        .bind(&finding.payload)
        .bind(&finding.remediation)
        .bind(&finding.discovered_by)
        .bind(&finding.evidence)
        .bind(finding.false_positive)
        .bind(finding.confirmed)
        .bind(finding.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_workflow_findings(&self, execution_id: &str) -> Result<Vec<WorkflowFinding>> {
        let findings = sqlx::query_as::<_, WorkflowFinding>(
            "SELECT * FROM workflow_findings WHERE execution_id = ? ORDER BY created_at",
        )
        .bind(execution_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(findings)
    }

    // Vulnerability operations
    pub async fn create_vulnerability(&self, vuln: &Vulnerability) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO vulnerabilities (
                id, scan_id, title, severity, cvss, description, url, parameter,
                payload, remediation, discovered_by, timestamp, false_positive, confirmed, evidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&vuln.id)
        .bind(&vuln.scan_id)
        .bind(&vuln.title)
        .bind(&vuln.severity)
        .bind(vuln.cvss)
        .bind(&vuln.description)
        .bind(&vuln.url)
        .bind(&vuln.parameter)
        .bind(&vuln.payload)
        .bind(&vuln.remediation)
        .bind(&vuln.discovered_by)
        .bind(vuln.timestamp)
        .bind(vuln.false_positive)
        .bind(vuln.confirmed)
        .bind(&vuln.evidence)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_vulnerabilities_by_scan(&self, scan_id: &str) -> Result<Vec<Vulnerability>> {
        let vulns = sqlx::query_as::<_, Vulnerability>(
            "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY timestamp DESC",
        )
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(vulns)
    }

    pub async fn list_vulnerabilities(&self) -> Result<Vec<Vulnerability>> {
        let vulns = sqlx::query_as::<_, Vulnerability>(
            "SELECT * FROM vulnerabilities ORDER BY timestamp DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(vulns)
    }

    pub async fn delete_vulnerability(&self, vuln_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM vulnerabilities WHERE id = ?")
            .bind(vuln_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // Report operations
    pub async fn create_report(&self, report: &Report) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO reports (id, scan_id, title, content, format, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&report.id)
        .bind(&report.scan_id)
        .bind(&report.title)
        .bind(&report.content)
        .bind(&report.format)
        .bind(report.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_report_export(&self, export: &ReportExport) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO report_exports (report_id, file_path, size_bytes, sha256, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(report_id) DO UPDATE SET
                file_path = excluded.file_path,
                size_bytes = excluded.size_bytes,
                sha256 = excluded.sha256,
                created_at = excluded.created_at
            "#,
        )
        .bind(&export.report_id)
        .bind(&export.file_path)
        .bind(export.size_bytes)
        .bind(&export.sha256)
        .bind(export.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_report_export(&self, report_id: &str) -> Result<Option<ReportExport>> {
        Ok(
            sqlx::query_as::<_, ReportExport>("SELECT * FROM report_exports WHERE report_id = ?")
                .bind(report_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn list_reports(&self) -> Result<Vec<Report>> {
        let reports = sqlx::query_as::<_, Report>("SELECT * FROM reports ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;

        Ok(reports)
    }

    pub async fn get_report(&self, report_id: &str) -> Result<Option<Report>> {
        let report = sqlx::query_as::<_, Report>("SELECT * FROM reports WHERE id = ?")
            .bind(report_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(report)
    }

    pub async fn delete_report(&self, report_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM reports WHERE id = ?")
            .bind(report_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT value FROM app_settings WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|item| item.0))
    }

    pub async fn upsert_setting(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO app_settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(key)
        .bind(value)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_mcp_client_profile(
        &self,
        profile: &crate::governance::McpClientProfile,
    ) -> Result<()> {
        let capabilities = serde_json::to_string(&profile.capabilities)?;
        sqlx::query(
            r#"
            INSERT INTO mcp_client_profiles (
                id, name, capabilities, created_at, last_seen_at, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                capabilities = excluded.capabilities,
                last_seen_at = excluded.last_seen_at,
                revoked_at = excluded.revoked_at
            "#,
        )
        .bind(&profile.id)
        .bind(&profile.name)
        .bind(capabilities)
        .bind(profile.created_at)
        .bind(profile.last_seen_at)
        .bind(profile.revoked_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn touch_mcp_client_profile(&self, profile_id: &str) -> Result<()> {
        sqlx::query("UPDATE mcp_client_profiles SET last_seen_at = ? WHERE id = ?")
            .bind(Utc::now())
            .bind(profile_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_mcp_client_profile(
        &self,
        profile_id: &str,
    ) -> Result<Option<crate::governance::McpClientProfile>> {
        let row = sqlx::query_as::<_, McpClientProfileRow>(
            "SELECT id, name, capabilities, created_at, last_seen_at, revoked_at FROM mcp_client_profiles WHERE id = ?",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(profile_from_row).transpose()
    }

    pub async fn upsert_engagement_scope(
        &self,
        scope: &crate::governance::EngagementScope,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO engagement_scopes (
                id, revision, name, principal_id, targets, workflow_ids,
                allowed_risk_tier, budget, starts_at, expires_at, signature,
                created_at, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                revision = excluded.revision,
                name = excluded.name,
                targets = excluded.targets,
                workflow_ids = excluded.workflow_ids,
                allowed_risk_tier = excluded.allowed_risk_tier,
                budget = excluded.budget,
                starts_at = excluded.starts_at,
                expires_at = excluded.expires_at,
                signature = excluded.signature,
                revoked_at = excluded.revoked_at
            "#,
        )
        .bind(&scope.id)
        .bind(scope.revision as i64)
        .bind(&scope.name)
        .bind(&scope.principal_id)
        .bind(serde_json::to_string(&scope.targets)?)
        .bind(serde_json::to_string(&scope.workflow_ids)?)
        .bind(
            serde_json::to_string(&scope.allowed_risk_tier)?
                .trim_matches('"')
                .to_string(),
        )
        .bind(serde_json::to_string(&scope.budget)?)
        .bind(scope.starts_at)
        .bind(scope.expires_at)
        .bind(&scope.signature)
        .bind(scope.created_at)
        .bind(scope.revoked_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_engagement_scope(
        &self,
        scope_id: &str,
    ) -> Result<Option<crate::governance::EngagementScope>> {
        let row = sqlx::query_as::<_, EngagementScopeRow>(
            r#"
            SELECT id, revision, name, principal_id, targets, workflow_ids,
                   allowed_risk_tier, budget, starts_at, expires_at, signature,
                   created_at, revoked_at
            FROM engagement_scopes WHERE id = ?
            "#,
        )
        .bind(scope_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(scope_from_row).transpose()
    }

    pub async fn list_engagement_scopes(
        &self,
        principal_id: &str,
    ) -> Result<Vec<crate::governance::EngagementScope>> {
        let rows = sqlx::query_as::<_, EngagementScopeRow>(
            r#"
            SELECT id, revision, name, principal_id, targets, workflow_ids,
                   allowed_risk_tier, budget, starts_at, expires_at, signature,
                   created_at, revoked_at
            FROM engagement_scopes
            WHERE principal_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(principal_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(scope_from_row).collect()
    }

    pub async fn revoke_engagement_scope(&self, scope_id: &str) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE engagement_scopes SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(Utc::now())
        .bind(scope_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn upsert_workflow_revision(
        &self,
        revision: &crate::governance::WorkflowRevisionRecord,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO workflow_revisions (
                id, workflow_id, revision_hash, document, immutable, created_at
            ) VALUES (?, ?, ?, ?, 1, ?)
            ON CONFLICT(revision_hash) DO NOTHING
            "#,
        )
        .bind(&revision.id)
        .bind(&revision.workflow_id)
        .bind(&revision.revision_hash)
        .bind(serde_json::to_string(&revision.document)?)
        .bind(revision.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_workflow_revision(
        &self,
        revision_hash: &str,
    ) -> Result<Option<crate::governance::WorkflowRevisionRecord>> {
        let row = sqlx::query_as::<_, WorkflowRevisionRow>(
            r#"
            SELECT id, workflow_id, revision_hash, document, immutable, created_at
            FROM workflow_revisions WHERE revision_hash = ?
            "#,
        )
        .bind(revision_hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(workflow_revision_from_row).transpose()
    }

    pub async fn upsert_workflow_trust(
        &self,
        trust: &crate::governance::WorkflowTrustRecord,
    ) -> Result<()> {
        let source = serde_json::to_string(&trust.source)?
            .trim_matches('"')
            .to_string();
        sqlx::query(
            r#"
            INSERT INTO workflow_trust (
                revision_hash, source, verifier_version, evidence_hash,
                trusted_at, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(revision_hash) DO UPDATE SET
                source = excluded.source,
                verifier_version = excluded.verifier_version,
                evidence_hash = excluded.evidence_hash,
                trusted_at = excluded.trusted_at,
                revoked_at = excluded.revoked_at
            "#,
        )
        .bind(&trust.revision_hash)
        .bind(source)
        .bind(&trust.verifier_version)
        .bind(&trust.evidence_hash)
        .bind(trust.trusted_at)
        .bind(trust.revoked_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_workflow_trust(
        &self,
        revision_hash: &str,
    ) -> Result<Option<crate::governance::WorkflowTrustRecord>> {
        let row = sqlx::query_as::<_, WorkflowTrustRow>(
            r#"
            SELECT revision_hash, source, verifier_version, evidence_hash, trusted_at, revoked_at
            FROM workflow_trust WHERE revision_hash = ?
            "#,
        )
        .bind(revision_hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(workflow_trust_from_row).transpose()
    }

    pub async fn reserve_idempotency_key(
        &self,
        principal_id: &str,
        idempotency_key: &str,
        capability: &crate::governance::Capability,
        request_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<IdempotencyReservation> {
        let capability = serde_json::to_string(capability)?
            .trim_matches('"')
            .to_string();
        let now = Utc::now();
        let pending_response = format!("__pending__:{request_hash}");
        sqlx::query(
            "DELETE FROM mcp_idempotency_keys WHERE principal_id = ? AND idempotency_key = ? AND expires_at <= ?",
        )
        .bind(principal_id)
        .bind(idempotency_key)
        .bind(now)
        .execute(&self.pool)
        .await?;

        let inserted = sqlx::query(
            r#"
            INSERT INTO mcp_idempotency_keys (
                principal_id, idempotency_key, capability, response, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(principal_id, idempotency_key) DO NOTHING
            "#,
        )
        .bind(principal_id)
        .bind(idempotency_key)
        .bind(&capability)
        .bind(&pending_response)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        if inserted.rows_affected() == 1 {
            return Ok(IdempotencyReservation::Acquired);
        }

        let existing: Option<(String, String)> = sqlx::query_as(
            r#"
            SELECT capability, response FROM mcp_idempotency_keys
            WHERE principal_id = ? AND idempotency_key = ?
            "#,
        )
        .bind(principal_id)
        .bind(idempotency_key)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match existing {
            Some((stored_capability, _)) if stored_capability != capability => {
                IdempotencyReservation::Conflict
            }
            Some((_, response)) if response == pending_response => {
                IdempotencyReservation::InProgress
            }
            Some((_, response)) if response == "__pending__" => IdempotencyReservation::InProgress,
            Some((_, response)) if response.starts_with("__pending__:") => {
                IdempotencyReservation::Conflict
            }
            Some((_, response)) if response.starts_with("__complete__:") => {
                let remainder = response.trim_start_matches("__complete__:");
                match remainder.split_once(':') {
                    Some((stored_hash, payload)) if stored_hash == request_hash => {
                        IdempotencyReservation::Replayed(payload.to_string())
                    }
                    _ => IdempotencyReservation::Conflict,
                }
            }
            // Backward compatibility for completed entries written before
            // request fingerprints were introduced.
            Some((_, response)) => IdempotencyReservation::Replayed(response),
            None => IdempotencyReservation::InProgress,
        })
    }

    pub async fn complete_idempotency_key(
        &self,
        principal_id: &str,
        idempotency_key: &str,
        request_hash: &str,
        response: &str,
    ) -> Result<()> {
        let pending_response = format!("__pending__:{request_hash}");
        let completed_response = format!("__complete__:{request_hash}:{response}");
        let updated = sqlx::query(
            r#"
            UPDATE mcp_idempotency_keys SET response = ?
            WHERE principal_id = ? AND idempotency_key = ? AND response = ?
            "#,
        )
        .bind(completed_response)
        .bind(principal_id)
        .bind(idempotency_key)
        .bind(pending_response)
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(anyhow!("idempotency_conflict"));
        }
        Ok(())
    }

    pub async fn release_idempotency_key(
        &self,
        principal_id: &str,
        idempotency_key: &str,
        request_hash: &str,
    ) -> Result<()> {
        let pending_response = format!("__pending__:{request_hash}");
        sqlx::query(
            r#"
            DELETE FROM mcp_idempotency_keys
            WHERE principal_id = ? AND idempotency_key = ? AND response = ?
            "#,
        )
        .bind(principal_id)
        .bind(idempotency_key)
        .bind(pending_response)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn latest_audit_hash(&self) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT event_hash FROM mcp_audit_events ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|value| value.0))
    }

    pub async fn append_mcp_audit_event(
        &self,
        event: &crate::governance::McpAuditEvent,
    ) -> Result<()> {
        let capability = serde_json::to_string(&event.capability)?
            .trim_matches('"')
            .to_string();
        sqlx::query(
            r#"
            INSERT INTO mcp_audit_events (
                id, principal_id, capability, request_id, scope_id,
                sanitized_arguments, outcome, correlation_id, previous_hash,
                event_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&event.id)
        .bind(&event.principal_id)
        .bind(capability)
        .bind(&event.request_id)
        .bind(&event.scope_id)
        .bind(serde_json::to_string(&event.sanitized_arguments)?)
        .bind(&event.outcome)
        .bind(&event.correlation_id)
        .bind(&event.previous_hash)
        .bind(&event.event_hash)
        .bind(event.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_mcp_audit_events(
        &self,
        principal_id: &str,
        limit: u32,
    ) -> Result<Vec<crate::governance::McpAuditEvent>> {
        let rows = sqlx::query_as::<_, McpAuditEventRow>(
            r#"
            SELECT id, principal_id, capability, request_id, scope_id,
                   sanitized_arguments, outcome, correlation_id, previous_hash,
                   event_hash, created_at
            FROM mcp_audit_events
            WHERE principal_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            "#,
        )
        .bind(principal_id)
        .bind(limit.clamp(1, 200) as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(audit_event_from_row).collect()
    }
}

fn profile_from_row(row: McpClientProfileRow) -> Result<crate::governance::McpClientProfile> {
    Ok(crate::governance::McpClientProfile {
        id: row.id,
        name: row.name,
        capabilities: serde_json::from_str(&row.capabilities)?,
        created_at: row.created_at,
        last_seen_at: row.last_seen_at,
        revoked_at: row.revoked_at,
    })
}

fn scope_from_row(row: EngagementScopeRow) -> Result<crate::governance::EngagementScope> {
    let risk_json = format!("\"{}\"", row.allowed_risk_tier);
    Ok(crate::governance::EngagementScope {
        id: row.id,
        revision: row.revision as u64,
        name: row.name,
        principal_id: row.principal_id,
        targets: serde_json::from_str(&row.targets)?,
        workflow_ids: serde_json::from_str(&row.workflow_ids)?,
        allowed_risk_tier: serde_json::from_str(&risk_json)?,
        budget: serde_json::from_str(&row.budget)?,
        starts_at: row.starts_at,
        expires_at: row.expires_at,
        signature: row.signature,
        created_at: row.created_at,
        revoked_at: row.revoked_at,
    })
}

fn audit_event_from_row(row: McpAuditEventRow) -> Result<crate::governance::McpAuditEvent> {
    Ok(crate::governance::McpAuditEvent {
        id: row.id,
        principal_id: row.principal_id,
        capability: serde_json::from_str(&format!("\"{}\"", row.capability))?,
        request_id: row.request_id,
        scope_id: row.scope_id,
        sanitized_arguments: serde_json::from_str(&row.sanitized_arguments)?,
        outcome: row.outcome,
        correlation_id: row.correlation_id,
        previous_hash: row.previous_hash,
        event_hash: row.event_hash,
        created_at: row.created_at,
    })
}

fn workflow_revision_from_row(
    row: WorkflowRevisionRow,
) -> Result<crate::governance::WorkflowRevisionRecord> {
    Ok(crate::governance::WorkflowRevisionRecord {
        id: row.id,
        workflow_id: row.workflow_id,
        revision_hash: row.revision_hash,
        document: serde_json::from_str(&row.document)?,
        created_at: row.created_at,
        immutable: row.immutable,
    })
}

fn workflow_trust_from_row(
    row: WorkflowTrustRow,
) -> Result<crate::governance::WorkflowTrustRecord> {
    Ok(crate::governance::WorkflowTrustRecord {
        revision_hash: row.revision_hash,
        source: serde_json::from_str(&format!("\"{}\"", row.source))?,
        verifier_version: row.verifier_version,
        evidence_hash: row.evidence_hash,
        trusted_at: row.trusted_at,
        revoked_at: row.revoked_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::{
        AuthorizedTarget, Capability, EngagementScope, McpClientProfile, RiskTier, ScopeBudget,
        WorkflowRevisionRecord, WorkflowTrustRecord, WorkflowTrustSource,
    };
    use chrono::Duration as ChronoDuration;
    use serde_json::json;
    use tempfile::TempDir;

    fn sample_scan(id: &str, status: &str) -> Scan {
        let now = Utc::now();
        Scan {
            id: id.to_string(),
            name: "Test scan".to_string(),
            target: "127.0.0.1".to_string(),
            status: status.to_string(),
            scan_type: "test".to_string(),
            workflow_id: Some("test-workflow".to_string()),
            started: now,
            completed: None,
            progress: 0,
            current_test: None,
            current_step: None,
            total_steps: Some(1),
            duration: None,
            estimated_time: None,
            description: None,
            tags: None,
            working_directory: None,
            agents: None,
            command_log: None,
            target_validated: true,
            vulnerabilities: Some(0),
            critical: Some(0),
            high: Some(0),
            medium: Some(0),
            low: Some(0),
            created_at: now,
            updated_at: now,
        }
    }

    fn sample_execution(id: &str, scan_id: &str, status: &str) -> WorkflowExecution {
        let now = Utc::now();
        WorkflowExecution {
            id: id.to_string(),
            scan_id: Some(scan_id.to_string()),
            workflow_id: "test-workflow".to_string(),
            status: status.to_string(),
            started: now,
            completed: None,
            current_step: Some("test-step".to_string()),
            progress: 10,
            inputs: r#"{"target":"127.0.0.1"}"#.to_string(),
            working_directory: Some("/tmp/unihack-test".to_string()),
            logs: "[]".to_string(),
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn enables_foreign_keys_on_every_pool_connection() {
        let temp_dir = TempDir::new().unwrap();
        let database = Database::new(temp_dir.path().to_path_buf()).await.unwrap();
        let mut connections = Vec::new();
        for _ in 0..5 {
            connections.push(database.pool.acquire().await.unwrap());
        }

        for connection in &mut connections {
            let enabled: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
                .fetch_one(&mut **connection)
                .await
                .unwrap();
            assert_eq!(enabled, 1);
        }
    }

    #[tokio::test]
    async fn persists_step_execution_state() {
        let temp_dir = TempDir::new().unwrap();
        let database = Database::new(temp_dir.path().to_path_buf()).await.unwrap();
        database
            .create_scan(&sample_scan("scan-1", "running"))
            .await
            .unwrap();
        database
            .create_workflow_execution(&sample_execution("execution-1", "scan-1", "running"))
            .await
            .unwrap();

        let step = WorkflowStepExecution {
            execution_id: "execution-1".to_string(),
            step_id: "test-step".to_string(),
            status: "completed".to_string(),
            started: Some(Utc::now()),
            completed: Some(Utc::now()),
            exit_code: Some(0),
            stdout: r#"["ok"]"#.to_string(),
            stderr: "[]".to_string(),
            artifacts: "[]".to_string(),
            updated_at: Utc::now(),
        };
        database
            .upsert_workflow_step_execution(&step)
            .await
            .unwrap();

        let stored = database
            .get_workflow_step_executions("execution-1")
            .await
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].status, "completed");
        assert_eq!(stored[0].stdout, r#"["ok"]"#);
    }

    #[tokio::test]
    async fn marks_abandoned_work_as_interrupted_on_restart() {
        let temp_dir = TempDir::new().unwrap();
        {
            let database = Database::new(temp_dir.path().to_path_buf()).await.unwrap();
            database
                .create_scan(&sample_scan("scan-2", "running"))
                .await
                .unwrap();
            database
                .create_workflow_execution(&sample_execution("execution-2", "scan-2", "running"))
                .await
                .unwrap();
            database
                .upsert_workflow_step_execution(&WorkflowStepExecution {
                    execution_id: "execution-2".to_string(),
                    step_id: "test-step".to_string(),
                    status: "running".to_string(),
                    started: Some(Utc::now()),
                    completed: None,
                    exit_code: None,
                    stdout: "[]".to_string(),
                    stderr: "[]".to_string(),
                    artifacts: "[]".to_string(),
                    updated_at: Utc::now(),
                })
                .await
                .unwrap();
        }

        let database = Database::new(temp_dir.path().to_path_buf()).await.unwrap();
        let scan = database.get_scan("scan-2").await.unwrap().unwrap();
        let execution = database
            .get_workflow_execution("execution-2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(scan.status, "interrupted");
        assert_eq!(execution.status, "interrupted");
        let steps = database
            .get_workflow_step_executions("execution-2")
            .await
            .unwrap();
        assert_eq!(steps[0].status, "interrupted");
    }

    #[tokio::test]
    async fn governed_execution_binding_is_atomic_and_counted() {
        let temp_dir = TempDir::new().unwrap();
        let database = Database::new(temp_dir.path().to_path_buf()).await.unwrap();
        let profile = McpClientProfile::owner_automation();
        database.upsert_mcp_client_profile(&profile).await.unwrap();
        let revision = WorkflowRevisionRecord::from_document(
            "test-workflow",
            json!({ "id": "test-workflow" }),
        )
        .unwrap();
        database.upsert_workflow_revision(&revision).await.unwrap();
        database
            .upsert_workflow_trust(&WorkflowTrustRecord {
                revision_hash: revision.revision_hash.clone(),
                source: WorkflowTrustSource::Packaged,
                verifier_version: Some("test".to_string()),
                evidence_hash: None,
                trusted_at: Utc::now(),
                revoked_at: None,
            })
            .await
            .unwrap();
        let mut scope = EngagementScope::new(
            "Test scope",
            profile.id.clone(),
            vec![AuthorizedTarget::parse("127.0.0.1").unwrap()],
            vec!["test-workflow".to_string()],
            RiskTier::Active,
            Utc::now() - ChronoDuration::minutes(1),
            Utc::now() + ChronoDuration::hours(1),
            ScopeBudget::default(),
        )
        .unwrap();
        scope.sign(b"test-signing-key").unwrap();
        database.upsert_engagement_scope(&scope).await.unwrap();
        database
            .create_scan(&sample_scan("governed-scan", "pending"))
            .await
            .unwrap();
        let governance = WorkflowExecutionGovernance {
            execution_id: "governed-execution".to_string(),
            revision_hash: revision.revision_hash.clone(),
            scope_id: scope.id.clone(),
            principal_id: profile.id,
            request_id: "request-1".to_string(),
            created_at: Utc::now(),
        };
        database
            .create_governed_workflow_execution(
                &sample_execution("governed-execution", "governed-scan", "running"),
                &governance,
            )
            .await
            .unwrap();

        let stored = database
            .get_workflow_execution_governance("governed-execution")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.revision_hash, revision.revision_hash);
        assert_eq!(database.count_scope_executions(&scope.id).await.unwrap(), 1);
        assert_eq!(
            database
                .count_scope_active_executions(&scope.id)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn idempotency_reservation_replays_and_rejects_capability_reuse() {
        let temp_dir = TempDir::new().unwrap();
        let database = Database::new(temp_dir.path().to_path_buf()).await.unwrap();
        let profile = McpClientProfile::owner_automation();
        database.upsert_mcp_client_profile(&profile).await.unwrap();
        let expiry = Utc::now() + ChronoDuration::hours(1);

        assert_eq!(
            database
                .reserve_idempotency_key(
                    &profile.id,
                    "request-key-123",
                    &Capability::ExecuteWorkflow,
                    "request-hash-1",
                    expiry,
                )
                .await
                .unwrap(),
            IdempotencyReservation::Acquired
        );
        assert_eq!(
            database
                .reserve_idempotency_key(
                    &profile.id,
                    "request-key-123",
                    &Capability::ExecuteWorkflow,
                    "request-hash-1",
                    expiry,
                )
                .await
                .unwrap(),
            IdempotencyReservation::InProgress
        );
        database
            .complete_idempotency_key(
                &profile.id,
                "request-key-123",
                "request-hash-1",
                r#"{"runId":"1"}"#,
            )
            .await
            .unwrap();
        assert_eq!(
            database
                .reserve_idempotency_key(
                    &profile.id,
                    "request-key-123",
                    &Capability::ExecuteWorkflow,
                    "request-hash-1",
                    expiry,
                )
                .await
                .unwrap(),
            IdempotencyReservation::Replayed(r#"{"runId":"1"}"#.to_string())
        );
        assert_eq!(
            database
                .reserve_idempotency_key(
                    &profile.id,
                    "request-key-123",
                    &Capability::CancelExecution,
                    "request-hash-1",
                    expiry,
                )
                .await
                .unwrap(),
            IdempotencyReservation::Conflict
        );
        assert_eq!(
            database
                .reserve_idempotency_key(
                    &profile.id,
                    "request-key-123",
                    &Capability::ExecuteWorkflow,
                    "request-hash-2",
                    expiry,
                )
                .await
                .unwrap(),
            IdempotencyReservation::Conflict
        );
    }
}
