use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::FromRow;
use sqlx::SqlitePool;
use std::path::PathBuf;
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

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(app_data_dir: PathBuf) -> Result<Self> {
        // Ensure data directory exists
        println!("Creating app data directory: {}", app_data_dir.display());
        fs::create_dir_all(&app_data_dir).await?;

        // Verify directory was created
        if !app_data_dir.exists() {
            return Err(anyhow!("Failed to create app data directory"));
        }

        // Create database path
        let db_path = app_data_dir.join("scanner.db");

        // Debug: print the database path
        println!("Database path: {}", db_path.display());
        println!("Database path exists: {}", db_path.exists());

        // Try to create the database file explicitly
        if !db_path.exists() {
            println!("Creating database file...");
            fs::File::create(&db_path).await?;
            println!("Database file created successfully");
        }

        // Create connection pool - use simple file path format for SQLx
        let database_url = format!("sqlite:{}", db_path.display());
        println!("Database URL: {}", database_url);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await?;

        // Enable WAL mode for better concurrency
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&pool)
            .await?;

        // Enable foreign keys
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await?;

        let db = Self { pool };

        // Run migrations
        db.run_migrations().await?;

        Ok(db)
    }

    async fn run_migrations(&self) -> Result<()> {
        // Create tables
        let migrations = vec![
            include_str!("migrations/001_initial.sql"),
            include_str!("migrations/002_workflow_executions.sql"),
            include_str!("migrations/003_workflow_artifacts.sql"),
            include_str!("migrations/004_workflow_findings.sql"),
        ];

        for migration in migrations {
            sqlx::query(migration).execute(&self.pool).await?;
        }

        Ok(())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
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
        .bind(&scan.started)
        .bind(&scan.completed)
        .bind(scan.progress)
        .bind(&scan.current_test)
        .bind(&scan.current_step)
        .bind(&scan.total_steps)
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
        .bind(&scan.created_at)
        .bind(&scan.updated_at)
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
        .bind(&scan.completed)
        .bind(scan.progress)
        .bind(&scan.current_test)
        .bind(&scan.current_step)
        .bind(&scan.total_steps)
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
        .bind(&execution.started)
        .bind(&execution.completed)
        .bind(&execution.current_step)
        .bind(execution.progress)
        .bind(&execution.inputs)
        .bind(&execution.working_directory)
        .bind(&execution.logs)
        .bind(&execution.created_at)
        .bind(&execution.updated_at)
        .execute(&self.pool)
        .await?;

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
        .bind(&execution.completed)
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
        .bind(&artifact.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
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
        .bind(&finding.created_at)
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
        .bind(&vuln.timestamp)
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
        .bind(&report.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
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
}
