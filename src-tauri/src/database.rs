use std::path::PathBuf;
use sqlx::{Sqlite, SqlitePool, migrate::Migrator};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::fs;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(app_data_dir: PathBuf) -> Result<Self> {
        // Ensure data directory exists
        fs::create_dir_all(&app_data_dir).await?;

        // Create database path
        let db_path = app_data_dir.join("scanner.db");

        // Create connection pool with WAL mode
        let database_url = format!("sqlite:{}?mode=rwc", db_path.display());
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
        // Define migrations inline for now
        let migrations = vec![
            include_str!("migrations/001_initial.sql"),
            include_str!("migrations/002_workflow_executions.sql"),
            include_str!("migrations/003_workflow_artifacts.sql"),
            include_str!("migrations/004_workflow_findings.sql"),
        ];

        for migration in migrations {
            sqlx::query(migration)
                .execute(&self.pool)
                .await?;
        }

        Ok(())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

// Database models
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
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
    pub current_step: Option<i32>,
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

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WorkflowExecution {
    pub id: String,
    pub scan_id: Option<String>,
    pub workflow_id: String,
    pub status: String,
    pub started: DateTime<Utc>,
    pub completed: Option<DateTime<Utc>>,
    pub current_step: Option<String>,
    pub progress: i32,
    pub inputs: String, // JSON
    pub working_directory: String,
    pub logs: Option<String>, // JSON array
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WorkflowArtifact {
    pub id: String,
    pub execution_id: String,
    pub step_id: String,
    pub name: String,
    pub artifact_type: String,
    pub file_path: Option<String>,
    pub content: Option<String>,
    pub metadata_: String, // JSON
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WorkflowFinding {
    pub id: String,
    pub execution_id: String,
    pub step_id: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub cvss: Option<f32>,
    pub url: Option<String>,
    pub parameter: Option<String>,
    pub payload: Option<String>,
    pub remediation: Option<String>,
    pub discovered_by: String,
    pub evidence: Option<String>, // JSON
    pub false_positive: bool,
    pub confirmed: bool,
    pub created_at: DateTime<Utc>,
}

// Database operations
impl Database {
    pub async fn create_scan(&self, scan: &Scan) -> Result<Scan> {
        let scan_id = Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO scans (id, name, target, status, scan_type, workflow_id, started, progress, description, tags, working_directory, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&scan_id)
        .bind(&scan.name)
        .bind(&scan.target)
        .bind(&scan.status)
        .bind(&scan.scan_type)
        .bind(&scan.workflow_id)
        .bind(scan.started)
        .bind(scan.progress)
        .bind(&scan.description)
        .bind(&scan.tags)
        .bind(&scan.working_directory)
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        // Return the created scan with the generated ID
        Ok(Scan {
            id: scan_id,
            ..scan.clone()
        })
    }

    pub async fn get_scan(&self, scan_id: &str) -> Result<Option<Scan>> {
        let scan = sqlx::query_as::<_, Scan>(
            "SELECT * FROM scans WHERE id = ?"
        )
        .bind(scan_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(scan)
    }

    pub async fn list_scans(&self) -> Result<Vec<Scan>> {
        let scans = sqlx::query_as::<_, Scan>(
            "SELECT * FROM scans ORDER BY started DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(scans)
    }

    pub async fn update_scan(&self, scan_id: &str, updates: &Scan) -> Result<()> {
        sqlx::query(
            "UPDATE scans
             SET name = ?, target = ?, status = ?, scan_type = ?, workflow_id = ?, completed = ?, progress = ?,
                 current_test = ?, current_step = ?, total_steps = ?, duration = ?, estimated_time = ?,
                 description = ?, tags = ?, working_directory = ?, agents = ?, command_log = ?,
                 target_validated = ?, vulnerabilities = ?, critical = ?, high = ?, medium = ?, low = ?,
                 updated_at = ?
             WHERE id = ?"
        )
        .bind(&updates.name)
        .bind(&updates.target)
        .bind(&updates.status)
        .bind(&updates.scan_type)
        .bind(&updates.workflow_id)
        .bind(updates.completed)
        .bind(updates.progress)
        .bind(&updates.current_test)
        .bind(updates.current_step)
        .bind(updates.total_steps)
        .bind(&updates.duration)
        .bind(&updates.estimated_time)
        .bind(&updates.description)
        .bind(&updates.tags)
        .bind(&updates.working_directory)
        .bind(&updates.agents)
        .bind(&updates.command_log)
        .bind(updates.target_validated)
        .bind(updates.vulnerabilities)
        .bind(updates.critical)
        .bind(updates.high)
        .bind(updates.medium)
        .bind(updates.low)
        .bind(Utc::now())
        .bind(scan_id)
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

    pub async fn create_workflow_execution(&self, execution: &WorkflowExecution) -> Result<WorkflowExecution> {
        let execution_id = Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO workflow_executions (id, scan_id, workflow_id, status, started, current_step, progress, inputs, working_directory, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&execution_id)
        .bind(&execution.scan_id)
        .bind(&execution.workflow_id)
        .bind(&execution.status)
        .bind(execution.started)
        .bind(&execution.current_step)
        .bind(execution.progress)
        .bind(&execution.inputs)
        .bind(&execution.working_directory)
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        Ok(WorkflowExecution {
            id: execution_id,
            ..execution.clone()
        })
    }

    pub async fn get_workflow_execution(&self, execution_id: &str) -> Result<Option<WorkflowExecution>> {
        let execution = sqlx::query_as::<_, WorkflowExecution>(
            "SELECT * FROM workflow_executions WHERE id = ?"
        )
        .bind(execution_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(execution)
    }

    pub async fn update_workflow_execution(&self, execution_id: &str, updates: &WorkflowExecution) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_executions
             SET status = ?, completed = ?, current_step = ?, progress = ?, logs = ?, updated_at = ?
             WHERE id = ?"
        )
        .bind(&updates.status)
        .bind(updates.completed)
        .bind(&updates.current_step)
        .bind(updates.progress)
        .bind(&updates.logs)
        .bind(Utc::now())
        .bind(execution_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn list_workflow_executions(&self) -> Result<Vec<WorkflowExecution>> {
        let executions = sqlx::query_as::<_, WorkflowExecution>(
            "SELECT * FROM workflow_executions ORDER BY started DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(executions)
    }

    pub async fn create_artifact(&self, artifact: &WorkflowArtifact) -> Result<WorkflowArtifact> {
        let artifact_id = Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO workflow_artifacts (id, execution_id, step_id, name, artifact_type, file_path, content, metadata_, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&artifact_id)
        .bind(&artifact.execution_id)
        .bind(&artifact.step_id)
        .bind(&artifact.name)
        .bind(&artifact.artifact_type)
        .bind(&artifact.file_path)
        .bind(&artifact.content)
        .bind(&artifact.metadata_)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        Ok(WorkflowArtifact {
            id: artifact_id,
            ..artifact.clone()
        })
    }

    pub async fn get_artifacts(&self, execution_id: &str) -> Result<Vec<WorkflowArtifact>> {
        let artifacts = sqlx::query_as::<_, WorkflowArtifact>(
            "SELECT * FROM workflow_artifacts WHERE execution_id = ? ORDER BY created_at"
        )
        .bind(execution_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(artifacts)
    }

    pub async fn create_finding(&self, finding: &WorkflowFinding) -> Result<WorkflowFinding> {
        let finding_id = Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO workflow_findings (id, execution_id, step_id, title, severity, description, cvss, url, parameter, payload, remediation, discovered_by, evidence, false_positive, confirmed, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&finding_id)
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
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        Ok(WorkflowFinding {
            id: finding_id,
            ..finding.clone()
        })
    }

    pub async fn get_findings(&self, execution_id: &str) -> Result<Vec<WorkflowFinding>> {
        let findings = sqlx::query_as::<_, WorkflowFinding>(
            "SELECT * FROM workflow_findings WHERE execution_id = ? ORDER BY created_at"
        )
        .bind(execution_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(findings)
    }
}
