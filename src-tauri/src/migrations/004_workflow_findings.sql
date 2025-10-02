-- 004_workflow_findings.sql
CREATE TABLE IF NOT EXISTS workflow_findings (
    id TEXT PRIMARY KEY NOT NULL,
    execution_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT,
    description TEXT,
    cvss REAL,
    url TEXT,
    parameter TEXT,
    payload TEXT,
    remediation TEXT,
    discovered_by TEXT,
    evidence TEXT,
    false_positive BOOLEAN NOT NULL DEFAULT FALSE,
    confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (execution_id) REFERENCES workflow_executions (id) ON DELETE CASCADE
);
