-- Workflow artifacts table
CREATE TABLE IF NOT EXISTS workflow_artifacts (
    id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    name TEXT NOT NULL,
    artifact_type TEXT NOT NULL, -- file, directory, content
    file_path TEXT,
    content TEXT,
    metadata_ TEXT NOT NULL, -- JSON
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (execution_id) REFERENCES workflow_executions(id) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_workflow_artifacts_execution_id ON workflow_artifacts(execution_id);
CREATE INDEX IF NOT EXISTS idx_workflow_artifacts_step_id ON workflow_artifacts(step_id);
CREATE INDEX IF NOT EXISTS idx_workflow_artifacts_type ON workflow_artifacts(artifact_type);
