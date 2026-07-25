-- Durable per-step execution state. This keeps scan history usable after the
-- desktop process exits and avoids storing an unbounded execution object only
-- in memory.
CREATE TABLE IF NOT EXISTS workflow_step_executions (
    execution_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started DATETIME,
    completed DATETIME,
    exit_code INTEGER,
    stdout TEXT NOT NULL DEFAULT '[]',
    stderr TEXT NOT NULL DEFAULT '[]',
    artifacts TEXT NOT NULL DEFAULT '[]',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (execution_id, step_id),
    FOREIGN KEY (execution_id) REFERENCES workflow_executions (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_workflow_steps_execution_id
    ON workflow_step_executions(execution_id);
CREATE INDEX IF NOT EXISTS idx_workflow_steps_status
    ON workflow_step_executions(status);
