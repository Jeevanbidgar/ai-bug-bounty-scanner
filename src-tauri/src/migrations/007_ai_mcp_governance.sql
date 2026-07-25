CREATE TABLE IF NOT EXISTS workflow_revisions (
    id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL,
    revision_hash TEXT NOT NULL UNIQUE,
    document TEXT NOT NULL,
    immutable INTEGER NOT NULL DEFAULT 1 CHECK (immutable = 1),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_workflow_revisions_workflow
    ON workflow_revisions(workflow_id, created_at DESC);

CREATE TABLE IF NOT EXISTS workflow_trust (
    revision_hash TEXT PRIMARY KEY,
    source TEXT NOT NULL CHECK (source IN ('packaged', 'user_reviewed', 'deterministic_verifier')),
    verifier_version TEXT,
    evidence_hash TEXT,
    trusted_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (revision_hash) REFERENCES workflow_revisions(revision_hash)
);

CREATE TABLE IF NOT EXISTS mcp_client_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    capabilities TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS engagement_scopes (
    id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL,
    name TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    targets TEXT NOT NULL,
    workflow_ids TEXT NOT NULL,
    allowed_risk_tier TEXT NOT NULL,
    budget TEXT NOT NULL,
    starts_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (principal_id) REFERENCES mcp_client_profiles(id)
);

CREATE INDEX IF NOT EXISTS idx_engagement_scopes_principal
    ON engagement_scopes(principal_id, expires_at DESC);

CREATE TABLE IF NOT EXISTS workflow_execution_governance (
    execution_id TEXT PRIMARY KEY,
    revision_hash TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (execution_id) REFERENCES workflow_executions(id) ON DELETE CASCADE,
    FOREIGN KEY (revision_hash) REFERENCES workflow_revisions(revision_hash),
    FOREIGN KEY (scope_id) REFERENCES engagement_scopes(id),
    FOREIGN KEY (principal_id) REFERENCES mcp_client_profiles(id)
);

CREATE TABLE IF NOT EXISTS mcp_idempotency_keys (
    principal_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    capability TEXT NOT NULL,
    response TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (principal_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS mcp_audit_events (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    request_id TEXT NOT NULL,
    scope_id TEXT,
    sanitized_arguments TEXT NOT NULL,
    outcome TEXT NOT NULL,
    correlation_id TEXT,
    previous_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mcp_audit_created
    ON mcp_audit_events(created_at DESC);

CREATE TABLE IF NOT EXISTS agent_provider_profiles (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL CHECK (provider IN ('openai', 'anthropic')),
    model TEXT NOT NULL,
    endpoint TEXT,
    credential_reference TEXT NOT NULL,
    full_text_evidence_consent INTEGER NOT NULL DEFAULT 0,
    limits TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_sessions (
    id TEXT PRIMARY KEY,
    provider_profile_id TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (provider_profile_id) REFERENCES agent_provider_profiles(id),
    FOREIGN KEY (scope_id) REFERENCES engagement_scopes(id)
);

CREATE TABLE IF NOT EXISTS agent_runs (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    status TEXT NOT NULL,
    budget_snapshot TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    error_code TEXT,
    FOREIGN KEY (session_id) REFERENCES agent_sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agent_steps (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    kind TEXT NOT NULL,
    capability TEXT,
    request TEXT NOT NULL,
    response TEXT,
    status TEXT NOT NULL,
    idempotency_key TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY (run_id) REFERENCES agent_runs(id) ON DELETE CASCADE,
    UNIQUE (run_id, sequence)
);

CREATE TABLE IF NOT EXISTS evidence_manifests (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    provider_request_id TEXT,
    artifact_ids TEXT NOT NULL,
    content_hashes TEXT NOT NULL,
    redaction_summary TEXT NOT NULL,
    input_bytes INTEGER NOT NULL,
    token_usage TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES agent_runs(id) ON DELETE CASCADE
);
