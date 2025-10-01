-- Initial database schema for AI Bug Bounty Scanner
-- Creates tables for scans and related data

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    scan_type TEXT NOT NULL,
    workflow_id TEXT,
    started DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed DATETIME,
    progress INTEGER DEFAULT 0,
    current_test TEXT,
    current_step INTEGER,
    total_steps INTEGER,
    duration TEXT,
    estimated_time TEXT,
    description TEXT,
    tags TEXT, -- JSON array
    working_directory TEXT,
    agents TEXT, -- JSON array
    command_log TEXT, -- JSON
    target_validated BOOLEAN DEFAULT FALSE,
    vulnerabilities INTEGER DEFAULT 0,
    critical INTEGER DEFAULT 0,
    high INTEGER DEFAULT 0,
    medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss REAL,
    description TEXT NOT NULL,
    url TEXT,
    parameter TEXT,
    payload TEXT,
    remediation TEXT,
    discovered_by TEXT NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    false_positive BOOLEAN DEFAULT FALSE,
    confirmed BOOLEAN DEFAULT FALSE,
    evidence TEXT, -- JSON
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'html',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);
