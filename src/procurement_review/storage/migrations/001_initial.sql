-- Migration: 001_initial.sql
-- Description: Initial schema for immutable review repository, runs, findings, and feedback.
-- Security: Stores opaque IDs, revisions, states, hashes, and artifact refs only. No sensitive plaintext.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reviews (
    case_id TEXT PRIMARY KEY,
    current_revision INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL,
    original_file_hash TEXT NOT NULL,
    artifact_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS review_revisions (
    case_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    state TEXT NOT NULL,
    original_file_hash TEXT NOT NULL,
    artifact_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (case_id, revision),
    FOREIGN KEY (case_id) REFERENCES reviews(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    parent_run_id TEXT,
    state TEXT NOT NULL,
    stale INTEGER NOT NULL DEFAULT 0,
    invalidation_reason TEXT,
    artifact_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES reviews(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS run_rules (
    run_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    rule_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, rule_id, rule_version),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    requirement_id TEXT NOT NULL,
    result TEXT NOT NULL,
    risk TEXT NOT NULL,
    artifact_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS feedbacks (
    feedback_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    idempotency_key TEXT UNIQUE NOT NULL,
    artifact_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_runs_case_id ON runs(case_id);
CREATE INDEX IF NOT EXISTS idx_runs_stale ON runs(stale);
CREATE INDEX IF NOT EXISTS idx_run_rules_rule_id ON run_rules(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_feedbacks_run_id ON feedbacks(run_id);
CREATE INDEX IF NOT EXISTS idx_feedbacks_idempotency ON feedbacks(idempotency_key);
