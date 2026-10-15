-- Migration: 002_rules.sql
-- Description: Schema for sources, rules, and requirements.
-- Security: Stores opaque IDs, versions, statuses, hashes, and artifact refs only.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sources (
    source_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    issuer TEXT NOT NULL,
    version TEXT NOT NULL,
    verified_at TEXT,
    verified_by TEXT,
    content_hash TEXT NOT NULL,
    artifact_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    rule_id TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    effective_from TEXT,
    effective_to TEXT,
    artifact_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (rule_id, version)
);

CREATE TABLE IF NOT EXISTS requirements (
    requirement_id TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    artifact_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (rule_id, rule_version) REFERENCES rules(rule_id, version) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_rules_status ON rules(status);
CREATE INDEX IF NOT EXISTS idx_rules_category ON rules(category);
CREATE INDEX IF NOT EXISTS idx_requirements_rule ON requirements(rule_id, rule_version);
