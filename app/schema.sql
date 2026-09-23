-- ISO 27001:2022 Gap Assessment Evidence Engine
-- SQLite schema (v1.0)
-- 4 主题 / 93 控制项

-- ============================================
-- ISO 27001:2022 控制项主表
-- ============================================
CREATE TABLE IF NOT EXISTS iso_controls (
    control_id        TEXT PRIMARY KEY,                  -- e.g. "A.5.23"
    theme             TEXT NOT NULL,                     -- A.5 Organizational / A.6 People / A.7 Physical / A.8 Technological
    title             TEXT NOT NULL,
    description       TEXT NOT NULL,
    is_applicable     INTEGER NOT NULL DEFAULT 1,        -- SoA: 适用性 0/1
    soa_justification TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'NOT_EVALUATED',  -- COMPLIANT/PARTIALLY_COMPLIANT/NON_COMPLIANT/NOT_EVALUATED
    risk_rating       TEXT NOT NULL DEFAULT 'MEDIUM',    -- CRITICAL/HIGH/MEDIUM/LOW
    owner             TEXT NOT NULL DEFAULT 'IT Security',
    is_new_2022       INTEGER NOT NULL DEFAULT 0,        -- 2022 新增控制项标记
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_controls_theme ON iso_controls(theme);
CREATE INDEX IF NOT EXISTS idx_controls_status ON iso_controls(status);

-- ============================================
-- Evidence 证据库（含 SHA-256 防篡改）
-- ============================================
CREATE TABLE IF NOT EXISTS evidence_items (
    evidence_id      TEXT PRIMARY KEY,                   -- UUID
    control_id       TEXT NOT NULL,
    source_name      TEXT NOT NULL,                      -- GitHub_API_Connector / Okta_IAM_API / ...
    collected_at     TEXT NOT NULL DEFAULT (datetime('now')),
    content_payload  TEXT NOT NULL,                      -- JSON string
    sha256_hash      TEXT NOT NULL,                       -- 64 char hex
    FOREIGN KEY (control_id) REFERENCES iso_controls(control_id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_control ON evidence_items(control_id);
CREATE INDEX IF NOT EXISTS idx_evidence_source ON evidence_items(source_name);

-- ============================================
-- Corrective Action Plan (CAP) 整改追踪
-- ============================================
CREATE TABLE IF NOT EXISTS corrective_action_plans (
    cap_id             TEXT PRIMARY KEY,                 -- UUID
    control_id         TEXT NOT NULL,
    gap_description    TEXT NOT NULL,
    remediation_action TEXT NOT NULL,
    assigned_owner     TEXT NOT NULL,
    due_date           TEXT NOT NULL,                    -- ISO date
    status             TEXT NOT NULL DEFAULT 'OPEN',     -- OPEN/IN_PROGRESS/RESOLVED/RISK_ACCEPTED
    created_at         TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at        TEXT,
    FOREIGN KEY (control_id) REFERENCES iso_controls(control_id)
);

CREATE INDEX IF NOT EXISTS idx_caps_status ON corrective_action_plans(status);
CREATE INDEX IF NOT EXISTS idx_caps_due_date ON corrective_action_plans(due_date);

-- ============================================
-- 审计 trail（记录所有读写操作）
-- ============================================
CREATE TABLE IF NOT EXISTS audit_trail (
    audit_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    actor         TEXT NOT NULL,                         -- user / system / collector_name
    action        TEXT NOT NULL,                         -- READ_CONTROL / UPDATE_CONTROL / COLLECT_EVIDENCE / VERIFY_HASH / CREATE_CAP / ...
    entity_type   TEXT,
    entity_id     TEXT,
    details       TEXT,                                  -- 额外信息 JSON
    occurred_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_trail(actor);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_trail(action);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_trail(occurred_at);