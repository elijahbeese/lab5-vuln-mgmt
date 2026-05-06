-- ============================================================================
-- Lab 5: ACAS-Equivalent Vulnerability Management Pipeline
-- SQLite schema
-- ============================================================================
-- Author:  Elijah Beese
-- System:  RHEL 9.6 (Plow), kernel 5.14.0-570.12.1.el9_6
-- Purpose: Store OpenSCAP OVAL scan results, triage decisions, 800-53
--          control mappings, and POA&M items for offline vuln management.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- ============================================================================
-- SECTION 1: SCAN METADATA
-- ============================================================================
-- One row per `oscap oval eval` execution. Immutable snapshot.
-- ============================================================================

CREATE TABLE IF NOT EXISTS scans (
    scan_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_date            TEXT    NOT NULL,                       -- ISO8601 UTC
    feed_file            TEXT    NOT NULL,                       -- e.g. 'rhel-9.oval.xml'
    feed_sha256          TEXT    NOT NULL,                       -- chain-of-custody hash
    system_fingerprint   TEXT    NOT NULL,                       -- JSON: os, kernel, selinux, etc.
    total_definitions    INTEGER NOT NULL,
    true_count           INTEGER NOT NULL,
    notes                TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scan_date);

-- ============================================================================
-- SECTION 2: VULNERABILITIES (canonical RHSA list)
-- ============================================================================
-- Deduplicated across scans. Same RHSA flagged in 5 scans = 1 row here, 5 in
-- findings. first_seen/last_seen track the lifecycle.
-- ============================================================================

CREATE TABLE IF NOT EXISTS vulnerabilities (
    rhsa_id              TEXT    PRIMARY KEY,                    -- e.g. 'RHSA-2025:9978'
    definition_id        TEXT    NOT NULL UNIQUE,                -- e.g. 'oval:com.redhat.rhsa:def:20259978'
    title                TEXT    NOT NULL,                       -- full title from OVAL feed
    severity             TEXT    NOT NULL                        -- enforced enum
        CHECK (severity IN ('Critical', 'Important', 'Moderate', 'Low', 'Unknown')),
    package_name         TEXT,                                   -- derived from title
    class                TEXT    NOT NULL                        -- patch advisory type
        CHECK (class IN ('rhsa', 'rhba', 'rhea')),
    first_seen_scan_id   INTEGER NOT NULL,
    last_seen_scan_id    INTEGER NOT NULL,
    FOREIGN KEY (first_seen_scan_id) REFERENCES scans(scan_id),
    FOREIGN KEY (last_seen_scan_id)  REFERENCES scans(scan_id)
);

CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_package  ON vulnerabilities(package_name);

-- ============================================================================
-- SECTION 3: VULNERABILITY-CVE MAPPING
-- ============================================================================
-- An RHSA covers multiple CVEs. Many-to-many.
-- ============================================================================

CREATE TABLE IF NOT EXISTS vulnerability_cves (
    rhsa_id              TEXT    NOT NULL,
    cve_id               TEXT    NOT NULL,                       -- e.g. 'CVE-2025-32462'
    PRIMARY KEY (rhsa_id, cve_id),
    FOREIGN KEY (rhsa_id) REFERENCES vulnerabilities(rhsa_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vuln_cves_cve ON vulnerability_cves(cve_id);

-- ============================================================================
-- SECTION 4: FINDINGS (per-scan detection events)
-- ============================================================================
-- Every (scan, vuln) pair where OVAL evaluated to true.
-- ============================================================================

CREATE TABLE IF NOT EXISTS findings (
    finding_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id              INTEGER NOT NULL,
    rhsa_id              TEXT    NOT NULL,
    oval_result          TEXT    NOT NULL DEFAULT 'true',
    affected_packages    TEXT,                                   -- JSON array of installed pkg versions
    UNIQUE (scan_id, rhsa_id),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (rhsa_id) REFERENCES vulnerabilities(rhsa_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan  ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_rhsa  ON findings(rhsa_id);

-- ============================================================================
-- SECTION 5: TRIAGE DECISIONS (append-only audit log)
-- ============================================================================
-- Triage attaches to the RHSA, not the per-scan finding. Decisions persist
-- across scans. Append-only: never UPDATE a row, always INSERT a new one and
-- mark the old one superseded=1. Current status = most recent superseded=0 row.
-- ============================================================================

CREATE TABLE IF NOT EXISTS triage_decisions (
    decision_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rhsa_id              TEXT    NOT NULL,
    status               TEXT    NOT NULL
        CHECK (status IN (
            'open',
            'in_progress',
            'mitigated',
            'risk_accepted',
            'false_positive',
            'remediated'
        )),
    decided_at           TEXT    NOT NULL,                       -- ISO8601 UTC
    decided_by           TEXT    NOT NULL,
    notes                TEXT,
    superseded           INTEGER NOT NULL DEFAULT 0
        CHECK (superseded IN (0, 1)),
    FOREIGN KEY (rhsa_id) REFERENCES vulnerabilities(rhsa_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_triage_rhsa     ON triage_decisions(rhsa_id);
CREATE INDEX IF NOT EXISTS idx_triage_current  ON triage_decisions(rhsa_id, superseded);

-- ============================================================================
-- SECTION 6: 800-53 CONTROL CATALOG
-- ============================================================================
-- Preloaded from NIST 800-53 Rev 5 Moderate baseline. Static reference data.
-- ============================================================================

CREATE TABLE IF NOT EXISTS controls_800_53 (
    control_id           TEXT    PRIMARY KEY,                    -- e.g. 'AC-17', 'SI-2'
    family               TEXT    NOT NULL,                       -- e.g. 'AC', 'SI'
    title                TEXT    NOT NULL,                       -- e.g. 'Remote Access'
    baseline             TEXT    NOT NULL                        -- which baselines include it
        CHECK (baseline IN ('Low', 'Moderate', 'High', 'Privacy', 'None')),
    description          TEXT
);

CREATE INDEX IF NOT EXISTS idx_controls_family ON controls_800_53(family);

-- ============================================================================
-- SECTION 7: VULNERABILITY-CONTROL MAPPINGS
-- ============================================================================
-- Many-to-many. `confidence` indicates how the mapping was created.
-- ============================================================================

CREATE TABLE IF NOT EXISTS vuln_control_mappings (
    rhsa_id              TEXT    NOT NULL,
    control_id           TEXT    NOT NULL,
    confidence           TEXT    NOT NULL DEFAULT 'auto'
        CHECK (confidence IN ('auto', 'manual', 'verified')),
    PRIMARY KEY (rhsa_id, control_id),
    FOREIGN KEY (rhsa_id)    REFERENCES vulnerabilities(rhsa_id) ON DELETE CASCADE,
    FOREIGN KEY (control_id) REFERENCES controls_800_53(control_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vcm_control ON vuln_control_mappings(control_id);

-- ============================================================================
-- SECTION 8: POA&M ITEMS
-- ============================================================================
-- Plan of Action & Milestones — formal ATO tracking. Column structure mirrors
-- the eMASS POA&M template so export to XLSX is a straight column mapping.
-- ============================================================================

CREATE TABLE IF NOT EXISTS poam_items (
    poam_id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    rhsa_id                   TEXT    NOT NULL,
    created_at                TEXT    NOT NULL,
    created_by                TEXT    NOT NULL,
    weakness_description      TEXT    NOT NULL,
    security_control_number   TEXT,                              -- primary 800-53 control
    office_org                TEXT    NOT NULL DEFAULT 'YOUR-ORG',
    resources_required        TEXT,
    scheduled_completion      TEXT,                              -- ISO8601 date
    milestones                TEXT,
    mitigations               TEXT,
    raw_severity              TEXT
        CHECK (raw_severity IN ('Critical', 'Important', 'Moderate', 'Low', NULL)),
    relevance_of_threat       TEXT
        CHECK (relevance_of_threat IN ('High', 'Medium', 'Low', NULL)),
    likelihood                TEXT
        CHECK (likelihood IN ('High', 'Medium', 'Low', NULL)),
    impact                    TEXT
        CHECK (impact IN ('High', 'Medium', 'Low', NULL)),
    residual_risk_level       TEXT
        CHECK (residual_risk_level IN ('High', 'Medium', 'Low', NULL)),
    status                    TEXT    NOT NULL DEFAULT 'Ongoing'
        CHECK (status IN ('Ongoing', 'Risk Accepted', 'Completed')),
    comments                  TEXT,
    FOREIGN KEY (rhsa_id) REFERENCES vulnerabilities(rhsa_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_poam_status ON poam_items(status);
CREATE INDEX IF NOT EXISTS idx_poam_rhsa   ON poam_items(rhsa_id);

-- ============================================================================
-- SECTION 9: CONVENIENCE VIEWS
-- ============================================================================
-- These are not strictly necessary but make the Flask UI queries way cleaner.
-- ============================================================================

-- Current triage status per vulnerability (most recent non-superseded row).
CREATE VIEW IF NOT EXISTS v_current_triage AS
SELECT t.rhsa_id, t.status, t.decided_at, t.decided_by, t.notes
FROM triage_decisions t
WHERE t.superseded = 0;

-- Latest scan info — useful for the dashboard.
CREATE VIEW IF NOT EXISTS v_latest_scan AS
SELECT *
FROM scans
ORDER BY scan_date DESC
LIMIT 1;

-- Open findings (current scan, not yet remediated/accepted).
CREATE VIEW IF NOT EXISTS v_open_findings AS
SELECT
    f.finding_id,
    f.scan_id,
    v.rhsa_id,
    v.title,
    v.severity,
    v.package_name,
    COALESCE(ct.status, 'open') AS current_status,
    f.affected_packages
FROM findings f
JOIN vulnerabilities v   ON f.rhsa_id = v.rhsa_id
LEFT JOIN v_current_triage ct ON v.rhsa_id = ct.rhsa_id
WHERE f.scan_id = (SELECT scan_id FROM v_latest_scan)
  AND COALESCE(ct.status, 'open') NOT IN ('remediated', 'risk_accepted', 'false_positive');

-- Severity rollup for the dashboard.
CREATE VIEW IF NOT EXISTS v_severity_summary AS
SELECT severity, COUNT(*) AS count
FROM v_open_findings
GROUP BY severity;
