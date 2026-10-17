-- Security Incident Detection and Response Management System

-- Users and Identity
CREATE TABLE IF NOT EXISTS users (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name       TEXT NOT NULL,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,            
    department      TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'Regular User'
                    CHECK (role IN ('Security Administrator', 'Security Analyst',
                                    'Regular User', 'Auditor')),
    account_status  TEXT NOT NULL DEFAULT 'Active'
                    CHECK (account_status IN ('Active', 'Inactive', 'Suspended')),
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_login      TEXT                      
);

-- Assets
CREATE TABLE IF NOT EXISTS assets (
    asset_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_name        TEXT NOT NULL,
    asset_type        TEXT NOT NULL
                      CHECK (asset_type IN ('Server', 'Workstation', 'Database',
                                            'Application', 'Network Device',
                                            'Cloud Resource')),
    ip_address        TEXT NOT NULL,
    operating_system  TEXT,                     -- optional ("if applicable")
    department        TEXT NOT NULL,
    owner_id          INTEGER NOT NULL REFERENCES users(user_id),
    location          TEXT,
    criticality_level TEXT NOT NULL
                      CHECK (criticality_level IN ('Low', 'Medium', 'High', 'Critical')),
    status            TEXT NOT NULL DEFAULT 'Active'
                      CHECK (status IN ('Active', 'Inactive', 'Under Maintenance')),
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL,
    cve_id           TEXT NOT NULL,
    cvss_score       REAL NOT NULL CHECK (cvss_score >= 0.0 AND cvss_score <= 10.0),
    severity_level   TEXT NOT NULL
                     CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
    asset_id         INTEGER NOT NULL REFERENCES assets(asset_id),
    discovery_source TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'Open'
                     CHECK (status IN ('Open', 'Under Investigation', 'In Progress',
                                       'Resolved', 'Closed')),
    creation_date    TEXT NOT NULL DEFAULT (date('now')),
    resolution_date  TEXT,                    
    UNIQUE (cve_id, asset_id)
);

-- Incidents
CREATE TABLE IF NOT EXISTS incidents (
    incident_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL,
    category            TEXT NOT NULL,
    severity_level      TEXT NOT NULL
                        CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
    reporter_id         INTEGER NOT NULL REFERENCES users(user_id),
    asset_id            INTEGER NOT NULL REFERENCES assets(asset_id),
    assigned_analyst_id INTEGER REFERENCES users(user_id),
    status              TEXT NOT NULL DEFAULT 'Open'
                        CHECK (status IN ('Open', 'Under Investigation', 'Mitigated',
                                          'Resolved', 'Closed')),
    creation_date       TEXT NOT NULL DEFAULT (date('now')),
    resolution_date     TEXT
);

-- Investigation notes
CREATE TABLE IF NOT EXISTS investigation_notes (
    note_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id   INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    analyst_id    INTEGER NOT NULL REFERENCES users(user_id),
    note_content  TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Threat intelligence 
CREATE TABLE IF NOT EXISTS threats (
    threat_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type    TEXT NOT NULL
                   CHECK (threat_type IN ('IP Address', 'Domain', 'File Hash',
                                          'Malware Signature', 'Other')),
    threat_value   TEXT NOT NULL,
    description    TEXT NOT NULL,
    severity_level TEXT NOT NULL
                   CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
    source         TEXT NOT NULL,
    date_added     TEXT NOT NULL DEFAULT (date('now')),
    UNIQUE (threat_type, threat_value)
);

-- Audit logs
CREATE TABLE IF NOT EXISTS logs (
    log_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    action          TEXT NOT NULL,
    description     TEXT NOT NULL,
    timestamp       TEXT NOT NULL DEFAULT (datetime('now')),
    severity_level  TEXT NOT NULL DEFAULT 'Information'
                    CHECK (severity_level IN ('Information', 'Warning', 'Error',
                                              'Critical')),
    related_service TEXT NOT NULL
);

-- Audit logs must not change after creation.
CREATE TRIGGER IF NOT EXISTS logs_no_update
BEFORE UPDATE ON logs
WHEN NEW.log_id          IS NOT OLD.log_id
  OR NEW.action          IS NOT OLD.action
  OR NEW.description     IS NOT OLD.description
  OR NEW.timestamp       IS NOT OLD.timestamp
  OR NEW.severity_level  IS NOT OLD.severity_level
  OR NEW.related_service IS NOT OLD.related_service
  OR NEW.user_id         IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'Audit logs cannot be modified after creation');
END;

-- Notifications 
CREATE TABLE IF NOT EXISTS notifications (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    incident_id     INTEGER REFERENCES incidents(incident_id) ON DELETE SET NULL,
    title           TEXT NOT NULL,
    message         TEXT NOT NULL,
    notification_type TEXT NOT NULL DEFAULT 'System Notification'
                      CHECK (notification_type IN ('Incident Assignment', 'Security Alert',
                                                    'System Notification', 'Threat Alert',
                                                    'Vulnerability Alert')),
    severity_level  TEXT NOT NULL DEFAULT 'Low'
                    CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
    is_read         INTEGER NOT NULL DEFAULT 0 CHECK (is_read IN (0, 1)),
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    read_date       TEXT
);

-- Playbooks
CREATE TABLE IF NOT EXISTS playbooks (
    playbook_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_name     TEXT NOT NULL CHECK (length(trim(playbook_name)) > 0),
    description       TEXT NOT NULL,
    incident_category TEXT NOT NULL CHECK (length(trim(incident_category)) > 0),
    severity_level    TEXT NOT NULL
                      CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
    created_by        INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Response actions
CREATE TABLE IF NOT EXISTS response_actions (
    action_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id        INTEGER NOT NULL REFERENCES playbooks(playbook_id) ON DELETE CASCADE,
    action_description TEXT NOT NULL,
    step_number        INTEGER NOT NULL CHECK (typeof(step_number) = 'integer' AND step_number > 0),
    status             TEXT NOT NULL DEFAULT 'Pending'
                       CHECK (status IN ('Pending', 'In Progress', 'Completed')),
    assigned_user_id   INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    completion_date    TEXT,
    updated_at         TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (playbook_id, step_number),
    CHECK (status = 'Completed' OR completion_date IS NULL)
);

-- Historical action/playbook IDs are snapshots, retained after their deletion.
CREATE TABLE IF NOT EXISTS response_action_history (
    history_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id          INTEGER NOT NULL,
    playbook_id        INTEGER NOT NULL,
    action_description TEXT NOT NULL,
    step_number        INTEGER NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('Pending', 'In Progress', 'Completed')),
    assigned_user_id   INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    completion_date    TEXT,
    changed_by         INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    changed_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS response_action_history_action
ON response_action_history (action_id, history_id);
