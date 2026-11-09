-- 001_init: 初始 schema（对应 docs/design.md §8.2）
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    client_id     TEXT NOT NULL,
    refresh_token TEXT NOT NULL,              -- 最新 RT，grant 成功后事务内更新
    proxy         TEXT NOT NULL DEFAULT '',
    checks_json   TEXT NOT NULL DEFAULT '{}', -- {"rules":true,"imap":false,...}
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS account_state (
    account_id        INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    status            TEXT NOT NULL DEFAULT 'unknown', -- ok|degraded|failed|unknown|baseline_missing
    consecutive_fail  INTEGER NOT NULL DEFAULT 0,
    last_check_at     TEXT,
    last_alert_at     TEXT,
    last_alert_status TEXT
);

CREATE TABLE IF NOT EXISTS rule_snapshots (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    rules_json TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    taken_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS check_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    run_id      TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'sched',   -- sched|manual|cli|snapshot
    started_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    finished_at TEXT,
    status      TEXT                             -- 账号级状态，结束时写入
);

CREATE TABLE IF NOT EXISTS check_results (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER NOT NULL REFERENCES check_runs(id) ON DELETE CASCADE,
    check_name     TEXT NOT NULL,  -- c1_token / c2_me / c3_recv / c5_rules / ...
    result         TEXT NOT NULL,  -- pass|fail|unavailable|error
    classification TEXT NOT NULL DEFAULT '',
    detail         TEXT NOT NULL DEFAULT '', -- 脱敏摘要，禁止含 token/密码
    duration_ms    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_check_runs_account ON check_runs(account_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_check_results_run  ON check_results(run_id);

CREATE TABLE IF NOT EXISTS alert_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    from_status TEXT NOT NULL,
    to_status   TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    channel     TEXT NOT NULL DEFAULT '',
    sent_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    error       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS notify_channels (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT NOT NULL, -- webhook|smtp
    name        TEXT NOT NULL DEFAULT '',
    config_json TEXT NOT NULL DEFAULT '{}',
    enabled     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at TEXT NOT NULL
);
