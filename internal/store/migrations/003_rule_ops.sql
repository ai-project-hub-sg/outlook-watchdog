-- 003_rule_ops: 规则管理写操作审计（谁在何时对哪个账号改了什么规则）
CREATE TABLE rule_ops(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES accounts(id),
  op TEXT NOT NULL,            -- create / update / toggle / delete
  rule_id TEXT,                -- Graph messageRule id
  rule_name TEXT,
  detail TEXT,                 -- 动作摘要（已脱敏）
  created_at TEXT NOT NULL
);
CREATE INDEX idx_rule_ops_acct ON rule_ops(account_id, id DESC);
