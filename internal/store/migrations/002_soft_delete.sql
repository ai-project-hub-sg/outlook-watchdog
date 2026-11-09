-- 002: 账号软删除（保留历史数据）
ALTER TABLE accounts ADD COLUMN deleted_at TEXT NOT NULL DEFAULT '';
