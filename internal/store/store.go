// Package store 提供 SQLite 持久化：连接、迁移、各表 DAO。
// SQLite 是运行时唯一权威数据源（docs/design.md §8）。
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB 包装 *sql.DB。
type DB struct {
	*sql.DB
}

// Account 对应 accounts 表。
type Account struct {
	ID           int64           `json:"id"`
	Email        string          `json:"email"`
	ClientID     string          `json:"client_id"`
	RefreshToken string          `json:"-"` // 不随 JSON 输出
	Proxy        string          `json:"proxy"`
	Checks       map[string]bool `json:"checks"`
	Enabled      bool            `json:"enabled"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
}

// State 对应 account_state 表。
type State struct {
	AccountID       int64  `json:"account_id"`
	Status          string `json:"status"`
	ConsecutiveFail int    `json:"consecutive_fail"`
	LastCheckAt     string `json:"last_check_at"`
	LastAlertAt     string `json:"last_alert_at"`
	LastAlertStatus string `json:"last_alert_status"`
}

// CheckResult 对应 check_results 表。
type CheckResult struct {
	Check          string `json:"check"`
	Result         string `json:"result"` // pass|fail|unavailable|error
	Classification string `json:"classification"`
	Detail         string `json:"detail"` // 脱敏摘要
	DurationMS     int64  `json:"duration_ms"`
}

// Open 打开（必要时创建）SQLite 并执行迁移。
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite 单写者
	d := &DB{db}
	if err := d.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

// migrate 应用 migrations/ 下未执行的 NNN_*.sql（按文件名排序）。
func (d *DB) migrate() error {
	names, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	sort.Slice(names, func(i, j int) bool { return names[i].Name() < names[j].Name() })

	var cur int
	row := d.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_version`)
	if err := row.Scan(&cur); err != nil {
		// schema_version 表可能尚不存在（全新库）——先跑全部迁移
		cur = 0
	}

	for _, n := range names {
		base := strings.TrimSuffix(n.Name(), ".sql")
		num, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil || num <= cur {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + n.Name())
		if err != nil {
			return err
		}
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", n.Name(), err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version(version) VALUES (?)`, num); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s version bump: %w", n.Name(), err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ---- accounts ----

// AddAccount 新增账号并初始化 account_state。
func (d *DB) AddAccount(ctx context.Context, a *Account) (int64, error) {
	cj, err := json.Marshal(a.Checks)
	if err != nil {
		return 0, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO accounts(email, client_id, refresh_token, proxy, checks_json, enabled)
		 VALUES (?,?,?,?,?,?)`,
		a.Email, a.ClientID, a.RefreshToken, a.Proxy, string(cj), a.Enabled)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO account_state(account_id, status) VALUES (?, 'unknown')`, id); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// GetAccount 按 id 或 email 取账号。
func (d *DB) GetAccount(ctx context.Context, idOrEmail string) (*Account, error) {
	q := `SELECT id,email,client_id,refresh_token,proxy,checks_json,enabled,created_at,updated_at FROM accounts WHERE `
	var arg any
	if id, err := strconv.ParseInt(idOrEmail, 10, 64); err == nil {
		q += `id=?`
		arg = id
	} else {
		q += `email=?`
		arg = idOrEmail
	}
	var a Account
	var cj string
	err := d.QueryRowContext(ctx, q, arg).Scan(
		&a.ID, &a.Email, &a.ClientID, &a.RefreshToken, &a.Proxy, &cj,
		&a.Enabled, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(cj), &a.Checks); err != nil {
		a.Checks = map[string]bool{}
	}
	return &a, nil
}

// ListAccounts 返回全部账号（enabledOnly 时仅启用）。
func (d *DB) ListAccounts(ctx context.Context, enabledOnly bool) ([]*Account, error) {
	q := `SELECT id,email,client_id,refresh_token,proxy,checks_json,enabled,created_at,updated_at FROM accounts WHERE deleted_at=''`
	if enabledOnly {
		q += ` AND enabled=1`
	}
	q += ` ORDER BY id`
	rows, err := d.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Account
	for rows.Next() {
		var a Account
		var cj string
		if err := rows.Scan(&a.ID, &a.Email, &a.ClientID, &a.RefreshToken, &a.Proxy,
			&cj, &a.Enabled, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(cj), &a.Checks)
		out = append(out, &a)
	}
	return out, rows.Err()
}

// UpdateRefreshToken 在事务内写回轮换后的新 RT（RT 轮换持久化，AGENTS.md §4.3.3）。
func (d *DB) UpdateRefreshToken(ctx context.Context, accountID int64, newRT string) error {
	_, err := d.ExecContext(ctx,
		`UPDATE accounts SET refresh_token=?, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?`,
		newRT, accountID)
	return err
}

// UpdateAccountChecks 更新检查开关。
func (d *DB) UpdateAccountChecks(ctx context.Context, id int64, checks map[string]bool) error {
	cj, err := json.Marshal(checks)
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx,
		`UPDATE accounts SET checks_json=?, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?`,
		string(cj), id)
	return err
}

// DeleteAccount 删除账号（级联删除状态/基线/历史）。
func (d *DB) DeleteAccount(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM accounts WHERE id=?`, id)
	return err
}

// SoftDeleteAccount 软删除：列表隐藏但保留全部历史（重授权等场景）。
func (d *DB) SoftDeleteAccount(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx,
		`UPDATE accounts SET deleted_at=?, enabled=0, updated_at=? WHERE id=?`,
		NowUTC(), NowUTC(), id)
	return err
}

// UpdateAccountAuth 重新授权回写：更新 RT 与 client_id（保留历史/基线）。
func (d *DB) UpdateAccountAuth(ctx context.Context, id int64, rt, clientID string) error {
	_, err := d.ExecContext(ctx,
		`UPDATE accounts SET refresh_token=?, client_id=?, updated_at=? WHERE id=?`,
		rt, clientID, NowUTC(), id)
	return err
}

// ---- account_state ----

// GetState 取账号当前状态；无记录时返回 unknown。
func (d *DB) GetState(ctx context.Context, accountID int64) (*State, error) {
	var s State
	err := d.QueryRowContext(ctx,
		`SELECT account_id,status,consecutive_fail,
		        COALESCE(last_check_at,''),COALESCE(last_alert_at,''),COALESCE(last_alert_status,'')
		 FROM account_state WHERE account_id=?`, accountID).
		Scan(&s.AccountID, &s.Status, &s.ConsecutiveFail, &s.LastCheckAt, &s.LastAlertAt, &s.LastAlertStatus)
	if err == sql.ErrNoRows {
		return &State{AccountID: accountID, Status: "unknown"}, nil
	}
	return &s, err
}

// SetState 更新账号状态。
func (d *DB) SetState(ctx context.Context, s *State) error {
	_, err := d.ExecContext(ctx,
		`INSERT INTO account_state(account_id,status,consecutive_fail,last_check_at,last_alert_at,last_alert_status)
		 VALUES (?,?,?,?,?,?)
		 ON CONFLICT(account_id) DO UPDATE SET
		   status=excluded.status, consecutive_fail=excluded.consecutive_fail,
		   last_check_at=excluded.last_check_at,
		   last_alert_at=excluded.last_alert_at, last_alert_status=excluded.last_alert_status`,
		s.AccountID, s.Status, s.ConsecutiveFail, s.LastCheckAt, s.LastAlertAt, s.LastAlertStatus)
	return err
}

// ---- rule_snapshots ----

// SaveRuleSnapshot 建立/覆盖 rules 基线。
func (d *DB) SaveRuleSnapshot(ctx context.Context, accountID int64, rulesJSON, sha string) error {
	_, err := d.ExecContext(ctx,
		`INSERT INTO rule_snapshots(account_id,rules_json,sha256,taken_at)
		 VALUES (?,?,?,strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		 ON CONFLICT(account_id) DO UPDATE SET
		   rules_json=excluded.rules_json, sha256=excluded.sha256, taken_at=excluded.taken_at`,
		accountID, rulesJSON, sha)
	return err
}

// GetRuleSnapshot 取基线；无则返回 nil,nil。
func (d *DB) GetRuleSnapshot(ctx context.Context, accountID int64) (rulesJSON, sha string, err error) {
	err = d.QueryRowContext(ctx,
		`SELECT rules_json,sha256 FROM rule_snapshots WHERE account_id=?`, accountID).
		Scan(&rulesJSON, &sha)
	if err == sql.ErrNoRows {
		return "", "", nil
	}
	return rulesJSON, sha, err
}

// ---- rule_ops（规则管理写操作审计） ----

// RuleOp 一次规则写操作记录。
type RuleOp struct {
	ID        int64
	Op        string
	RuleID    string
	RuleName  string
	Detail    string
	CreatedAt string
}

// AddRuleOp 记录一次规则写操作。
func (d *DB) AddRuleOp(ctx context.Context, accountID int64, op, ruleID, ruleName, detail string) error {
	_, err := d.ExecContext(ctx,
		`INSERT INTO rule_ops(account_id,op,rule_id,rule_name,detail,created_at)
		 VALUES (?,?,?,?,?,strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
		accountID, op, ruleID, ruleName, detail)
	return err
}

// ListRuleOps 取账号最近规则操作（倒序）。
func (d *DB) ListRuleOps(ctx context.Context, accountID int64, limit int) ([]RuleOp, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT id,op,rule_id,rule_name,detail,created_at FROM rule_ops
		 WHERE account_id=? ORDER BY id DESC LIMIT ?`, accountID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleOp
	for rows.Next() {
		var o RuleOp
		if err := rows.Scan(&o.ID, &o.Op, &o.RuleID, &o.RuleName, &o.Detail, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ---- check_runs / check_results ----

// StartRun 开启一次检查运行，返回 run 主键 id。
func (d *DB) StartRun(ctx context.Context, accountID int64, runID, source string) (int64, error) {
	res, err := d.ExecContext(ctx,
		`INSERT INTO check_runs(account_id,run_id,source) VALUES (?,?,?)`, accountID, runID, source)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishRun 结束运行并写入账号级状态。
func (d *DB) FinishRun(ctx context.Context, runPK int64, status string) error {
	_, err := d.ExecContext(ctx,
		`UPDATE check_runs SET finished_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'), status=? WHERE id=?`,
		status, runPK)
	return err
}

// AddResult 记录单个检查结果。
func (d *DB) AddResult(ctx context.Context, runPK int64, r *CheckResult) error {
	_, err := d.ExecContext(ctx,
		`INSERT INTO check_results(run_id,check_name,result,classification,detail,duration_ms)
		 VALUES (?,?,?,?,?,?)`,
		runPK, r.Check, r.Result, r.Classification, r.Detail, r.DurationMS)
	return err
}

// ---- notify_channels ----

// Channel 对应 notify_channels 表。
type Channel struct {
	ID      int64             `json:"id"`
	Type    string            `json:"type"` // webhook|smtp
	Name    string            `json:"name"`
	Config  map[string]string `json:"config"`
	Enabled bool              `json:"enabled"`
}

// AddChannel 新增告警通道。
func (d *DB) AddChannel(ctx context.Context, c *Channel) (int64, error) {
	cj, err := json.Marshal(c.Config)
	if err != nil {
		return 0, err
	}
	res, err := d.ExecContext(ctx,
		`INSERT INTO notify_channels(type,name,config_json,enabled) VALUES (?,?,?,?)`,
		c.Type, c.Name, string(cj), c.Enabled)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListChannels 返回告警通道（enabledOnly 时仅启用）。
func (d *DB) ListChannels(ctx context.Context, enabledOnly bool) ([]*Channel, error) {
	q := `SELECT id,type,name,config_json,enabled FROM notify_channels`
	if enabledOnly {
		q += ` WHERE enabled=1`
	}
	q += ` ORDER BY id`
	rows, err := d.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Channel
	for rows.Next() {
		var c Channel
		var cj string
		if err := rows.Scan(&c.ID, &c.Type, &c.Name, &cj, &c.Enabled); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(cj), &c.Config)
		out = append(out, &c)
	}
	return out, rows.Err()
}

// DeleteChannel 删除通道。
func (d *DB) DeleteChannel(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM notify_channels WHERE id=?`, id)
	return err
}

// ---- alert_events ----

// RecordAlert 记录一次告警事件。
func (d *DB) RecordAlert(ctx context.Context, accountID int64, from, to, reason, channel, sendErr string) error {
	_, err := d.ExecContext(ctx,
		`INSERT INTO alert_events(account_id,from_status,to_status,reason,channel,error)
		 VALUES (?,?,?,?,?,?)`, accountID, from, to, reason, channel, sendErr)
	return err
}

// AlertEvent 对应 alert_events 表。
type AlertEvent struct {
	ID         int64  `json:"id"`
	AccountID  int64  `json:"account_id"`
	FromStatus string `json:"from_status"`
	ToStatus   string `json:"to_status"`
	Reason     string `json:"reason"`
	Channel    string `json:"channel"`
	SentAt     string `json:"sent_at"`
	Error      string `json:"error"`
}

// ListAlerts 返回最近告警事件（倒序，limit 条）。
func (d *DB) ListAlerts(ctx context.Context, limit int) ([]*AlertEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.QueryContext(ctx,
		`SELECT id,account_id,from_status,to_status,reason,channel,sent_at,error
		 FROM alert_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AlertEvent
	for rows.Next() {
		var e AlertEvent
		if err := rows.Scan(&e.ID, &e.AccountID, &e.FromStatus, &e.ToStatus,
			&e.Reason, &e.Channel, &e.SentAt, &e.Error); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// MarkAlerted 更新 last_alert_status/last_alert_at（告警或恢复后调用）。
func (d *DB) MarkAlerted(ctx context.Context, accountID int64, status string) error {
	_, err := d.ExecContext(ctx,
		`UPDATE account_state SET last_alert_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'),
		 last_alert_status=? WHERE account_id=?`, status, accountID)
	return err
}

// ---- settings ----

// GetSetting 取设置项；无则返回 ""。
func (d *DB) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := d.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// SetSetting 写设置项。
func (d *DB) SetSetting(ctx context.Context, key, value string) error {
	_, err := d.ExecContext(ctx,
		`INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value)
	return err
}

// SetAccountEnabled 开关账号。
func (d *DB) SetAccountEnabled(ctx context.Context, id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := d.ExecContext(ctx, `UPDATE accounts SET enabled=?, updated_at=? WHERE id=?`,
		v, NowUTC(), id)
	return err
}

// RunWithResults 是一次运行及其各检查项结果（账号详情页用）。
type RunWithResults struct {
	ID         int64         `json:"id"`
	Source     string        `json:"source"`
	StartedAt  string        `json:"started_at"`
	FinishedAt string        `json:"finished_at"`
	Status     string        `json:"status"`
	Results    []CheckResult `json:"results"`
}

// ListRuns 返回账号最近 N 次运行（含各检查项结果）。
func (d *DB) ListRuns(ctx context.Context, accountID int64, limit int) ([]*RunWithResults, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT id, source, started_at, COALESCE(finished_at,''), COALESCE(status,'')
		 FROM check_runs WHERE account_id=? ORDER BY id DESC LIMIT ?`, accountID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RunWithResults
	for rows.Next() {
		r := &RunWithResults{}
		if err := rows.Scan(&r.ID, &r.Source, &r.StartedAt, &r.FinishedAt, &r.Status); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, r := range out {
		rs, err := d.listResults(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		r.Results = rs
	}
	return out, nil
}

func (d *DB) listResults(ctx context.Context, runPK int64) ([]CheckResult, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT check_name, result, classification, detail, duration_ms
		 FROM check_results WHERE run_id=? ORDER BY id`, runPK)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckResult
	for rows.Next() {
		var r CheckResult
		if err := rows.Scan(&r.Check, &r.Result, &r.Classification, &r.Detail, &r.DurationMS); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LastCheckTime 返回某账号某检查项最近一次运行的开始时间（C8 限频用）。
func (d *DB) LastCheckTime(ctx context.Context, accountID int64, checkName string) (string, error) {
	var ts string
	err := d.QueryRowContext(ctx,
		`SELECT r.started_at FROM check_results cr
		 JOIN check_runs r ON r.id=cr.run_id
		 WHERE r.account_id=? AND cr.check_name=?
		 ORDER BY cr.id DESC LIMIT 1`, accountID, checkName).Scan(&ts)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return ts, err
}

// GlobalRun 是跨账号的一次运行（日志查询页用）。
type GlobalRun struct {
	ID         int64  `json:"id"`
	AccountID  int64  `json:"account_id"`
	Email      string `json:"email"`
	Source     string `json:"source"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	Status     string `json:"status"`
}

// ListAllRuns 跨账号分页查询运行记录；accountID/status 非零值时作过滤。
func (d *DB) ListAllRuns(ctx context.Context, accountID int64, status string, limit, offset int) ([]*GlobalRun, int, error) {
	where, args := "", []any{}
	if accountID > 0 {
		where += " AND r.account_id=?"
		args = append(args, accountID)
	}
	if status != "" {
		where += " AND r.status=?"
		args = append(args, status)
	}
	var total int
	if err := d.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM check_runs r WHERE 1=1`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT r.id, r.account_id, a.email, r.source, r.started_at,
	             COALESCE(r.finished_at,''), COALESCE(r.status,'')
	      FROM check_runs r JOIN accounts a ON a.id=r.account_id
	      WHERE 1=1` + where + ` ORDER BY r.id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*GlobalRun
	for rows.Next() {
		g := &GlobalRun{}
		if err := rows.Scan(&g.ID, &g.AccountID, &g.Email, &g.Source, &g.StartedAt, &g.FinishedAt, &g.Status); err != nil {
			return nil, 0, err
		}
		out = append(out, g)
	}
	return out, total, rows.Err()
}

// CreateSession 写入会话（token 由调用方生成）。
func (d *DB) CreateSession(ctx context.Context, token string, ttl time.Duration) error {
	exp := time.Now().UTC().Add(ttl).Format(time.RFC3339)
	_, err := d.ExecContext(ctx, `INSERT INTO sessions(token, expires_at) VALUES(?,?)`, token, exp)
	return err
}

// GetSession 校验会话未过期；过期即删并返回 false。
func (d *DB) GetSession(ctx context.Context, token string) (bool, error) {
	var exp string
	err := d.QueryRowContext(ctx, `SELECT expires_at FROM sessions WHERE token=?`, token).Scan(&exp)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	t, err := time.Parse(time.RFC3339, exp)
	if err != nil || time.Now().UTC().After(t) {
		_, _ = d.ExecContext(ctx, `DELETE FROM sessions WHERE token=?`, token)
		return false, nil
	}
	return true, nil
}

// DeleteSession 注销会话。
func (d *DB) DeleteSession(ctx context.Context, token string) error {
	_, err := d.ExecContext(ctx, `DELETE FROM sessions WHERE token=?`, token)
	return err
}

// NowUTC 返回 ISO8601 UTC 时间戳（与 SQLite 默认值同格式）。
func NowUTC() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}
