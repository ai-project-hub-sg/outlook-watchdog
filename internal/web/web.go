// Package web 提供 WebUI：session 认证、CSRF、服务端渲染页面。
// 所有输出（含模板上下文）不得包含 refresh_token、密码等秘密原文；
// 邮箱等标识按 MaskEmail 规则脱敏（AGENTS.md §4.4）。
package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"outlook-watchdog/internal/check"
	"outlook-watchdog/internal/classify"
	"outlook-watchdog/internal/graph"
	"outlook-watchdog/internal/msauth"
	"outlook-watchdog/internal/sched"
	"outlook-watchdog/internal/store"
)

//go:embed templates static
var assets embed.FS

const (
	cookieName  = "wd_session"
	sessionTTL  = 12 * time.Hour
	csrfField   = "csrf"
	loginMaxTry = 5 // 窗口内最大失败次数
	loginWindow = 10 * time.Minute
)

var errTooMany = errors.New("尝试过多，请稍后再试")

// Server 是 WebUI 服务。
type Server struct {
	db      *store.DB
	sc      *sched.Scheduler
	tpl     *template.Template
	mux     *http.ServeMux
	version string
	started time.Time

	mu      sync.Mutex
	failIPs map[string][]time.Time  // 登录限速
	pending map[string]*pendingFlow // device flow 进行中的授权（RT 不出服务端）
}

// pendingFlow 跟踪一次 device code 授权；RT 仅存在服务端内存，不进 HTML。
type pendingFlow struct {
	ClientID   string
	DeviceCode string
	ExpiresAt  time.Time
	Done       bool
	Err        string
	RT         string
	Email      string // 授权实际绑定的账号（/me 识别）
}

// New 构建服务（version 供状态页展示）。
func New(db *store.DB, version string) (*Server, error) {
	tpl, err := template.New("").Funcs(template.FuncMap{
		"mask":     maskForTpl,
		"maskText": maskEmailsInText,
		"badge":    badgeForTpl,
		"seq":      seq,
		"add":      func(a, b int) int { return a + b },
		"join":     strings.Join,
		"eqStr":    func(a, b string) bool { return a == b },
	}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("templates: %w", err)
	}
	s := &Server{
		db: db, tpl: tpl, mux: http.NewServeMux(),
		version: version, started: time.Now(), failIPs: map[string][]time.Time{},
		pending: map[string]*pendingFlow{},
	}
	s.sc = &sched.Scheduler{DB: db, NewRunner: func() *check.Runner { return check.NewRunner(db) }}
	s.routes()
	return s, nil
}

// Scheduler 返回内部调度器（serve 命令据此启动 Loop）。
func (s *Server) Scheduler() *sched.Scheduler { return s.sc }

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.requireAuth(s.pageDashboard))
	s.mux.HandleFunc("/login", s.pageLogin)
	s.mux.HandleFunc("/setup", s.pageSetup)
	s.mux.HandleFunc("/logout", s.handleLogout)
	s.mux.HandleFunc("/accounts", s.requireAuth(s.pageAccounts))
	s.mux.HandleFunc("/accounts/import", s.requireAuth(s.handleImportAccounts))
	s.mux.HandleFunc("/logs", s.requireAuth(s.pageLogs))
	s.mux.HandleFunc("/accounts/add", s.requireAuth(s.handleAddAccount))
	s.mux.HandleFunc("/accounts/delete", s.requireAuth(s.handleDeleteAccount))
	s.mux.HandleFunc("/accounts/toggle", s.requireAuth(s.handleToggleAccount))
	s.mux.HandleFunc("/accounts/checks", s.requireAuth(s.handleUpdateChecks))
	s.mux.HandleFunc("/account/", s.requireAuth(s.pageAccountDetail))
	s.mux.HandleFunc("/account/check", s.requireAuth(s.handleCheckNow))
	s.mux.HandleFunc("/account/snapshot", s.requireAuth(s.handleSnapshot))
	s.mux.HandleFunc("/alerts", s.requireAuth(s.pageAlerts))
	s.mux.HandleFunc("/settings", s.requireAuth(s.pageSettings))
	s.mux.HandleFunc("/settings/save", s.requireAuth(s.handleSaveSettings))
	s.mux.HandleFunc("/settings/password", s.requireAuth(s.handleChangePassword))
	s.mux.HandleFunc("/channels", s.requireAuth(s.pageChannels))
	s.mux.HandleFunc("/channels/add", s.requireAuth(s.handleAddChannel))
	s.mux.HandleFunc("/channels/delete", s.requireAuth(s.handleDeleteChannel))
	s.mux.HandleFunc("/channels/test", s.requireAuth(s.handleTestChannel))
	s.mux.HandleFunc("/token/start", s.requireAuth(s.handleTokenStart))
	s.mux.HandleFunc("/token/poll", s.requireAuth(s.handleTokenPoll))
	s.mux.HandleFunc("/static/", http.FileServer(http.FS(assets)).ServeHTTP)
}

// Handler 返回根 handler（含安全头）。
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		s.mux.ServeHTTP(w, r)
	})
}

// ---- auth ----

func (s *Server) adminSet(ctx context.Context) bool {
	v, err := s.db.GetSetting(ctx, "admin.password_hash")
	return err == nil && v != ""
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminSet(r.Context()) {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ok, err := s.db.GetSession(r.Context(), c.Value)
		if err != nil || !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// csrfCheck 校验表单 POST 的 CSRF token（与会话绑定）。
func (s *Server) csrfCheck(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return r.FormValue(csrfField) == csrfToken(c.Value)
}

// csrfToken 由 session token 派生（无状态 CSRF：token 本身不可猜）。
func csrfToken(session string) string {
	h := sha256Hex("csrf:" + session)
	return h[:32]
}

func (s *Server) csrfOf(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return csrfToken(c.Value)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimited 记录一次登录失败并返回是否超限。
func (s *Server) rateLimited(ip string, failed bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	lst := s.failIPs[ip]
	keep := lst[:0]
	for _, t := range lst {
		if now.Sub(t) < loginWindow {
			keep = append(keep, t)
		}
	}
	if failed {
		keep = append(keep, now)
	}
	s.failIPs[ip] = keep
	return len(keep) > loginMaxTry
}

// ---- pages ----

type pageData struct {
	Title   string
	CSRF    string
	Path    string
	Flash   string
	Data    any
	Version string
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	if data == nil {
		data = map[string]any{}
	}
	pd := pageData{Title: name, CSRF: s.csrfOf(r), Path: r.URL.Path, Data: data, Version: s.version}
	if f := r.URL.Query().Get("flash"); f != "" {
		pd.Flash = f
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, pd); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "渲染失败", 500)
	}
}

func (s *Server) pageSetup(w http.ResponseWriter, r *http.Request) {
	if s.adminSet(r.Context()) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		pw, pw2 := r.FormValue("password"), r.FormValue("password2")
		if len(pw) < 10 || pw != pw2 {
			s.render(w, r, "setup", map[string]any{"Err": "密码至少10位且两次输入一致"})
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err := s.db.SetSetting(r.Context(), "admin.password_hash", string(hash)); err != nil {
			s.render(w, r, "setup", map[string]any{"Err": err.Error()})
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, "setup", nil)
}

func (s *Server) pageLogin(w http.ResponseWriter, r *http.Request) {
	if !s.adminSet(r.Context()) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	ip := clientIP(r)
	if r.Method == http.MethodPost {
		if s.rateLimited(ip, false) {
			s.render(w, r, "login", map[string]any{"Err": errTooMany.Error()})
			return
		}
		hash, _ := s.db.GetSetting(r.Context(), "admin.password_hash")
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.FormValue("password"))) != nil {
			s.rateLimited(ip, true)
			s.render(w, r, "login", map[string]any{"Err": "密码错误"})
			return
		}
		tok := randToken()
		if err := s.db.CreateSession(r.Context(), tok, sessionTTL); err != nil {
			s.render(w, r, "login", map[string]any{"Err": err.Error()})
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: cookieName, Value: tok, Path: "/", HttpOnly: true,
			SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds()),
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", nil)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		_ = s.db.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- dashboard ----

type dashRow struct {
	ID              int64
	Email           string
	Enabled         bool
	Status          string
	ConsecutiveFail int
	LastCheckAt     string
	HasBaseline     bool
}

func (s *Server) pageDashboard(w http.ResponseWriter, r *http.Request) {
	accs, _ := s.db.ListAccounts(r.Context(), false)
	rows := make([]dashRow, 0, len(accs))
	var okCnt, failCnt, disCnt int
	for _, a := range accs {
		st, _ := s.db.GetState(r.Context(), a.ID)
		row := dashRow{ID: a.ID, Email: a.Email, Enabled: a.Enabled, Status: "unknown"}
		if st != nil {
			row.Status, row.ConsecutiveFail, row.LastCheckAt = st.Status, st.ConsecutiveFail, st.LastCheckAt
		}
		_, sha, _ := s.db.GetRuleSnapshot(r.Context(), a.ID)
		row.HasBaseline = sha != ""
		if !a.Enabled {
			disCnt++
		} else if row.Status == "ok" {
			okCnt++
		} else if st != nil && st.LastCheckAt != "" {
			failCnt++
		}
		rows = append(rows, row)
	}
	alerts, _ := s.db.ListAlerts(r.Context(), 8)
	s.render(w, r, "dashboard", map[string]any{
		"Rows": rows, "Alerts": alerts,
		"OkCnt": okCnt, "FailCnt": failCnt, "DisCnt": disCnt, "Total": len(accs),
	})
}

// ---- accounts ----

func (s *Server) pageAccounts(w http.ResponseWriter, r *http.Request) {
	accs, _ := s.db.ListAccounts(r.Context(), false)
	type row struct {
		*store.Account
		RT          string
		Status      string
		HasBaseline bool
	}
	rows := make([]row, 0, len(accs))
	for _, a := range accs {
		st, _ := s.db.GetState(r.Context(), a.ID)
		status := "unknown"
		if st != nil {
			status = st.Status
		}
		_, sha, _ := s.db.GetRuleSnapshot(r.Context(), a.ID)
		rows = append(rows, row{a, maskRT(a.RefreshToken), status, sha != ""})
	}
	defCID, _ := s.db.GetSetting(r.Context(), "app.client_id")
	s.render(w, r, "accounts", map[string]any{"Rows": rows, "DefaultClientID": defCID})
}

// defaultClientID 取表单值，空则回落 settings 的 app.client_id。
func (s *Server) defaultClientID(ctx context.Context, formVal string) string {
	if v := strings.TrimSpace(formVal); v != "" {
		return v
	}
	v, _ := s.db.GetSetting(ctx, "app.client_id")
	return v
}

var knownChecks = []string{
	"c1_token", "c2_me", "c3_recv", "c5_rules",
	"c4_send", "c6_imap", "c7_smtp", "c8_roundtrip",
}

func (s *Server) handleAddAccount(w http.ResponseWriter, r *http.Request) {
	if !s.csrfCheck(r) {
		http.Error(w, "CSRF", 403)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	rt := strings.TrimSpace(r.FormValue("refresh_token"))
	cid := s.defaultClientID(r.Context(), r.FormValue("client_id"))
	// token_ref：网页授权向导取得的 RT（仅服务端持有，不经浏览器）
	if ref := strings.TrimSpace(r.FormValue("token_ref")); ref != "" {
		s.mu.Lock()
		pf := s.pending[ref]
		if pf != nil && pf.Done && pf.RT != "" {
			rt = pf.RT
			if strings.TrimSpace(r.FormValue("client_id")) == "" {
				cid = pf.ClientID
			}
			if email == "" {
				email = pf.Email // /me 识别的授权实际账号
			}
			delete(s.pending, ref)
		}
		s.mu.Unlock()
	}
	if email == "" || rt == "" || cid == "" {
		http.Redirect(w, r, "/accounts?flash="+urlq("email/client_id/refresh_token 必填"), 303)
		return
	}
	checks := map[string]bool{}
	for _, c := range knownChecks {
		checks[c] = r.FormValue("chk_"+c) == "on"
	}
	a := &store.Account{Email: email, ClientID: cid, RefreshToken: rt, Checks: checks, Enabled: true}
	id, err := s.db.AddAccount(r.Context(), a)
	if err != nil {
		http.Redirect(w, r, "/accounts?flash="+urlq("添加失败: "+err.Error()), 303)
		return
	}
	// 新账号立即后台跑一轮，避免用户干等一个调度周期
	go s.sc.RunOnce(context.Background(), "manual", s.threshold(context.Background()), id)
	http.Redirect(w, r, "/accounts?flash="+urlq("已添加 "+email+"，后台检查中（首轮 degraded 提示缺规则基线属正常，进详情页建基线即可）"), 303)
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if !s.csrfCheck(r) {
		http.Error(w, "CSRF", 403)
		return
	}
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	_ = s.db.DeleteAccount(r.Context(), id)
	http.Redirect(w, r, "/accounts?flash="+urlq("已删除"), 303)
}

func (s *Server) handleToggleAccount(w http.ResponseWriter, r *http.Request) {
	if !s.csrfCheck(r) {
		http.Error(w, "CSRF", 403)
		return
	}
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	_ = s.db.SetAccountEnabled(r.Context(), id, r.FormValue("enabled") == "1")
	http.Redirect(w, r, "/accounts", 303)
}

func (s *Server) handleUpdateChecks(w http.ResponseWriter, r *http.Request) {
	if !s.csrfCheck(r) {
		http.Error(w, "CSRF", 403)
		return
	}
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	checks := map[string]bool{}
	for _, c := range knownChecks {
		checks[c] = r.FormValue("chk_"+c) == "on"
	}
	_ = s.db.UpdateAccountChecks(r.Context(), id, checks)
	http.Redirect(w, r, "/account/"+strconv.FormatInt(id, 10), 303)
}

func (s *Server) pageAccountDetail(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/account/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	a, err := s.db.GetAccount(r.Context(), idStr)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	st, _ := s.db.GetState(r.Context(), id)
	runs, _ := s.db.ListRuns(r.Context(), id, 20)
	baseJSON, sha, _ := s.db.GetRuleSnapshot(r.Context(), id)
	var baseRules []classify.NormRule
	if baseJSON != "" {
		_ = json.Unmarshal([]byte(baseJSON), &baseRules)
	}
	s.render(w, r, "account", map[string]any{
		"A": a, "RT": maskRT(a.RefreshToken), "State": st,
		"Runs": runs, "BaselineSHA": sha, "Checks": knownChecks,
		"BaseRules": baseRules,
	})
}

func (s *Server) handleCheckNow(w http.ResponseWriter, r *http.Request) {
	if !s.csrfCheck(r) {
		http.Error(w, "CSRF", 403)
		return
	}
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	go s.sc.RunOnce(context.Background(), "manual", s.threshold(r.Context()), id)
	back := "/account/" + strconv.FormatInt(id, 10)
	if r.FormValue("back") == "list" {
		back = "/accounts"
	}
	http.Redirect(w, r, back+"?flash="+urlq("已触发检查（稍后刷新查看）"), 303)
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.csrfCheck(r) {
		http.Error(w, "CSRF", 403)
		return
	}
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	a, err := s.db.GetAccount(r.Context(), strconv.FormatInt(id, 10))
	if err != nil {
		http.Redirect(w, r, "/accounts?flash="+urlq("账号不存在"), 303)
		return
	}
	sha, err := check.NewRunner(s.db).SnapshotBaseline(r.Context(), a)
	msg := "基线已建立 sha=" + sha[:12]
	if err != nil {
		msg = "基线失败: " + err.Error()
	}
	http.Redirect(w, r, "/account/"+strconv.FormatInt(id, 10)+"?flash="+urlq(msg), 303)
}

func (s *Server) threshold(ctx context.Context) int {
	_, _, t := s.sc.Params(ctx)
	return t
}

// handleImportAccounts 批量粘贴导入：每行 `email,client_id,refresh_token`
// （client_id 可空 → 用默认）。
func (s *Server) handleImportAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.csrfCheck(r) {
		http.Error(w, "CSRF", 403)
		return
	}
	var okCnt, failCnt int
	for _, line := range strings.Split(r.FormValue("bulk"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			failCnt++
			continue
		}
		email := strings.TrimSpace(parts[0])
		cid, rt := "", ""
		if len(parts) == 2 {
			rt = strings.TrimSpace(parts[1])
		} else {
			cid, rt = strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
		}
		cid = s.defaultClientID(r.Context(), cid)
		if email == "" || rt == "" || cid == "" {
			failCnt++
			continue
		}
		a := &store.Account{
			Email: email, ClientID: cid, RefreshToken: rt, Enabled: true,
			Checks: map[string]bool{"c1_token": true, "c2_me": true, "c3_recv": true, "c5_rules": true},
		}
		if _, err := s.db.AddAccount(r.Context(), a); err != nil {
			failCnt++
			continue
		}
		okCnt++
	}
	http.Redirect(w, r, "/accounts?flash="+urlq(fmt.Sprintf("导入完成：成功 %d 条，失败 %d 条", okCnt, failCnt)), 303)
}

// ---- logs ----

func (s *Server) pageLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	accountID, _ := strconv.ParseInt(q.Get("account"), 10, 64)
	status := q.Get("status")
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	const per = 50
	runs, total, err := s.db.ListAllRuns(r.Context(), accountID, status, per, (page-1)*per)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if q.Get("format") == "jsonl" {
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=watchdog-runs.jsonl")
		enc := json.NewEncoder(w)
		for _, g := range runs {
			g.Email = maskForTpl(g.Email) // 导出同样遵守脱敏纪律
			_ = enc.Encode(g)
		}
		return
	}
	accs, _ := s.db.ListAccounts(r.Context(), false)
	s.render(w, r, "logs", map[string]any{
		"Runs": runs, "Accounts": accs, "Total": total, "Page": page,
		"Pages": (total + per - 1) / per, "Account": accountID, "Status": status,
	})
}

// ---- alerts ----

func (s *Server) pageAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	alerts, _ := s.db.ListAlerts(r.Context(), limit)
	s.render(w, r, "alerts", map[string]any{"Alerts": alerts})
}

// ---- settings / channels ----

func (s *Server) pageSettings(w http.ResponseWriter, r *http.Request) {
	iv, jt, th := s.sc.Params(r.Context())
	cid, _ := s.db.GetSetting(r.Context(), "app.client_id")
	last, next := s.sc.RoundInfo()
	fmtT := func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format("2006-01-02 15:04:05Z")
	}
	s.render(w, r, "settings", map[string]any{
		"IntervalMin": iv, "Jitter": jt, "Threshold": th,
		"ClientID":  cid,
		"Uptime":    time.Since(s.started).Round(time.Second).String(),
		"LastRound": fmtT(last), "NextRound": fmtT(next),
	})
}

func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	if !s.csrfCheck(r) {
		http.Error(w, "CSRF", 403)
		return
	}
	for _, kv := range [][2]string{
		{"schedule.interval_min", r.FormValue("interval_min")},
		{"schedule.jitter", r.FormValue("jitter")},
		{"schedule.fail_threshold", r.FormValue("fail_threshold")},
		{"app.client_id", r.FormValue("client_id")},
	} {
		if kv[1] != "" {
			_ = s.db.SetSetting(r.Context(), kv[0], kv[1])
		}
	}
	http.Redirect(w, r, "/settings?flash="+urlq("已保存"), 303)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !s.csrfCheck(r) {
		http.Error(w, "CSRF", 403)
		return
	}
	old, pw, pw2 := r.FormValue("old"), r.FormValue("password"), r.FormValue("password2")
	hash, _ := s.db.GetSetting(r.Context(), "admin.password_hash")
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(old)) != nil || len(pw) < 10 || pw != pw2 {
		http.Redirect(w, r, "/settings?flash="+urlq("旧密码错误或新密码不合规（≥10位且两次一致）"), 303)
		return
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	_ = s.db.SetSetting(r.Context(), "admin.password_hash", string(h))
	http.Redirect(w, r, "/settings?flash="+urlq("密码已更新"), 303)
}

func (s *Server) pageChannels(w http.ResponseWriter, r *http.Request) {
	chs, _ := s.db.ListChannels(r.Context(), false)
	s.render(w, r, "channels", map[string]any{"Channels": chs})
}

func (s *Server) handleAddChannel(w http.ResponseWriter, r *http.Request) {
	if !s.csrfCheck(r) {
		http.Error(w, "CSRF", 403)
		return
	}
	c := &store.Channel{Type: r.FormValue("type"), Name: r.FormValue("name"), Enabled: true}
	cfg := map[string]string{}
	switch c.Type {
	case "webhook":
		cfg["url"] = r.FormValue("url")
		cfg["token"] = r.FormValue("token")
	case "smtp":
		cfg["host"] = r.FormValue("host")
		cfg["port"] = r.FormValue("port")
		cfg["user"] = r.FormValue("user")
		cfg["pass"] = r.FormValue("pass")
		cfg["to"] = r.FormValue("to")
	default:
		http.Redirect(w, r, "/channels?flash="+urlq("未知类型"), 303)
		return
	}
	c.Config = cfg
	if _, err := s.db.AddChannel(r.Context(), c); err != nil {
		http.Redirect(w, r, "/channels?flash="+urlq("添加失败: "+err.Error()), 303)
		return
	}
	http.Redirect(w, r, "/channels?flash="+urlq("已添加通道"), 303)
}

func (s *Server) handleDeleteChannel(w http.ResponseWriter, r *http.Request) {
	if !s.csrfCheck(r) {
		http.Error(w, "CSRF", 403)
		return
	}
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	_ = s.db.DeleteChannel(r.Context(), id)
	http.Redirect(w, r, "/channels", 303)
}

func (s *Server) handleTestChannel(w http.ResponseWriter, r *http.Request) {
	if !s.csrfCheck(r) {
		http.Error(w, "CSRF", 403)
		return
	}
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	err := sendTest(r.Context(), s.db, id)
	msg := "测试发送成功"
	if err != nil {
		msg = "发送失败: " + err.Error()
	}
	http.Redirect(w, r, "/channels?flash="+urlq(msg), 303)
}

// ---- device flow（网页授权向导；RT 仅服务端持有）----

func (s *Server) handleTokenStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !s.csrfCheck(r) {
		http.Error(w, "bad request", 400)
		return
	}
	cid := s.defaultClientID(r.Context(), r.FormValue("client_id"))
	if cid == "" {
		writeJSON(w, 400, map[string]any{"err": "client_id 必填（或在设置页配置默认）"})
		return
	}
	scope := msauth.GraphScope
	if r.FormValue("scope") == "full" {
		scope = msauth.FullScope
	}
	dc, err := msauth.New().StartDeviceCode(r.Context(), cid, scope)
	if err != nil {
		writeJSON(w, 502, map[string]any{"err": "devicecode: " + err.Error()})
		return
	}
	id := randToken()[:16]
	pf := &pendingFlow{
		ClientID:   cid,
		DeviceCode: dc.DeviceCode,
		ExpiresAt:  time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second),
	}
	s.mu.Lock()
	// 顺手清理过期 pending
	for k, v := range s.pending {
		if time.Now().After(v.ExpiresAt) {
			delete(s.pending, k)
		}
	}
	s.pending[id] = pf
	s.mu.Unlock()
	go func() {
		rt, err := msauth.New().PollDeviceCode(context.Background(), cid, dc.DeviceCode, dc.Interval)
		if err == nil {
			// 授权成功：识别实际绑定的账号（device flow 签给浏览器会话里的
			// 微软账号，可能与用户预期不同），并采用轮换后的 RT。
			g, gerr := msauth.New().RefreshTokenGrant(context.Background(), cid, rt, msauth.GraphScope)
			if gerr == nil && g.OK {
				if g.NewRefreshToken != "" {
					rt = g.NewRefreshToken
				}
				if me, merr := graph.New(g.AccessToken).Me(context.Background()); merr == nil && me.StatusCode == 200 {
					var v struct {
						Mail              string `json:"mail"`
						UserPrincipalName string `json:"userPrincipalName"`
					}
					if json.Unmarshal(me.Body, &v) == nil {
						pf.Email = v.Mail
						if pf.Email == "" {
							pf.Email = v.UserPrincipalName
						}
					}
				}
			}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		pf.Done = true
		if err != nil {
			pf.Err = err.Error()
		} else {
			pf.RT = rt
		}
	}()
	writeJSON(w, 200, map[string]any{
		"id": id, "user_code": dc.UserCode, "url": dc.VerificationURL,
		"expires_in": dc.ExpiresIn,
	})
}

func (s *Server) handleTokenPoll(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	pf := s.pending[r.URL.Query().Get("id")]
	s.mu.Unlock()
	if pf == nil {
		writeJSON(w, 404, map[string]any{"err": "授权会话不存在或已过期"})
		return
	}
	out := map[string]any{"done": pf.Done}
	if pf.Done {
		if pf.Err != "" {
			out["err"] = pf.Err
		} else {
			out["ok"] = true
			out["email"] = pf.Email
		}
	}
	writeJSON(w, 200, out)
}

// ---- helpers ----

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// maskRT 只显示前后各 4 字符，中间省略。
func maskRT(rt string) string {
	if len(rt) <= 12 {
		return "****"
	}
	return rt[:4] + "…" + rt[len(rt)-4:]
}

func maskForTpl(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return "***"
	}
	name := parts[0]
	if len(name) <= 1 {
		return name + "***@" + parts[1]
	}
	return name[:1] + "***@" + parts[1]
}

func badgeForTpl(status string) string {
	switch status {
	case "ok":
		return "badge-ok"
	case "failed", "banned", "token_invalid":
		return "badge-bad"
	case "degraded":
		return "badge-warn"
	default:
		return "badge-dim"
	}
}

var emailRe = regexp.MustCompile(`([\w.+-]{1})[\w.+-]*(@[\w.-]+\.[A-Za-z]{2,})`)

// maskEmailsInText 掩码文本中出现的所有邮箱（保留首字符与完整域名，
// 域名是判断"转发到何处"的关键信息）。
func maskEmailsInText(s string) string {
	return emailRe.ReplaceAllString(s, "${1}***${2}")
}

func seq(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}
