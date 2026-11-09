// Package check 编排单账号检查管线：C1 token grant → C2/C3 Graph → C5 规则审计 → 聚合落库。
// 判定一律走 classify；本包只做编排与持久化。
package check

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"hash/fnv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"outlook-watchdog/internal/classify"
	"outlook-watchdog/internal/graph"
	"outlook-watchdog/internal/msauth"
	"outlook-watchdog/internal/probe"
	"outlook-watchdog/internal/store"
)

// Runner 执行检查管线。
type Runner struct {
	Store     *store.DB
	Auth      *msauth.Client
	GraphBase string // 测试注入；空=默认 Graph v1.0
	Scope     string // 空=msauth.GraphScope
	Now       func() string

	lastGrant *msauth.GrantResult // 本轮 grant 结果（C1 pass 后供 graph 使用）
}

// Outcome 是一轮单账号检查的结果。
type Outcome struct {
	AccountID int64
	Status    string
	Results   []store.CheckResult
	Err       error // 编排层错误（非账号判定）
}

// NewRunner 构造默认 Runner。
func NewRunner(db *store.DB) *Runner {
	return &Runner{Store: db, Auth: msauth.New(), Scope: msauth.GraphScope, Now: store.NowUTC}
}

func (r *Runner) newRunID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

// RunAccount 对单个账号执行一轮检查并落库；返回账号级状态。
func (r *Runner) RunAccount(ctx context.Context, a *store.Account, trigger string) (*Outcome, error) {
	runID := r.newRunID()
	runPK, err := r.Store.StartRun(ctx, a.ID, runID, trigger)
	if err != nil {
		return nil, err
	}
	out := &Outcome{AccountID: a.ID}
	defer func() {
		out.Status = classify.Aggregate(toOutcomes(out.Results))
		_ = r.Store.FinishRun(ctx, runPK, out.Status)
		_ = r.updateState(ctx, a.ID, out.Status)
	}()

	// ---- C1: token grant ----
	c1 := r.checkToken(ctx, a)
	out.Results = append(out.Results, c1)
	_ = r.Store.AddResult(ctx, runPK, &c1)
	if c1.Result != "pass" {
		return out, nil // token 挂了 → 后续检查无从谈起
	}

	// ---- 组装 graph client ----
	gc := graph.New(r.lastGrant.AccessToken)
	gc.Base = r.GraphBase

	// ---- C2: /me ----
	out.Results = append(out.Results, r.simpleGraphCheck(ctx, "c2_me", gc.Me))
	// ---- C3: messages top1 ----
	out.Results = append(out.Results, r.simpleGraphCheck(ctx, "c3_recv", gc.TopMessage))
	for i := len(out.Results) - 2; i < len(out.Results); i++ {
		_ = r.Store.AddResult(ctx, runPK, &out.Results[i])
	}

	// ---- C5: rules 审计（默认开） ----
	if a.Checks == nil || a.Checks["c5_rules"] || a.Checks["rules"] {
		cr := r.checkRules(ctx, a, gc)
		out.Results = append(out.Results, cr)
		_ = r.Store.AddResult(ctx, runPK, &cr)
	}

	// 核心四件套健康度：任一非 pass 视为异常，真发信检查升到 ~3 次/天
	coreOK := true
	for _, cr := range out.Results {
		if coreCheckNames[cr.Check] && cr.Result != "pass" {
			coreOK = false
			break
		}
	}

	// ---- C4: 发信能力（默认关；真实发信到自己；自适应限频） ----
	if a.Checks["c4_send"] && r.dueRealMail(ctx, a, "c4_send", coreOK) {
		cr := r.checkSend(ctx, a, gc)
		out.Results = append(out.Results, cr)
		_ = r.Store.AddResult(ctx, runPK, &cr)
	}

	// ---- C6/C7: 协议探测（默认关；scope 不足→unavailable） ----
	if a.Checks["c6_imap"] {
		cr := r.checkProto(ctx, a, "c6_imap", "https://outlook.office.com/IMAP.AccessAsUser.All", "outlook.office365.com", probe.IMAP)
		out.Results = append(out.Results, cr)
		_ = r.Store.AddResult(ctx, runPK, &cr)
	}
	if a.Checks["c7_smtp"] {
		cr := r.checkProto(ctx, a, "c7_smtp", "https://outlook.office.com/SMTP.Send", "smtp.office365.com", probe.SMTP)
		out.Results = append(out.Results, cr)
		_ = r.Store.AddResult(ctx, runPK, &cr)
	}

	// ---- C8: roundtrip（默认关；自适应限频，未到跳过） ----
	if a.Checks["c8_roundtrip"] && r.dueRealMail(ctx, a, "c8_roundtrip", coreOK) {
		cr := r.checkRoundtrip(ctx, a, gc)
		out.Results = append(out.Results, cr)
		_ = r.Store.AddResult(ctx, runPK, &cr)
	}

	return out, nil
}

// coreCheckNames 核心四件套：token/me/收件/规则审计。
var coreCheckNames = map[string]bool{
	"c1_token": true, "c2_me": true, "c3_recv": true, "c5_rules": true, "rules": true,
}

// StableOffset 由 key 生成确定性偏移（FNV-1a），用于每账号错峰。
func StableOffset(key string, mod time.Duration) time.Duration {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return time.Duration(h.Sum64() % uint64(mod))
}

// realMailGap 真实发信类检查（c4/c8）的最小间隔：核心健康→约 1 次/天；
// 核心异常→约 3 次/天便于排查。账号级稳定抖动使各账号节奏错开。
func realMailGap(a *store.Account, coreOK bool) time.Duration {
	if coreOK {
		return 24*time.Hour - StableOffset(a.Email+"|r24", 2*time.Hour)
	}
	return 8*time.Hour - StableOffset(a.Email+"|r8", time.Hour)
}

// dueRealMail 判断真实发信检查是否到点（未到点则本轮跳过，不影响其他检查）。
func (r *Runner) dueRealMail(ctx context.Context, a *store.Account, checkName string, coreOK bool) bool {
	last, _ := r.Store.LastCheckTime(ctx, a.ID, checkName)
	if last == "" {
		return true
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", last)
	if err != nil {
		return true
	}
	return time.Since(t) >= realMailGap(a, coreOK)
}

// checkSend 用 Graph sendMail 给自己发一封，仅验证发信能力。
func (r *Runner) checkSend(ctx context.Context, a *store.Account, gc *graph.Client) store.CheckResult {
	start := time.Now()
	res := store.CheckResult{Check: "c4_send"}
	cr, err := gc.SendMail(ctx, a.Email, "[watchdog-probe] send capability "+store.NowUTC(), "send capability probe")
	res.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		c := classify.ClassifyNetworkError(err)
		res.Result, res.Classification, res.Detail = "error", string(c.Classification), c.Detail
		return res
	}
	res.Result, res.Classification, res.Detail = classifyGraphStatus(cr.StatusCode, cr.Body)
	return res
}

// checkProto 协议探测通用骨架：RT 按需兑换协议资源 AT（子集赎回）；
// 兑换失败（未同意该 scope）→ unavailable（status-codes §3）。
func (r *Runner) checkProto(ctx context.Context, a *store.Account, name, scope, host string,
	fn func(context.Context, string, string, string) error) store.CheckResult {
	start := time.Now()
	res := store.CheckResult{Check: name}
	g, err := r.Auth.RefreshTokenGrant(ctx, a.ClientID, a.RefreshToken, scope+" offline_access")
	if err != nil {
		c := classify.ClassifyNetworkError(err)
		res.Result, res.Classification, res.Detail = "error", string(c.Classification), c.Detail
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}
	if !g.OK {
		res.Result, res.Classification, res.Detail = "unavailable", "scope_missing",
			scope+" 未同意（重新授权选「完整」可覆盖）"
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}
	if g.NewRefreshToken != "" {
		_ = r.Store.UpdateRefreshToken(ctx, a.ID, g.NewRefreshToken)
	}
	if err := fn(ctx, host, a.Email, g.AccessToken); err != nil {
		if strings.Contains(err.Error(), "SmtpClientAuthentication is disabled") {
			res.Result, res.Classification, res.Detail = "unavailable", "smtp_disabled",
				"SMTP AUTH 对该邮箱被禁用（个人邮箱无开关，可关闭本检查项）"
		} else {
			res.Result, res.Classification, res.Detail = "fail", "auth_failed", truncateStr(err.Error(), 120)
		}
	} else {
		res.Result, res.Classification, res.Detail = "pass", "ok", "xoauth2 ok"
	}
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

// checkRoundtrip 端到端：发唯一标记信给自己 → 轮询收件箱命中 → 删除探信。
func (r *Runner) checkRoundtrip(ctx context.Context, a *store.Account, gc *graph.Client) store.CheckResult {
	start := time.Now()
	res := store.CheckResult{Check: "c8_roundtrip"}
	marker := fmt.Sprintf("[wd-probe] %d", time.Now().UnixNano())
	cr, err := gc.SendMail(ctx, a.Email, marker, "watchdog roundtrip probe")
	if err != nil {
		c := classify.ClassifyNetworkError(err)
		res.Result, res.Classification, res.Detail = "error", string(c.Classification), c.Detail
		return res
	}
	if cr.StatusCode < 200 || cr.StatusCode >= 300 {
		res.Result, res.Classification, res.Detail = classifyGraphStatus(cr.StatusCode, cr.Body)
		res.Detail = "sendMail: " + res.Detail
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			res.Result, res.Classification, res.Detail = "error", "network", "ctx canceled"
			res.DurationMS = time.Since(start).Milliseconds()
			return res
		case <-time.After(10 * time.Second):
		}
		msgs, status, err := gc.RecentInbox(ctx, 10)
		if err != nil || status != 200 {
			continue
		}
		for _, m := range msgs {
			if strings.Contains(m.Subject, marker) {
				lat := time.Since(start).Milliseconds()
				_, _ = gc.DeleteMessage(ctx, m.ID) // 清理探信，失败不计较
				res.Result, res.Classification, res.Detail = "pass", "ok",
					fmt.Sprintf("roundtrip ok latency=%dms", lat)
				res.DurationMS = lat
				return res
			}
		}
	}
	res.Result, res.Classification, res.Detail = "fail", "roundtrip_timeout", "90s 内未收到探信"
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

// checkToken 执行 C1。
func (r *Runner) checkToken(ctx context.Context, a *store.Account) store.CheckResult {
	start := time.Now()
	scope := r.Scope
	if scope == "" {
		scope = msauth.GraphScope
	}
	gres, err := r.Auth.RefreshTokenGrant(ctx, a.ClientID, a.RefreshToken, scope)
	res := store.CheckResult{Check: "c1_token", DurationMS: time.Since(start).Milliseconds()}
	if err != nil {
		c := classify.ClassifyNetworkError(err)
		res.Result, res.Classification, res.Detail = "error", string(c.Classification), c.Detail
		return res
	}
	r.lastGrant = gres
	if gres.OK {
		res.Result, res.Classification, res.Detail = "pass", string(classify.ClassOK), gres.Detail
		if gres.NewRefreshToken != "" && gres.NewRefreshToken != a.RefreshToken {
			if err := r.Store.UpdateRefreshToken(ctx, a.ID, gres.NewRefreshToken); err != nil {
				res.Detail += " (rt persist failed: " + err.Error() + ")"
			} else {
				a.RefreshToken = gres.NewRefreshToken
			}
		}
		return res
	}
	result := "fail"
	if gres.Classification == classify.ClassNetwork || gres.Classification == classify.ClassThrottled || gres.Classification == classify.ClassUnknownError {
		result = "error"
	}
	res.Result, res.Classification, res.Detail = result, string(gres.Classification), gres.Detail
	return res
}

// simpleGraphCheck 把一次 Graph 调用归一化为 CheckResult。
func (r *Runner) simpleGraphCheck(ctx context.Context, name string, call func(context.Context) (*graph.CallResult, error)) store.CheckResult {
	start := time.Now()
	res := store.CheckResult{Check: name, DurationMS: 0}
	cr, err := call(ctx)
	res.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		c := classify.ClassifyNetworkError(err)
		res.Result, res.Classification, res.Detail = "error", string(c.Classification), c.Detail
		return res
	}
	res.Result, res.Classification, res.Detail = classifyGraphStatus(cr.StatusCode, cr.Body)
	return res
}

// checkRules 执行 C5 规则审计。
func (r *Runner) checkRules(ctx context.Context, a *store.Account, gc *graph.Client) store.CheckResult {
	start := time.Now()
	res := store.CheckResult{Check: "c5_rules"}
	rules, status, err := gc.MessageRules(ctx)
	res.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		c := classify.ClassifyNetworkError(err)
		res.Result, res.Classification, res.Detail = "error", string(c.Classification), c.Detail
		return res
	}
	if status != http.StatusOK {
		res.Result, res.Classification, res.Detail = classifyGraphStatus(status, nil)
		return res
	}

	cur := classify.NormalizeRules(rules)
	baseJSON, _, err := r.Store.GetRuleSnapshot(ctx, a.ID)
	if err != nil {
		res.Result, res.Classification, res.Detail = "error", "db", err.Error()
		return res
	}
	if baseJSON == "" {
		res.Result, res.Classification, res.Detail = "unavailable", "baseline_missing",
			"rules baseline not set (run: watchdog snapshot)"
		return res
	}
	var base []classify.NormRule
	if err := json.Unmarshal([]byte(baseJSON), &base); err != nil {
		res.Result, res.Classification, res.Detail = "error", "baseline_corrupt", err.Error()
		return res
	}
	diff := classify.DiffRules(base, cur)
	switch diff.Verdict {
	case "pass":
		res.Result, res.Classification, res.Detail = "pass", "rules_ok", fmt.Sprintf("%d rules unchanged", len(cur))
	case "degraded":
		res.Result, res.Classification, res.Detail = "fail", "rules_changed",
			truncateStr(joinSemi(diff.Notes), 200)
	case "fail":
		res.Result, res.Classification, res.Detail = "fail", "rules_suspicious",
			truncateStr(joinSemi(append(diff.FailReasons, diff.Notes...)), 200)
	}
	return res
}

// SnapshotBaseline 建立/重置某账号的 rules 基线（CLI snapshot 用）。
func (r *Runner) SnapshotBaseline(ctx context.Context, a *store.Account) (sha string, err error) {
	scope := r.Scope
	if scope == "" {
		scope = msauth.GraphScope
	}
	gres, err := r.Auth.RefreshTokenGrant(ctx, a.ClientID, a.RefreshToken, scope)
	if err != nil {
		return "", err
	}
	if !gres.OK {
		return "", fmt.Errorf("token grant failed: %s", gres.Detail)
	}
	if gres.NewRefreshToken != "" {
		_ = r.Store.UpdateRefreshToken(ctx, a.ID, gres.NewRefreshToken)
	}
	gc := graph.New(gres.AccessToken)
	gc.Base = r.GraphBase
	rules, status, err := gc.MessageRules(ctx)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("messageRules http %d", status)
	}
	canonical, sha, err := classify.SnapshotHash(classify.NormalizeRules(rules))
	if err != nil {
		return "", err
	}
	return sha, r.Store.SaveRuleSnapshot(ctx, a.ID, canonical, sha)
}

// updateState 更新账号级状态与连续失败计数。
func (r *Runner) updateState(ctx context.Context, accountID int64, status string) error {
	s, err := r.Store.GetState(ctx, accountID)
	if err != nil {
		return err
	}
	if status == classify.StatusFailed || status == classify.StatusUnknown || status == classify.StatusDegraded {
		s.ConsecutiveFail++
	} else {
		s.ConsecutiveFail = 0
	}
	s.Status = status
	s.LastCheckAt = r.Now()
	return r.Store.SetState(ctx, s)
}

// classifyGraphStatus Graph HTTP 状态 → result/classification/detail。
func classifyGraphStatus(status int, body []byte) (result, cls, detail string) {
	code := graphErrorCode(body)
	switch {
	case status >= 200 && status < 300:
		return "pass", "ok", fmt.Sprintf("http %d", status)
	case status == 401:
		return "fail", "graph_unauthorized", fmt.Sprintf("401 %s", code)
	case status == 403:
		return "unavailable", "capability_unavailable", fmt.Sprintf("403 %s", code)
	case status == 404 || status == 410:
		return "fail", "mailbox_gone", fmt.Sprintf("%d %s", status, code)
	case status == 429 || status >= 500:
		return "error", "throttled_or_server", fmt.Sprintf("%d %s", status, code)
	default:
		return "error", "unknown_error", fmt.Sprintf("%d %s", status, code)
	}
}

func graphErrorCode(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Code != "" {
		return truncateStr(e.Error.Code+": "+e.Error.Message, 120)
	}
	return ""
}

func toOutcomes(rs []store.CheckResult) []classify.CheckOutcome {
	out := make([]classify.CheckOutcome, len(rs))
	for i, r := range rs {
		out[i] = classify.CheckOutcome{Check: r.Check, Result: r.Result,
			Classification: classify.Classification(r.Classification)}
	}
	return out
}

func joinSemi(ss []string) string {
	s := ""
	for i, x := range ss {
		if i > 0 {
			s += "; "
		}
		s += x
	}
	return s
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
