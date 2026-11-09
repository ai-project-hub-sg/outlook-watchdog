// Package check 编排单账号检查管线：C1 token grant → C2/C3 Graph → C5 规则审计 → 聚合落库。
// 判定一律走 classify；本包只做编排与持久化。
package check

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"outlook-watchdog/internal/classify"
	"outlook-watchdog/internal/graph"
	"outlook-watchdog/internal/msauth"
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
	if a.Checks == nil || a.Checks["rules"] {
		cr := r.checkRules(ctx, a, gc)
		out.Results = append(out.Results, cr)
		_ = r.Store.AddResult(ctx, runPK, &cr)
	}

	return out, nil
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
	if status == classify.StatusFailed || status == classify.StatusUnknown {
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
