// Package sched 常驻调度：按 interval+jitter 轮询启用账号，检查并派发迁移告警。
package sched

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"outlook-watchdog/internal/check"
	"outlook-watchdog/internal/notify"
	"outlook-watchdog/internal/store"
)

// Defaults 调度参数默认值（settings 表可覆盖）。
const (
	DefaultIntervalMin   = 15
	DefaultJitter        = 0.2
	DefaultFailThreshold = 2
)

// Scheduler 调度器。
type Scheduler struct {
	DB        *store.DB
	NewRunner func() *check.Runner
	OnRound   func(a *store.Account, status string, err error) // 日志钩子
}

// Params 从 settings 表读取调度参数（带默认值）。
func (s *Scheduler) Params(ctx context.Context) (intervalMin int, jitter float64, threshold int) {
	intervalMin, jitter, threshold = DefaultIntervalMin, DefaultJitter, DefaultFailThreshold
	if v, err := s.DB.GetSetting(ctx, "schedule.interval_min"); err == nil && v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 5 {
			intervalMin = n
		}
	}
	if v, err := s.DB.GetSetting(ctx, "schedule.jitter"); err == nil && v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f < 0.9 {
			jitter = f
		}
	}
	if v, err := s.DB.GetSetting(ctx, "schedule.fail_threshold"); err == nil && v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			threshold = n
		}
	}
	return
}

// RunOnce 对启用账号跑一轮（onlyID!=0 时只查该账号），返回各账号结果。
func (s *Scheduler) RunOnce(ctx context.Context, source string, threshold int, onlyID int64) []*check.Outcome {
	var outs []*check.Outcome
	var accounts []*store.Account
	var err error
	if onlyID != 0 {
		var a *store.Account
		if a, err = s.DB.GetAccount(ctx, strconv.FormatInt(onlyID, 10)); err == nil {
			accounts = []*store.Account{a}
		}
	} else {
		accounts, err = s.DB.ListAccounts(ctx, true)
	}
	if err != nil {
		s.report(nil, "", fmt.Errorf("list accounts: %w", err))
		return outs
	}
	for _, a := range accounts {
		prev, _ := s.DB.GetState(ctx, a.ID)
		prevStatus := "unknown"
		if prev != nil {
			prevStatus = prev.Status
		}
		r := s.NewRunner()
		out, err := r.RunAccount(ctx, a, source)
		if err != nil {
			out = &check.Outcome{AccountID: a.ID, Status: "unknown", Err: err}
			s.report(a, "", fmt.Errorf("run: %w", err))
		} else {
			s.report(a, out.Status, nil)
		}
		reason := summarizeReason(out)
		if derr := notify.Dispatch(ctx, s.DB, a, prevStatus, out.Status, reason, threshold); derr != nil {
			s.report(a, out.Status, fmt.Errorf("alert dispatch: %w", derr))
		}
		outs = append(outs, out)
	}
	return outs
}

// Loop 常驻循环：每轮间隔 interval ± jitter；ctx 取消即退。
func (s *Scheduler) Loop(ctx context.Context) {
	intervalMin, jitter, threshold := s.Params(ctx)
	base := time.Duration(intervalMin) * time.Minute
	s.report(nil, "", fmt.Errorf("scheduler start: interval=%v jitter=%.2f threshold=%d", base, jitter, threshold))
	for {
		s.RunOnce(ctx, "sched", threshold, 0)
		wait := base + time.Duration((rand.Float64()*2-1)*jitter*float64(base))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (s *Scheduler) report(a *store.Account, status string, err error) {
	if s.OnRound != nil {
		s.OnRound(a, status, err)
	}
}

// summarizeReason 提取告警用的简短原因（取第一个非 pass 的检查）。
func summarizeReason(out *check.Outcome) string {
	for _, r := range out.Results {
		if r.Result != "pass" {
			return fmt.Sprintf("%s %s: %s", r.Check, r.Classification, r.Detail)
		}
	}
	return out.Status
}
