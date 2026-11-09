// Package sched 常驻调度：按 interval+jitter 轮询启用账号，检查并派发迁移告警。
package sched

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"outlook-watchdog/internal/check"
	"outlook-watchdog/internal/notify"
	"outlook-watchdog/internal/store"
)

// Defaults 调度参数默认值（settings 表可覆盖）。
const (
	DefaultIntervalMin   = 60
	DefaultJitter        = 0.2
	DefaultFailThreshold = 2
)

// Scheduler 调度器。
type Scheduler struct {
	DB        *store.DB
	NewRunner func() *check.Runner
	OnRound   func(a *store.Account, status string, err error) // 日志钩子

	mu        sync.Mutex
	lastRound time.Time // 上次轮次完成时间（零值=未跑过）
	nextRound time.Time // 下轮计划时间（零值=Loop 未启动）
	lastSlot  map[int64]time.Time // 每账号上次运行的周期槽起点（防同槽重跑）
}

// RoundInfo 返回调度器运行态（WebUI 状态页用）。
func (s *Scheduler) RoundInfo() (last, next time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRound, s.nextRound
}

func (s *Scheduler) setRound(last, next time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !last.IsZero() {
		s.lastRound = last
	}
	s.nextRound = next
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
		outs = append(outs, s.runOne(ctx, a, source, threshold))
	}
	return outs
}

func (s *Scheduler) runOne(ctx context.Context, a *store.Account, source string, threshold int) *check.Outcome {
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
	return out
}

// Loop 常驻循环：每账号按稳定相位错峰运行——周期为 interval，
// 账号 i 在槽起点 + phase_i + 微扰处运行（phase 由邮箱哈希决定，重启不漂移）。
func (s *Scheduler) Loop(ctx context.Context) {
	intervalMin, _, threshold := s.Params(ctx)
	base := time.Duration(intervalMin) * time.Minute
	if s.lastSlot == nil {
		s.lastSlot = map[int64]time.Time{}
	}
	s.report(nil, "", fmt.Errorf("scheduler start: interval=%v phased-per-account threshold=%d", base, threshold))
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		s.runDue(ctx, base, threshold)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// runDue 扫描到期账号并运行；到期时间 = 槽起点 + 账号相位 + 确定性微扰。
func (s *Scheduler) runDue(ctx context.Context, base time.Duration, threshold int) {
	accounts, err := s.DB.ListAccounts(ctx, true)
	if err != nil {
		s.report(nil, "", fmt.Errorf("list accounts: %w", err))
		return
	}
	now := time.Now()
	slot := now.Truncate(base)
	var nextDue time.Time
	for _, a := range accounts {
		phase := check.StableOffset(a.Email, base*85/100)
		micro := check.StableOffset(a.Email+"|micro|"+slot.Format("06010215"), 3*time.Minute)
		due := slot.Add(phase).Add(micro)
		if !now.Before(due) && s.lastSlot[a.ID] != slot {
			s.lastSlot[a.ID] = slot
			s.runOne(ctx, a, "sched", threshold)
			s.setRound(now, time.Time{})
		}
		if next := slot.Add(base).Add(phase).Add(micro); nextDue.IsZero() || next.Before(nextDue) {
			nextDue = next
		}
	}
	s.setRound(time.Time{}, nextDue)
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
