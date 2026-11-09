// alert.go：状态迁移告警判定（status-codes.md §5）与通道分发。
package notify

import (
	"context"
	"fmt"
	"time"

	"outlook-watchdog/internal/classify"
	"outlook-watchdog/internal/store"
)

func isBadStatus(s string) bool {
	return s == classify.StatusFailed || s == classify.StatusDegraded || s == classify.StatusUnknown
}

// DecideAlert 纯函数：给定迁移前后状态、连续失败数与阈值，决定是否告警。
// 返回 "alert" | "recovery" | ""。
func DecideAlert(lastAlertStatus, newStatus string, consecutiveFail, threshold int) string {
	if !isBadStatus(newStatus) {
		if isBadStatus(lastAlertStatus) {
			return "recovery" // 从已告警的坏状态恢复
		}
		return ""
	}
	if consecutiveFail >= threshold && newStatus != lastAlertStatus {
		return "alert" // 新坏状态且已过确认阈值（同状态不重复告警）
	}
	return ""
}

// Dispatch 评估并按需发送告警/恢复通知；记录 alert_events 与 last_alert_status。
// prevStatus 由调用方在跑检查前取自 GetState（RunAccount 会覆盖它）。
func Dispatch(ctx context.Context, db *store.DB, a *store.Account, prevStatus, newStatus, reason string, threshold int) error {
	s, err := db.GetState(ctx, a.ID)
	if err != nil {
		return err
	}
	kind := DecideAlert(s.LastAlertStatus, newStatus, s.ConsecutiveFail, threshold)
	if kind == "" {
		return nil
	}

	channels, err := db.ListChannels(ctx, true)
	if err != nil {
		return err
	}

	msg := buildMessage(a, prevStatus, newStatus, reason, kind)
	var firstErr error
	if len(channels) == 0 {
		_ = db.RecordAlert(ctx, a.ID, prevStatus, newStatus, kind+": "+reason, "(none)", "no enabled channel")
	} else {
		for _, ch := range channels {
			sender, ok := Senders[ch.Type]
			var sendErr string
			if !ok {
				sendErr = "unknown channel type"
			} else if err := sender.Send(ctx, ch.Config, msg); err != nil {
				sendErr = err.Error()
				if firstErr == nil {
					firstErr = err
				}
			}
			_ = db.RecordAlert(ctx, a.ID, prevStatus, newStatus, kind+": "+reason, ch.Type+":"+ch.Name, sendErr)
		}
	}
	return db.MarkAlerted(ctx, a.ID, newStatus)
}

// buildMessage 组装告警/恢复消息（邮箱脱敏）。
func buildMessage(a *store.Account, from, to, reason, kind string) *Message {
	who := MaskEmail(a.Email)
	var subject string
	if kind == "recovery" {
		subject = fmt.Sprintf("[watchdog·恢复] %s %s→ok", who, from)
	} else {
		subject = fmt.Sprintf("[watchdog·异常] %s %s→%s", who, from, to)
	}
	return &Message{
		Subject: subject,
		Body:    fmt.Sprintf("账号: %s\n状态: %s → %s\n原因: %s\n时间: %s", who, from, to, reason, time.Now().UTC().Format(time.RFC3339)),
		Account: who, From: from, To: to,
		At: time.Now().UTC().Format(time.RFC3339),
	}
}

// MaskEmail 与 CLI 同款脱敏（本包自包含实现）。
func MaskEmail(e string) string {
	i := 0
	for ; i < len(e); i++ {
		if e[i] == '@' {
			break
		}
	}
	if i == 0 || i == len(e) {
		return "****"
	}
	local, domain := e[:i], e[i:]
	if len(local) <= 2 {
		return local[:1] + "***" + domain
	}
	return local[:1] + "***" + local[len(local)-1:] + domain
}
