package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"outlook-watchdog/internal/notify"
	"outlook-watchdog/internal/store"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// urlq 供 flash 消息安全拼进重定向 URL。
func urlq(s string) string { return url.QueryEscape(s) }

// sendTest 向指定通道发一条测试消息。
func sendTest(ctx context.Context, db *store.DB, id int64) error {
	chs, err := db.ListChannels(ctx, false)
	if err != nil {
		return err
	}
	for _, ch := range chs {
		if ch.ID != id {
			continue
		}
		sender, ok := notify.Senders[ch.Type]
		if !ok {
			return errText("未知通道类型 " + ch.Type)
		}
		return sender.Send(ctx, ch.Config, &notify.Message{
			Subject: "[watchdog·测试] WebUI 通道验证",
			Body:    "WebUI 触发的测试消息。\n时间: " + time.Now().UTC().Format(time.RFC3339),
			At:      time.Now().UTC().Format(time.RFC3339),
		})
	}
	return errText("通道不存在")
}

type errText string

func (e errText) Error() string { return string(e) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
