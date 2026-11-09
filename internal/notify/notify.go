// Package notify 实现告警发送（webhook / 独立 SMTP）与状态迁移告警判定。
// 告警通道必须独立于被监控账号（AGENTS.md §4.4）。
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"time"
)

// Message 告警消息。
type Message struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Account string `json:"account,omitempty"`
	From    string `json:"from_status,omitempty"`
	To      string `json:"to_status,omitempty"`
	At      string `json:"at"`
}

// Sender 按通道 config 发送。
type Sender interface {
	Send(ctx context.Context, cfg map[string]string, msg *Message) error
}

// Senders 注册的通道实现。
var Senders = map[string]Sender{
	"webhook": &Webhook{},
	"smtp":    &SMTP{},
}

// ---- webhook ----

// Webhook POST JSON 到 url（兼容 ntfy/Bark/Server酱/自定义网关）。
type Webhook struct{ HTTP *http.Client }

func (w *Webhook) Send(ctx context.Context, cfg map[string]string, msg *Message) error {
	url := cfg["url"]
	if url == "" {
		return fmt.Errorf("webhook: missing url")
	}
	b, _ := json.Marshal(msg)
	hc := w.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if t := cfg["token"]; t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook http %d", resp.StatusCode)
	}
	return nil
}

// ---- smtp ----

// SMTP 用独立发信账号发告警邮件。config: host, port, user, pass, to, [from_name]
type SMTP struct {
	DialTLS func(addr string) (net.Conn, error) // 可注入（测试）
}

func (s *SMTP) Send(ctx context.Context, cfg map[string]string, msg *Message) error {
	host, port, user, pass, to := cfg["host"], cfg["port"], cfg["user"], cfg["pass"], cfg["to"]
	if host == "" || user == "" || to == "" {
		return fmt.Errorf("smtp: missing host/user/to")
	}
	if port == "" {
		port = "465"
	}
	addr := net.JoinHostPort(host, port)

	var client *smtp.Client
	var err error
	if port == "465" { // 隐式 TLS（163/QQ 常用）
		dial := s.DialTLS
		if dial == nil {
			dial = func(a string) (net.Conn, error) {
				return tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", a,
					&tls.Config{ServerName: host})
			}
		}
		conn, err := dial(addr)
		if err != nil {
			return fmt.Errorf("smtp dial tls: %w", err)
		}
		client, err = smtp.NewClient(conn, host)
		if err != nil {
			return fmt.Errorf("smtp client: %w", err)
		}
	} else {
		client, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("smtp dial: %w", err)
		}
		defer client.Close()
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: host}); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
		}
	}
	defer client.Quit()

	if pass != "" {
		if err := client.Auth(smtp.PlainAuth("", user, pass, host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(user); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	from := cfg["from_name"]
	if from == "" {
		from = "outlook-watchdog"
	}
	fmt.Fprintf(wc, "From: %s <%s>\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		from, user, to, mimeQ(msg.Subject), msg.Body)
	return wc.Close()
}

// mimeQ 用 Q-encoding 编 non-ASCII 主题，避免裸 UTF-8 被部分 MTA 拒收。
func mimeQ(s string) string {
	need := false
	for _, r := range s {
		if r > 127 {
			need = true
			break
		}
	}
	if !need {
		return s
	}
	return "=?UTF-8?Q?" + qEncode(s) + "?="
}

func qEncode(s string) string {
	var b bytes.Buffer
	for _, c := range []byte(s) {
		if c >= 33 && c <= 126 && c != '=' && c != '?' && c != '_' {
			b.WriteByte(c)
		} else if c == ' ' {
			b.WriteByte('_')
		} else {
			fmt.Fprintf(&b, "=%02X", c)
		}
	}
	return b.String()
}
