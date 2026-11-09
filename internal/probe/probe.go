// Package probe 实现 IMAP/SMTP XOAUTH2 认证探测（C6/C7）。
// 只验证认证握手，不读邮件、不发信。scope 不足直接报 unavailable。
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// TokenHasScope 解析 JWT access token 的 scp 声明，判断是否含目标 scope。
// Graph token 的 scp 形如 "Mail.Read User.Read ..."。
func TokenHasScope(accessToken, want string) bool {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Scp   string `json:"scp"`
		Roles string `json:"roles"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return false
	}
	for _, s := range strings.Fields(claims.Scp + " " + claims.Roles) {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// xoauth2Line 构造 XOAUTH2 初始响应。
func xoauth2Line(user, token string) string {
	return base64.StdEncoding.EncodeToString(
		[]byte("user=" + user + "\x01auth=Bearer " + token + "\x01\x01"))
}

// IMAP 对 outlook.office365.com:993 做 XOAUTH2 登录后立即 LOGOUT。
// 返回 nil 表示认证通过。
func IMAP(ctx context.Context, host, user, token string) error {
	d := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", host+":993", &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	if _, err := rw.ReadString('\n'); err != nil { // 服务问候
		return err
	}
	// AUTHENTICATE XOAUTH2：先发命令等 "+ "，再发凭据行。
	if _, err := fmt.Fprintf(rw, "a1 AUTHENTICATE XOAUTH2 %s\r\n", xoauth2Line(user, token)); err != nil {
		return err
	}
	if err := rw.Flush(); err != nil {
		return err
	}
	// 响应可能是 "+ <challenge>"（需回空行）或直接 OK/NO。
	for i := 0; i < 4; i++ {
		line, err := rw.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "+") {
			fmt.Fprintf(rw, "\r\n")
			_ = rw.Flush()
			continue
		}
		if strings.HasPrefix(line, "a1 OK") {
			fmt.Fprintf(rw, "a2 LOGOUT\r\n")
			_ = rw.Flush()
			return nil
		}
		return fmt.Errorf("imap auth rejected: %s", line)
	}
	return fmt.Errorf("imap auth: unexpected responses")
}

// smtpXoauth2 实现 net/smtp 的 Auth 接口（XOAUTH2）。
type smtpXoauth2 struct{ user, token string }

func (a *smtpXoauth2) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	resp := "user=" + a.user + "\x01auth=Bearer " + a.token + "\x01\x01"
	return "XOAUTH2", []byte(resp), nil
}
func (a *smtpXoauth2) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return []byte{}, nil
	}
	return nil, nil
}

// SMTP 对 smtp.office365.com:587 做 STARTTLS + XOAUTH2 AUTH（不发信）。
func SMTP(ctx context.Context, host, user, token string) error {
	d := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", host+":587")
	if err != nil {
		return err
	}
	defer conn.Close()
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello("watchdog.local"); err != nil {
		return err
	}
	if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
		return err
	}
	return c.Auth(&smtpXoauth2{user: user, token: token})
}
