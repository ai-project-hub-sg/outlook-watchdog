// Package graph 是 Microsoft Graph v1.0 的最小客户端（/me、messages、messageRules）。
// 只返回原始结果，不做状态判定（判定在 classify）。
package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"outlook-watchdog/internal/classify"
)

const baseURL = "https://graph.microsoft.com/v1.0"

// Client 包装 access_token 调用。
type Client struct {
	HTTP  *http.Client
	Token string
	Base  string // 测试可覆盖，缺省 graph v1.0
}

// New 创建客户端。
func New(token string) *Client {
	return &Client{HTTP: &http.Client{Timeout: 20 * time.Second}, Token: token, Base: baseURL}
}

// CallResult 是一次 Graph 调用的归一化结果。
type CallResult struct {
	StatusCode int
	Body       []byte
}

// get 发起 GET 请求并返回 (status, body)。
func (c *Client) get(ctx context.Context, path string) (*CallResult, error) {
	base := c.Base
	if base == "" {
		base = baseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return &CallResult{StatusCode: resp.StatusCode, Body: body}, nil
}

// Me 调 GET /me —— 探活 + 验证 token 有效。
func (c *Client) Me(ctx context.Context) (*CallResult, error) {
	return c.get(ctx, "/me")
}

// TopMessage 调 GET /me/messages?$top=1&$select=id —— 只验证可读，不取正文。
func (c *Client) TopMessage(ctx context.Context) (*CallResult, error) {
	return c.get(ctx, "/me/messages?%24top=1&%24select=id")
}

// MessageRules 调 GET /me/mailFolders/inbox/messageRules，返回原始规则列表。
func (c *Client) MessageRules(ctx context.Context) ([]classify.MessageRule, int, error) {
	res, err := c.get(ctx, "/me/mailFolders/inbox/messageRules")
	if err != nil {
		return nil, 0, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, res.StatusCode, nil
	}
	var payload struct {
		Value []classify.MessageRule `json:"value"`
	}
	if err := json.Unmarshal(res.Body, &payload); err != nil {
		return nil, res.StatusCode, fmt.Errorf("parse messageRules: %w", err)
	}
	return payload.Value, res.StatusCode, nil
}

// SendMail 调 POST /me/sendMail（可选检查，默认关闭）。
func (c *Client) SendMail(ctx context.Context, to, subject, body string) (*CallResult, error) {
	payload := map[string]any{
		"message": map[string]any{
			"subject": subject,
			"body":    map[string]string{"contentType": "Text", "content": body},
			"toRecipients": []map[string]any{
				{"emailAddress": map[string]string{"address": to}},
			},
		},
		"saveToSentItems": false,
	}
	b, _ := json.Marshal(payload)
	base := c.Base
	if base == "" {
		base = baseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/me/sendMail",
		strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rbody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return &CallResult{StatusCode: resp.StatusCode, Body: rbody}, nil
}
