// Package msauth 实现 OAuth2 refresh_token grant（consumers 租户）与 RT 轮换。
// 仅标准库：grant 就是一次 form POST（AGENTS.md §4.5）。
package msauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"outlook-watchdog/internal/classify"
)

// DefaultAuthority 消费者账号 token 端点。
const DefaultAuthority = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"

// GraphScope 常规检查所需的最小 scope 集合。
const GraphScope = "https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/MailboxSettings.Read offline_access"

// Client 是可注入 http.Client 的 grant 客户端。
type Client struct {
	HTTP      *http.Client
	Authority string // 缺省 DefaultAuthority
}

// GrantResult 是一次 grant 的结果。
type GrantResult struct {
	OK              bool
	AccessToken     string
	NewRefreshToken string // 微软轮换后的新 RT；为空表示响应未返回
	ExpiresIn       int
	Classification  classify.Classification
	Detail          string
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes"`
}

// New 返回使用默认 http.Client 的 grant 客户端。
func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 20 * time.Second}, Authority: DefaultAuthority}
}

// RefreshTokenGrant 用 RT 换 AT；errCode/errDesc 走分类器，网络错误返回 err。
func (c *Client) RefreshTokenGrant(ctx context.Context, clientID, refreshToken, scope string) (*GrantResult, error) {
	authority := c.Authority
	if authority == "" {
		authority = DefaultAuthority
	}
	form := url.Values{
		"client_id":     {clientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	if scope != "" {
		form.Set("scope", scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authority,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return &GrantResult{
			Classification: classify.ClassUnknownError,
			Detail:         fmt.Sprintf("unparseable response (%d)", resp.StatusCode),
		}, nil
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 && tr.AccessToken != "" {
		return &GrantResult{
			OK:              true,
			AccessToken:     tr.AccessToken,
			NewRefreshToken: tr.RefreshToken,
			ExpiresIn:       tr.ExpiresIn,
			Classification:  classify.ClassOK,
			Detail:          "token grant ok",
		}, nil
	}

	r := classify.ClassifyTokenGrant(resp.StatusCode, tr.Error, tr.ErrorDescription)
	return &GrantResult{Classification: r.Classification, Detail: r.Detail}, nil
}
