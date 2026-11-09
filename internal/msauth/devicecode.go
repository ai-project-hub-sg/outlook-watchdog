// devicecode.go：OAuth2 device code flow，用于一次性获取初始 refresh_token。
// 用法：程序打印 verification URL + user_code → 用户在浏览器完成登录 → 轮询换 RT。
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
)

// DefaultDeviceCodeClientID 为 Azure CLI 公开 client_id（支持 MSA device code flow）。
const DefaultDeviceCodeClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

const deviceCodeEndpoint = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"

// DeviceCodeChallenge 是 device code 响应。
type DeviceCodeChallenge struct {
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// StartDeviceCode 请求 device code。
func (c *Client) StartDeviceCode(ctx context.Context, clientID, scope string) (*DeviceCodeChallenge, error) {
	form := url.Values{"client_id": {clientID}, "scope": {scope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceCodeEndpoint,
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var dc DeviceCodeChallenge
	if err := json.Unmarshal(body, &dc); err != nil {
		return nil, fmt.Errorf("devicecode response: %w (body: %.120s)", err, body)
	}
	if dc.DeviceCode == "" {
		return nil, fmt.Errorf("devicecode failed: %.200s", body)
	}
	return &dc, nil
}

// PollDeviceCode 按 interval 轮询直到用户完成授权或超时，返回 RT。
func (c *Client) PollDeviceCode(ctx context.Context, clientID, deviceCode string, intervalSec int) (refreshToken string, err error) {
	if intervalSec <= 0 {
		intervalSec = 5
	}
	authority := c.Authority
	if authority == "" {
		authority = DefaultAuthority
	}
	tick := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-tick.C:
		}
		form := url.Values{
			"client_id":   {clientID},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceCode},
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, authority,
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		hc := c.HTTP
		if hc == nil {
			hc = &http.Client{Timeout: 20 * time.Second}
		}
		resp, err := hc.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		var tr struct {
			RefreshToken string `json:"refresh_token"`
			Error        string `json:"error"`
		}
		if json.Unmarshal(body, &tr) != nil {
			continue
		}
		switch {
		case tr.RefreshToken != "":
			return tr.RefreshToken, nil
		case tr.Error == "authorization_pending":
			continue
		case tr.Error == "slow_down":
			intervalSec += 5
			tick.Reset(time.Duration(intervalSec) * time.Second)
			continue
		default:
			return "", fmt.Errorf("devicecode poll: %s", tr.Error)
		}
	}
}
