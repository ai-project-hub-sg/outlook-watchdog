package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"outlook-watchdog/internal/store"
)

const testRT = "TEST-REFRESH-TOKEN-SHOULD-NEVER-RENDER-0123456789abcdef"

func newTestServer(t *testing.T) (*Server, *store.DB) {
	t.Helper()
	db, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(db, "test")
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}

// loginSession 设置管理员密码并返回有效 session cookie。
func loginSession(t *testing.T, s *Server, db *store.DB) *http.Cookie {
	t.Helper()
	h, _ := bcrypt.GenerateFromPassword([]byte("test-password-123"), bcrypt.MinCost)
	if err := db.SetSetting(context.Background(), "admin.password_hash", string(h)); err != nil {
		t.Fatal(err)
	}
	tok := randToken()
	if err := db.CreateSession(context.Background(), tok, time.Hour); err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: cookieName, Value: tok}
}

// TestNoSecretRendered：各页面不得渲染完整 RT/密码（AGENTS 脱敏纪律）。
func TestNoSecretRendered(t *testing.T) {
	s, db := newTestServer(t)
	cookie := loginSession(t, s, db)
	ctx := context.Background()
	id, err := db.AddAccount(ctx, &store.Account{
		Email: "victim@outlook.com", ClientID: "cid", RefreshToken: testRT,
		Checks: map[string]bool{"c1_token": true}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.RecordAlert(ctx, id, "ok", "failed", "fwd=attacker@evil.com", "smtp:x", "")
	for _, path := range []string{"/", "/accounts", "/account/1", "/alerts", "/settings", "/channels"} {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s => %d", path, rec.Code)
		}
		body := rec.Body.String()
		if strings.Contains(body, testRT) {
			t.Errorf("%s 泄露了完整 refresh_token", path)
		}
		if strings.Contains(body, "attacker@evil.com") {
			t.Errorf("%s 未掩码告警中的邮箱", path)
		}
	}
}

// TestAuthRequired：未登录访问受保护页面必须跳登录；无管理员时跳 setup。
func TestAuthRequired(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 303 || rec.Header().Get("Location") != "/setup" {
		t.Fatalf("期望跳 /setup，得到 %d %s", rec.Code, rec.Header().Get("Location"))
	}
	// setup/login 页本身必须可渲染（无 Data 注入时不得渲染失败）。
	// 未设管理员：/setup=200 渲染，/login→/setup；设管理员后：/login=200，/setup→/。
	check := func(path string, want int) {
		req = httptest.NewRequest("GET", path, nil)
		rec = httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != want || (want == 200 && strings.Contains(rec.Body.String(), "渲染失败")) {
			t.Fatalf("%s 渲染异常: code=%d want=%d", path, rec.Code, want)
		}
	}
	check("/setup", 200)
	check("/login", 303)
	h, _ := bcrypt.GenerateFromPassword([]byte("x-1234567890"), bcrypt.MinCost)
	_ = s.db.SetSetting(context.Background(), "admin.password_hash", string(h))
	check("/login", 200)
	check("/setup", 303)
}

// TestCSRFFails：缺少 CSRF token 的写请求必须 403。
func TestCSRFFails(t *testing.T) {
	s, db := newTestServer(t)
	cookie := loginSession(t, s, db)
	form := url.Values{"id": {"1"}}
	req := httptest.NewRequest("POST", "/accounts/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("期望 403，得到 %d", rec.Code)
	}
}

// TestRuleOpsGuards：规则写接口未登录跳登录、缺 CSRF 拒绝（不触网）。
func TestRuleOpsGuards(t *testing.T) {
	s, db := newTestServer(t)
	cookie := loginSession(t, s, db)

	req := httptest.NewRequest("GET", "/account/rules?id=1", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 303 {
		t.Fatalf("未登录应跳登录，得到 %d", rec.Code)
	}

	for _, path := range []string{"/account/rule/save", "/account/rule/toggle", "/account/rule/delete"} {
		form := url.Values{"id": {"1"}, "rule_id": {"r1"}}
		req = httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rec = httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code == 200 {
			t.Fatalf("%s 缺 CSRF 不应成功", path)
		}
	}
}

func TestMaskEmailsInText(t *testing.T) {
	got := maskEmailsInText("fwd=attacker@evil.com; 通知 admin@corp.io")
	if strings.Contains(got, "attacker@") || strings.Contains(got, "admin@") {
		t.Errorf("未掩码: %s", got)
	}
	if !strings.Contains(got, "@evil.com") || !strings.Contains(got, "@corp.io") {
		t.Errorf("域名应保留: %s", got)
	}
}
