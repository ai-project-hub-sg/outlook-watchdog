package check

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"outlook-watchdog/internal/classify"
	"outlook-watchdog/internal/store"
)

// fakeMS 起假 token + Graph 端点。
func fakeMS(t *testing.T, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", tokenHandler)
	mux.HandleFunc("/v1.0/me", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"id":"u1","userPrincipalName":"t@outlook.com"}`))
	})
	mux.HandleFunc("/v1.0/me/messages", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"value":[{"id":"m1"}]}`))
	})
	mux.HandleFunc("/v1.0/me/mailFolders/inbox/messageRules", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"value":[]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func tokenOK(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at-1", "refresh_token": "rt-rotated", "expires_in": 3600,
	})
}

func newTestRunner(t *testing.T, srv *httptest.Server) (*Runner, *store.DB) {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	r := NewRunner(db)
	r.Auth.Authority = srv.URL + "/token"
	r.GraphBase = srv.URL + "/v1.0"
	return r, db
}

func addAccount(t *testing.T, db *store.DB) *store.Account {
	id, err := db.AddAccount(context.Background(), &store.Account{
		Email: "t@outlook.com", ClientID: "cid", RefreshToken: "rt-old",
		Checks: map[string]bool{"rules": true}, Enabled: true,
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	a, err := db.GetAccount(context.Background(), "t@outlook.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if a.ID != id {
		t.Fatal("id mismatch")
	}
	return a
}

func TestRunAccount_OK(t *testing.T) {
	srv := fakeMS(t, tokenOK)
	r, db := newTestRunner(t, srv)
	a := addAccount(t, db)

	// 先建基线（空规则集）
	if _, err := r.SnapshotBaseline(context.Background(), a); err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	out, err := r.RunAccount(context.Background(), a, "test")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Status != classify.StatusOK {
		t.Fatalf("status=%s results=%+v", out.Status, out.Results)
	}
	if len(out.Results) != 4 { // c1+c2+c3+c5
		t.Fatalf("want 4 results, got %d", len(out.Results))
	}

	// RT 轮换已持久化
	got, _ := db.GetAccount(context.Background(), "t@outlook.com")
	if got.RefreshToken != "rt-rotated" {
		t.Fatalf("RT not rotated: %s", got.RefreshToken)
	}
	// 状态落库
	s, _ := db.GetState(context.Background(), a.ID)
	if s.Status != "ok" || s.ConsecutiveFail != 0 {
		t.Fatalf("state=%+v", s)
	}
}

func TestRunAccount_Banned(t *testing.T) {
	srv := fakeMS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"User account is found to be in service abuse mode."}`))
	})
	r, db := newTestRunner(t, srv)
	a := addAccount(t, db)

	out, err := r.RunAccount(context.Background(), a, "test")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Status != classify.StatusFailed {
		t.Fatalf("status=%s", out.Status)
	}
	if len(out.Results) != 1 || out.Results[0].Classification != "banned" {
		t.Fatalf("results=%+v", out.Results)
	}
	s, _ := db.GetState(context.Background(), a.ID)
	if s.ConsecutiveFail != 1 {
		t.Fatalf("consecutive_fail=%d", s.ConsecutiveFail)
	}
}

func TestRunAccount_RulesSuspicious(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", tokenOK)
	mux.HandleFunc("/v1.0/me", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) })
	mux.HandleFunc("/v1.0/me/messages", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":[]}`))
	})
	mux.HandleFunc("/v1.0/me/mailFolders/inbox/messageRules", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{
			"displayName": "evil", "isEnabled": true,
			"actions": map[string]any{"forwardTo": []map[string]any{
				{"emailAddress": map[string]string{"address": "attacker@evil.com"}},
			}},
		}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	r, db := newTestRunner(t, srv)
	a := addAccount(t, db)
	// 基线 = 空规则（手动建，不走 snapshot——因为服务端现在已返回恶意规则）
	if err := db.SaveRuleSnapshot(context.Background(), a.ID, `[]`, "sha0"); err != nil {
		t.Fatal(err)
	}

	out, err := r.RunAccount(context.Background(), a, "test")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Status != classify.StatusFailed {
		t.Fatalf("status=%s results=%+v", out.Status, out.Results)
	}
	var c5 *store.CheckResult
	for i := range out.Results {
		if out.Results[i].Check == "c5_rules" {
			c5 = &out.Results[i]
		}
	}
	if c5 == nil || c5.Classification != "rules_suspicious" {
		t.Fatalf("c5=%+v", c5)
	}
}

func TestRunAccount_NoBaseline(t *testing.T) {
	srv := fakeMS(t, tokenOK)
	r, db := newTestRunner(t, srv)
	a := addAccount(t, db)

	out, err := r.RunAccount(context.Background(), a, "test")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// 无基线 → c5 unavailable → 账号级 degraded
	if out.Status != classify.StatusDegraded {
		t.Fatalf("status=%s", out.Status)
	}
}
