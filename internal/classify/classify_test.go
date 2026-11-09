package classify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type tokenErrPayload struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func loadFixture(t *testing.T, name string) (code, desc string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	var p tokenErrPayload
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return p.Error, p.ErrorDescription
}

func TestClassifyTokenGrant_Golden(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		status  int
		errCode string
		want    Classification
	}{
		{"service abuse mode→banned", "aadsts70000_abuse.json", 400, "", ClassBanned},
		{"disabled→banned", "aadsts50057_disabled.json", 400, "", ClassBanned},
		{"locked→banned", "aadsts50053_locked.json", 400, "", ClassBanned},
		{"RT expired→token_invalid", "invalid_grant_expired.json", 400, "", ClassTokenInvalid},
		{"interaction_required→reauth", "interaction_required.json", 400, "", ClassReauthRequired},
		{"invalid_client→config_error", "invalid_client.json", 400, "", ClassConfigError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, desc := loadFixture(t, c.fixture)
			if c.errCode != "" {
				code = c.errCode
			}
			got := ClassifyTokenGrant(c.status, code, desc)
			if got.Classification != c.want {
				t.Fatalf("got %s want %s (detail: %s)", got.Classification, c.want, got.Detail)
			}
		})
	}
}

func TestClassifyTokenGrant_StatusMatrix(t *testing.T) {
	cases := []struct {
		name   string
		status int
		code   string
		desc   string
		want   Classification
	}{
		{"success", 200, "", "", ClassOK},
		{"throttled", 429, "", "", ClassThrottled},
		{"server 5xx", 503, "", "Service Unavailable", ClassNetwork},
		{"network", -1, "", "dial tcp timeout", ClassNetwork},
		{"invalid_grant generic→token_invalid", 400, "invalid_grant", "The token is not valid", ClassTokenInvalid},
		{"password changed→token_invalid", 400, "invalid_grant", "user changed their password", ClassTokenInvalid},
		{"abuse in desc without code", 400, "invalid_grant", "User account is found to be in service abuse mode", ClassBanned},
		{"unknown 4xx", 418, "teapot", "i'm a teapot", ClassUnknownError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyTokenGrant(c.status, c.code, c.desc)
			if got.Classification != c.want {
				t.Fatalf("got %s want %s", got.Classification, c.want)
			}
		})
	}
}

func TestAggregate(t *testing.T) {
	mk := func(result string, cls Classification) CheckOutcome {
		return CheckOutcome{Check: "x", Result: result, Classification: cls}
	}
	cases := []struct {
		name string
		in   []CheckOutcome
		want string
	}{
		{"all pass→ok", []CheckOutcome{mk("pass", ClassOK), mk("pass", ClassOK)}, StatusOK},
		{"banned→failed", []CheckOutcome{mk("fail", ClassBanned)}, StatusFailed},
		{"token_invalid→failed", []CheckOutcome{mk("fail", ClassTokenInvalid)}, StatusFailed},
		{"unavailable→degraded", []CheckOutcome{mk("pass", ClassOK), mk("unavailable", "capability_unavailable")}, StatusDegraded},
		{"all error→unknown", []CheckOutcome{mk("error", ClassNetwork), mk("error", ClassThrottled)}, StatusUnknown},
		{"pass+error→degraded", []CheckOutcome{mk("pass", ClassOK), mk("error", ClassNetwork)}, StatusDegraded},
		{"fail overrides", []CheckOutcome{mk("pass", ClassOK), mk("fail", ClassBanned), mk("error", ClassNetwork)}, StatusFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Aggregate(c.in); got != c.want {
				t.Fatalf("got %s want %s", got, c.want)
			}
		})
	}
}
