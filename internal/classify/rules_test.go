package classify

import (
	"encoding/json"
	"testing"
)

func rule(name string, actions string) MessageRule {
	var r MessageRule
	r.DisplayName = name
	r.IsEnabled = true
	json.Unmarshal([]byte(`{`+actions+`}`), &r.Actions)
	return r
}

func TestNormalizeAndSnapshot(t *testing.T) {
	rules := []MessageRule{
		rule("b", `"forwardTo":[{"emailAddress":{"address":"x@a.com"}}]`),
		rule("a", `"moveToFolder":"archive"`),
	}
	norm := NormalizeRules(rules)
	if norm[0].Name != "a" || norm[1].Name != "b" {
		t.Fatalf("not sorted: %+v", norm)
	}
	c1, sha1, _ := SnapshotHash(norm)
	norm[0], norm[1] = norm[1], norm[0] // 乱序后重排应同 hash
	c2, sha2, _ := SnapshotHash(NormalizeRules(rules))
	if sha1 != sha2 {
		t.Fatalf("hash unstable: %s vs %s", sha1, sha2)
	}
	if c1 != c2 {
		t.Fatal("canonical differs")
	}
}

func TestDiffRules(t *testing.T) {
	base := NormalizeRules([]MessageRule{
		rule("keep", `"markAsRead":true`),
	})

	t.Run("unchanged→pass", func(t *testing.T) {
		d := DiffRules(base, base)
		if d.Verdict != "pass" {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("new forward rule→fail", func(t *testing.T) {
		cur := append([]NormRule{}, base...)
		cur = append(cur, NormalizeRules([]MessageRule{
			rule("evil", `"forwardTo":[{"emailAddress":{"address":"attacker@evil.com"}}]`),
		})...)
		d := DiffRules(base, cur)
		if d.Verdict != "fail" || len(d.FailReasons) == 0 {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("hidden move+stop→fail", func(t *testing.T) {
		cur := append([]NormRule{}, base...)
		cur = append(cur, NormalizeRules([]MessageRule{
			rule("hide", `"moveToFolder":"rsssubscriptions","stopProcessingRules":true`),
		})...)
		d := DiffRules(base, cur)
		if d.Verdict != "fail" {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("forward target changed→fail", func(t *testing.T) {
		base2 := NormalizeRules([]MessageRule{
			rule("fwd", `"forwardTo":[{"emailAddress":{"address":"me@ok.com"}}]`),
		})
		cur := NormalizeRules([]MessageRule{
			rule("fwd", `"forwardTo":[{"emailAddress":{"address":"attacker@evil.com"}}]`),
		})
		d := DiffRules(base2, cur)
		if d.Verdict != "fail" {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("benign new rule→degraded", func(t *testing.T) {
		cur := append([]NormRule{}, base...)
		cur = append(cur, NormalizeRules([]MessageRule{
			rule("sort", `"moveToFolder":"inbox"`),
		})...)
		d := DiffRules(base, cur)
		if d.Verdict != "degraded" || len(d.Notes) == 0 {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("removed rule→degraded note", func(t *testing.T) {
		d := DiffRules(base, []NormRule{})
		if d.Verdict != "degraded" {
			t.Fatalf("%+v", d)
		}
	})
}
