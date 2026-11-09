package notify

import "testing"

func TestDecideAlert(t *testing.T) {
	cases := []struct {
		name        string
		lastAlert   string
		newStatus   string
		consecutive int
		threshold   int
		want        string
	}{
		{"ok→failed 未达阈值不告警", "", "failed", 1, 2, ""},
		{"ok→failed 达阈值告警", "", "failed", 2, 2, "alert"},
		{"同状态不重复告警", "failed", "failed", 5, 2, ""},
		{"degraded 达阈值告警", "", "degraded", 2, 2, "alert"},
		{"unknown 达阈值告警", "", "unknown", 3, 2, "alert"},
		{"从已告警状态恢复→recovery", "failed", "ok", 0, 2, "recovery"},
		{"未告警过的 ok 不通知", "", "ok", 0, 2, ""},
		{"ok→degraded 未达阈值", "", "degraded", 1, 2, ""},
		{"坏状态间切换告警", "failed", "degraded", 4, 2, "alert"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DecideAlert(c.lastAlert, c.newStatus, c.consecutive, c.threshold); got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestMaskEmail(t *testing.T) {
	if got := MaskEmail("yjpcrseukw@outlook.com"); got != "y***w@outlook.com" {
		t.Fatalf("got %s", got)
	}
	if got := MaskEmail("ab@c.com"); got != "a***@c.com" {
		t.Fatalf("got %s", got)
	}
}
