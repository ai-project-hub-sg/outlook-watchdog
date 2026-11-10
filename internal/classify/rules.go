// rules.go：收件箱规则（messageRules）基线快照与差异判定。
// 口径见 docs/status-codes.md §6。
package classify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MessageRule 是 Graph messageRules 响应中一条规则的最小模型。
type MessageRule struct {
	ID          string          `json:"id"` // 写操作（PATCH/DELETE）需要
	DisplayName string          `json:"displayName"`
	Sequence    int             `json:"sequence"`
	IsEnabled   bool            `json:"isEnabled"`
	Conditions  json.RawMessage `json:"conditions"`
	Actions     struct {
		ForwardTo             []mailRef `json:"forwardTo"`
		ForwardAsAttachmentTo []mailRef `json:"forwardAsAttachmentTo"`
		RedirectTo            []mailRef `json:"redirectTo"`
		MoveToFolder          string    `json:"moveToFolder"`
		StopProcessingRules   bool      `json:"stopProcessingRules"`
		Delete                bool      `json:"delete"`
	} `json:"actions"`
}

type mailRef struct {
	EmailAddress struct {
		Address string `json:"address"`
	} `json:"emailAddress"`
}

// FwdAddrs / FwdAttachAddrs / RedirectAddrs 返回各转发动作的目标地址列表。
func (r *MessageRule) FwdAddrs() []string       { return addrSet(r.Actions.ForwardTo) }
func (r *MessageRule) FwdAttachAddrs() []string { return addrSet(r.Actions.ForwardAsAttachmentTo) }
func (r *MessageRule) RedirectAddrs() []string  { return addrSet(r.Actions.RedirectTo) }

// NormRule 是用于基线比较的规范化规则。
type NormRule struct {
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	Conditions string   `json:"conditions,omitempty"`
	Forward    []string `json:"forward,omitempty"`
	FwdAttach  []string `json:"fwd_attach,omitempty"`
	Redirect   []string `json:"redirect,omitempty"`
	MoveTo     string   `json:"move_to,omitempty"`
	StopProc   bool     `json:"stop_proc,omitempty"`
	Delete     bool     `json:"delete,omitempty"`
}

// hiddenFolderKeys 命中即视为"隐藏类文件夹"（status-codes §6.2）。
var hiddenFolderKeys = []string{"deleteditem", "rss", "junkemail", "archive"}

// NormalizeRules 把 Graph 原始规则列表转成规范化集合（按 name 排序）。
func NormalizeRules(raw []MessageRule) []NormRule {
	out := make([]NormRule, 0, len(raw))
	for _, r := range raw {
		nr := NormRule{
			Name:       r.DisplayName,
			Enabled:    r.IsEnabled,
			Conditions: canonicalJSON(r.Conditions),
			Forward:    addrSet(r.Actions.ForwardTo),
			FwdAttach:  addrSet(r.Actions.ForwardAsAttachmentTo),
			Redirect:   addrSet(r.Actions.RedirectTo),
			MoveTo:     strings.ToLower(r.Actions.MoveToFolder),
			StopProc:   r.Actions.StopProcessingRules,
			Delete:     r.Actions.Delete,
		}
		out = append(out, nr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SnapshotHash 计算规范化基线的 sha256 与规范化 JSON。
func SnapshotHash(rules []NormRule) (canonical string, sha string, err error) {
	b, err := json.Marshal(rules)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(b)
	return string(b), hex.EncodeToString(sum[:]), nil
}

// RulesDiff 是基线对比结果。
type RulesDiff struct {
	Verdict     string   `json:"verdict"` // pass|degraded|fail
	FailReasons []string `json:"fail_reasons,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

// DiffRules 对比基线（nil = 无基线，由调用方判 baseline_missing）与当前规则。
func DiffRules(baseline, current []NormRule) RulesDiff {
	var d RulesDiff
	old := map[string]NormRule{}
	for _, r := range baseline {
		old[r.Name] = r
	}
	cur := map[string]NormRule{}
	for _, r := range current {
		cur[r.Name] = r
	}

	for _, r := range current {
		o, ok := old[r.Name]
		switch {
		case !ok: // 新增规则
			if reason := suspiciousRuleReason(r); reason != "" {
				d.FailReasons = append(d.FailReasons, "新增可疑规则 "+r.Name+": "+reason)
			} else {
				d.Notes = append(d.Notes, "新增规则 "+r.Name)
			}
		case forwardTargetsChanged(o, r):
			d.FailReasons = append(d.FailReasons, "既有规则 "+r.Name+" 的转发/重定向目标被修改")
		default:
			if !rulesEqual(o, r) {
				d.Notes = append(d.Notes, "规则 "+r.Name+" 有变化")
			}
		}
	}
	for _, r := range baseline {
		if _, ok := cur[r.Name]; !ok {
			d.Notes = append(d.Notes, "规则 "+r.Name+" 已删除")
		}
	}

	switch {
	case len(d.FailReasons) > 0:
		d.Verdict = "fail"
	case len(d.Notes) > 0:
		d.Verdict = "degraded"
	default:
		d.Verdict = "pass"
	}
	return d
}

// suspiciousRuleReason 判定新增规则是否属于可疑（转发/隐藏类）。
func suspiciousRuleReason(r NormRule) string {
	var parts []string
	if len(r.Forward) > 0 {
		parts = append(parts, "forwardTo="+strings.Join(r.Forward, ","))
	}
	if len(r.FwdAttach) > 0 {
		parts = append(parts, "forwardAsAttachmentTo="+strings.Join(r.FwdAttach, ","))
	}
	if len(r.Redirect) > 0 {
		parts = append(parts, "redirectTo="+strings.Join(r.Redirect, ","))
	}
	if r.StopProc && isHiddenFolder(r.MoveTo) {
		parts = append(parts, "moveTo "+r.MoveTo+" + stopProcessing（隐藏邮件特征）")
	}
	return strings.Join(parts, "; ")
}

// forwardTargetsChanged 判定既有规则的转发/重定向目标集合是否变化。
func forwardTargetsChanged(o, n NormRule) bool {
	return !eqSet(o.Forward, n.Forward) ||
		!eqSet(o.FwdAttach, n.FwdAttach) ||
		!eqSet(o.Redirect, n.Redirect)
}

func rulesEqual(a, b NormRule) bool {
	return a.Name == b.Name && a.Enabled == b.Enabled &&
		a.Conditions == b.Conditions && a.MoveTo == b.MoveTo &&
		a.StopProc == b.StopProc && a.Delete == b.Delete &&
		eqSet(a.Forward, b.Forward) && eqSet(a.FwdAttach, b.FwdAttach) &&
		eqSet(a.Redirect, b.Redirect)
}

func isHiddenFolder(f string) bool {
	for _, k := range hiddenFolderKeys {
		if strings.Contains(f, k) {
			return true
		}
	}
	return false
}

func addrSet(refs []mailRef) []string {
	set := map[string]bool{}
	for _, r := range refs {
		a := strings.ToLower(strings.TrimSpace(r.EmailAddress.Address))
		if a != "" {
			set[a] = true
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func eqSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func canonicalJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return string(raw)
	}
	return string(b)
}
