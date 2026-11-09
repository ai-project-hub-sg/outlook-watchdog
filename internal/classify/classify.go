// Package classify 实现"原始错误 → 检查状态 → 账号状态"的判定口径。
// 唯一权威来源：docs/status-codes.md。本包全部为纯函数，便于表驱动测试。
package classify

import (
	"fmt"
	"strings"
)

// Classification 是 token grant 响应的分类（status-codes.md §2）。
type Classification string

const (
	ClassOK             Classification = "ok"
	ClassBanned         Classification = "banned"          // 锁定/封禁/滥用/禁用 → failed
	ClassTokenInvalid   Classification = "token_invalid"   // RT 过期/失效/密码变更 → failed
	ClassReauthRequired Classification = "reauth_required" // 需重新交互授权 → failed
	ClassConfigError    Classification = "config_error"    // client_id 不匹配等 → failed
	ClassThrottled      Classification = "throttled"       // 429 → 不计账号故障
	ClassNetwork        Classification = "network"         // 网络/超时/5xx → error
	ClassUnknownError   Classification = "unknown_error"   // 未归类 → error，待人工归类
)

// Result 是一次检查的分类结果。
type Result struct {
	Classification Classification
	Detail         string // 脱敏摘要（可落库），禁止含 token/密码
}

// bannedKeywords 命中即判 banned（对 error_description 做包含匹配，小写化后比较）。
// 维护规则：见 status-codes.md §2——以 error_description 全文为准。
var bannedKeywords = []string{
	"service abuse", "abuse mode",
	"account is locked", "account has been locked", "blocked",
	"account is disabled", "user account is disabled",
	"suspended", "aadsts50057", "aadsts50053",
}

// reauthKeywords 命中即判需重新授权。
var reauthKeywords = []string{
	"interaction_required", "consent_required", "authorization_pending is not", // pending 由轮询层处理
}

// invalidKeywords 命中 invalid_grant 时进一步细分 token_invalid。
var invalidKeywords = []string{
	"expired", "revoked", "invalid refresh token", "does not match",
	"password has changed", "sts50052", "sts700084", "sts700082",
}

// ClassifyTokenGrant 对 token endpoint 响应分类。
// httpStatus<0 表示未拿到 HTTP 响应（网络错误）。
func ClassifyTokenGrant(httpStatus int, errCode, errDesc string) Result {
	low := strings.ToLower(errCode + " " + errDesc)

	if httpStatus < 0 {
		return Result{ClassNetwork, "network error: " + truncate(errDesc, 120)}
	}
	if httpStatus >= 200 && httpStatus < 300 {
		return Result{ClassOK, "token grant ok"}
	}
	if httpStatus == 429 {
		return Result{ClassThrottled, "throttled (429)"}
	}
	if httpStatus >= 500 {
		return Result{ClassNetwork, truncatef("server %d: %s", httpStatus, errDesc)}
	}

	for _, k := range bannedKeywords {
		if strings.Contains(low, k) {
			return Result{ClassBanned, "banned/locked: " + truncate(errDesc, 120)}
		}
	}
	switch errCode {
	case "interaction_required":
		return Result{ClassReauthRequired, "interaction required: " + truncate(errDesc, 120)}
	case "invalid_client", "unauthorized_client", "invalid_request":
		if strings.Contains(low, "scope") || strings.Contains(low, "unauthorized") {
			return Result{ClassConfigError, "client/scope config error: " + truncate(errDesc, 120)}
		}
		return Result{ClassConfigError, "invalid_client: " + truncate(errDesc, 120)}
	}
	if errCode == "invalid_grant" {
		for _, k := range invalidKeywords {
			if strings.Contains(low, k) {
				return Result{ClassTokenInvalid, "refresh token invalid: " + truncate(errDesc, 120)}
			}
		}
		for _, k := range reauthKeywords {
			if strings.Contains(low, k) {
				return Result{ClassReauthRequired, "reauth required: " + truncate(errDesc, 120)}
			}
		}
		// invalid_grant 未细分 → 保守归 token_invalid（多数情形即 RT 失效）
		return Result{ClassTokenInvalid, "invalid_grant: " + truncate(errDesc, 120)}
	}
	return Result{ClassUnknownError, truncatef("%d %s: %s", httpStatus, errCode, errDesc)}
}

// ClassifyNetworkError 网络层错误统一为 network。
func ClassifyNetworkError(err error) Result {
	return Result{ClassNetwork, "network error: " + truncate(err.Error(), 120)}
}

// FailClasses 判定为账号级 failed 的分类集合。
func FailClasses(c Classification) bool {
	switch c {
	case ClassBanned, ClassTokenInvalid, ClassReauthRequired, ClassConfigError:
		return true
	}
	return false
}

// AccountStatus 账号级状态。
const (
	StatusOK              = "ok"
	StatusDegraded        = "degraded"
	StatusFailed          = "failed"
	StatusUnknown         = "unknown"
	StatusBaselineMissing = "baseline_missing"
)

// CheckOutcome 单检查的归一化结果（与 store.CheckResult 对齐但解耦）。
type CheckOutcome struct {
	Check          string
	Result         string // pass|fail|unavailable|error
	Classification Classification
}

// degradedClasses 判定为"发现异常但严重度为 degraded"的分类（status-codes §6：
// 非转发/非隐藏类规则变化 → degraded；基线缺失 → baseline_missing 提示）。
var degradedClasses = map[Classification]bool{
	"rules_changed":    true,
	"baseline_missing": true,
}

// Aggregate 按 status-codes.md §4 聚合账号级状态。
func Aggregate(outcomes []CheckOutcome) string {
	hasFail, hasDegraded, hasErr, hasPass := false, false, false, false
	for _, o := range outcomes {
		switch o.Result {
		case "fail":
			if degradedClasses[o.Classification] {
				hasDegraded = true
			} else {
				hasFail = true
			}
		case "unavailable":
			hasDegraded = true
		case "error":
			hasErr = true
		case "pass":
			hasPass = true
		}
	}
	switch {
	case hasFail:
		return StatusFailed
	case hasDegraded || (hasErr && hasPass):
		return StatusDegraded
	case hasPass:
		return StatusOK
	default:
		return StatusUnknown
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func truncatef(format string, args ...any) string {
	return truncate(fmt.Sprintf(format, args...), 160)
}
