# 状态判定口径（唯一权威来源）

> 本文件定义"原始错误 → 检查状态 → 账号状态"的映射。**代码中的分类逻辑必须与本表一致**；
> 发现新错误模式时先归类、写入本文档与 `docs/decisions/`，再改代码（AGENTS.md §5）。
> 初始版本主要参考 `daimon3332/OutlookManage/backend/services/diagnostics.py` 的分类经验与微软 AADSTS 官方错误文档，落地时用真实账号校准。

## 1. 检查级结果（check result）

| result | 含义 |
|--------|------|
| `pass` | 检查通过 |
| `fail` | 检查失败且可归因于账号/凭据状态 |
| `unavailable` | 检查无法执行（scope 缺失、该检查未启用、依赖的前置检查失败） |
| `error` | 检查执行出错且无法归因（网络、超时、5xx、未知响应） |

## 2. token grant 分类（C1，最关键）

对 `POST {authority}/oauth2/v2.0/token`（grant_type=refresh_token）的响应分类：

| 条件（匹配优先级从上到下） | classification | 账号状态 | 说明 |
|---|---|---|---|
| HTTP 200 | `ok` | 继续后续检查 | 同时持久化返回的新 refresh_token |
| `invalid_grant` + `error_description` 含 `service abuse`/`abuse mode` | `banned` | failed | 滥用封禁。微软常返回 AADSTS70000，**以 error_description 全文为准** |
| `invalid_grant` + 含 `blocked`/`locked`/`suspended`/`disabled`（如 AADSTS50057、AADSTS50053） | `banned` | failed | 账号级锁定/禁用 |
| `interaction_required` / `invalid_grant` + `consent` | `reauth_required` | failed | 需重新交互授权 |
| `invalid_grant` 其他（expired/revoked/密码变更等） | `token_invalid` | failed | RT 失效，需重新获取 RT |
| `invalid_client` / `unauthorized_client` | `config_error` | failed | client_id 与 RT 不匹配或配置错 |
| HTTP 429 | `throttled` | error→unavailable | 尊重 Retry-After，不计为账号故障 |
| 网络错误/超时/HTTP 5xx | `network` | error | 计入连续失败计数 |
| 其他 4xx 未知 | `unknown_error` | error | 记日志待归类（见 §5） |

## 3. Graph/协议检查分类（C2–C8）

| 场景 | result | 计入 |
|------|--------|------|
| 期望 2xx 且实际 2xx | `pass` | — |
| 401/403 + `InvalidAuthenticationToken`/scope 不足 | `unavailable` | degraded（非账号锁定） |
| sendMail/IMAP/SMTP 认证被拒（非 scope 类） | `fail` | 该检查失败 |
| 404/410 账号不存在 | `fail` | 账号级异常→failed |
| 网络错误/超时/5xx/429 | `error` | 计入连续失败计数 |

## 4. 账号级状态聚合

- `ok`：所有启用且 available 的检查 pass
- `failed`：任一检查 classification ∈ {`banned`,`token_invalid`,`reauth_required`,`config_error`}，或必要检查 `fail`
- `degraded`：无 failed 级问题，但有检查 fail/unavailable（如仅 IMAP 挂、messageRules 403）
- `unknown`：所有结果都是 error 类（纯网络问题）
- `baseline_missing`：rules 检查启用但尚未 snapshot 基线（degraded 的一种，提示一次）

## 5. 告警口径

- 仅账号级状态**迁移**时告警：→{failed,degraded} 发异常告警，→ok 发恢复通知。
- `unknown` 连续 N 轮（`fail_threshold`，默认2；纯网络连续3轮仍算 unknown）才发"无法确认账号健康"告警。
- 同状态不重复告警；告警内容必须含分类原因（如 `banned: service abuse mode`）。
- 新出现的未归类错误一律先按 `unknown_error` 处理（不误报账号异常），人工归类后更新本表与 classify。

## 6. 规则审计口径（C5）

- 基线 = `watchdog snapshot` 时 `messageRules` 全量规则的规范化快照（排序后 JSON + sha256）。
- 异常判定（命中任一即 fail）：
  1. 存在基线外新增规则，且动作含 `forwardTo`/`forwardAsAttachmentTo`/`redirectTo`
  2. 存在基线外新增规则，且动作含 `moveToFolder`（RSS/Deleted/Archive 等隐藏类）+ `stopProcessingRules`
  3. 基线内既有转发/重定向规则被修改目标地址
- 非转发/非隐藏类规则变化（如普通移动规则增删）→ `degraded` 并提示"规则有变化，请确认"，不直接判 fail。
- 已知的口径边界：outlook.com 网页端"自动转发"开关若不映射为 messageRule，则不在本检查覆盖范围（待 spike 验证，见 design.md §14）。
