# M6：协议探测（C6/C7）+ 发信/roundtrip（C4/C8）

- 日期：2026-11-09
- 分支：main
- 类型：feat
- 相关 commit / tag：M6 提交

## 1. 背景

完成检查矩阵剩余四项（design §4）：C4 发信能力、C6 IMAP XOAUTH2、C7 SMTP XOAUTH2、C8 端到端 roundtrip。全部默认关（真实发信/协议探测，按需开启）。

## 2. 修改情况

- 代码：
  - `internal/probe`：TokenHasScope（解析 JWT scp/roles 声明）、IMAP XOAUTH2（tls+AUTHENTICATE+LOGOUT）、SMTP（STARTTLS+net/smtp 自定义 XOAUTH2 Auth，不发信）
  - `internal/graph`：RecentInbox（收件箱 topN 精简视图）、DeleteMessage（roundtrip 清理）
  - `internal/check`：checkSend（sendMail 给自己）、checkProto（scope 缺失→unavailable）、checkRoundtrip（唯一标记→10s 轮询≤90s→命中报延迟→删探信）；C8 ≥30min 限频（LastCheckTime）
  - `internal/store`：LastCheckTime
  - `internal/web`：knownChecks 扩到 8 项；表单 ⚠ 标注真实发信项（默认不勾）

## 3. 完成情况

- 已完成：四项全部真实账号验证（下表）
- 未完成：无——M6 范围全交付
- 遗留问题 / 风险：C6/C7 真实握手未验证（当前 token 无协议 scope，scope_missing 路径已验证；真握手需 outlook.office.com scope 的 RT）；roundtrip 限频只在 enabled 时生效
- 下一步：M7 发布打磨（Windows/Linux 二进制 + release 脚本实测 + deploy 定稿）

## 4. 影响

| 对象 | 变更前 | 变更后 | 说明 |
|------|--------|--------|------|
| 检查矩阵 | C1/C2/C3/C5 | +C4/C6/C7/C8 | 新项默认关 |
| 聚合 | — | unavailable→degraded | scope_missing 不误报 failed |
| 真实发信 | 无 | c4/c8 发到自己 | 探信自删，C8 限频 30min |

## 5. 验证

- 真实账号（s***6@outlook.com）一轮全项：
  - `c4_send pass`（sendMail 202）
  - `c6_imap/c7_smtp unavailable scope_missing`（JWT 无协议 scope，正确降级）
  - `c8_roundtrip pass latency=10398ms`（探信→收件箱命中→自删）
  - 聚合 `degraded`（unavailable 计入，符合 status-codes §4）
- 测试：`go test ./...` 全绿
- 坑记录：旧二进制驻留导致新检查不执行（重启后正常）——验证新功能必须先确认 bin 已重建且进程已重启
