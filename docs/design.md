# outlook-watchdog 详细设计

> 本文档是项目的**架构与计划唯一权威来源**。状态判定口径见 [status-codes.md](./status-codes.md)。
> 修改架构、口径、配置/存储结构属重大变更，按 AGENTS.md §7/§9 流程走。

## 1. 背景与目标

监控个人 Outlook / Hotmail（@outlook.com、@hotmail.com、@live.com 等 MSA 消费者账号）的健康状态：

1. 账号是否被锁定/封禁
2. 能否正常收发邮件
3. 转发设置（收件箱规则）是否异常
4. 异常时通过独立渠道告警（邮件 / webhook）
5. 提供**内置 WebUI 管理后台**：大盘、账号管理、手动操作、调度/告警配置、日志查询、运行状态

**明确的非目标**：不监控 M365 企业租户邮箱（那套用 EXO PowerShell + Graph 应用权限更合适）；不做账号注册、改密、解封；不做多用户系统。

## 2. 前提与账号接入方式

- 微软 2024-09 起已对消费级账号关闭 IMAP/SMTP basic auth，**一切访问走 OAuth2**。
- 每个被监控账号需要一份 `email + client_id + refresh_token`（RT 通过一次性设备码/授权码流程获取，获取工具另议，可用现成方案如 Outlook-Oauth-GetToken，也可写 device code flow 小工具；WebUI 内提供录入入口，不内嵌授权流程）。
- RT 授权时的 scope 决定检查能力（见 §4 表）。同一 RT 在刷新时可按子集 scope 换不同 audience 的 access_token（Graph 用 `graph.microsoft.com/*`，IMAP/SMTP 探测用 `outlook.office.com/*`）。
- **RT 轮换**：微软每次 grant 都返回新 RT，必须持久化最新值，否则原 RT 过期后监控失联（见 §8）。

## 3. 总体架构

```
cron/TaskScheduler ──> watchdog check --once ─┐
                                              ├─> 对库中每个启用账号:
watchdog serve (调度器 + WebUI, interval+jitter) ┘      │
                                                      ▼
                              ┌─────────── 检查管线（按序，短路可选）───────────┐
                              │ 1. token grant  → 分类器 → ok/锁定/失效/unknown │
                              │ 2. graph 探活   → /me, /messages?$top=1        │
                              │ 3. rules 审计   → messageRules diff vs 基线     │
                              │ 4. 协议探测(选) → IMAP/SMTP XOAUTH2 登录        │
                              │ 5. roundtrip(选)→ 发信→收信闭环验证            │
                              └──────────────────────────────────────────────┘
                                                      │
                              分类器(classify) → 账号级状态 → SQLite
                                                      │
                              状态迁移? ──是──> notify (webhook / 独立SMTP)
                                                      │
WebUI (浏览器) <── HTTP/session ──> internal/web ──> SQLite（同一数据源）
```

- `serve` 单进程内运行调度循环与 HTTP 服务；`check --once` 与 serve 共用同一套 check/store 代码，便于 cron 轻量用法。
- 多账号规模预设：几十个以内（如需上千再评估任务队列，记为决策）。

## 4. 检查项定义

| # | 检查 | 方法 | 所需 scope | 默认 | 说明 |
|---|------|------|-----------|------|------|
| C1 | 锁定/封禁 | POST `{authority}/oauth2/v2.0/token`，grant_type=refresh_token | `offline_access` | 开 | 错误码→状态见 status-codes.md |
| C2 | Graph 探活 | GET `/v1.0/me` | `User.Read` | 开 | 200=token 可用 |
| C3 | 收信能力 | GET `/me/messages?$top=1` | `Mail.Read` | 开 | 只读不取正文 |
| C4 | 发信能力(轻) | POST `/me/sendMail` 发到自己 | `Mail.Send` | **关** | 真实产生邮件，开启需限频 |
| C5 | 规则审计 | GET `/me/mailFolders/inbox/messageRules` | `MailboxSettings.Read` | 开 | 与基线 diff，重点查 forwardTo/redirectTo/转移隐藏类动作 |
| C6 | IMAP 探测 | `outlook.office365.com:993` XOAUTH2 登录后登出 | `IMAP.AccessAsUser.All` | 关 | 只验证认证，不读邮件 |
| C7 | SMTP 探测 | `smtp.office365.com:587` STARTTLS+XOAUTH2 AUTH | `SMTP.Send` | 关 | 只验证认证，不发信 |
| C8 | roundtrip | C4 发唯一 token 邮件→C3 轮询收件箱 | Mail.Send+Mail.Read | **关** | 端到端验证，频率≥30min |

- 每个账号可在 WebUI 单独开关检查项；未授权的 scope → 该检查记 `capability_unavailable`（见口径），**不误报为账号故障**。
- 失败重试：网络类错误最多 3 次指数退避；HTTP 429 尊重 `Retry-After`；4xx 不重试。

## 5. 状态模型

账号级状态（详见 status-codes.md）：

| 状态 | 含义 | 告警 |
|------|------|------|
| `ok` | 全部已启用检查通过 | 迁移时发"恢复"通知 |
| `degraded` | 部分检查失败但账号未被锁（如仅 IMAP 挂、scope 缺） | 可配置 |
| `failed` | banned/locked/token_invalid/reauth_required | 告警 |
| `unknown` | 纯网络/限流导致，连续 N 次（默认3）后才升级 | 升级后告警 |
| `baseline_missing` | 规则基线未建立 | 首次提示一次 |

**口径核心**：`banned`（锁定/封禁）与 `token_invalid`（RT 过期/密码变更）与 `unknown`（网络抖动）必须区分——三者处置完全不同。

## 6. 告警设计

- **触发**：仅在账号级状态**迁移**时告警（含 →ok 的恢复通知）；同状态重复不告警。
- **去抖**：`failed`/`degraded` 需连续 `fail_threshold`（默认2）轮确认后才告警，防瞬时抖动。
- **通道**（均独立于被监控账号，WebUI 可配置多条）：
  - generic webhook：POST JSON 到任意 URL（兼容 ntfy/Bark/Server酱/Telegram 网关等 preset）
  - SMTP：用**独立发信账号**发告警邮件（绝不用被监控账号——它锁了告警就死了）
- **内容**：账号（脱敏显示，如 `t***k@outlook.com`）、旧状态→新状态、失败检查项、分类原因、时间、run_id。
- 告警事件落库 `alert_events`；WebUI 有"发送测试告警"按钮。

## 7. WebUI 设计（完整管理后台）

### 7.1 技术形态

- **Go embed + html/template + htmx**（htmx.min.js vendored 进 `web/static/`），服务端渲染为主；无 node 构建链，保持单二进制。
- 样式：手写少量 CSS 或 vendored 极简 classless 框架（如 Pico）；暗色/响应式非目标。
- htmx 负责局部刷新（状态表轮询、表单提交、分页）；少量 vanilla JS 兜底交互。
- 另提供 JSON API（`/api/v1/*`）便于脚本化与未来扩展；页面与 API 共用 handler 层。

### 7.2 页面清单

| 路由 | 页面 | 功能 |
|------|------|------|
| `/login` `/logout` | 登录 | 单管理员密码，session cookie |
| `/` | 大盘 | 每账号状态卡/表：状态、各检查项结果、上次检查、连续失败；最近告警；自动轮询刷新 |
| `/accounts` | 账号列表 | 增删改、启停、检查项开关、批量导入（文本粘贴 `email----client_id----rt`） |
| `/accounts/{id}` | 账号详情 | 编辑（RT 掩码显示）、每账号检查历史、规则基线查看与 diff 详情、按钮：立即检查/重建基线 |
| `/alerts` | 告警历史 | alert_events 列表，筛选分页 |
| `/logs` | 检查日志 | check_runs/check_results 查询：按账号/状态/时间筛选、分页、导出 jsonl/csv |
| `/settings` | 系统设置 | 调度参数（interval/jitter/fail_threshold）、告警渠道（webhook/SMTP 增改+测试按钮）、修改管理员密码 |
| `/system` | 运行状态 | 调度器状态、下一轮时间、DB 大小、版本、Go runtime 摘要 |

### 7.3 认证与安全

- 单管理员：首次启动无凭据时进入 setup 流程（或 `--init-password`/env 注入），密码以 **argon2id/bcrypt 哈希**存 `settings` 表，永不存明文。
- Session：随机 256-bit token，cookie `HttpOnly; SameSite=Lax`，默认 12h 过期，服务端 `sessions` 表可吊销。
- CSRF：每 session 生成 token，非 GET 请求校验 header（htmx `hx-headers` 注入）。
- 登录限速：同 IP 连续失败指数退避（≥5 次锁定 5min）。
- 默认绑定 `127.0.0.1:8080`；绑到非回环地址时启动日志与 `/system` 页必须提示"确认已设密码、建议反代 HTTPS"。
- 所有页面/ API 输出中 RT/密码一律掩码（`r****n` 只露首尾 2 字符）；详情接口不返回完整凭据。

## 8. 配置与存储设计

### 8.1 引导配置 `config.yaml`（gitignore）

只保留进程级引导项，业务数据全部在库中：

```yaml
listen: 127.0.0.1:8080
data_dir: data/            # SQLite 所在目录
log_dir: logs/
# admin_password: ${WATCHDOG_ADMIN_PASSWORD}   # 可选：免 setup 首启注入，仅存哈希
```

### 8.2 SQLite（`data/watchdog.sqlite`，pure-Go `modernc.org/sqlite`）

运行时唯一权威数据源；`PRAGMA journal_mode=WAL; foreign_keys=ON`；结构变更只经 `internal/store/migrations/NNN_*.sql`。

```sql
accounts(id, email UNIQUE, client_id, refresh_token, proxy,
         checks_json,        -- {rules:true, imap:false, ...}
         enabled, created_at, updated_at)
account_state(account_id PK→accounts.id, status, consecutive_fail,
              last_check_at, last_alert_at, last_alert_status)
rule_snapshots(account_id PK→accounts.id, rules_json, sha256, taken_at)
check_runs(id, account_id, run_id, trigger,  -- sched|manual|cli
           started_at, finished_at, status)
check_results(id, run_id→check_runs.id, check,    -- c1_token / c3_recv / ...
              result,                              -- pass|fail|unavailable|error
              classification, detail, duration_ms)
alert_events(id, account_id, from_status, to_status, reason,
             channel, sent_at, error)
notify_channels(id, type, name, config_json, enabled)  -- webhook|smtp
settings(key PK, value)                                -- schedule params, admin pw hash
sessions(token PK, created_at, expires_at)
```

要点：

- 新 RT 每次 grant 成功后写回 `accounts.refresh_token`（事务内，失败记 error 并告警——丢 RT = 监控失联）。
- `check_results.detail` 只存脱敏错误摘要与分类；**token/密码永不落库**。
- 大批量清理：`check_runs` 保留策略（默认 90 天，`settings` 可调，每日任务删除）。

## 9. CLI 设计

```
watchdog serve [--listen :8080]      # 调度器 + WebUI 常驻（主用法）
watchdog check --once [--account x]  # 跑一轮；exit: 0全ok / 1有failed|degraded / 2程序错误
watchdog snapshot --account x        # 建立/重置 rules 基线
watchdog status                      # 打印各账号当前状态表
watchdog test-notify                 # 发测试告警
watchdog migrate                     # 手动执行 DB 迁移（serve 启动时自动执行）
watchdog get-token --email x         # (可选) 设备码流获取初始 RT
```

## 10. 目录结构

```
cmd/watchdog/main.go        # CLI 入口（urfave/cli 或标准 flag）
internal/config/            # 引导配置加载、校验、env 展开
internal/store/             # SQLite：连接、migrations/、各表 DAO
internal/msauth/            # token 刷新、audience scope 切换、RT 轮换回调
internal/graph/             # Graph 客户端：/me、messages、sendMail、messageRules
internal/probe/             # IMAP/SMTP XOAUTH2 探测
internal/classify/          # 错误→状态分类（纯函数，对应 status-codes.md）
internal/check/             # 检查项编排
internal/notify/            # webhook + smtp 告警
internal/sched/             # run 循环、jitter、限流、日志清理任务
internal/web/               # HTTP 服务：handlers、session/CSRF 中间件、embed
web/templates/              # html/template 页面（embed）
web/static/                 # htmx.min.js、css（embed）
docs/                       # design.md / status-codes.md / devlog/ / decisions/
config.example.yaml
data/ logs/                 # 运行态（gitignore）
```

## 11. 技术选型

- Go ≥ 1.22，标准库为主（`net/http`、`encoding/json`、`html/template`、`embed`）。
- 依赖尽量少且可审计：
  - `modernc.org/sqlite`（pure-Go SQLite，免 cgo，交叉编译友好）
  - `gopkg.in/yaml.v3`（引导配置）
  - `golang.org/x/crypto`（argon2/bcrypt 密码哈希）
  - `github.com/emersion/go-imap/v2` + `go-sasl`（C6）；`net/smtp`+自写 XOAUTH2 Auth（C7）
  - htmx 前端库以文件形式 vendored 进 `web/static/`（记录版本）
- 不引 MSAL-Go、不引 web 框架（标准库 mux + 自写中间件足够，依赖面越小越好审计）。
- 测试：`httptest` 起假 token/Graph 端点 + handler 测试；真实微软错误载荷做 golden fixture（来源：OutlookManage `diagnostics.py` + 官方 AADSTS 文档）；禁止真实外网单测（live 测试用 `//go:build live` 隔离）。

## 12. 里程碑

| 里程碑 | 内容 | 验收 |
|--------|------|------|
| M1 骨架+锁定检测 | 引导配置、SQLite+migrations、msauth、classify、`check --once` | 单账号跑出 ok/banned/token_invalid 三态，fixture 单测通过 |
| M2 Graph 检查+规则审计 | C2/C3/C5、snapshot 基线、diff 判定 | 改动测试账号规则能被 diff 出 |
| M3 告警+调度 | notify(webhook+smtp)、迁移去抖、sched 循环、日志清理 | 模拟状态迁移收到告警与恢复通知 |
| M4 WebUI 基础 | serve、setup/login/session/CSRF、大盘页、账号 CRUD、手动检查、账号详情+历史 | 浏览器完成"加账号→检查→看状态"闭环 |
| M5 WebUI 完整后台 | settings、告警渠道配置+测试、logs 查询/导出、基线 diff 页、system 页 | 全流程配置均可在网页完成 |
| M6 协议探测+roundtrip | C6/C7、可选 C8 | 带 IMAP scope 账号探测通过 |
| M7 打磨发布 | README/config.example、批量导入、release 构建 | 全流程走通，文档齐 |

## 13. 验证策略

- 单元：classify 全分类表（golden fixtures）、rules diff、状态迁移与去抖、RT 轮换持久化、密码哈希与会话、CSRF 中间件、settings 读写。
- Handler：`httptest` + 内存 SQLite 跑关键路由（登录、账号 CRUD、权限拦截、掩码输出——**断言响应中不出现完整 RT**）。
- 集成（build tag `live`，手动跑）：用 1-2 个**自有测试账号**验证全链路。
- 对账式验证（参考模板精神）：每实现一个检查项，用真实账号手动触发对应异常（改密码使 RT 失效、加转发规则）确认判定正确，结果记 devlog。

## 14. 已知风险与待验证（spike）

1. **消费者"自动转发"开关的 API 可见性**：outlook.com 网页端 Settings→Mail→Forwarding 的设置不一定走 messageRules。**Spike**：用测试账号开关该设置，观察 `messageRules`/`mailboxSettings` 响应是否变化；若不可见，在 status-codes 中明确"仅审计规则类转发"的口径边界并写入 README 局限。
2. **scope 与 client_id 绑定**：IMAP/SMTP scope 常需特定公开 client_id（如 Thunderbird `9e5f94bc-...`）在首次授权时声明；RT 授权时没要的 scope 事后补不了 → 账号表单中做 scope 提示与检查结果展示。
3. **风控**：高频/规律化请求可能触发微软风控 → 默认 interval≥15m + jitter + 支持每账号代理。
4. **banned 判定置信度**：`service abuse mode` 是社区验证过的信号，但微软文案可能变 → classify 用"包含匹配+兜底表"，新错误码先记 unknown 再人工归类（见 AGENTS.md §5）。
5. **RT 轮换失败**：DB 写失败可能丢新 RT → 写失败要告警且下一轮用旧 RT 重试（旧 RT 通常仍有一窗口期有效）。
6. **凭据 at rest**：RT 存 SQLite 明文列——依赖文件系统权限（0600）与进程隔离；可选加密列（env 注入 key）列为后续增强，记为决策候选而非默认。
7. **登录暴力破解**：局域网/VPS 暴露面 → session 限速 + 固定延迟响应 + 不区分"用户不存在/密码错"。
8. **config.yaml 与 DB 的一致性**：业务配置只允许 DB 改（WebUI/CLI 写库），config.yaml 只含引导项——禁止双写漂移。

## 15. 构建、发布与部署

### 15.1 构建矩阵

开发在 Windows，交付为静态单二进制。依赖全部 pure-Go（`modernc.org/sqlite`、无 MSAL、无 web 框架），模板/静态资源经 `go:embed` 内嵌——因此 **`CGO_ENABLED=0` 交叉编译无任何障碍**。

| 目标 | 用途 | 命令（开发机 git-bash / Linux 通用） |
|------|------|------|
| windows/amd64 | 本机开发测试 | `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(git describe --tags --always)" -o dist/watchdog-windows-amd64.exe ./cmd/watchdog` |
| linux/amd64 | 服务器部署 | `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=$(git describe --tags --always)" -o dist/watchdog-linux-amd64 ./cmd/watchdog` |
| linux/arm64 | ARM VPS（可选） | `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -X main.version=$(git describe --tags --always)" -o dist/watchdog-linux-arm64 ./cmd/watchdog` |

- 版本号：`main.version` 经 `-X` 注入 git describe；commit/时间由 `runtime/debug.ReadBuildInfo` 自动携带，在 `/system` 页与 `watchdog status` 展示。
- 统一入口：`scripts/release.sh` 一次产出全部目标到 `dist/`（gitignore）。
- 可选增强：接 goreleaser（当前不引入，记为候选）。

### 15.2 部署形态

- 部署物 = 单个二进制 + `config.yaml`（引导项）+ `data/`（SQLite，自动初始化与迁移）。
- `watchdog serve` 以 systemd 常驻，启动时自动 `migrate`；升级 = 换二进制 + `systemctl restart`。
- **对外暴露必须经反向代理 HTTPS**（Caddy 最简）；二进制本身只监听 `127.0.0.1:8080`。明文 HTTP 直挂公网属高危（管理着真实邮箱凭据）。
- 完整安装步骤、systemd unit、反代配置、升级与备份流程见 [deploy.md](./deploy.md)。

## 16. 参考项目（知识来源，非依赖）

- `daimon3332/OutlookManage`：`backend/services/diagnostics.py`（AADSTS→健康分类）、`scope.md`（scope 矩阵）、WebUI 功能形态参考——本项目分类知识与页面信息架构主要来源
- `daimon3332/Outlook-Oauth-GetToken`：初始 RT 获取方案
- `0xa1bed0/mail-healthcheck`：roundtrip 与防滥用节流设计参考
- `pholzaepfel/o365-email-rule-monitor`：规则告警语义参考（M365 侧）
