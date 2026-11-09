# AGENTS.md

> 本文件写给 AI 编码代理（Devin / Codex / Claude Code / Cursor 等）和协作开发者。
> 人类读者请先看 [README.md](./README.md)。
> 规则用"必须 / 禁止"表述。如临时指令与本文件冲突，先向项目负责人确认，不要自行取舍。

---

## 0. 开工前必读

按顺序读完再动手：

1. `README.md`：目标与口径摘要
2. `docs/design.md`：架构、检查项定义、里程碑，**设计唯一权威来源**
3. `docs/status-codes.md`：错误 → 状态判定口径，**分类唯一权威来源**
4. `docs/devlog/` 中最近 3 篇：上次做到哪、有什么遗留

---

## 1. 项目一句话

对个人 Outlook / Hotmail 账号做无人值守健康检查（账号是否被锁定、能否收发邮件、转发/收件箱规则是否异常），状态迁移时通过**独立渠道**（webhook / 独立 SMTP）告警；Go 单二进制 + 内嵌 WebUI 管理后台（embed + htmx，无 node 构建链），`serve` 常驻提供调度与界面，`check --once` 可走 cron。

---

## 2. 目录职责

| 路径 | 职责 | 规则 |
|------|------|------|
| `cmd/watchdog/` | CLI 入口与子命令 | 只负责参数解析与编排，不写业务逻辑 |
| `internal/config/` | 引导配置加载、校验、`${ENV}` 展开 | 只管进程级项（listen/data_dir）；业务配置在库中 |
| `internal/store/` | SQLite 连接、`migrations/`、各表 DAO | schema 变更只能走 `migrations/NNN_*.sql`，属重大变更 |
| `internal/msauth/` | token 刷新、audience scope 切换 | RT 轮换必须回调持久化层 |
| `internal/graph/` | Graph 客户端（/me、messages、sendMail、messageRules） | 不做判定，只返回原始结果 |
| `internal/probe/` | IMAP/SMTP XOAUTH2 探测 | 可选检查，独立成包 |
| `internal/classify/` | 错误 → 状态分类 | **纯函数**，口径以 status-codes.md 为准 |
| `internal/check/` | 检查项编排（C1–C8） | 编排不含分类逻辑 |
| `internal/notify/` | webhook / SMTP 告警 | 告警通道必须独立于被监控账号 |
| `internal/sched/` | run 循环、jitter、限流、日志清理 | |
| `internal/web/` | HTTP 服务：handlers、session/CSRF 中间件、embed | 输出一律脱敏（见 §4.1） |
| `web/templates/` `web/static/` | html/template 页面、vendored htmx/css | 由 `internal/web` embed；禁止引入 node 构建链 |
| `docs/design.md` / `docs/status-codes.md` | 设计与口径权威文档 | 代码不得与之矛盾 |
| `docs/deploy.md` | Linux 部署、systemd、HTTPS 反代 | 部署流程变更同步此文件 |
| `scripts/release.sh` | 交叉编译发布脚本 | 构建目标/ldflags 变更同步此文件 |
| `docs/devlog/` `docs/decisions/` | 开发记录 / 决策记录 | 见 §8、§5 |
| `config.example.yaml` | 引导配置模板 | 可提交；schema 变动必须同步 |
| `config.yaml` `.env` | 真实凭据 | **禁止提交**，见 §4.1 |
| `data/` `logs/` | watchdog.sqlite / 运行日志 | **禁止提交**，见 §4.3 |

---

## 3. 常用命令

```bash
go build -o bin/watchdog.exe ./cmd/watchdog   # 构建（Windows）
go test ./...                                 # 提交前必须通过
go vet ./... && gofmt -l .                    # 必须零输出

watchdog serve                   # 调度器 + WebUI 常驻（主用法）
watchdog check --once            # 跑一轮检查；exit 0 全ok / 1 有failed|degraded / 2 程序错误
watchdog snapshot --account x    # 建立/重置 rules 基线
watchdog status                  # 查看当前各账号状态
watchdog test-notify             # 验证告警通道
watchdog migrate                 # 手动执行 DB 迁移（serve 启动时自动执行）

bash scripts/release.sh          # 交叉编译发布：dist/ 下出 windows/linux 目标
                                 # 服务器部署与 HTTPS 反代见 docs/deploy.md

go test -tags=live ./internal/check/ -run Live   # 手动真实账号验证（不进 CI）
```

命令与 README 必须保持一致；新增或修改命令时同步更新两处。

---

## 4. 安全与运行铁律

### 4.1 凭据与脱敏

1. refresh_token、access_token、密码、SMTP 凭据只进 `config.yaml` / `.env` / SQLite 凭据列，**禁止提交 git，禁止写入日志、devlog、commit message、issue**。
2. 日志中的敏感值必须打码：token 一律不输出；email 输出形如 `t***k@outlook.com`。
3. **WebUI/API 输出同样必须脱敏**：接口与页面返回的 RT/密码只露首尾 2 字符；详情接口不返回完整凭据。handler 测试必须断言响应不含完整 RT。
4. 管理员密码只存 argon2id/bcrypt 哈希；session cookie 必须 `HttpOnly; SameSite=Lax`；非 GET 请求必须校验 CSRF token；登录必须限速。
5. `config.yaml`、`data/`、`logs/`、`.env` 必须在 `.gitignore` 中；新增凭据类配置项时同步检查。
6. **测试凭据使用纪律（用户明确要求，优先级最高）**：`.env` 中的账号密码仅可用于登录/获取 token 等真实测试，但必须满足：
   - 禁止以明文写入 `.env` 以外的任何文件、日志、测试 fixture、commit message、devlog、issue、页面输出；
   - 禁止上传到云端或任何外部服务；
   - 禁止在终端输出中显示明文（不用 `cat .env`/`echo` 打印；密码不进命令行参数——argv 会留在 shell history 与进程列表）；
   - 只允许通过不暴露明文的机制使用：`Set-Clipboard` 提取到剪贴板后粘贴、stdin 管道、环境变量注入（脚本内提取但不回显）。

### 4.2 调用纪律（防风控 + 防骚扰）

1. 检查 `interval` 不得低于 5m，默认 15m，必须叠加 `jitter`（±20%）；禁止把请求做成等间隔。
2. 网络类错误重试 ≤3 次，指数退避；HTTP 429 必须尊重 `Retry-After`；4xx 不重试。禁止无限重试。
3. `roundtrip` / `sendMail` 类真实发信检查默认关闭；开启后频率不得低于 30min/次。
4. 代理按账号配置；多账号并发默认 ≤3，避免同一出口 IP 高频请求微软端点。

### 4.3 状态与存储（SQLite 为运行时唯一权威数据源）

1. 开启 `PRAGMA journal_mode=WAL`、`foreign_keys=ON`；`data/` 目录权限 0700。
2. 表结构变更只能通过 `internal/store/migrations/NNN_说明.sql`，属破坏性变更（§9）。
3. **RT 轮换必须持久化**：每次成功 grant 返回的新 refresh_token 必须在事务内写回 `accounts` 表；写失败记 error 并告警——丢 RT = 监控失联。
4. `check_runs`/`check_results` 只增不删（保留期清理任务除外）；**失败的检查同样要记录**（含分类结果与脱敏错误摘要）；`detail` 字段禁止含 token/密码。
5. 业务配置（账号、调度参数、告警渠道）只允许经 WebUI/CLI 写库；`config.yaml` 只含引导项，**禁止双写漂移**。

### 4.4 告警纪律

1. **禁止用被监控账号发告警**（它锁死时告警就死了）；SMTP 告警必须用独立发信账号。
2. 只在账号级状态**迁移**时告警；同状态不重复告警；→ok 必须发恢复通知。
3. `failed`/`degraded` 需连续 `fail_threshold` 轮确认后才告警；`unknown` 与 `failed` 必须分开表述，禁止把网络抖动报成账号故障。

### 4.5 通用

1. 不引不必要依赖；能标准库解决的不用第三方（RT grant 就是一次 form POST）。
2. **禁止引入 cgo 依赖**——单二进制 `CGO_ENABLED=0` 交叉编译是硬要求（Windows 开发 → Linux 交付）；选依赖前确认 pure-Go。
3. 真实外网调用一律走可注入的 `*http.Client` / dialer，保证测试可替换。

---

## 5. 口径规则

1. 分类口径以 `docs/status-codes.md` 为准。代码里不得出现与文档不一致的隐含分类（如偷偷把 `unknown` 算进 `failed`）。
2. 遇到文档未覆盖的新错误码/新响应模式：**先归类，不要猜**。记录到 `docs/decisions/`、更新 `status-codes.md` 与 classify 实现，三处一起改。
3. `banned`（锁定/封禁）、`token_invalid`（RT 失效）、`unknown`（网络问题）是三类处置完全不同的问题，分类时禁止合并。
4. scope 缺失导致的 403 记 `unavailable`，禁止误报为账号异常。
5. 规则审计以 `snapshot` 显式建立的基线为准；未建基线记 `baseline_missing`，禁止拿空基线 diff 出满屏误报。
6. 修改口径 = 重大变更（见 §7.2）。

---

## 6. 代码与测试规范

- Go ≥ 1.22；格式化 `gofmt`，静态检查 `go vet`，建议 `golangci-lint run`。
- `classify`、规则 diff、状态聚合、去抖判断写成**纯函数**，便于表驱动测试。
- HTTP 依赖用 `httptest` 起假端点；微软真实错误载荷存 `internal/classify/testdata/` 做 golden fixture。
- 必须有测试的内容：
  - classify 全分类表（含 `service abuse` 文案变体、AADSTS50053/50057、429/5xx）
  - rules diff（新增转发规则→fail；新增普通规则→degraded；基线缺失→baseline_missing）
  - 状态迁移与 fail_threshold 去抖（不误报、不漏报恢复）
  - RT 轮换持久化（事务内写回）
  - config `${ENV}` 展开与校验
  - handler 测试（`httptest`+内存 SQLite）：登录/session/CSRF 拦截、账号 CRUD、**响应脱敏断言**
- **禁止真实外网单测**：需要真实账号的验证用 `//go:build live` 隔离，手动执行并记 devlog。
- 每完成一个检查项，用自有测试账号**手动触发对应异常**（改密码→token_invalid；加转发规则→rules fail）做一次对账验证，结果记 devlog。

---

## 7. Git 工作流

### 7.1 分支

| 分支 | 用途 |
|------|------|
| `main` | 稳定分支，任何时候都应可构建、测试通过 |
| `feat/<主题>` | 新功能（如 `feat/imap-probe`） |
| `fix/<主题>` | 缺陷修复 |
| `refactor/<主题>` | 重构 |
| `breaking/<主题>` | 破坏性变更（见 §9） |
| `docs/<主题>` | 仅文档 |

### 7.2 什么是"重大变更"（必须开分支）

满足任一条即视为重大变更：

- 修改状态判定口径（status-codes.md 的映射、聚合、告警规则）
- 修改 config schema、SQLite schema（migration）或凭据存储方式
- 改变 CLI 子命令、参数、退出码语义或 HTTP API 契约
- 新增/删除检查项、告警渠道或 WebUI 页面
- 改变认证/会话/CSRF 机制或脱敏策略
- 引入新的核心依赖（含前端库——当前仅 vendored htmx）

不确定算不算时，按重大变更处理。

### 7.3 小变更与阶段提交

- 小变更（文档修订、单点 bug、补测试）可以直接在当前分支提交。
- **每完成一个小阶段就 commit 一次**。"小阶段"举例：classify 分类表完成并有测试；一个检查项编排通了；一个告警通道可用。
- 禁止把多个阶段混成一个 commit；禁止"攒一大堆最后一起提交"。
- 提交前必须：`go test ./...` 通过、`gofmt`/`vet` 干净、相关文档（README / design / status-codes / devlog）已更新。

### 7.4 Commit 信息

格式：Conventional Commits，中文描述。

```
<type>(<scope>): <一句话摘要>

背景：为什么做
改动：改了什么（文件/函数/配置项）
完成情况：已完成 X；未完成 Y；已知问题 Z
影响：状态/行为变化（无则写"无"）
验证：跑了哪些测试/对账
```

- `type`：`feat` `fix` `docs` `refactor` `test` `chore`
- `scope`：`auth` `graph` `probe` `rules` `store` `web` `notify` `sched` `cli` `config` `docs`
- 破坏性变更在正文末尾追加 `BREAKING CHANGE:` 段落，写法见 §9。

### 7.5 合并规则

1. 重大变更分支合并到 `main` 前：测试通过、devlog 已写、README/design/status-codes 已同步、与 `main` 无冲突。
2. 使用 `git merge --no-ff`，保留分支历史。
3. 合并后打 tag（如 `v0.1.0-m1`），并在 devlog 中记录 tag。
4. 合并破坏性变更前，必须得到项目负责人明确确认。

### 7.6 禁止事项

- 禁止 force push `main`。
- 禁止在测试失败时合并。
- 禁止提交 `config.yaml`、`.env`、token、`data/`、`logs/`。
- 禁止用 `--no-verify` 绕过检查。

---

## 8. 开发记录（devlog）

每次开发（一个分支或一个独立任务）在 `docs/devlog/` 新增一篇：`YYYY-MM-DD-<主题>.md`，使用附录 A 模板。必须写清：

1. **背景**：为什么做这件事，触发原因，相关决策
2. **修改情况**：改了哪些文件、检查项、配置项
3. **完成情况**：已完成 / 未完成 / 遗留问题 / 下一步
4. **影响**：状态口径、告警行为、配置/存储结构变化
5. **验证**：测试与真实账号对账（手动触发异常 → 观察判定是否符合口径）

开发过程中每个阶段性 commit 后，都要在同一篇 devlog 中追加进展，保持 devlog 与 Git 历史一致。

---

## 9. 破坏性变更

**定义**：删除、重命名或改变已有的检查项/状态口径/config schema/SQLite schema/CLI 或 API 语义，或会使历史状态无法正确迁移的任何改动。

在 §7 的基础上额外要求：

1. 必须使用 `breaking/<主题>` 分支。
2. **动手前先备份**：复制 `data/watchdog.sqlite` 到 `data/backup/`（带时间戳），并给 `main` 打 tag `pre-<主题>`。
3. devlog 必须增写"破坏性变更详情"（模板见附录 A），包含：
   - 变更内容（变更前 → 变更后，逐项列出）
   - 变更原因与替代方案
   - 影响范围（受影响的检查项、状态、告警行为、命令）
   - 迁移步骤（可照做的命令）
   - 回滚步骤（可照做的命令）
   - 验证结果
4. 提交信息末尾追加：

   ```
   BREAKING CHANGE: <一句话说明>
   影响：<受影响对象>
   迁移：<迁移方式>
   回滚：<回滚方式>
   ```

5. 合并前须获得项目负责人确认；合并后打 tag `post-<主题>`。

---

## 10. 代理行为准则

1. 动手前用几句话说明计划；涉及重大变更时，先征得确认。
2. 口径不明确、微软接口行为不确定时，提问或标记 spike，不要猜（典型例子：消费者"自动转发"是否经 messageRules 可见，见 design.md §14）。
3. 每个阶段结束时汇报：做了什么、验证了什么、还有什么未完成、有什么风险。
4. 测试或真实账号验证中观察到与 `status-codes.md` 不符的行为时，先记录并告知，不要悄悄修改分类逻辑去"对齐"现象。
5. 不要为了"让测试通过"而改测试断言或放宽口径；如测试与口径冲突，先确认哪个是对的。
6. 保持改动最小：不顺手重构无关代码，不顺手改无关文档。

---

## 11. 完成定义（DoD）

一项任务只有同时满足下面全部条件才算完成：

- [ ] 功能按 `docs/design.md` 实现，分类行为与 `docs/status-codes.md` 一致
- [ ] 测试已添加并通过，`gofmt`/`vet` 干净；真实外网测试走 `live` tag 隔离
- [ ] 检查记录与 WebUI/API 输出字段完整、无敏感信息泄漏（含脱敏断言）
- [ ] `config.example.yaml`、README、`docs/` 已同步（如有变动）
- [ ] devlog 已写，包含背景、修改、完成情况、对账结果
- [ ] 已按 §7 提交（破坏性变更另按 §9）

---

## 附录 A：devlog 模板（复制为 `docs/devlog/YYYY-MM-DD-<主题>.md`）

```markdown
# <主题>

- 日期：YYYY-MM-DD
- 分支：<branch>
- 类型：feat / fix / refactor / docs / breaking
- 相关 commit / tag：<hash 或 tag>

## 1. 背景
<为什么做；触发原因；相关决策链接>

## 2. 修改情况
- 代码：
- 检查项 / 口径：
- 配置 / 文档：

## 3. 完成情况
- 已完成：
- 未完成：
- 遗留问题 / 风险：
- 下一步：

## 4. 影响
| 对象 | 变更前 | 变更后 | 说明 |
|------|--------|--------|------|

## 5. 验证
- 测试：
- 对账（真实账号手动触发异常 → 判定结果）：

## 6. 破坏性变更详情（非破坏性变更删除本节）
- 变更内容（前 → 后）：
- 变更原因与替代方案：
- 影响范围：
- 迁移步骤：
- 回滚步骤：
- 备份位置 / tag：
- 负责人确认：
```

## 附录 B：commit 示例

```
feat(auth): 实现 refresh_token grant 与 AADSTS 分类器

背景：M1 阶段需先打通"锁定检测"主链路，token grant 是所有检查的前置。
改动：新增 internal/msauth/grant.go、internal/classify/aadsts.go；
      分类表对齐 status-codes.md §2；state 增加 rotated RT 持久化。
完成情况：已完成 ok/banned/token_invalid/unknown 四态分类；sendMail 检查未做。
影响：无（首个功能）。
验证：go test ./... 通过；testdata golden 覆盖 service abuse/50053/50057/429。
```
