# outlook-watchdog

个人 Outlook.com/Hotmail 邮箱健康监控：账号是否被锁定、能否正常收发邮件、
转发规则是否被篡改；异常时经独立通道（SMTP/webhook）发邮件告警，恢复后通知。

内置 WebUI 管理后台（账号管理、OAuth 授权向导、检查历史、告警渠道、调度配置、
日志导出），Go 单二进制交付（CGO_ENABLED=0，SQLite 嵌入式存储）。

## 检查项

| 检查 | 内容 | 默认 |
|---|---|---|
| c1_token | refresh_token 兑换，识别锁定/禁用/滥用（AADSTS 分类） | 开 |
| c2_me | Graph `/me` 探活 | 开 |
| c3_recv | 收件箱 top1 读 | 开 |
| c5_rules | 收件规则与基线比对（forwardTo/redirectTo/隐藏移动/删除） | 开 |
| c4_send | Graph sendMail 探信（真实发信） | 关 |
| c6_imap | IMAP XOAUTH2 认证探活 | 关 |
| c7_smtp | SMTP XOAUTH2 认证探活（个人邮箱微软禁 SMTP AUTH，恒 unavailable） | 关 |
| c8_roundtrip | 自发→收→删 端到端 roundtrip（真实发信） | 关 |

调度：核心检查每小时一轮，每账号相位错峰（哈希散布+微扰）；真实发信类
自适应限频——核心健康时约 1 次/天，核心异常时升至约 3 次/天辅助排查。

新账号首次检查为 `degraded · 需建基线`（c5 无基准），属预期——进详情页
确认当前规则集后点「重建规则基线」即转 `ok`。基线不自动建立，防止把已有
恶意转发规则洗进基准。

## 快速开始（WebUI，推荐）

```bash
go build -o bin/watchdog.exe ./cmd/watchdog   # 或取 dist/ 预编译包
./bin/watchdog.exe serve                       # http://127.0.0.1:8080
```

1. 首启 → `/setup` 设置管理员密码（bcrypt，≥10 位）
2. 账号页 →「发起授权」→ 输设备码登录目标邮箱（无痕窗口避免签错账号）
   → 自动识别绑定邮箱、自动添加、自动首轮检查
3. 详情页 →「重建规则基线」→ 状态转 `ok`
4. 通道页 → 添加 SMTP 告警通道（发信方需 SMTP 授权码，如 163 客户端授权码）
   → 「测试」验证路由

授权范围：「标准」= Graph 四项（核心检查够用）；「完整」附加
IMAP/SMTP 协议 scope（自建 Entra app 才支持，见 docs/register-app.md）。
默认 client_id 为 Microsoft Graph PowerShell 公共应用，可在设置页覆盖。

## 命令行

```bash
watchdog serve                       # 调度器 + WebUI 单进程
watchdog check --once [--account x]  # 手动一轮（exit 1=有异常）
watchdog snapshot --account x        # 重建 c5 规则基线
watchdog status                      # 账号当前状态
watchdog account add|list|remove     # 账号管理
watchdog channel add|list|remove     # 告警通道
watchdog test-notify --id N          # 通道测试
watchdog alerts                      # 告警历史
watchdog settings list|set           # 调度参数（schedule.interval_min 等）
watchdog get-token --client-id X --save-env OUTLOOK_RT1  # CLI 取 RT
watchdog migrate                     # 执行数据库迁移
```

## 部署到 Linux

```bash
bash scripts/release.sh   # 产出 dist/watchdog-{windows-amd64.exe,linux-amd64,linux-arm64}
scp dist/watchdog-linux-amd64 server:/opt/watchdog/watchdog
```

服务器端**只需一个引导配置** `/opt/watchdog/config.yaml`：

```yaml
listen: 127.0.0.1:8080          # 公网必须套 HTTPS 反代（Caddy/nginx）
data_dir: /opt/watchdog/data    # SQLite+凭据所在，chmod 700
log_dir: /opt/watchdog/logs
```

**不需要 .env**——`.env` 只是开发期本地秘密注入手段；生产秘密经 WebUI
写入（RT 服务端持有、密码 bcrypt），`${ENV}` 占位符在 config.yaml 里也支持，
由进程环境变量展开。systemd 单元与反代示例见 [docs/deploy.md](docs/deploy.md)。

## 安全纪律

- RT/密码/授权码永不进 HTML、日志、JSONL 导出；RT 仅前后 4 字符掩码显示
- 所有页面邮箱地址掩码（首字符+域名保留，便于识别转发目标）
- session cookie 12h、CSRF 校验、登录限速 5 次/10 分钟
- 删除账号默认软删除（保留全部检查/告警历史），可选硬删除

## 文档

- [docs/design.md](docs/design.md) 架构与决策
- [docs/status-codes.md](docs/status-codes.md) 状态口径（ok/degraded/failed/unavailable/error）
- [docs/deploy.md](docs/deploy.md) Linux 部署（systemd/反代）
- [docs/register-app.md](docs/register-app.md) 自建 Entra app（含实测结论）
- [docs/devlog/](docs/devlog/) 里程碑开发日志
- [AGENTS.md](AGENTS.md) 协作规范
