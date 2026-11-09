# 部署指南（Linux）

> 开发在 Windows 交叉编译 linux/amd64 二进制，scp 到服务器以 systemd 常驻运行。
> 对外提供服务必须套 HTTPS 反代——本工具管理真实邮箱凭据，明文 HTTP 公网直挂 = 凭据裸奔。

## 1. 构建（Windows 开发机，git-bash）

```bash
# 本机测试版
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/watchdog.exe ./cmd/watchdog

# Linux 部署版（或用 scripts/release.sh 一次出全部目标）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags="-s -w -X main.version=$(git describe --tags --always)" \
  -o dist/watchdog-linux-amd64 ./cmd/watchdog
```

## 2. 服务器安装

```bash
# 专用用户与目录
sudo useradd -r -s /usr/sbin/nologin watchdog
sudo mkdir -p /opt/watchdog/{data,logs}
sudo cp dist/watchdog-linux-amd64 /opt/watchdog/watchdog
sudo chmod 750 /opt/watchdog/watchdog
sudo chown -R watchdog:watchdog /opt/watchdog
sudo chmod 700 /opt/watchdog/data          # 凭据所在，必须收紧

# 引导配置（仅需这几项）
sudo -u watchdog tee /opt/watchdog/config.yaml <<'EOF'
listen: 127.0.0.1:8080
data_dir: /opt/watchdog/data
log_dir: /opt/watchdog/logs
admin_password: ${WATCHDOG_ADMIN_PASSWORD}   # 或留空走首启 setup 页
EOF
sudo chmod 600 /opt/watchdog/config.yaml
```

## 3. systemd 常驻

`/etc/systemd/system/watchdog.service`：

```ini
[Unit]
Description=outlook-watchdog
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=watchdog
Group=watchdog
WorkingDirectory=/opt/watchdog
ExecStart=/opt/watchdog/watchdog serve
Restart=on-failure
RestartSec=5s
Environment=WATCHDOG_ADMIN_PASSWORD=改成强密码
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/watchdog/data /opt/watchdog/logs
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now watchdog
systemctl status watchdog     # 首次启动自动建库跑 migration，随后按引导到 :8080 完成 setup
```

## 4. HTTPS 反代（Caddy，最简）

`/etc/caddy/Caddyfile`：

```
watchdog.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

```bash
sudo systemctl reload caddy
```

nginx 等价配置略。反代落地后浏览器访问 `https://watchdog.example.com` 登录管理后台。

**公网部署额外注意**：

- 管理员密码必须强随机（建议 ≥16 位）；登录已内置限速但仍建议叠加反代层限流。
- 确认 `listen` 保持 `127.0.0.1:8080`，仅反代可触达；`sudo ss -tlnp | grep 8080` 复核。
- 如需对公网开放，考虑再叠一层（如只允许办公网出口 IP 访问反代）。

## 5. 升级

```bash
# 本地交叉编译新版本 → scp 上传 → 替换 → 重启
scp dist/watchdog-linux-amd64 server:/tmp/watchdog
ssh server 'sudo systemctl stop watchdog && sudo cp /tmp/watchdog /opt/watchdog/watchdog \
  && sudo chown watchdog:watchdog /opt/watchdog/watchdog && sudo systemctl start watchdog'
```

启动时自动执行 DB migration；破坏性 schema 变更按 AGENTS.md §9 需先备份并打 tag。

## 6. 备份

```bash
# SQLite 在线备份（WAL 下安全做法）
sudo -u watchdog sqlite3 /opt/watchdog/data/watchdog.sqlite \
  ".backup '/opt/watchdog/backup/watchdog-$(date +%F).sqlite'"
```

建议每日 cron 备份 + 异地拷贝。`data/` 内含全部账号 RT，备份文件与生产库同等密级。

## 7. Windows 本机测试（开发自测流程）

```powershell
go build -o bin\watchdog.exe .\cmd\watchdog
.\bin\watchdog.exe serve          # 默认 127.0.0.1:8080，浏览器打开完成 setup
```

本机无需 systemd/反代；`data/`、`logs/`、`config.yaml` 均已在 .gitignore。
