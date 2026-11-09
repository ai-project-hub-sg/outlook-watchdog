# outlook-watchdog
检查outlook邮箱是否被锁定。能否正常收发邮件。转发设置是否正常。如果异常将邮件提醒。

内置 WebUI 管理后台（账号管理、检查历史、告警渠道、调度配置），Go 单二进制交付。

## 快速开始

```bash
go build -o bin/watchdog.exe ./cmd/watchdog

# 1) device code 拿 refresh_token（浏览器登录一次；RT 直接写入 .env）
./bin/watchdog.exe get-token \
  --client-id 14d82eec-204b-4c2f-b7e8-296a70dab67e \
  --save-env OUTLOOK_RT1

# 2) 登记账号（RT 走环境变量，不进命令行）
./bin/watchdog.exe account add --email you@outlook.com \
  --client-id 14d82eec-204b-4c2f-b7e8-296a70dab67e --rt-env OUTLOOK_RT1

# 3) 建立转发规则基线 + 跑检查
./bin/watchdog.exe snapshot --account you@outlook.com
./bin/watchdog.exe check --once     # exit 0 全ok / 1 有异常 / 2 程序错误
./bin/watchdog.exe status
```

设计与口径文档：[docs/design.md](docs/design.md) · [docs/status-codes.md](docs/status-codes.md) · 部署：[docs/deploy.md](docs/deploy.md) · 协作规范：[AGENTS.md](AGENTS.md)
