// watchdog CLI 入口：参数解析 + 编排，业务逻辑在各 internal 包。
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"outlook-watchdog/internal/check"
	"outlook-watchdog/internal/classify"
	"outlook-watchdog/internal/config"
	"outlook-watchdog/internal/msauth"
	"outlook-watchdog/internal/notify"
	"outlook-watchdog/internal/sched"
	"outlook-watchdog/internal/store"
	"outlook-watchdog/internal/web"
)

var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `outlook-watchdog %s — 个人 Outlook/Hotmail 账号健康看门狗

用法:
  watchdog serve                        调度器 + WebUI 常驻（监听 config.yaml listen）
  watchdog check --once [--account x]   跑一轮检查
  watchdog snapshot --account x         建立/重置 rules 基线
  watchdog status                       查看各账号当前状态
  watchdog account add --email x --client-id y --rt-env VAR [--proxy p]
  watchdog account list
  watchdog account remove --account x
  watchdog run                        常驻调度循环（interval+jitter）
  watchdog channel add|list|remove    告警通道管理（webhook / 独立SMTP）
  watchdog test-notify                发送测试告警
  watchdog settings [list|set ...]    调度参数查看/修改
  watchdog get-token [--client-id id] [--scope s] [--save-env NAME]
  watchdog migrate                      执行 DB 迁移
  watchdog version

凭据安全：RT 一律经环境变量传入（--rt-env 指定变量名），禁止命令行明文。
`, version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cfg, err := config.Load(os.Getenv("WATCHDOG_CONFIG"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var code int
	switch os.Args[1] {
	case "check":
		code = cmdCheck(ctx, cfg, os.Args[2:])
	case "run":
		code = cmdRun(ctx, cfg, os.Args[2:])
	case "snapshot":
		code = cmdSnapshot(ctx, cfg, os.Args[2:])
	case "status":
		code = cmdStatus(ctx, cfg, os.Args[2:])
	case "account":
		code = cmdAccount(ctx, cfg, os.Args[2:])
	case "channel":
		code = cmdChannel(ctx, cfg, os.Args[2:])
	case "alerts":
		code = cmdAlerts(ctx, cfg, os.Args[2:])
	case "test-notify":
		code = cmdTestNotify(ctx, cfg, os.Args[2:])
	case "settings":
		code = cmdSettings(ctx, cfg, os.Args[2:])
	case "get-token":
		code = cmdGetToken(ctx, cfg, os.Args[2:])
	case "migrate":
		code = cmdMigrate(ctx, cfg, os.Args[2:])
	case "serve":
		code = cmdServe(ctx, cfg, os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "--help", "-h":
		usage()
	default:
		usage()
		code = 2
	}
	os.Exit(code)
}

func openStore(cfg *config.Config) (*store.DB, error) {
	return store.Open(cfg.DBPath())
}

// ---- check ----

func newScheduler(db *store.DB) *sched.Scheduler {
	return &sched.Scheduler{
		DB:        db,
		NewRunner: func() *check.Runner { return check.NewRunner(db) },
	}
}

func cmdCheck(ctx context.Context, cfg *config.Config, args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	once := fs.Bool("once", true, "跑一轮后退出")
	acct := fs.String("account", "", "只检查指定账号（id 或 email）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	_ = *once

	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 2
	}
	defer db.Close()

	var onlyID int64
	var byEmail map[int64]*store.Account
	if *acct != "" {
		a, err := db.GetAccount(ctx, *acct)
		if err != nil {
			fmt.Fprintln(os.Stderr, "account:", err)
			return 2
		}
		onlyID = a.ID
	}
	all, _ := db.ListAccounts(ctx, false)
	byEmail = map[int64]*store.Account{}
	for _, a := range all {
		byEmail[a.ID] = a
	}
	if len(all) == 0 {
		fmt.Println("无账号（用 watchdog account add 添加）")
		return 0
	}

	s := newScheduler(db)
	_, _, threshold := s.Params(ctx)
	outs := s.RunOnce(ctx, "cli", threshold, onlyID)
	worst := 0
	for _, out := range outs {
		a := byEmail[out.AccountID]
		if a == nil {
			continue
		}
		if out.Err != nil {
			fmt.Fprintf(os.Stderr, "[%s] run error: %v\n", maskEmail(a.Email), out.Err)
			worst = 2
			continue
		}
		printOutcome(a, out)
		if out.Status == classify.StatusFailed || out.Status == classify.StatusDegraded {
			if worst < 1 {
				worst = 1
			}
		}
	}
	return worst
}

// ---- run（调度循环，无 WebUI） ----

func cmdRun(ctx context.Context, cfg *config.Config, args []string) int {
	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 2
	}
	defer db.Close()
	s := newScheduler(db)
	s.OnRound = func(a *store.Account, status string, err error) {
		ts := time.Now().Format("15:04:05")
		if err != nil {
			fmt.Printf("[%s] %v\n", ts, err)
			return
		}
		if a == nil {
			fmt.Printf("[%s] %s\n", ts, status)
			return
		}
		fmt.Printf("[%s] %s => %s\n", ts, maskEmail(a.Email), status)
	}
	s.Loop(ctx)
	return 0
}

func printOutcome(a *store.Account, out *check.Outcome) {
	fmt.Printf("[%s] => %s\n", maskEmail(a.Email), out.Status)
	for _, r := range out.Results {
		fmt.Printf("    %-9s %-12s %-18s %s\n", r.Check, r.Result, r.Classification, r.Detail)
	}
}

// ---- serve ----

func cmdServe(ctx context.Context, cfg *config.Config, args []string) int {
	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 2
	}
	defer db.Close()

	srv, err := web.New(db, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "web:", err)
		return 2
	}
	sc := srv.Scheduler()
	sc.OnRound = func(a *store.Account, status string, err error) {
		ts := time.Now().Format("15:04:05")
		if err != nil {
			fmt.Printf("[%s] %v\n", ts, err)
			return
		}
		if a == nil {
			fmt.Printf("[%s] %s\n", ts, status)
			return
		}
		fmt.Printf("[%s] %s => %s\n", ts, maskEmail(a.Email), status)
	}
	go sc.Loop(ctx)

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shCtx)
	}()
	fmt.Printf("watchdog %s 监听 http://%s （公网访问请经 HTTPS 反代）\n", version, cfg.Listen)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "http:", err)
		return 2
	}
	return 0
}

// ---- snapshot ----

func cmdSnapshot(ctx context.Context, cfg *config.Config, args []string) int {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	acct := fs.String("account", "", "账号 id 或 email（必填）")
	if err := fs.Parse(args); err != nil || *acct == "" {
		fmt.Fprintln(os.Stderr, "需要 --account")
		return 2
	}
	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 2
	}
	defer db.Close()
	a, err := db.GetAccount(ctx, *acct)
	if err != nil {
		fmt.Fprintln(os.Stderr, "account:", err)
		return 2
	}
	r := check.NewRunner(db)
	sha, err := r.SnapshotBaseline(ctx, a)
	if err != nil {
		fmt.Fprintln(os.Stderr, "snapshot:", err)
		return 1
	}
	fmt.Printf("[%s] rules 基线已建立 sha256=%s\n", maskEmail(a.Email), sha[:12])
	return 0
}

// ---- status ----

func cmdStatus(ctx context.Context, cfg *config.Config, args []string) int {
	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 2
	}
	defer db.Close()
	accounts, err := db.ListAccounts(ctx, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 2
	}
	fmt.Printf("%-3s %-26s %-16s %-6s %-20s %s\n", "ID", "EMAIL", "STATUS", "FAIL", "LAST_CHECK", "ENABLED")
	for _, a := range accounts {
		s, _ := db.GetState(ctx, a.ID)
		fmt.Printf("%-3d %-26s %-16s %-6d %-20s %v\n",
			a.ID, maskEmail(a.Email), s.Status, s.ConsecutiveFail, s.LastCheckAt, a.Enabled)
	}
	return 0
}

// ---- account ----

func cmdAccount(ctx context.Context, cfg *config.Config, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "account 子命令: add|list|remove")
		return 2
	}
	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 2
	}
	defer db.Close()

	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("account add", flag.ContinueOnError)
		email := fs.String("email", "", "邮箱")
		clientID := fs.String("client-id", "", "client_id")
		rtEnv := fs.String("rt-env", "", "存放 refresh_token 的环境变量名（安全：不进 argv）")
		proxy := fs.String("proxy", "", "可选代理，如 socks5://127.0.0.1:7890")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *email == "" || *clientID == "" || *rtEnv == "" {
			fmt.Fprintln(os.Stderr, "需要 --email --client-id --rt-env")
			return 2
		}
		rt := os.Getenv(*rtEnv)
		if rt == "" {
			fmt.Fprintf(os.Stderr, "环境变量 %s 为空（检查 .env 是否已加载该变量名）\n", *rtEnv)
			return 2
		}
		id, err := db.AddAccount(ctx, &store.Account{
			Email: *email, ClientID: *clientID, RefreshToken: rt, Proxy: *proxy,
			Checks: map[string]bool{
				"c1_token": true, "c2_me": true, "c3_recv": true, "c5_rules": true,
			}, Enabled: true,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "add:", err)
			return 1
		}
		fmt.Printf("已添加账号 id=%d email=%s\n", id, maskEmail(*email))
		return 0

	case "list":
		accounts, err := db.ListAccounts(ctx, false)
		if err != nil {
			fmt.Fprintln(os.Stderr, "list:", err)
			return 2
		}
		for _, a := range accounts {
			fmt.Printf("%-3d %-26s client=%s proxy=%s enabled=%v\n",
				a.ID, maskEmail(a.Email), maskMiddle(a.ClientID), a.Proxy, a.Enabled)
		}
		return 0

	case "remove":
		fs := flag.NewFlagSet("account remove", flag.ContinueOnError)
		acct := fs.String("account", "", "id 或 email")
		if err := fs.Parse(args[1:]); err != nil || *acct == "" {
			return 2
		}
		a, err := db.GetAccount(ctx, *acct)
		if err != nil {
			fmt.Fprintln(os.Stderr, "account:", err)
			return 2
		}
		if err := db.DeleteAccount(ctx, a.ID); err != nil {
			fmt.Fprintln(os.Stderr, "remove:", err)
			return 1
		}
		fmt.Printf("已删除账号 %s\n", maskEmail(a.Email))
		return 0
	}
	fmt.Fprintln(os.Stderr, "account 子命令: add|list|remove")
	return 2
}

// ---- get-token ----

func cmdGetToken(ctx context.Context, cfg *config.Config, args []string) int {
	fs := flag.NewFlagSet("get-token", flag.ContinueOnError)
	clientID := fs.String("client-id", msauth.DefaultDeviceCodeClientID, "client_id（默认 Azure CLI 公开 id）")
	scope := fs.String("scope", msauth.GraphScope, "请求 scope")
	saveEnv := fs.String("save-env", "", "把 RT 以 NAME=<rt> 追加写入 .env 的变量名（推荐：RT 不经终端回显）")
	timeout := fs.Duration("timeout", 10*time.Minute, "等待授权超时")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	c := msauth.New()
	dc, err := c.StartDeviceCode(ctx, *clientID, *scope)
	if err != nil {
		fmt.Fprintln(os.Stderr, "devicecode:", err)
		return 1
	}
	fmt.Printf("请打开 %s 输入代码 %s 完成登录（%d 秒内有效）\n",
		dc.VerificationURL, dc.UserCode, dc.ExpiresIn)

	cctx, ccancel := context.WithTimeout(ctx, *timeout)
	defer ccancel()
	rt, err := c.PollDeviceCode(cctx, *clientID, dc.DeviceCode, dc.Interval)
	if err != nil {
		fmt.Fprintln(os.Stderr, "poll:", err)
		return 1
	}
	if *saveEnv != "" {
		if err := appendEnv(".env", *saveEnv, rt); err != nil {
			fmt.Fprintln(os.Stderr, "save-env:", err)
			return 1
		}
		fmt.Printf("授权成功，refresh_token 已写入 .env 变量 %s（未回显明文）\n", *saveEnv)
		return 0
	}
	// 无 --save-env 时才打印到终端（仅显示一次，由用户自行存入 .env）
	fmt.Println("授权成功。refresh_token（仅显示一次，请存入 .env 对应变量）:")
	fmt.Println(rt)
	return 0
}

// appendEnv 把 KEY=VALUE 追加到 .env 文件末尾。
func appendEnv(path, key, value string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "\n%s=\"%s\"", key, value)
	return err
}

// ---- migrate ----

func cmdMigrate(ctx context.Context, cfg *config.Config, args []string) int {
	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		return 1
	}
	defer db.Close()
	fmt.Println("migrations applied")
	return 0
}

// ---- channel ----

func cmdChannel(ctx context.Context, cfg *config.Config, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "channel 子命令: add|list|remove")
		return 2
	}
	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 2
	}
	defer db.Close()

	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "channel add webhook|smtp ...")
			return 2
		}
		switch args[1] {
		case "webhook":
			fs := flag.NewFlagSet("channel add webhook", flag.ContinueOnError)
			name := fs.String("name", "webhook", "通道名")
			url := fs.String("url", "", "webhook URL")
			token := fs.String("token-env", "", "可选：存放 Authorization token 的环境变量名")
			if err := fs.Parse(args[2:]); err != nil || *url == "" {
				fmt.Fprintln(os.Stderr, "需要 --url")
				return 2
			}
			c := &store.Channel{Type: "webhook", Name: *name, Enabled: true,
				Config: map[string]string{"url": *url}}
			if *token != "" {
				c.Config["token"] = os.Getenv(*token)
			}
			id, err := db.AddChannel(ctx, c)
			if err != nil {
				fmt.Fprintln(os.Stderr, "add:", err)
				return 1
			}
			fmt.Printf("已添加 webhook 通道 id=%d\n", id)
			return 0
		case "smtp":
			fs := flag.NewFlagSet("channel add smtp", flag.ContinueOnError)
			name := fs.String("name", "smtp", "通道名")
			host := fs.String("host", "", "SMTP 主机（如 smtp.163.com）")
			port := fs.String("port", "465", "端口：465=SSL，587/25=STARTTLS")
			user := fs.String("user", "", "发信账号（须独立于被监控账号）")
			passEnv := fs.String("pass-env", "", "存放 SMTP 密码/授权码的环境变量名")
			to := fs.String("to", "", "告警接收邮箱")
			if err := fs.Parse(args[2:]); err != nil || *host == "" || *user == "" || *to == "" || *passEnv == "" {
				fmt.Fprintln(os.Stderr, "需要 --host --user --to --pass-env")
				return 2
			}
			pass := os.Getenv(*passEnv)
			if pass == "" {
				fmt.Fprintf(os.Stderr, "环境变量 %s 为空\n", *passEnv)
				return 2
			}
			id, err := db.AddChannel(ctx, &store.Channel{Type: "smtp", Name: *name, Enabled: true,
				Config: map[string]string{"host": *host, "port": *port, "user": *user, "pass": pass, "to": *to}})
			if err != nil {
				fmt.Fprintln(os.Stderr, "add:", err)
				return 1
			}
			fmt.Printf("已添加 smtp 通道 id=%d (%s→%s)\n", id, maskEmail(*user), maskEmail(*to))
			return 0
		}
		fmt.Fprintln(os.Stderr, "channel add 类型: webhook|smtp")
		return 2

	case "list":
		chs, err := db.ListChannels(ctx, false)
		if err != nil {
			fmt.Fprintln(os.Stderr, "list:", err)
			return 2
		}
		for _, c := range chs {
			masked := map[string]string{}
			for k, v := range c.Config {
				if k == "pass" || k == "token" {
					v = "****"
				}
				masked[k] = v
			}
			fmt.Printf("%-3d %-8s %-12s enabled=%v %v\n", c.ID, c.Type, c.Name, c.Enabled, masked)
		}
		return 0

	case "remove":
		fs := flag.NewFlagSet("channel remove", flag.ContinueOnError)
		id := fs.Int64("id", 0, "通道 id")
		if err := fs.Parse(args[1:]); err != nil || *id == 0 {
			return 2
		}
		if err := db.DeleteChannel(ctx, *id); err != nil {
			fmt.Fprintln(os.Stderr, "remove:", err)
			return 1
		}
		fmt.Printf("已删除通道 id=%d\n", *id)
		return 0
	}
	fmt.Fprintln(os.Stderr, "channel 子命令: add|list|remove")
	return 2
}

// ---- test-notify ----

func cmdTestNotify(ctx context.Context, cfg *config.Config, args []string) int {
	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 2
	}
	defer db.Close()
	chs, err := db.ListChannels(ctx, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "channels:", err)
		return 2
	}
	if len(chs) == 0 {
		fmt.Println("无启用告警通道（用 watchdog channel add 添加）")
		return 0
	}
	msg := &notify.Message{
		Subject: "[watchdog·测试] 告警通道验证",
		Body:    "这是一条测试告警。\n时间: " + time.Now().UTC().Format(time.RFC3339),
		At:      time.Now().UTC().Format(time.RFC3339),
	}
	code := 0
	for _, ch := range chs {
		sender, ok := notify.Senders[ch.Type]
		if !ok {
			fmt.Printf("通道 %d (%s): 未知类型\n", ch.ID, ch.Type)
			code = 1
			continue
		}
		if err := sender.Send(ctx, ch.Config, msg); err != nil {
			fmt.Printf("通道 %d (%s:%s): 发送失败 %v\n", ch.ID, ch.Type, ch.Name, err)
			code = 1
		} else {
			fmt.Printf("通道 %d (%s:%s): 发送成功\n", ch.ID, ch.Type, ch.Name)
		}
	}
	return code
}

// ---- alerts ----

func cmdAlerts(ctx context.Context, cfg *config.Config, args []string) int {
	fs := flag.NewFlagSet("alerts", flag.ContinueOnError)
	limit := fs.Int("limit", 20, "条数")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 2
	}
	defer db.Close()
	evs, err := db.ListAlerts(ctx, *limit)
	if err != nil {
		fmt.Fprintln(os.Stderr, "alerts:", err)
		return 2
	}
	fmt.Printf("%-4s %-20s %-12s %-22s %s\n", "ID", "SENT_AT", "TRANSITION", "CHANNEL", "REASON/ERROR")
	for _, e := range evs {
		tr := e.FromStatus + "→" + e.ToStatus
		errTag := ""
		if e.Error != "" {
			errTag = " err=" + e.Error
		}
		fmt.Printf("%-4d %-20s %-12s %-22s %s%s\n", e.ID, e.SentAt, tr, e.Channel, e.Reason, errTag)
	}
	return 0
}

// ---- settings ----

func cmdSettings(ctx context.Context, cfg *config.Config, args []string) int {
	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 2
	}
	defer db.Close()
	if len(args) == 0 || args[0] == "list" {
		s := newScheduler(db)
		iv, jt, th := s.Params(ctx)
		fmt.Printf("schedule.interval_min=%d\nschedule.jitter=%.2f\nschedule.fail_threshold=%d\n", iv, jt, th)
		return 0
	}
	if args[0] == "set" && len(args) == 3 {
		key := args[1]
		if !strings.Contains(key, ".") {
			key = "schedule." + key
		}
		if err := db.SetSetting(ctx, key, args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "set:", err)
			return 1
		}
		fmt.Printf("%s=%s\n", key, args[2])
		return 0
	}
	fmt.Fprintln(os.Stderr, "settings [list|set interval_min|jitter|fail_threshold <值>]")
	return 2
}

// ---- 脱敏工具 ----

func maskEmail(e string) string {
	local, domain, ok := strings.Cut(e, "@")
	if !ok || len(local) == 0 {
		return maskMiddle(e)
	}
	if len(local) <= 2 {
		return local[:1] + "***@" + domain
	}
	return local[:1] + "***" + local[len(local)-1:] + "@" + domain
}

func maskMiddle(s string) string {
	if len(s) <= 6 {
		return "****"
	}
	return s[:3] + "…" + s[len(s)-2:]
}
