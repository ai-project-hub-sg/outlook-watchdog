// watchdog CLI 入口：参数解析 + 编排，业务逻辑在各 internal 包。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"outlook-watchdog/internal/check"
	"outlook-watchdog/internal/classify"
	"outlook-watchdog/internal/config"
	"outlook-watchdog/internal/msauth"
	"outlook-watchdog/internal/store"
)

var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `outlook-watchdog %s — 个人 Outlook/Hotmail 账号健康看门狗

用法:
  watchdog serve                        调度器 + WebUI 常驻（M4 实现）
  watchdog check --once [--account x]   跑一轮检查
  watchdog snapshot --account x         建立/重置 rules 基线
  watchdog status                       查看各账号当前状态
  watchdog account add --email x --client-id y --rt-env VAR [--proxy p]
  watchdog account list
  watchdog account remove --account x
  watchdog get-token [--client-id id] [--scope s]   device code 获取初始 RT
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
	case "snapshot":
		code = cmdSnapshot(ctx, cfg, os.Args[2:])
	case "status":
		code = cmdStatus(ctx, cfg, os.Args[2:])
	case "account":
		code = cmdAccount(ctx, cfg, os.Args[2:])
	case "get-token":
		code = cmdGetToken(ctx, cfg, os.Args[2:])
	case "migrate":
		code = cmdMigrate(ctx, cfg, os.Args[2:])
	case "serve":
		fmt.Fprintln(os.Stderr, "serve 将在 M4 里程碑提供（调度器+WebUI）")
		code = 2
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

	var accounts []*store.Account
	if *acct != "" {
		a, err := db.GetAccount(ctx, *acct)
		if err != nil {
			fmt.Fprintln(os.Stderr, "account:", err)
			return 2
		}
		accounts = []*store.Account{a}
	} else {
		accounts, err = db.ListAccounts(ctx, true)
		if err != nil {
			fmt.Fprintln(os.Stderr, "store:", err)
			return 2
		}
	}
	if len(accounts) == 0 {
		fmt.Println("无启用账号（用 watchdog account add 添加）")
		return 0
	}

	r := check.NewRunner(db)
	worst := 0
	for _, a := range accounts {
		ar := *a // 每账号独立状态
		out, err := r.RunAccount(ctx, &ar, "cli")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] run error: %v\n", maskEmail(ar.Email), err)
			worst = 2
			continue
		}
		printOutcome(&ar, out)
		if out.Status == classify.StatusFailed || out.Status == classify.StatusDegraded {
			if worst < 1 {
				worst = 1
			}
		}
	}
	return worst
}

func printOutcome(a *store.Account, out *check.Outcome) {
	fmt.Printf("[%s] => %s\n", maskEmail(a.Email), out.Status)
	for _, r := range out.Results {
		fmt.Printf("    %-9s %-12s %-18s %s\n", r.Check, r.Result, r.Classification, r.Detail)
	}
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
			Checks: map[string]bool{"rules": true}, Enabled: true,
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
