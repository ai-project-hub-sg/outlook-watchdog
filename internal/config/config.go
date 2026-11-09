// Package config 负责引导配置加载：config.yaml（进程级项）+ .env（凭据源）。
// 业务配置（账号、调度、告警渠道）一律在 SQLite 中，不在此层。
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 是引导配置，对应 config.yaml。
type Config struct {
	Listen        string `yaml:"listen"`
	DataDir       string `yaml:"data_dir"`
	LogDir        string `yaml:"log_dir"`
	AdminPassword string `yaml:"admin_password"` // 可选：支持 ${ENV}；仅哈希入库，明文不持久化
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// LoadEnvFile 把 .env 中的 KEY=VALUE 注入进程环境（不覆盖已存在的变量）。
// 文件不存在时静默跳过；返回是否加载了文件。
func LoadEnvFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if _, exists := os.LookupEnv(k); !exists {
			os.Setenv(k, v)
		}
	}
	return true, sc.Err()
}

// expandEnv 把字符串中的 ${VAR} 替换为环境变量值；未定义变量替换为空串。
func expandEnv(s string) string {
	return envRef.ReplaceAllStringFunc(s, func(m string) string {
		return os.Getenv(envRef.FindStringSubmatch(m)[1])
	})
}

// Load 读取并校验 config.yaml；configPath 缺省为 "config.yaml"。
// 顺带尝试加载同目录及当前目录的 .env。
func Load(configPath string) (*Config, error) {
	if configPath == "" {
		configPath = "config.yaml"
	}
	LoadEnvFile(".env")
	LoadEnvFile(filepath.Join(filepath.Dir(configPath), ".env"))

	raw, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			c := defaultConfig()
			return c, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.AdminPassword = expandEnv(c.AdminPassword)
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func defaultConfig() *Config {
	c := &Config{}
	c.applyDefaults()
	return c
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	if c.LogDir == "" {
		c.LogDir = "logs"
	}
}

func (c *Config) validate() error {
	host, _, err := splitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("invalid listen %q: %w", c.Listen, err)
	}
	if host != "" && host != "127.0.0.1" && host != "localhost" && c.AdminPassword == "" {
		fmt.Fprintf(os.Stderr, "[warn] listen=%s 非回环地址且未设置管理员密码，请确认已完成账号设置\n", c.Listen)
	}
	return nil
}

func splitHostPort(addr string) (host, port string, err error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", "", fmt.Errorf("missing port")
	}
	return addr[:i], addr[i+1:], nil
}

// DBPath 返回 SQLite 文件路径。
func (c *Config) DBPath() string {
	return filepath.Join(c.DataDir, "watchdog.sqlite")
}
