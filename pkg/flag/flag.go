package flag

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
)

type Config struct {
	EnableWeb  bool
	ListenAddr string
	ListenPort int
	LogLevel   string
}

// GetEnv 获取环境变量
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvAsInt 获取整数类型环境变量
func GetEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// GetEnvAsBool 获取布尔类型环境变量
func GetEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// ParseFlags 解析命令行参数
func ParseFlags() *Config {
	cfg := &Config{}

	// 定义默认值
	defaultEnableWeb := GetEnvAsBool("DNSFLUX_ENABLE_WEB", false)
	defaultListenAddr := GetEnv("DNSFLUX_HOST", "127.0.0.1")
	defaultListenPort := GetEnvAsInt("DNSFLUX_PORT", 58080)
	defaultLogLevel := GetEnv("DNSFLUX_LOG_LEVEL", "info")

	// 定义命令行参数
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "使用说明: %s [选项]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "选项:\n")
		fmt.Fprintf(os.Stderr, "  -w, --web\t\t是否启用 Web 服务 (默认值: %v)\n", defaultEnableWeb)
		fmt.Fprintf(os.Stderr, "  -a, --addr string\t\tWeb服务监听地址 (默认值: \"%s\")\n", defaultListenAddr)
		fmt.Fprintf(os.Stderr, "  -p, --port int\t\tWeb服务监听端口 (默认值: %d)\n", defaultListenPort)
		fmt.Fprintf(os.Stderr, "  -l, --log-level string\t日志级别 [debug, info, warn, error] (默认值: \"%s\")\n", defaultLogLevel)
		fmt.Fprintf(os.Stderr, "  -h, --help\t\t\t显示帮助信息\n")
		fmt.Fprintf(os.Stderr, "\n示例:\n")
		fmt.Fprintf(os.Stderr, "  %s -a 0.0.0.0 -p 1688 -l info\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --addr=0.0.0.0 --port=1688 --log-level=info\n", os.Args[0])
	}

	// 定义命令行参数（包含简写）
	flag.BoolVar(&cfg.EnableWeb, "web", defaultEnableWeb, "是否启用 Web 服务")
	flag.BoolVar(&cfg.EnableWeb, "w", defaultEnableWeb, "是否启用 Web 服务 (简写)")
	flag.StringVar(&cfg.ListenAddr, "addr", defaultListenAddr, "Web服务监听地址")
	flag.StringVar(&cfg.ListenAddr, "a", defaultListenAddr, "Web服务监听地址 (简写)")
	flag.IntVar(&cfg.ListenPort, "port", defaultListenPort, "Web服务监听端口")
	flag.IntVar(&cfg.ListenPort, "p", defaultListenPort, "服务监听端口 (简写)")
	flag.StringVar(&cfg.LogLevel, "log-level", defaultLogLevel, "日志级别 (debug, info, warn, error)")
	flag.StringVar(&cfg.LogLevel, "l", defaultLogLevel, "日志级别 (简写)")
	flag.BoolVar(&cfg.EnableWeb, "h", false, "显示帮助信息")

	// 解析命令行参数
	flag.Parse()

	// 设置日志级别（覆盖默认配置）
	if err := cfg.SetLogLevel(); err != nil {
		logrus.Fatalf("Failed to set log level: %v", err)
	}

	return cfg
}

// SetLogLevel 设置日志级别
func (c *Config) SetLogLevel() error {
	level, err := logrus.ParseLevel(c.LogLevel)
	if err != nil {
		return err
	}
	logrus.SetLevel(level)
	return nil
}
