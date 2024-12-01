package main

import (
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"dnsflux/common"
	"dnsflux/platform"
)

func main() {
	// 配置日志
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.Printf("启动DNS监控(Platform: %s)...\n", runtime.GOOS)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 异步启动 DNS 监控
	go platform.DnsFluxImpl()

	// 启动 Web 服务器（使用 goroutine 避免阻塞）
	go common.StartWebServer()

	// 等待系统退出信号
	<-sigChan

	log.Println("程序已退出")
}
