package main

import (
	"DNSMontior/platform"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 异步启动 DNS 监控
	go platform.DNSMonitorImpl()

	// 等待系统退出信号
	<-sigChan

	println("程序收到退出信号，正在关闭...")
}
