package main

import (
	"context"
	"dnsflux/internal/collector"
	"dnsflux/internal/store/memory"
	"dnsflux/internal/utils"
	"dnsflux/internal/web"
	"dnsflux/pkg/flag"
	"dnsflux/pkg/logger"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

// 版本信息变量（通过 -ldflags 在构建时设置）
var (
	Version = "dev"
)

func main() {
	// 加载完整配置（包括命令行参数和环境变量）
	cfg := flag.ParseFlags()

	// 初始化日志
	logger.InitLogger()

	logger.Info("DNSFlux 启动中...")
	logger.Info(fmt.Sprintf("版本: %s", Version))
	logger.Info(fmt.Sprintf("配置: %+v", cfg))

	// 创建存储
	store := memory.New(5000)
	defer store.Close()

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 根据命令行参数决定是否启动 Web 服务器
	var webServer *web.Server
	if cfg.EnableWeb {
		// 检测并获取可用端口
		availablePort := utils.FindAvailablePort(cfg.ListenPort, cfg.ListenAddr)
		if availablePort != cfg.ListenPort {
			logger.Info(fmt.Sprintf("默认端口 %d 被占用，使用端口 %d", cfg.ListenPort, availablePort))
			cfg.ListenPort = availablePort
		}

		// 创建 Web 服务器
		webServer = web.New(store, cfg.ListenAddr, cfg.ListenPort)

		// 启动 Web 服务器
		go func() {
			if err := webServer.Start(ctx); err != nil && err != http.ErrServerClosed {
				logger.Error(fmt.Sprintf("Web 服务器启动失败: %v", err))
			}
		}()

		logger.Info(fmt.Sprintf("DNSFlux Web 面板已启动，访问 http://%s:%d 查看 Web 界面", cfg.ListenAddr, cfg.ListenPort))
	}
	logger.Info(fmt.Sprintf("当前平台: %s/%s", runtime.GOOS, runtime.GOARCH))

	// 创建平台采集器
	platformCollector := collector.NewPlatformCollector()
	if platformCollector == nil {
		logger.Error(fmt.Sprintf("当前平台 (%s) 暂不支持 DNS 采集，程序退出", runtime.GOOS))
		os.Exit(1)
	}

	go func() {
		if err := platformCollector.Start(ctx); err != nil {
			logger.Error(fmt.Sprintf("采集器启动失败: %v", err))
			return
		}
	}()

	// 订阅采集器数据并转发到存储和 Web 服务器
	go func() {
		ch := platformCollector.Subscribe()
		for {
			select {
			case <-ctx.Done():
				return
			case record, ok := <-ch:
				if !ok {
					return
				}

				// 添加到存储
				store.AddRecord(record)

				// 输出到控制台 - 格式化DNS查询记录
				dnsOutput := record.FormatDNSRecord()
				fmt.Print(dnsOutput)

				// 保存到JSON文件
				if err := record.SaveDNSRecordToJSON(); err != nil {
					logger.Error(fmt.Sprintf("Failed to save DNS record to JSON: %v", err))
				}
			}
		}
	}()

	defer platformCollector.Stop()

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	// 优雅关闭
	cancel()

	// 给服务器一些时间来关闭
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if webServer != nil {
		if err := webServer.Stop(shutdownCtx); err != nil {
			log.Printf("Web 服务器关闭失败: %v", err)
		}
	}

	log.Printf("DNSFlux 已退出")
}
