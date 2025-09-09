//go:build windows

package collector

import (
	"context"
	"dnsflux/internal/collector/windows"
	"dnsflux/internal/model"
)

// WindowsCollector Windows 平台的 DNS 采集器包装器
type WindowsCollector struct {
	recordCh         chan model.DNSRecord
	ctx              context.Context
	cancel           context.CancelFunc
	windowsCollector *windows.WindowsCollector
}

// newPlatformCollector 创建 Windows 平台采集器
func newPlatformCollector() Collector {
	return &WindowsCollector{
		recordCh:         make(chan model.DNSRecord, 100),
		windowsCollector: windows.NewCollector(),
	}
}

// Name 返回采集器名称
func (c *WindowsCollector) Name() string {
	return c.windowsCollector.Name()
}

// Start 启动采集器
func (c *WindowsCollector) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	// 启动底层 Windows 采集器
	if err := c.windowsCollector.Start(ctx); err != nil {
		return err
	}

	// 启动数据转发协程
	go c.forwardData()
	return nil
}

// Stop 停止采集器
func (c *WindowsCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}

	if c.windowsCollector != nil {
		c.windowsCollector.Stop()
	}

	close(c.recordCh)
	return nil
}

// Subscribe 订阅 DNS 记录
func (c *WindowsCollector) Subscribe() <-chan model.DNSRecord {
	return c.recordCh
}

// forwardData 转发数据从底层采集器到统一接口
func (c *WindowsCollector) forwardData() {
	windowsRecordCh := c.windowsCollector.Subscribe()

	for {
		select {
		case <-c.ctx.Done():
			return
		case record, ok := <-windowsRecordCh:
			if !ok {
				return
			}

			select {
			case c.recordCh <- record:
			case <-c.ctx.Done():
				return
			}
		}
	}
}
