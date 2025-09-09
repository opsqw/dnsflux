//go:build linux

package collector

import (
	"context"
	"dnsflux/internal/collector/linux"
	"dnsflux/internal/model"
)

// LinuxCollector Linux 平台的 DNS 采集器包装器
type LinuxCollector struct {
	recordCh       chan model.DNSRecord
	ctx            context.Context
	cancel         context.CancelFunc
	linuxCollector *linux.LinuxCollector
}

// newPlatformCollector 创建 Linux 平台采集器
func newPlatformCollector() Collector {
	return &LinuxCollector{
		recordCh:       make(chan model.DNSRecord, 100),
		linuxCollector: linux.NewCollector(),
	}
}

// Name 返回采集器名称
func (c *LinuxCollector) Name() string {
	return c.linuxCollector.Name()
}

// Start 启动采集器
func (c *LinuxCollector) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	// 启动底层 Linux 采集器
	if err := c.linuxCollector.Start(ctx); err != nil {
		return err
	}

	// 启动数据转发协程
	go c.forwardData()
	return nil
}

// Stop 停止采集器
func (c *LinuxCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}

	if c.linuxCollector != nil {
		c.linuxCollector.Stop()
	}

	close(c.recordCh)
	return nil
}

// Subscribe 订阅 DNS 记录
func (c *LinuxCollector) Subscribe() <-chan model.DNSRecord {
	return c.recordCh
}

// forwardData 转发数据从底层采集器到统一接口
func (c *LinuxCollector) forwardData() {
	linuxRecordCh := c.linuxCollector.Subscribe()

	for {
		select {
		case <-c.ctx.Done():
			return
		case record, ok := <-linuxRecordCh:
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
