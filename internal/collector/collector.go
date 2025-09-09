package collector

import (
	"context"
	"dnsflux/internal/model"
)

// Collector DNS 采集器接口
type Collector interface {
	// Start 启动采集器
	Start(ctx context.Context) error

	// Stop 停止采集器
	Stop() error

	// Subscribe 订阅 DNS 记录
	Subscribe() <-chan model.DNSRecord

	// Name 返回采集器名称
	Name() string
}

// Manager 采集器管理器
type Manager struct {
	collectors []Collector
	recordCh   chan model.DNSRecord
}

// NewManager 创建采集器管理器
func NewManager() *Manager {
	return &Manager{
		collectors: make([]Collector, 0),
		recordCh:   make(chan model.DNSRecord, 1000), // 带缓冲的通道
	}
}

// AddCollector 添加采集器
func (m *Manager) AddCollector(collector Collector) {
	m.collectors = append(m.collectors, collector)
}

// Start 启动所有采集器
func (m *Manager) Start(ctx context.Context) error {
	for _, collector := range m.collectors {
		go m.runCollector(ctx, collector)
	}
	return nil
}

// Stop 停止所有采集器
func (m *Manager) Stop() error {
	for _, collector := range m.collectors {
		if err := collector.Stop(); err != nil {
			// 记录错误但继续停止其他采集器
			continue
		}
	}
	close(m.recordCh)
	return nil
}

// Subscribe 订阅所有采集器的记录
func (m *Manager) Subscribe() <-chan model.DNSRecord {
	return m.recordCh
}

// NewPlatformCollector 创建平台特定的采集器
// 具体实现通过构建标签在不同文件中提供
func NewPlatformCollector() Collector {
	return newPlatformCollector()
}

// runCollector 运行单个采集器
func (m *Manager) runCollector(ctx context.Context, collector Collector) {
	if err := collector.Start(ctx); err != nil {
		return
	}

	ch := collector.Subscribe()
	for {
		select {
		case <-ctx.Done():
			collector.Stop()
			return
		case record, ok := <-ch:
			if !ok {
				return
			}
			// 转发记录到管理器的通道
			select {
			case m.recordCh <- record:
			case <-ctx.Done():
				return
			}
		}
	}
}
