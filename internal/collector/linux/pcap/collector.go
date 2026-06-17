//go:build linux

package pcap

import (
	"context"
	"dnsflux/internal/model"
)

// PcapCollector 基于 AF_PACKET 和 Procfs 的采集器
type PcapCollector struct {
	recordCh chan model.DNSRecord
}

// NewCollector 创建 Pcap 采集器
func NewCollector() *PcapCollector {
	return &PcapCollector{
		recordCh: make(chan model.DNSRecord, 100),
	}
}

// Name 返回采集器名称
func (c *PcapCollector) Name() string {
	return "Linux Pcap DNS Collector"
}

// Start 启动采集器
func (c *PcapCollector) Start(ctx context.Context) error {
	// TODO: 实现 AF_PACKET 抓包逻辑
	return nil
}

// Stop 停止采集器
func (c *PcapCollector) Stop() error {
	close(c.recordCh)
	return nil
}

// Subscribe 订阅 DNS 记录
func (c *PcapCollector) Subscribe() <-chan model.DNSRecord {
	return c.recordCh
}
