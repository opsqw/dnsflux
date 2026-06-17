//go:build linux

package linux

import (
	"context"
	"dnsflux/internal/collector/linux/ebpf"
	"dnsflux/internal/collector/linux/pcap"
	"dnsflux/internal/model"
	"dnsflux/pkg/logger"
	"os"
)

// LinuxCollectorManager Linux 平台采集器管理器
// 负责根据环境选择 ebpf 或 pcap 模式
type LinuxCollectorManager struct {
	recordCh chan model.DNSRecord
	ctx      context.Context
	cancel   context.CancelFunc
	
	// 当前活跃的采集器
	activeCollector interface {
		Start(context.Context) error
		Stop() error
		Subscribe() <-chan model.DNSRecord
		Name() string
	}
}

// NewLinuxCollector 创建 Linux 平台采集器
func NewLinuxCollector() *LinuxCollectorManager {
	return &LinuxCollectorManager{
		recordCh: make(chan model.DNSRecord, 1000),
	}
}

// Name 返回采集器名称
func (m *LinuxCollectorManager) Name() string {
	if m.activeCollector != nil {
		return m.activeCollector.Name()
	}
	return "Linux Collector Manager"
}

// Start 启动采集器
func (m *LinuxCollectorManager) Start(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)

	// 1. 尝试启动 eBPF 采集器
	useEbpf := true
	if os.Geteuid() != 0 {
		logger.Warn("非 root 权限，eBPF 采集器可能无法工作，尝试降级到 Pcap 模式...")
		useEbpf = false
	}

	if useEbpf {
		ebpfCollector := ebpf.NewCollector()
		if err := ebpfCollector.Start(m.ctx); err != nil {
			logger.Error("eBPF 采集器启动失败: " + err.Error() + "，尝试降级到 Pcap 模式...")
			useEbpf = false
		} else {
			m.activeCollector = ebpfCollector
			logger.Info("已启动 eBPF 采集模式")
		}
	}

	// 2. 如果 eBPF 不可用或启动失败，尝试启动 Pcap 采集器
	if !useEbpf {
		pcapCollector := pcap.NewCollector()
		if err := pcapCollector.Start(m.ctx); err != nil {
			logger.Error("Pcap 采集器启动失败: " + err.Error())
			return err
		}
		m.activeCollector = pcapCollector
		logger.Info("已启动 Pcap 采集模式")
	}

	// 转发数据
	go m.forwardData(m.activeCollector.Subscribe())

	return nil
}

// Stop 停止采集器
func (m *LinuxCollectorManager) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}
	if m.activeCollector != nil {
		m.activeCollector.Stop()
	}
	close(m.recordCh)
	return nil
}

// Subscribe 订阅 DNS 记录
func (m *LinuxCollectorManager) Subscribe() <-chan model.DNSRecord {
	return m.recordCh
}

// forwardData 转发数据到统一通道
func (m *LinuxCollectorManager) forwardData(ch <-chan model.DNSRecord) {
	for {
		select {
		case <-m.ctx.Done():
			return
		case record, ok := <-ch:
			if !ok {
				return
			}
			select {
			case m.recordCh <- record:
			case <-m.ctx.Done():
				return
			}
		}
	}
}
