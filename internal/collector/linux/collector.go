//go:build linux

package linux

import (
	"bytes"
	"context"
	"dnsflux/internal/model"
	"dnsflux/pkg/logger"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// 网络协议映射
var protocolMap = map[uint16]string{
	6:  "TCP",
	17: "UDP",
}

// DNS查询类型映射
var dnsTypeMap = map[uint16]string{
	1:  "A",
	2:  "NS",
	5:  "CNAME",
	6:  "SOA",
	12: "PTR",
	15: "MX",
	16: "TXT",
	28: "AAAA",
	33: "SRV",
}

// DNSQueryInfo DNS查询信息
type DNSQueryInfo struct {
	QueryName string
	QueryType uint16
}

// ProcessInfo 进程信息结构
type ProcessInfo struct {
	Name string
	Path string
}

// LinuxCollector Linux 平台的 DNS 采集器
type LinuxCollector struct {
	recordCh chan model.DNSRecord
	spec     *ebpf.CollectionSpec
	coll     *ebpf.Collection
	links    []link.Link
	reader   *ringbuf.Reader
	ctx      context.Context
	cancel   context.CancelFunc
	// 保存已加载的 BPF 对象以便在 Stop 时关闭
	objs dns_bpfObjects
}

// NewCollector 创建 Linux 采集器
func NewCollector() *LinuxCollector {
	return &LinuxCollector{
		recordCh: make(chan model.DNSRecord, 100),
	}
}

// Name 返回采集器名称
func (c *LinuxCollector) Name() string {
	return "Linux eBPF DNS Collector"
}

// Start 启动采集器
func (c *LinuxCollector) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	// 检查 root 权限
	if os.Geteuid() != 0 {
		return fmt.Errorf("必须以 root 权限运行此程序")
	}

	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("移除内存限制失败: %w", err)
	}

	// 加载 eBPF 程序
	if err := c.loadEBPFProgram(); err != nil {
		return fmt.Errorf("加载 eBPF 程序失败: %w", err)
	}

	logger.Info(fmt.Sprintf("启动 %s", c.Name()))

	// 启动数据收集协程
	go c.collectData()

	return nil
}

// Stop 停止采集器
func (c *LinuxCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}

	// 清理资源
	for _, l := range c.links {
		l.Close()
	}

	if c.reader != nil {
		c.reader.Close()
	}

	// 关闭 BPF 对象（程序与映射）
	_ = c.objs.Close()

	if c.coll != nil {
		c.coll.Close()
	}

	close(c.recordCh)
	return nil
}

// Subscribe 订阅 DNS 记录
func (c *LinuxCollector) Subscribe() <-chan model.DNSRecord {
	return c.recordCh
}

// loadEBPFProgram 加载 eBPF 程序
func (c *LinuxCollector) loadEBPFProgram() error {
	// 使用 bpf2go 生成的装载函数加载嵌入的字节码
	spec, err := loadDns_bpf()
	if err != nil {
		logger.Error("加载 eBPF spec 失败")
		return fmt.Errorf("加载 eBPF spec 失败: %w", err)
	}
	c.spec = spec

	// 加载对象（程序和映射）
	var objs dns_bpfObjects
	if err := loadDns_bpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("加载 eBPF 对象失败: %w", err)
	}
	c.objs = objs

	// 附加 kprobes 到 udp_sendmsg / tcp_sendmsg
	kprobes := []struct {
		name    string
		program *ebpf.Program
	}{
		{"udp_sendmsg", c.objs.TraceUdpSendmsg},
		{"tcp_sendmsg", c.objs.TraceTcpSendmsg},
	}

	for _, kp := range kprobes {
		probe, err := link.Kprobe(kp.name, kp.program, nil)
		if err != nil {
			return fmt.Errorf("附加 kprobe %s 失败: %w", kp.name, err)
		}
		c.links = append(c.links, probe)
	}

	// 打开 ring buffer 读取 events 映射
	r, err := ringbuf.NewReader(c.objs.Events)
	if err != nil {
		return fmt.Errorf("打开 ringbuf 失败: %w", err)
	}
	c.reader = r

	logger.Info("eBPF 程序加载成功，已附加 kprobe 并初始化 ring buffer")
	return nil
}

// collectData 收集数据（真实 eBPF 实现）
func (c *LinuxCollector) collectData() {
	if c.reader == nil {
		// 如果没有 eBPF reader，无法进行真实DNS采集
		logger.Error("eBPF reader 未初始化，无法进行DNS采集")
		return
	}

	// 定义与 C 结构体完全匹配的事件结构
	var event struct {
		Timestamp uint64
		PID       uint32
		TGID      uint32
		UID       uint32
		GID       uint32
		Ifindex   uint32
		Comm      [64]byte
		Sport     uint16
		Dport     uint16
		Saddr     uint32
		Daddr     uint32
		Protocol  uint16
		PktLen    uint16
		PktData   [512]byte
	}

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			record, err := c.reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			if event.PktLen > 0 {
				dnsInfo := c.parseDNSPacket(event.PktData[:event.PktLen])
				if dnsInfo != nil {
					procInfo := c.getProcessInfo(event.PID)

					// 获取查询类型
					qtype := fmt.Sprintf("TYPE%d", dnsInfo.QueryType)
					if t, ok := dnsTypeMap[dnsInfo.QueryType]; ok {
						qtype = t
					}

					currentTime := c.getBeijingTime()

					record := model.DNSRecord{
						Timestamp:   currentTime,
						QueryName:   dnsInfo.QueryName,
						QueryType:   qtype,
						QueryResult: "-",
						ProcessID:   event.PID,
						ProcessName: procInfo.Name,
						ProcessPath: procInfo.Path,
						ClientIP: fmt.Sprintf("%d.%d.%d.%d",
							byte(event.Saddr),
							byte(event.Saddr>>8),
							byte(event.Saddr>>16),
							byte(event.Saddr>>24)),
					}

					select {
					case c.recordCh <- record:
					case <-c.ctx.Done():
						return
					}
				}
			}
		}
	}
}

// getBeijingTime 获取北京时间
func (c *LinuxCollector) getBeijingTime() time.Time {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		loc = time.FixedZone("CST", 8*3600)
	}
	return time.Now().In(loc)
}

// getProcessInfo 获取进程信息
func (c *LinuxCollector) getProcessInfo(pid uint32) ProcessInfo {
	info := ProcessInfo{
		Name: "unknown",
		Path: "unknown",
	}

	// 获取进程名
	if commBytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		info.Name = strings.TrimSpace(string(commBytes))
	}

	// 获取进程路径
	if exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		info.Path = exePath
	} else if cmdlineBytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		args := strings.Split(string(cmdlineBytes), "\x00")
		if len(args) > 0 && args[0] != "" {
			info.Path = args[0]
		}
	}

	return info
}

// parseDNSPacket 解析 DNS 数据包
func (c *LinuxCollector) parseDNSPacket(data []byte) *DNSQueryInfo {
	if len(data) < 12 {
		return nil
	}

	// 检查是否是查询包（QR=0）
	flags := binary.BigEndian.Uint16(data[2:4])
	if (flags & 0x8000) != 0 {
		return nil
	}

	// 问题数必须 >= 1
	qdcount := binary.BigEndian.Uint16(data[4:6])
	if qdcount == 0 {
		return nil
	}

	offset := 12
	var queryName []byte

	// 解析域名
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			break
		}
		if length > 63 || offset+1+length > len(data) {
			return nil
		}
		if len(queryName) > 0 {
			queryName = append(queryName, '.')
		}
		queryName = append(queryName, data[offset+1:offset+1+length]...)
		offset += length + 1
	}

	// 确保有足够的数据读取类型(type)与类(class)
	if offset+5 > len(data) { // 1字节结尾 + 2字节type + 2字节class
		return nil
	}

	offset++ // 跳过结尾的0
	queryType := binary.BigEndian.Uint16(data[offset:])

	if len(queryName) == 0 {
		return nil
	}

	return &DNSQueryInfo{
		QueryName: string(queryName),
		QueryType: queryType,
	}
}
