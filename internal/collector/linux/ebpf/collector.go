//go:build linux

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-D__TARGET_ARCH_x86" -tags "linux,amd64" dns_bpf bpf/dnsfilter.c -- -I bpf -I /usr/include
// go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-D__TARGET_ARCH_arm64" -tags "linux,arm64" dns_bpf bpf/dnsfilter.c -- -I bpf -I /usr/include

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
	"syscall"
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
	QueryName   string
	QueryType   uint16
	IsResponse  bool
	QueryResult string
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
	objs      dns_bpfObjects
	rawSocket int // Raw Socket 文件描述符
}

// NewCollector 创建 Linux 采集器
func NewCollector() *LinuxCollector {
	return &LinuxCollector{
		recordCh:  make(chan model.DNSRecord, 100),
		rawSocket: -1,
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

	// 关闭 Raw Socket
	if c.rawSocket != -1 {
		syscall.Close(c.rawSocket)
		c.rawSocket = -1
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

// checkKernelVersion 检查内核版本兼容性
func (c *LinuxCollector) checkKernelVersion() error {
	// 读取内核版本信息
	data, err := ioutil.ReadFile("/proc/version")
	if err != nil {
		return fmt.Errorf("无法读取内核版本: %w", err)
	}
	
	versionStr := string(data)
	logger.Info("当前内核版本: " + strings.TrimSpace(versionStr))
	
	// 检查是否支持eBPF
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return fmt.Errorf("系统不支持eBPF，请确保内核版本 >= 4.4 且启用了CONFIG_BPF_SYSCALL")
	}
	
	return nil
}

// htons converts a short integer to network byte order
func htons(n uint16) uint16 {
	return (n<<8)&0xff00 | (n>>8)&0x00ff
}

// loadEBPFProgram 加载 eBPF 程序
func (c *LinuxCollector) loadEBPFProgram() error {
	// 检查内核版本兼容性
	if err := c.checkKernelVersion(); err != nil {
		return fmt.Errorf("内核兼容性检查失败: %w", err)
	}
	
	// 使用 bpf2go 生成的装载函数加载嵌入的字节码
	spec, err := loadDns_bpf()
	if err != nil {
		logger.Error("加载 eBPF spec 失败")
		return fmt.Errorf("加载 eBPF spec 失败: %w", err)
	}
	c.spec = spec

	// 配置加载选项
	opts := &ebpf.CollectionOptions{}
	
	// 加载对象（程序和映射）
	if err := loadDns_bpfObjects(&c.objs, opts); err != nil {
		// 提供更详细的错误信息
		if strings.Contains(err.Error(), "CO-RE relocation") {
			return fmt.Errorf("CO-RE重定位失败，可能是内核版本不兼容。请确保:\n" +
				"1. 内核版本 >= 5.8 (推荐)\n" +
				"2. 启用了BTF支持 (CONFIG_DEBUG_INFO_BTF=y)\n" +
				"3. 安装了内核调试信息包\n" +
				"原始错误: %w", err)
		}
		return fmt.Errorf("加载 eBPF 对象失败: %w", err)
	}

	// 1. 附加 Kprobes (KprobeUdpSendmsg, KprobeTcpSendmsg) 和 Kretprobe (KretprobeUdpSendmsg)
	kprobes := []struct {
		name    string
		program *ebpf.Program
		isRet   bool
	}{
		{"udp_sendmsg", c.objs.KprobeUdpSendmsg, false},
		{"udp_sendmsg", c.objs.KretprobeUdpSendmsg, true},
		{"tcp_sendmsg", c.objs.KprobeTcpSendmsg, false},
	}

	for _, kp := range kprobes {
		var probe link.Link
		var err error
		if kp.isRet {
			probe, err = link.Kretprobe(kp.name, kp.program, nil)
		} else {
			probe, err = link.Kprobe(kp.name, kp.program, nil)
		}
		if err != nil {
			return fmt.Errorf("附加 kprobe/kretprobe %s (isRet: %t) 失败: %w", kp.name, kp.isRet, err)
		}
		c.links = append(c.links, probe)
	}

	// 2. 创建 Raw Socket 并附加 Socket Filter
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("创建 Raw Socket 失败: %w", err)
	}
	c.rawSocket = fd

	// 附加 Socket Filter 程序到 Raw Socket (SO_ATTACH_BPF = 50)
	if err := syscall.SetsockoptInt(c.rawSocket, syscall.SOL_SOCKET, 50, c.objs.SocketDnsFilter.FD()); err != nil {
		syscall.Close(c.rawSocket)
		c.rawSocket = -1
		return fmt.Errorf("附加 Socket Filter 失败: %w", err)
	}

	logger.Info("Socket Filter 已成功附加到 Raw Socket")

	// 打开 ring buffer 读取 events 映射
	r, err := ringbuf.NewReader(c.objs.Events)
	if err != nil {
		return fmt.Errorf("打开 ringbuf 失败: %w", err)
	}
	c.reader = r

	logger.Info("eBPF 程序加载成功，Kprobe 和 Socket Filter 已就绪")
	return nil
}

// collectData 收集数据（真实 eBPF 实现）
func (c *LinuxCollector) collectData() {
	if c.reader == nil {
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
				dnsInfo := c.parseDNSPacket(event.PktData[:event.PktLen], event.Protocol)
				if dnsInfo != nil {
					// 如果 PID 为 0，尝试使用 Comm 名
					pName := string(bytes.TrimRight(event.Comm[:], "\x00"))
					if pName == "" {
						pName = "unknown"
					}
					
					pPath := "unknown"
					if event.PID > 0 {
						procInfo := c.getProcessInfo(event.PID)
						pName = procInfo.Name
						pPath = procInfo.Path
					}

					// 获取查询类型
					qtype := fmt.Sprintf("TYPE%d", dnsInfo.QueryType)
					if t, ok := dnsTypeMap[dnsInfo.QueryType]; ok {
						qtype = t
					}

					currentTime := c.getBeijingTime()

					clientIP := fmt.Sprintf("%d.%d.%d.%d",
						byte(event.Saddr),
						byte(event.Saddr>>8),
						byte(event.Saddr>>16),
						byte(event.Saddr>>24))
					if dnsInfo.IsResponse {
						clientIP = fmt.Sprintf("%d.%d.%d.%d",
							byte(event.Daddr),
							byte(event.Daddr>>8),
							byte(event.Daddr>>16),
							byte(event.Daddr>>24))
					}

					record := model.DNSRecord{
						Timestamp:   currentTime,
						QueryName:   dnsInfo.QueryName,
						QueryType:   qtype,
						QueryResult: dnsInfo.QueryResult,
						ProcessID:   event.PID,
						ProcessName: pName,
						ProcessPath: pPath,
						ClientIP:    clientIP,
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
func (c *LinuxCollector) parseDNSPacket(data []byte, protocol uint16) *DNSQueryInfo {
	if protocol == 6 { // TCP
		if len(data) < 14 { // 2 bytes length prefix + 12 bytes DNS header
			return nil
		}
		// Skip the 2-byte TCP length prefix
		data = data[2:]
	} else {
		if len(data) < 12 {
			return nil
		}
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	isResponse := (flags & 0x8000) != 0

	// 问题数必须 >= 1
	qdcount := binary.BigEndian.Uint16(data[4:6])
	ancount := binary.BigEndian.Uint16(data[6:8])
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
		if (length & 0xc0) == 0xc0 {
			if offset+2 > len(data) {
				return nil
			}
			offset += 2
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
	offset += 4 // 跳过 type 和 class

	if len(queryName) == 0 {
		return nil
	}

	info := &DNSQueryInfo{
		QueryName:  string(queryName),
		QueryType:  queryType,
		IsResponse: isResponse,
	}

	// 如果是响应包，且有应答记录，解析 IP 地址
	if isResponse && ancount > 0 {
		var results []string
		for i := 0; i < int(ancount) && offset < len(data); i++ {
			if offset >= len(data) {
				break
			}
			b := data[offset]
			if (b & 0xc0) == 0xc0 {
				if offset+2 > len(data) {
					break
				}
				offset += 2
			} else {
				for offset < len(data) {
					lenByte := int(data[offset])
					if lenByte == 0 {
						offset++
						break
					}
					if (lenByte & 0xc0) == 0xc0 {
						offset += 2
						break
					}
					offset += lenByte + 1
				}
			}

			if offset+10 > len(data) {
				break
			}

			ansType := binary.BigEndian.Uint16(data[offset:])
			rdLength := int(binary.BigEndian.Uint16(data[offset+8:]))
			offset += 10

			if offset+rdLength > len(data) {
				break
			}

			if ansType == 1 && rdLength == 4 { // A 记录
				ip := fmt.Sprintf("%d.%d.%d.%d",
					data[offset], data[offset+1], data[offset+2], data[offset+3])
				results = append(results, ip)
			} else if ansType == 28 && rdLength == 16 { // AAAA 记录
				var ipParts []string
				for j := 0; j < 16; j += 2 {
					ipParts = append(ipParts, fmt.Sprintf("%x", binary.BigEndian.Uint16(data[offset+j:])))
				}
				results = append(results, strings.Join(ipParts, ":"))
			} else if ansType == 5 { // CNAME 记录
				cname := parseDomainName(data, offset, offset+rdLength)
				if cname != "" {
					results = append(results, cname)
				}
			}

			offset += rdLength
		}

		if len(results) > 0 {
			info.QueryResult = strings.Join(results, ", ")
		} else {
			info.QueryResult = "-"
		}
	} else {
		info.QueryResult = "-"
	}

	return info
}

// parseDomainName 递归解析 DNS 数据包中的域名（支持压缩指针）
func parseDomainName(data []byte, startOffset, limit int) string {
	var domain []byte
	offset := startOffset
	visited := make(map[int]bool)

	for offset < len(data) && offset < limit {
		length := int(data[offset])
		if length == 0 {
			break
		}
		if (length & 0xc0) == 0xc0 {
			if offset+2 > len(data) {
				break
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:])) & 0x3fff
			if visited[ptr] {
				break
			}
			visited[ptr] = true
			domainTail := parseDomainName(data, ptr, len(data))
			if len(domain) > 0 {
				domain = append(domain, '.')
			}
			domain = append(domain, []byte(domainTail)...)
			break
		} else {
			if length > 63 || offset+1+length > len(data) {
				break
			}
			if len(domain) > 0 {
				domain = append(domain, '.')
			}
			domain = append(domain, data[offset+1:offset+1+length]...)
			offset += length + 1
		}
	}
	return string(domain)
}