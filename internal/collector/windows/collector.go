//go:build windows

package windows

import (
	"context"
	"dnsflux/internal/model"
	"dnsflux/pkg/logger"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/0xrawsec/golang-etw/etw"
)

const (
	// Microsoft-Windows-DNS-Client Provider GUID
	dnsProviderGUID = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"

	// 进程访问权限
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_QUERY_INFORMATION         = 0x0400
)

// Windows API 函数声明
var (
	modkernel32                    = syscall.NewLazyDLL("kernel32.dll")
	modpsapi                       = syscall.NewLazyDLL("psapi.dll")
	procQueryFullProcessImageNameW = modkernel32.NewProc("QueryFullProcessImageNameW")
	procGetProcessImageFileNameW   = modpsapi.NewProc("GetProcessImageFileNameW")
)

// DNS查询类型映射
var queryTypes = map[int]string{
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

// DNS查询状态码映射
var statusMap = map[int]string{
	0:    "succeeded",
	123:  "ERROR(query name error)",
	1460: "ERROR(query timeout)",
	9003: "ERROR(DNS name does not exist)",
	9501: "ERROR(query record not found)",
}

// IP地址匹配
var (
	// IPv4 地址模式
	ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

	// IPv6 地址模式 (包括压缩格式)
	ipv6Pattern = regexp.MustCompile(`(?i)\b(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|:(?::[0-9a-f]{1,4}){1,7})\b`)
)

type ETWConfig struct {
	// 事件ID白名单，为空则不过滤
	EventIDWhitelist []uint16
	// 域名黑名单，为空则不过滤
	DomainBlacklist []string
}

// 配置事件白名单ID和域名黑名单
var etwConfig = ETWConfig{
	// DNS查询事件ID：3006【开始查询】，3008【已完成的查询】，3009【发起索引查询】，3010【发起DNS服务查询】，3011【DNS服务器响应】，3018【缓存查询响应】，3020【索引查询响应】
	EventIDWhitelist: []uint16{3008},
	DomainBlacklist:  []string{"localhost"},
}

// WindowsCollector Windows 平台的 DNS 采集器
type WindowsCollector struct {
	recordCh chan model.DNSRecord
	ctx      context.Context
	cancel   context.CancelFunc
	session  *etw.RealTimeSession
	consumer interface{} // 保存 consumer 实例
}

// NewCollector 创建 Windows 采集器
func NewCollector() *WindowsCollector {
	return &WindowsCollector{
		recordCh: make(chan model.DNSRecord, 100),
	}
}

// Name 返回采集器名称
func (c *WindowsCollector) Name() string {
	return "Windows ETW DNS Collector"
}

// Start 启动采集器
func (c *WindowsCollector) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	logger.Info(fmt.Sprintf("启动 %s", c.Name()))

	// 创建实时会话
	c.session = etw.NewRealTimeSession("DNSMonitor")

	// 解析并启用 DNS Provider
	dnsProvider := etw.MustParseProvider(dnsProviderGUID)
	if err := c.session.EnableProvider(dnsProvider); err != nil {
		return fmt.Errorf("启用 Provider 失败: %v", err)
	}
	logger.Info("DNS Provider 启用成功")

	// 启动数据收集协程（使用真实ETW事件）
	go c.collectData()

	return nil
}

// Stop 停止采集器
func (c *WindowsCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}

	// 优雅停止 consumer（通过具备 Stop 方法的接口断言，避免具体类型依赖）
	if stopper, ok := c.consumer.(interface{ Stop() }); ok && stopper != nil {
		stopper.Stop()
	}

	if c.session != nil {
		c.session.Stop()
	}

	close(c.recordCh)
	return nil
}

// Subscribe 订阅 DNS 记录
func (c *WindowsCollector) Subscribe() <-chan model.DNSRecord {
	return c.recordCh
}

// collectData 收集数据（使用真实ETW事件）
func (c *WindowsCollector) collectData() {
	// 启动ETW事件处理
	if c.session == nil {
		logger.Error("ETW会话未初始化，无法进行DNS采集")
		return
	}

	// 创建实时 consumer 并从当前 session 消费事件
	consumer := etw.NewRealTimeConsumer(c.ctx)
	c.consumer = consumer
	consumer.FromSessions(c.session)

	// 使用默认回调，从 Events 通道消费事件
	go func() {
		for evt := range consumer.Events {
			c.handleProcessEvent(evt)
		}
	}()

	// 启动消费（阻塞直到 Stop 或上下文结束）
	if err := consumer.Start(); err != nil {
		logger.Error(fmt.Sprintf("ETW consumer 启动失败: %v", err))
		return
	}

	if err := consumer.Err(); err != nil {
		logger.Error(fmt.Sprintf("ETW consumer 运行错误: %v", err))
	}
}

// handleProcessEvent 处理 ETW 事件
func (c *WindowsCollector) handleProcessEvent(evt *etw.Event) {
	if evt.System.Provider.Guid == dnsProviderGUID {
		// 过滤白名单事件
		if !c.isEventIDAllowed(evt.System.EventID, etwConfig.EventIDWhitelist) {
			return
		}

		queryName, hasQuery := evt.EventData["QueryName"]
		if !hasQuery {
			return
		}

		// 过滤黑名单域名
		if c.isDomainBlocked(fmt.Sprintf("%v", queryName), etwConfig.DomainBlacklist) {
			return
		}

		queryType := c.getDNSQueryType(evt.EventData["QueryType"])

		result := ""
		if r, ok := evt.EventData["QueryResults"]; ok {
			result = c.formatDNSResult(fmt.Sprintf("%v", r))
		}

		processId := evt.System.Execution.ProcessID
		processName, processPath := c.getProcessInfo(processId)

		beijingTime := c.formatTimeAsBeijing(evt.System.TimeCreated.SystemTime)

		// 创建 DNS 记录
		record := model.DNSRecord{
			Timestamp:   beijingTime,
			QueryName:   fmt.Sprintf("%v", queryName),
			QueryType:   queryType,
			QueryResult: result,
			ProcessID:   processId,
			ProcessName: processName,
			ProcessPath: processPath,
			ClientIP:    "-",
		}

		select {
		case c.recordCh <- record:
		case <-c.ctx.Done():
			return
		}
	}
}

// 检查事件ID是否在白名单中
func (c *WindowsCollector) isEventIDAllowed(eventID uint16, whitelist []uint16) bool {
	if len(whitelist) == 0 {
		return true
	}
	for _, id := range whitelist {
		if eventID == id {
			return true
		}
	}
	return false
}

// 检查域名是否在黑名单中
func (c *WindowsCollector) isDomainBlocked(domain string, blacklist []string) bool {
	if len(blacklist) == 0 {
		return false
	}
	domain = strings.ToLower(domain)
	for _, blocked := range blacklist {
		if strings.Contains(domain, strings.ToLower(blocked)) {
			return true
		}
	}
	return false
}

// 获取进程路径
func (c *WindowsCollector) getProcessPath(processHandle syscall.Handle) string {
	// 创建缓冲区来存储路径信息
	buffer := make([]uint16, syscall.MAX_PATH)
	size := uint32(len(buffer))

	// 尝试调用 QueryFullProcessImageNameW
	ret, _, _ := procQueryFullProcessImageNameW.Call(
		uintptr(processHandle),
		uintptr(0),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret != 0 {
		return syscall.UTF16ToString(buffer[:size])
	}

	// 如果失败，尝试调用 GetProcessImageFileNameW
	ret, _, _ = procGetProcessImageFileNameW.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(size),
	)
	if ret != 0 {
		return syscall.UTF16ToString(buffer[:size])
	}

	// 如果都失败，返回空字符串
	return ""
}

// 获取进程名
func (c *WindowsCollector) getProcessName(processPath string) string {
	for i := len(processPath) - 1; i >= 0; i-- {
		if processPath[i] == '\\' {
			return processPath[i+1:]
		}
	}
	return processPath
}

// 获取进程信息
func (c *WindowsCollector) getProcessInfo(pid uint32) (name, path string) {
	// 使用 PROCESS_QUERY_LIMITED_INFORMATION 权限
	handle, err := syscall.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		logger.Warn(fmt.Sprintf("无法打开进程 %d: %v", pid, err))
		// 返回默认值或空值
		return fmt.Sprintf("PID: %d", pid), ""
	}
	defer syscall.CloseHandle(handle)

	// 获取路径信息
	path = c.getProcessPath(handle)
	if path == "" {
		return fmt.Sprintf("PID: %d", pid), ""
	}

	// 获取进程名称
	name = c.getProcessName(path)
	return name, path
}

// 获取DNS查询类型的字符串表示
func (c *WindowsCollector) getDNSQueryType(queryType interface{}) string {
	switch t := queryType.(type) {
	case float64:
		if name, ok := queryTypes[int(t)]; ok {
			return name
		}
		return fmt.Sprintf("UNKNOWN(%d)", int(t))
	case int:
		if name, ok := queryTypes[t]; ok {
			return name
		}
		return fmt.Sprintf("UNKNOWN(%d)", t)
	case string:
		tInt, err := strconv.Atoi(t)
		if err != nil {
			return fmt.Sprintf("UNKNOWN(%s)", t)
		}
		if name, ok := queryTypes[tInt]; ok {
			return name
		}
		return fmt.Sprintf("UNKNOWN(%d)", tInt)
	default:
		return fmt.Sprintf("%v", queryType)
	}
}

// 获取DNS查询状态的字符串表示
func (c *WindowsCollector) getDNSStatus(status interface{}) string {
	switch s := status.(type) {
	case float64:
		if statusStr, ok := statusMap[int(s)]; ok {
			return statusStr
		}
		return fmt.Sprintf("ERROR(%d)", int(s))
	case int:
		if statusStr, ok := statusMap[s]; ok {
			return statusStr
		}
		return fmt.Sprintf("ERROR(%d)", s)
	case string:
		sInt, err := strconv.Atoi(s)
		if err != nil {
			return ""
		}
		if statusStr, ok := statusMap[sInt]; ok {
			return statusStr
		}
		return fmt.Sprintf("ERROR(%d)", sInt)
	default:
		return fmt.Sprintf("%v", status)
	}
}

// 提取查询结果中的 IP 地址
func (c *WindowsCollector) extractIPs(result string) (ipv4s []string, ipv6s []string) {
	// 提取所有 IPv4 地址
	ipv4s = ipv4Pattern.FindAllString(result, -1)

	// 提取所有 IPv6 地址
	ipv6s = ipv6Pattern.FindAllString(result, -1)

	// 去重
	ipv4s = c.removeDuplicates(ipv4s)
	ipv6s = c.removeDuplicates(ipv6s)

	return
}

// 去重函数
func (c *WindowsCollector) removeDuplicates(arr []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range arr {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// 提取并格式化 IP 地址结果
func (c *WindowsCollector) formatDNSResult(result string) string {
	ipv4s, ipv6s := c.extractIPs(result)

	// 优先使用 IPv4 地址
	if len(ipv4s) > 0 {
		if len(ipv4s) == 1 {
			return ipv4s[0]
		}
		return strings.Join(ipv4s, ", ")
	}

	// 如果没有 IPv4 地址，则使用 IPv6 地址
	if len(ipv6s) > 0 {
		if len(ipv6s) == 1 {
			return ipv6s[0]
		}
		return strings.Join(ipv6s, ", ")
	}

	return ""
}

// 格式化为北京时间
func (c *WindowsCollector) formatTimeAsBeijing(t time.Time) time.Time {
	// 设置时区为北京
	const beijingTimeZone = "Asia/Shanghai"
	loc, err := time.LoadLocation(beijingTimeZone)
	if err != nil {
		return t // 如果加载时区失败，返回原始时间
	}

	// 将时间转换为北京时间并返回
	return t.In(loc)
}
