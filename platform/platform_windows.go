//go:build windows

package platform

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"dnsflux/common"
	"dnsflux/output"

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
	ipv6Pattern = regexp.MustCompile(`(?i)\b(?:(?:[0-9A-F]{1,4}:){7}[0-9A-F]{1,4}|(?:[0-9A-F]{1,4}:){6}:[0-9A-F]{1,4}|(?:[0-9A-F]{1,4}:){5}(?::[0-9A-F]{1,4}){1,2}|(?:[0-9A-F]{1,4}:){4}(?::[0-9A-F]{1,4}){1,3}|(?:[0-9A-F]{1,4}:){3}(?::[0-9A-F]{1,4}){1,4}|(?:[0-9A-F]{1,4}:){2}(?::[0-9A-F]{1,4}){1,5}|[0-9A-F]{1,4}:(?::[0-9A-F]{1,4}){1,6}|:(?:(?::[0-9A-F]{1,4}){1,7}|:)|FE80:(?::[0-9A-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:FFFF(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9A-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b`)
)

type Config struct {
	// 事件ID白名单，为空则不过滤
	EventIDWhitelist []uint16
	// 域名黑名单，为空则不过滤
	DomainBlacklist []string
}

// 配置事件白名单ID和域名黑名单
var config = Config{
	// DNS查询事件ID：3006【开始查询】，3008【已完成的查询】，3009【发起索引查询】，3010【发起DNS服务查询】，3011【DNS服务器响应】，3018【缓存查询响应】，3020【索引查询响应】
	EventIDWhitelist: []uint16{3008},
	DomainBlacklist:  []string{"localhost"},
}

// 检查事件ID是否在白名单中
func isEventIDAllowed(eventID uint16, whitelist []uint16) bool {
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
func isDomainBlocked(domain string, blacklist []string) bool {
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
func getProcessPath(processHandle syscall.Handle) string {
	// 创建缓冲区来存储路径信息
	buffer := make([]uint16, syscall.MAX_PATH)
	size := uint32(len(buffer))

	// 尝试调用 QueryFullProcessImageNameW
	ret, _, err := procQueryFullProcessImageNameW.Call(
		uintptr(processHandle),
		uintptr(0),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret != 0 {
		return syscall.UTF16ToString(buffer[:size])
	}

	// 如果失败，尝试调用 GetProcessImageFileNameW
	ret, _, err = procGetProcessImageFileNameW.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(size),
	)
	if ret != 0 {
		return syscall.UTF16ToString(buffer[:size])
	}

	log.Printf("无法获取进程路径, 错误: %v", err)
	// 如果都失败，返回空字符串
	return ""
}

// 获取进程名
func getProcessName(processPath string) string {
	for i := len(processPath) - 1; i >= 0; i-- {
		if processPath[i] == '\\' {
			return processPath[i+1:]
		}
	}
	return processPath
}

// 获取进程信息
func getProcessInfo(pid uint32) (name, path string) {
	// 使用 PROCESS_QUERY_LIMITED_INFORMATION 权限
	handle, err := syscall.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		log.Printf("无法打开进程 %d: %v", pid, err)
		// 返回默认值或空值
		return fmt.Sprintf("PID: %d", pid), ""
	}
	defer syscall.CloseHandle(handle)

	// 获取路径信息
	path = getProcessPath(handle)
	if path == "" {
		return fmt.Sprintf("PID: %d", pid), ""
	}

	// 获取进程名称
	name = getProcessName(path)
	return name, path
}

// 获取DNS查询类型的字符串表示
func getDNSQueryType(queryType interface{}) string {
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
func getDNSStatus(status interface{}) string {
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
func extractIPs(result string) (ipv4s []string, ipv6s []string) {
	// 提取所有 IPv4 地址
	ipv4s = ipv4Pattern.FindAllString(result, -1)

	// 提取所有 IPv6 地址
	ipv6s = ipv6Pattern.FindAllString(result, -1)

	// 去重
	ipv4s = removeDuplicates(ipv4s)
	ipv6s = removeDuplicates(ipv6s)

	return
}

// 去重函数
func removeDuplicates(arr []string) []string {
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
func formatDNSResult(result string) string {
	ipv4s, ipv6s := extractIPs(result)

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
func formatTimeAsBeijing(t time.Time) time.Time {
	// 设置时区为北京
	const beijingTimeZone = "Asia/Shanghai"
	loc, err := time.LoadLocation(beijingTimeZone)
	if err != nil {
		return t // 如果加载时区失败，返回原始时间
	}

	// 将时间转换为北京时间并返回
	return t.In(loc)
}

// 实现 Windows 平台 DNS 监控
func DnsFluxImpl() {
	// 创建实时会话
	session := etw.NewRealTimeSession("DNSMonitor")
	defer session.Stop()

	// 解析并启用 DNS Provider
	dnsProvider := etw.MustParseProvider(dnsProviderGUID)
	if err := session.EnableProvider(dnsProvider); err != nil {
		log.Fatalf("启用 Provider 失败: %v", err)
	}
	fmt.Println("DNS Provider 启用成功")

	// 创建消费者并启动异步监听
	ctx, cancel := context.WithCancel(context.Background())
	consumer := etw.NewRealTimeConsumer(ctx)
	defer cancel()
	defer consumer.Stop()

	// 将消费者与会话关联
	consumer.FromSessions(session)

	// 处理事件
	go func() {
		for evt := range consumer.Events {
			handleProcessEvent(evt)
		}
	}()

	// 启动消费者
	errChan := make(chan error, 1)
	go func() {
		if err := consumer.Start(); err != nil {
			errChan <- fmt.Errorf("DNS事件消费者启动失败: %v", err)
		}
	}()

	<-ctx.Done()
}

func handleProcessEvent(evt *etw.Event) {
	if evt.System.Provider.Guid == dnsProviderGUID {
		// 过滤白名单事件
		if !isEventIDAllowed(evt.System.EventID, config.EventIDWhitelist) {
			return
		}

		queryName, hasQuery := evt.EventData["QueryName"]
		if !hasQuery {
			return
		}

		// 过滤黑名单域名
		if isDomainBlocked(fmt.Sprintf("%v", queryName), config.DomainBlacklist) {
			return
		}

		queryType := getDNSQueryType(evt.EventData["QueryType"])

		result := ""
		if r, ok := evt.EventData["QueryResults"]; ok {
			result = formatDNSResult(fmt.Sprintf("%v", r))
		}

		status := ""
		if r, ok := evt.EventData["QueryStatus"]; ok {
			status = getDNSStatus(r)
		}
		if r, ok := evt.EventData["Status"]; ok {
			status = getDNSStatus(r)
		}

		processId := evt.System.Execution.ProcessID
		threadId := evt.System.Execution.ThreadID
		processName, processPath := getProcessInfo(processId)

		beijingTime := formatTimeAsBeijing(evt.System.TimeCreated.SystemTime)
		timestamp := beijingTime.Format("2001-02-03 04:05:06")

		// 格式化输出内容
		logEntry := fmt.Sprintf("\n检测到DNS查询:\n时间: %s\n查询域名: %s\n查询类型: %s\n查询状态: %s\n查询结果: %s\n进程ID: %d\n线程ID: %d\n进程名: %s\n进程路径: %s\n事件ID: %d\n------------------------\n",
			timestamp,
			queryName,
			queryType,
			status,
			result,
			processId,
			threadId,
			processName,
			processPath,
			evt.System.EventID,
		)

		// 控制台输出
		fmt.Print(logEntry)

		//// 调试用：打印完整事件数据
		//if data, err := json.MarshalIndent(evt, "", "  "); err == nil {
		//	fmt.Printf("调试信息 - 完整事件数据:\n%s\n", string(data))
		//}

		// 写入日志文件
		if err := output.WriteLog(logEntry); err != nil {
			log.Printf("写入日志失败: %v", err)
		}

		// 添加到 Web 展示
		common.AddDNSRecord(common.DNSRecord{
			Timestamp:   beijingTime,
			QueryName:   fmt.Sprintf("%v", queryName),
			QueryType:   queryType,
			QueryResult: result,
			ProcessID:   processId,
			ProcessName: processName,
			ProcessPath: processPath,
			ClientIP:    "-", // Windows ETW 事件中可能没有客户端 IP
		})

	}
}
