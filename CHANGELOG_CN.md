# 变更日志 (Changelog)

本项目的所有重大变更都将记录在此文件中。

---

## [v1.3.0] - 2026-06-17

此版本引入了重大漏洞修复、Linux eBPF 监控器新功能，以及代码库封装优化重构。

### 新增功能
- **Linux DNS 响应监控支持**：在 Linux 采集器中新增对 DNS 响应包（`QR=1`）的完整解析，现可提取解析出的 IPv4 (A)、IPv6 (AAAA) 及 CNAME 应答结果。
- **进程-响应关联**：在 eBPF 过滤器中实现了响应包的 IP/端口反向交换匹配，支持将接收到的 DNS 解析答案实时映射回发起请求的本地进程（获取 PID、进程名称及路径）。
- **ASCII 启动 Logo**：在程序启动时新增了炫酷的 ASCII 艺术字 Logo 以及动态版本号展示。

### 修复问题
- **eBPF 编译与 Go 1.20 兼容**：通过将 `cilium/ebpf` 降级到 `v0.11.0`、移除 `toolchain` 指令并将 `go.mod` 限制为 Go 1.20，解决了在旧主机开发环境下的编译错误与版本依赖冲突。
- **UDP 自动绑定（Autobind）追踪漏洞**：修复了未绑定 UDP 客户端套接字发起 DNS 请求时进程名显示为 `"unknown"` 的逻辑错误，通过在 `udp_sendmsg` 上挂载 `kprobe` + `kretprobe` 来暂存并精准匹配端口分配后的进程。
- **BPF 校验器报错 (`invalid zero-sized read`)**：通过位与限制 (`len &= 0x1FF`) 确保长度边界，并在类型强转截断前调用 `bpf_skb_load_bytes()` 拷贝，消除了校验器的安全加载报错。
- **BPF 校验器报错 (`no space left on device`)**：移除了默认 Collection 选项中过于冗长的 `LogLevelInstruction` 调试日志输出，避免了因校验器日志溢出导致内核拒绝装载程序的问题。
- **TCP DNS 长度前缀解析**：修正了 TCP DNS 的偏移量提取逻辑，自动剥离 TCP DNS 协议所需的 2 字节消息长度前缀。
- **重复的采集器接口声明**：移除了 `interface.go` 中重复声明的 `NewPlatformCollector()` 函数，解决了特定平台文件编译重定义冲突。

### 重构优化
- **内部配置封装**：将原先暴露在外的 `pkg/version` 和 `pkg/flag` 目录重构并移至内部包 `internal/config` 下，进一步提升了项目代码的内聚性和封装性。

---

## [v1.2.0] - 2024-01-15

初始的跨平台版本发布，带来了 Windows 平台的 ETW 监控支持。

### 新增功能
- **Windows ETW 采集器**：利用 Windows 的 ETW 事件追踪技术，监听 `Microsoft-Windows-DNS-Client` 提供程序，可在普通用户权限下运行。
- **Linux eBPF 采集器**：初始版本的 Linux 采集器，在 `udp_sendmsg` 和 `tcp_sendmsg` 系统调用入口处使用 Kprobes。
- **Web 可视化面板**：集成了轻量 Web 服务，提供实时 DNS 数据列表、搜索过滤及域名分析图表。
- **数据导出与归档**：支持终端实时日志格式化打印，并可自动将记录归档保存至本地 JSON 文件。
