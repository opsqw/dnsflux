# dnsflux

> 使用 golang 编写的用于 Windows 和 Linux 平台的 DNS 查询请求监控工具。

dnsflux 主要用于应急响应时，通过恶意域名检测定位到受害主机，但由于恶意进程生命周期短等原因，导致无法定位到恶意程序。通过实现监控DNS查询请求的同时记录进程等信息，辅助快速定位恶意程序。

- Windows 平台基于ETW事件，通过“Microsoft-Windows-DNS-Client”提供程序的事件跟踪，捕获ID为3008（已完成的查询）的事件。
- Linux 平台基于eBPF技术，通过加载过滤程序捕获内核网络数据包，从中解析DNS查询信息。

## Usages

### Windows

Release下载可执行文件，双击运行。

### Linux
> Linux 平台需要在特权模式或者 root 用户下运行。

```
sudo dnsflux
```
