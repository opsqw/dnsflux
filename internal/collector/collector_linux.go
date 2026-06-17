//go:build linux

package collector

import (
	"dnsflux/internal/collector/linux"
)

// NewPlatformCollector 创建 Linux 平台采集器
func NewPlatformCollector() Collector {
	return linux.NewLinuxCollector()
}
