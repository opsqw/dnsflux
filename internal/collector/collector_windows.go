//go:build windows

package collector

import (
	"dnsflux/internal/collector/windows"
)

// NewPlatformCollector 创建 Windows 平台采集器
func NewPlatformCollector() Collector {
	return windows.NewCollector()
}
