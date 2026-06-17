//go:build !linux && !windows

package collector

// NewPlatformCollector 为不支持的平台提供默认实现
func NewPlatformCollector() Collector {
	return nil
}