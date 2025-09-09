//go:build !linux && !windows

package collector

// newPlatformCollector 为不支持的平台提供默认实现
func newPlatformCollector() Collector {
	return nil
}
