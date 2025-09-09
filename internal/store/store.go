package store

import "dnsflux/internal/model"

// Store 定义数据存储接口
// 支持添加记录、查询记录和实时订阅功能
type Store interface {
	// AddRecord 添加新的 DNS 记录
	AddRecord(rec model.DNSRecord) error

	// GetRecent 获取最近的记录，limit <= 0 表示获取所有记录
	GetRecent(limit int) ([]model.DNSRecord, error)

	// Subscribe 订阅新记录，返回一个只读通道用于实时推送
	Subscribe() <-chan model.DNSRecord

	// Close 关闭存储，清理资源
	Close() error
}
