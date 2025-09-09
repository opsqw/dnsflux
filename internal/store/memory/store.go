package memory

import (
	"dnsflux/internal/model"
	"dnsflux/internal/store"
	"sync"
)

// memoryStore 内存存储实现
type memoryStore struct {
	mu      sync.RWMutex
	records []model.DNSRecord
	subs    []chan model.DNSRecord
	cap     int
	closed  bool
}

// New 创建新的内存存储实例
func New(capacity int) store.Store {
	if capacity <= 0 {
		capacity = 5000 // 默认容量
	}
	return &memoryStore{
		cap:     capacity,
		records: make([]model.DNSRecord, 0, capacity),
		subs:    make([]chan model.DNSRecord, 0),
	}
}

// AddRecord 添加新记录到存储中
func (m *memoryStore) AddRecord(rec model.DNSRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil // 已关闭，忽略新记录
	}

	// 头插，保持最新记录在前
	m.records = append([]model.DNSRecord{rec}, m.records...)

	// 控制容量，删除最旧的记录
	if len(m.records) > m.cap {
		m.records = m.records[:m.cap]
	}

	// 非阻塞广播给所有订阅者
	for i, ch := range m.subs {
		select {
		case ch <- rec:
			// 发送成功
		default:
			// 通道阻塞，移除该订阅者
			close(ch)
			m.subs = append(m.subs[:i], m.subs[i+1:]...)
		}
	}

	return nil
}

// GetRecent 获取最近的记录
func (m *memoryStore) GetRecent(limit int) ([]model.DNSRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > len(m.records) {
		limit = len(m.records)
	}

	// 复制数据避免并发问题
	out := make([]model.DNSRecord, limit)
	copy(out, m.records[:limit])
	return out, nil
}

// Subscribe 订阅新记录
func (m *memoryStore) Subscribe() <-chan model.DNSRecord {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		// 如果已关闭，返回一个已关闭的通道
		ch := make(chan model.DNSRecord)
		close(ch)
		return ch
	}

	ch := make(chan model.DNSRecord, 64) // 带缓冲避免阻塞
	m.subs = append(m.subs, ch)
	return ch
}

// Close 关闭存储
func (m *memoryStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true

	// 关闭所有订阅通道
	for _, ch := range m.subs {
		close(ch)
	}
	m.subs = nil
	m.records = nil

	return nil
}
