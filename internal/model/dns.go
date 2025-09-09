package model

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DNSRecord 定义通用的 DNS 记录结构在 collector/api/store 间复用
type DNSRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	QueryName   string    `json:"queryName"`
	QueryType   string    `json:"queryType"`
	QueryResult string    `json:"queryResult"`
	ProcessID   uint32    `json:"processId"`
	ProcessName string    `json:"processName"`
	ProcessPath string    `json:"processPath"`
	ClientIP    string    `json:"clientIP"`
}

// FormatDNSRecord 格式化DNS查询记录为字符串
func (r *DNSRecord) FormatDNSRecord() string {
	timestamp := r.Timestamp.In(time.Local).Format("2006-01-02 15:04:05")
	return fmt.Sprintf("\n[+] DNS Query Record\n"+
		"Timestamp    : %s\n"+
		"Query Name   : %s\n"+
		"Query Type   : %s\n"+
		"Query Result : %s\n"+
		"Process ID   : %d\n"+
		"Process Name : %s\n"+
		"Process Path : %s\n"+
		"Client IP    : %s\n"+
		"*************************************",
		timestamp,
		r.QueryName,
		r.QueryType,
		r.QueryResult,
		r.ProcessID,
		r.ProcessName,
		r.ProcessPath,
		r.ClientIP)
}

// SaveDNSRecordToJSON 保存DNS记录到JSON文件
func (r *DNSRecord) SaveDNSRecordToJSON() error {
	// 创建logs目录
	logsDir := "logs"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %v", err)
	}

	// 生成文件名（按日期）
	filename := fmt.Sprintf("dns_records_%s.json", time.Now().Format("2006-01-02"))
	filePath := filepath.Join(logsDir, filename)

	// 打开文件（追加模式）
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// 将记录编码为JSON
	jsonData, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("failed to marshal record to JSON: %v", err)
	}

	// 写入文件（每条记录一行）
	if _, err := file.Write(append(jsonData, '\n')); err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	return nil
}
