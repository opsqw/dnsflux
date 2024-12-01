package output

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var logFile *os.File

// InitLogger 初始化日志记录器
func InitLogger() error {
	// 创建logs目录
	logsDir := "logs"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %v", err)
	}

	// 生成日志文件名（使用当前日期）
	currentTime := time.Now()
	fileName := filepath.Join(logsDir, fmt.Sprintf("dns_%s.log", currentTime.Format("2006-01-02")))

	// 打开日志文件（追加模式）
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %v", err)
	}

	// 如果之前有打开的日志文件，关闭它
	if logFile != nil {
		logFile.Close()
	}

	logFile = file
	return nil
}

// WriteLog 写入日志条目
func WriteLog(logEntry string) error {
	if logFile == nil {
		if err := InitLogger(); err != nil {
			return fmt.Errorf("初始化日志记录器失败: %v", err)
		}
	}

	_, err := fmt.Fprintln(logFile, logEntry)
	return err
}

// Close 关闭日志文件
func Close() {
	if logFile != nil {
		logFile.Close()
		logFile = nil
	}
}
