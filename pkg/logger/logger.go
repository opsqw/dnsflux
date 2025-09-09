package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// CustomFormatter 自定义日志格式化器
type CustomFormatter struct {
	EnableColor bool // 是否启用颜色输出
}

// NewCustomFormatter 创建一个新的CustomFormatter实例
func NewCustomFormatter() *CustomFormatter {
	return &CustomFormatter{EnableColor: true}
}

// NewCustomFormatterWithColor 创建一个指定颜色设置的CustomFormatter实例
func NewCustomFormatterWithColor(enableColor bool) *CustomFormatter {
	return &CustomFormatter{EnableColor: enableColor}
}

// Format 实现logrus.Formatter接口
func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// 格式化时间戳
	timestamp := entry.Time.Format("2006-01-02 15:04:05.000")

	// 获取日志级别的颜色
	var levelColor int
	switch entry.Level {
	case logrus.DebugLevel:
		levelColor = 36 // 白色
	case logrus.InfoLevel:
		levelColor = 32 // 绿色
	case logrus.WarnLevel:
		levelColor = 33 // 黄色
	case logrus.ErrorLevel:
		levelColor = 31 // 红色
	case logrus.FatalLevel, logrus.PanicLevel:
		levelColor = 35 // 紫色
	}

	// 获取日志级别的四字母缩写
	levelShort := strings.ToUpper(entry.Level.String()[:4])

	// 构建日志级别文本（根据设置决定是否添加颜色）
	var levelText string
	if f.EnableColor {
		levelText = fmt.Sprintf("\033[%dm%s\033[0m", levelColor, levelShort)
	} else {
		levelText = levelShort
	}

	// 构建字段信息（排除 source 字段）
	var fieldsText string
	if len(entry.Data) > 0 {
		var fieldPairs []string
		for key, value := range entry.Data {
			if key != "source" { // 排除 source 字段
				fieldPairs = append(fieldPairs, fmt.Sprintf("%s=%v", key, value))
			}
		}
		if len(fieldPairs) > 0 {
			fieldsText = fmt.Sprintf(" [%s]", strings.Join(fieldPairs, ", "))
		}
	}

	// 构建日志消息（不包含来源标识）
	message := fmt.Sprintf("[%s] %s: %s%s\n",
		timestamp,
		levelText,
		entry.Message,
		fieldsText)

	return []byte(message), nil
}

// InitLogger 初始化日志配置
func InitLogger() {
	// 设置日志输出为标准输出
	logrus.SetOutput(os.Stdout)

	// 启用调用者信息报告
	logrus.SetReportCaller(true)

	// 设置自定义日志格式
	logrus.SetFormatter(NewCustomFormatter())

	// 默认日志级别为 Info
	logrus.SetLevel(logrus.InfoLevel)
}

// RotatingFileWriter 实现日志文件轮转的写入器
type RotatingFileWriter struct {
	filename    string
	maxSize     int64 // 最大文件大小（字节）
	maxFiles    int   // 最大文件数量
	currentFile *os.File
	currentSize int64
	mutex       sync.Mutex
}

// NewRotatingFileWriter 创建新的轮转文件写入器
func NewRotatingFileWriter(filename string, maxSizeMB, maxFiles int) (*RotatingFileWriter, error) {
	// 确保日志文件目录存在
	logDir := filepath.Dir(filename)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %v", err)
	}

	writer := &RotatingFileWriter{
		filename: filename,
		maxSize:  int64(maxSizeMB) * 1024 * 1024, // 转换为字节
		maxFiles: maxFiles,
	}

	// 打开当前日志文件
	if err := writer.openCurrentFile(); err != nil {
		return nil, err
	}

	return writer, nil
}

// Write 实现 io.Writer 接口
func (w *RotatingFileWriter) Write(p []byte) (n int, err error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	// 检查是否需要轮转
	if w.currentSize+int64(len(p)) > w.maxSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}

	// 写入数据
	n, err = w.currentFile.Write(p)
	if err == nil {
		w.currentSize += int64(n)
	}
	return n, err
}

// openCurrentFile 打开当前日志文件
func (w *RotatingFileWriter) openCurrentFile() error {
	file, err := os.OpenFile(w.filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %v", err)
	}

	// 获取文件当前大小
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("获取文件信息失败: %v", err)
	}

	w.currentFile = file
	w.currentSize = stat.Size()
	return nil
}

// rotate 执行日志文件轮转
func (w *RotatingFileWriter) rotate() error {
	// 关闭当前文件
	if w.currentFile != nil {
		w.currentFile.Close()
	}

	// 轮转文件名
	for i := w.maxFiles - 1; i > 0; i-- {
		oldName := fmt.Sprintf("%s.%d", w.filename, i)
		newName := fmt.Sprintf("%s.%d", w.filename, i+1)

		if i == w.maxFiles-1 {
			// 删除最老的文件
			os.Remove(newName)
		}

		if _, err := os.Stat(oldName); err == nil {
			os.Rename(oldName, newName)
		}
	}

	// 将当前文件重命名为 .1
	if _, err := os.Stat(w.filename); err == nil {
		os.Rename(w.filename, w.filename+".1")
	}

	// 创建新的当前文件
	return w.openCurrentFile()
}

// Close 关闭文件写入器
func (w *RotatingFileWriter) Close() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.currentFile != nil {
		return w.currentFile.Close()
	}
	return nil
}

// FileFormatterWriter 包装文件写入器，使用无颜色格式化器
type FileFormatterWriter struct {
	writer    io.Writer
	formatter logrus.Formatter
}

// Write 实现 io.Writer 接口，使用无颜色格式化器
func (w *FileFormatterWriter) Write(p []byte) (n int, err error) {
	return w.writer.Write(p)
}

// MultiFormatterWriter 支持不同输出目标使用不同格式化器的写入器
type MultiFormatterWriter struct {
	consoleWriter    io.Writer
	fileWriter       io.Writer
	consoleFormatter logrus.Formatter
	fileFormatter    logrus.Formatter
}

// Write 实现 io.Writer 接口
func (w *MultiFormatterWriter) Write(p []byte) (n int, err error) {
	// 直接写入，格式化已在 logrus 层面处理
	var totalN int
	var lastErr error

	// 写入控制台
	if w.consoleWriter != nil {
		n, err = w.consoleWriter.Write(p)
		totalN += n
		if err != nil {
			lastErr = err
		}
	}

	// 写入文件（需要去除颜色代码）
	if w.fileWriter != nil {
		// 去除 ANSI 颜色代码
		cleanData := removeANSIColors(p)
		n, err = w.fileWriter.Write(cleanData)
		if err != nil {
			lastErr = err
		}
	}

	return totalN, lastErr
}

// removeANSIColors 去除字节数组中的 ANSI 颜色代码
func removeANSIColors(data []byte) []byte {
	str := string(data)
	// 使用正则表达式去除 ANSI 转义序列
	// 匹配 \033[数字m 格式的颜色代码
	result := ""
	i := 0
	for i < len(str) {
		if i < len(str)-1 && str[i] == '\033' && str[i+1] == '[' {
			// 找到颜色代码的结束位置
			j := i + 2
			for j < len(str) && str[j] != 'm' {
				j++
			}
			if j < len(str) {
				i = j + 1 // 跳过整个颜色代码
				continue
			}
		}
		result += string(str[i])
		i++
	}
	return []byte(result)
}

// ConfigureLogger 根据配置重新设置日志系统
func ConfigureLogger(logLevel, logFile string, maxSizeMB, maxFiles int) error {
	// 设置日志级别
	if logLevel != "" {
		level, err := logrus.ParseLevel(logLevel)
		if err != nil {
			return fmt.Errorf("无效的日志级别 '%s': %v", logLevel, err)
		}
		logrus.SetLevel(level)
	}

	// 设置日志输出
	if logFile != "" {
		// 创建轮转文件写入器
		fileWriter, err := NewRotatingFileWriter(logFile, maxSizeMB, maxFiles)
		if err != nil {
			return err
		}

		// 创建多格式化器写入器，控制台带颜色，文件无颜色
		multiWriter := &MultiFormatterWriter{
			consoleWriter: os.Stdout,
			fileWriter:    fileWriter,
		}
		logrus.SetOutput(multiWriter)

		// 使用带颜色的格式化器（颜色代码会在写入文件时被去除）
		logrus.SetFormatter(NewCustomFormatterWithColor(true))
	} else {
		// 如果没有指定日志文件，只输出到控制台，使用带颜色的格式化器
		logrus.SetOutput(os.Stdout)
		logrus.SetFormatter(NewCustomFormatterWithColor(true))
	}

	return nil
}

// mergeFields 合并用户字段
func mergeFields(userFields ...logrus.Fields) logrus.Fields {
	var fields logrus.Fields
	if len(userFields) > 0 {
		fields = make(logrus.Fields)
		for k, v := range userFields[0] {
			fields[k] = v
		}
	} else {
		fields = make(logrus.Fields)
	}

	return fields
}

// 提供便捷的日志记录方法
func Debug(msg string, fields ...logrus.Fields) {
	mergedFields := mergeFields(fields...)
	logrus.WithFields(mergedFields).Debug(msg)
}

func Info(msg string, fields ...logrus.Fields) {
	mergedFields := mergeFields(fields...)
	logrus.WithFields(mergedFields).Info(msg)
}

func Warn(msg string, fields ...logrus.Fields) {
	mergedFields := mergeFields(fields...)
	logrus.WithFields(mergedFields).Warn(msg)
}

func Error(msg string, fields ...logrus.Fields) {
	mergedFields := mergeFields(fields...)
	logrus.WithFields(mergedFields).Error(msg)
}

func Fatal(msg string, fields ...logrus.Fields) {
	mergedFields := mergeFields(fields...)
	logrus.WithFields(mergedFields).Fatal(msg)
}
