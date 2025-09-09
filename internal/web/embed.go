package web

import (
	"embed"
	"io/fs"
)

// 嵌入静态资源到二进制文件中
//
//go:embed templates
var assets embed.FS

// TemplatesFS 返回模板文件系统
func TemplatesFS() (fs.FS, error) {
	return fs.Sub(assets, "templates")
}

// StaticFS 返回静态文件系统
func StaticFS() (fs.FS, error) {
	return fs.Sub(assets, "static")
}

// HasStatic 检查是否有静态文件
func HasStatic() bool {
	staticFS, err := StaticFS()
	if err != nil {
		return false
	}

	// 尝试读取目录来检查是否有文件
	if entries, err := fs.ReadDir(staticFS, "."); err == nil {
		return len(entries) > 0
	}
	return false
}
