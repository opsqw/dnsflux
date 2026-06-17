package frontend

import (
	"embed"
	"io/fs"
)

//go:embed index.html static/*
var assets embed.FS

// GetFS 返回嵌入的前端文件系统
func GetFS() fs.FS {
	return assets
}
