package utils

import (
	"fmt"
	"net"
)

// FindAvailablePort 从指定端口开始查找可用端口
func FindAvailablePort(startPort int, host string) int {
	port := startPort
	for {
		addr := fmt.Sprintf("%s:%d", host, port)
		listener, err := net.Listen("tcp", addr)
		if err == nil {
			listener.Close()
			return port
		}
		port++
		if port > 65535 {
			return startPort
		}
	}
}
