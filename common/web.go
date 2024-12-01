package common

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// DNSRecord 定义通用的 DNS 记录结构
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

var (
	// 存储 DNS 记录的切片，使用互斥锁保护
	dnsRecords      []DNSRecord
	dnsRecordsMutex sync.RWMutex
	clients         = make(map[*websocket.Conn]bool)
	clientsMu       sync.RWMutex
)

// AddDNSRecord 添加新的 DNS 记录并通知所有客户端
func AddDNSRecord(record DNSRecord) {
	dnsRecordsMutex.Lock()
	defer dnsRecordsMutex.Unlock()

	// 在开头添加新记录
	dnsRecords = append([]DNSRecord{record}, dnsRecords...)

	// 广播新记录给所有连接的客户端
	broadcastRecord(record)
}

// 处理 WebSocket 连接
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket 升级失败: %v", err)
		return
	}
	defer conn.Close()

	// 注册新客户端
	clientsMu.Lock()
	clients[conn] = true
	clientsMu.Unlock()

	// 客户端断开连接时清理
	defer func() {
		clientsMu.Lock()
		delete(clients, conn)
		clientsMu.Unlock()
	}()

	// 保持连接活跃
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// 广播记录给所有客户端
func broadcastRecord(record DNSRecord) {
	data, err := json.Marshal(record)
	if err != nil {
		log.Printf("JSON 序列化失败: %v", err)
		return
	}

	clientsMu.RLock()
	defer clientsMu.RUnlock()

	for client := range clients {
		err := client.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			log.Printf("发送消息失败: %v", err)
			client.Close()
			delete(clients, client)
		}
	}
}

// 检查端口是否可用
func isPortAvailable(port int) bool {
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	listener.Close()
	return true
}

// 获取随机可用端口
func getRandomAvailablePort() int {
	rand.Seed(time.Now().UnixNano())
	for {
		// 在2000-3000范围内随机选择端口
		port := rand.Intn(1001) + 2000
		if isPortAvailable(port) {
			return port
		}
	}
}

// StartWebServer 启动 Web 服务器
func StartWebServer() {
	// 获取可用的随机端口
	port := getRandomAvailablePort()

	// 静态文件处理
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// 主页
	http.HandleFunc("/", handleHome)
	// API 端点
	http.HandleFunc("/ws", handleWebSocket)

	// 启动服务器
	addr := fmt.Sprintf(":%d", port)
	log.Printf("Web 服务器启动在 http://localhost%s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Web 服务器启动失败: %v", err)
	}
}

// handleHome 处理主页请求
func handleHome(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/index.html"))
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
