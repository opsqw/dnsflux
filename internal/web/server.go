package web

import (
	"context"
	"dnsflux/internal/model"
	"dnsflux/internal/store"
	"dnsflux/pkg/logger"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type WebServerConfig struct {
	Addr string
}

// Server Web API 服务器
type Server struct {
	store    store.Store
	config   WebServerConfig
	upgrader websocket.Upgrader
	server   *http.Server
	mu       sync.RWMutex
	clients  map[*websocket.Conn]bool
}

// New 创建新的 API 服务器
func New(store store.Store, addr string, port int) *Server {
	return &Server{
		store:   store,
		config:  WebServerConfig{Addr: fmt.Sprintf("%s:%d", addr, port)},
		clients: make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // 允许跨域
			},
		},
	}
}

// Start 启动 Web 服务器
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// 注册路由
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/records", s.handleRecords)
	mux.HandleFunc("/ws", s.handleWebSocket)

	// 静态文件服务
	if HasStatic() {
		staticFS, err := StaticFS()
		if err == nil {
			mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
		}
	}

	s.server = &http.Server{
		Addr:    s.config.Addr,
		Handler: mux,
	}

	// 启动 WebSocket 广播
	go s.broadcastLoop(ctx)

	// 启动服务器
	return s.server.ListenAndServe()
}

// Stop 停止 Web 服务器
func (s *Server) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

// AddRecord 添加 DNS 记录（供外部调用）
func (s *Server) AddRecord(record model.DNSRecord) {
	if err := s.store.AddRecord(record); err != nil {
		logger.Error(fmt.Sprintf("添加记录失败: %v", err))
	}
}

// handleIndex 处理首页请求
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	templateFS, err := TemplatesFS()
	if err != nil {
		http.Error(w, "模板文件系统错误", http.StatusInternalServerError)
		return
	}

	tmplData, err := fs.ReadFile(templateFS, "index.html")
	if err != nil {
		http.Error(w, "读取模板文件失败", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.New("index").Parse(string(tmplData))
	if err != nil {
		http.Error(w, "解析模板失败", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, nil); err != nil {
		logger.Error(fmt.Sprintf("模板执行失败: %v", err))
	}
}

// handleRecords 处理获取记录的 API 请求
func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	records, err := s.store.GetRecent(100) // 获取最近 100 条记录
	if err != nil {
		http.Error(w, "获取记录失败", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(records); err != nil {
		logger.Error(fmt.Sprintf("JSON 编码失败: %v", err))
	}
}

// handleWebSocket 处理 WebSocket 连接
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Error(fmt.Sprintf("WebSocket 升级失败: %v", err))
		return
	}
	defer conn.Close()

	// 注册客户端
	s.mu.Lock()
	s.clients[conn] = true
	s.mu.Unlock()

	// 发送最近的记录
	if records, err := s.store.GetRecent(50); err == nil {
		for _, record := range records {
			if err := conn.WriteJSON(record); err != nil {
				break
			}
		}
	}

	// 保持连接并处理客户端消息
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}

	// 移除客户端
	s.mu.Lock()
	delete(s.clients, conn)
	s.mu.Unlock()
}

// broadcastLoop WebSocket 广播循环
func (s *Server) broadcastLoop(ctx context.Context) {
	ch := s.store.Subscribe()
	defer func() {
		// 关闭所有客户端连接
		s.mu.Lock()
		for conn := range s.clients {
			conn.Close()
		}
		s.mu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case record, ok := <-ch:
			if !ok {
				return
			}
			s.broadcast(record)
		}
	}
}

// broadcast 广播消息给所有 WebSocket 客户端
func (s *Server) broadcast(record model.DNSRecord) {
	s.mu.RLock()
	clients := make([]*websocket.Conn, 0, len(s.clients))
	for conn := range s.clients {
		clients = append(clients, conn)
	}
	s.mu.RUnlock()

	for _, conn := range clients {
		if err := conn.WriteJSON(record); err != nil {
			// 连接已断开，移除客户端
			s.mu.Lock()
			delete(s.clients, conn)
			s.mu.Unlock()
			conn.Close()
		}
	}
}
