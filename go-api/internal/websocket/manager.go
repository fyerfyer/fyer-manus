package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			// 在生产环境中应该进行更严格的Origin检查
			return true
		},
	}
)

// Manager WebSocket连接管理器
type Manager struct {
	hub         *Hub
	authService *service.AuthService
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.RWMutex
	started     bool
}

// NewManager 创建WebSocket管理器
func NewManager() *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		hub:         NewHub(),
		authService: service.NewAuthService(),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start 启动管理器
func (m *Manager) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		return
	}

	m.started = true

	// 启动Hub
	go m.hub.Run(m.ctx)

	logger.Info("websocket manager started")
}

// Stop 停止管理器
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.started {
		return
	}

	m.started = false
	m.cancel()
	m.hub.Stop()

	logger.Info("websocket manager stopped")
}

// HandleWebSocket 处理WebSocket连接
func (m *Manager) HandleWebSocket(c *gin.Context) {
	// 认证检查
	token := c.Query("token")
	if token == "" {
		// 尝试从Header获取
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" && len(authHeader) > 7 {
			token = authHeader[7:] // 移除 "Bearer " 前缀
		}
	}

	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	// 验证token
	claims, err := m.authService.ValidateToken(token)
	if err != nil {
		logger.Warn("websocket authentication failed",
			zap.Error(err),
			zap.String("remote_addr", c.ClientIP()),
		)
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "invalid token",
		})
		return
	}

	// 升级到WebSocket连接
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logger.Error("failed to upgrade websocket connection",
			zap.Error(err),
			zap.String("user_id", claims.UserID.String()),
		)
		return
	}

	// 创建客户端
	client := NewClient(conn, m.hub, claims.UserID, claims.Username)

	// 设置客户端元数据
	client.SetMetadata("user_agent", c.GetHeader("User-Agent"))
	client.SetMetadata("remote_addr", c.ClientIP())
	client.SetMetadata("roles", claims.Roles)
	client.SetMetadata("permissions", claims.Permissions)

	// 注册客户端
	m.hub.register <- client

	// 启动客户端
	client.Start(m.ctx)

	logger.Info("websocket connection established",
		zap.String("client_id", client.ID.String()),
		zap.String("user_id", claims.UserID.String()),
		zap.String("username", claims.Username),
		zap.String("remote_addr", c.ClientIP()),
	)
}

// GetStats 获取统计信息
func (m *Manager) GetStats() map[string]interface{} {
	hubStats := m.hub.GetStats()

	return map[string]interface{}{
		"hub_stats": hubStats,
		"status":    m.getStatus(),
	}
}

// getStatus 获取管理器状态
func (m *Manager) getStatus() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.started {
		return "running"
	}
	return "stopped"
}

// BroadcastToUser 向指定用户广播消息
func (m *Manager) BroadcastToUser(userID uuid.UUID, message interface{}) error {
	data, err := marshalMessage(message)
	if err != nil {
		return err
	}

	m.hub.Broadcast(&BroadcastMessage{
		Type:   BroadcastToUser,
		UserID: userID,
		Data:   data,
	})

	return nil
}

// BroadcastToSession 向会话广播消息
func (m *Manager) BroadcastToSession(sessionID uuid.UUID, message interface{}) error {
	data, err := marshalMessage(message)
	if err != nil {
		return err
	}

	m.hub.Broadcast(&BroadcastMessage{
		Type:      BroadcastToSession,
		SessionID: sessionID,
		Data:      data,
	})

	return nil
}

// BroadcastToAll 向所有用户广播消息
func (m *Manager) BroadcastToAll(message interface{}) error {
	data, err := marshalMessage(message)
	if err != nil {
		return err
	}

	m.hub.Broadcast(&BroadcastMessage{
		Type: BroadcastToAll,
		Data: data,
	})

	return nil
}

// JoinSession 用户加入会话
func (m *Manager) JoinSession(userID, sessionID uuid.UUID) {
	clients := m.hub.GetClientsByUser(userID)
	for _, client := range clients {
		m.hub.JoinSession(client, sessionID)
	}

	logger.Info("user joined session",
		zap.String("user_id", userID.String()),
		zap.String("session_id", sessionID.String()),
		zap.Int("client_count", len(clients)),
	)
}

// LeaveSession 用户离开会话
func (m *Manager) LeaveSession(userID, sessionID uuid.UUID) {
	clients := m.hub.GetClientsByUser(userID)
	for _, client := range clients {
		m.hub.LeaveSession(client, sessionID)
	}

	logger.Info("user left session",
		zap.String("user_id", userID.String()),
		zap.String("session_id", sessionID.String()),
		zap.Int("client_count", len(clients)),
	)
}

// GetUserClients 获取用户的客户端列表
func (m *Manager) GetUserClients(userID uuid.UUID) []map[string]interface{} {
	clients := m.hub.GetClientsByUser(userID)
	var result []map[string]interface{}

	for _, client := range clients {
		result = append(result, client.GetInfo())
	}

	return result
}

// DisconnectUser 断开用户的所有连接
func (m *Manager) DisconnectUser(userID uuid.UUID, reason string) {
	clients := m.hub.GetClientsByUser(userID)

	for _, client := range clients {
		// 发送断开连接消息
		client.SendError(reason, http.StatusForbidden)

		// 强制断开连接
		client.Close()
	}

	logger.Info("user disconnected",
		zap.String("user_id", userID.String()),
		zap.String("reason", reason),
		zap.Int("client_count", len(clients)),
	)
}

// IsUserConnected 检查用户是否在线
func (m *Manager) IsUserConnected(userID uuid.UUID) bool {
	clients := m.hub.GetClientsByUser(userID)
	return len(clients) > 0
}

// GetHub 获取Hub实例（用于高级操作）
func (m *Manager) GetHub() *Hub {
	return m.hub
}

// marshalMessage 序列化消息
func marshalMessage(message interface{}) ([]byte, error) {
	// 这里可以根据需要选择不同的序列化方式
	switch v := message.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		// 使用JSON序列化
		return json.Marshal(message)
	}
}

// ValidateClient 验证客户端权限
func (m *Manager) ValidateClient(client *Client, requiredPermission string) bool {
	permissions, ok := client.Metadata["permissions"].([]string)
	if !ok {
		return false
	}

	for _, permission := range permissions {
		if permission == "*" || permission == requiredPermission {
			return true
		}
	}

	return false
}

// NotifyUserStatusChange 通知用户状态变化
func (m *Manager) NotifyUserStatusChange(userID uuid.UUID, status string) {
	event := map[string]interface{}{
		"type":    "user_status_change",
		"user_id": userID,
		"status":  status,
		"time":    time.Now(),
	}

	m.BroadcastToUser(userID, event)
}

// Health 健康检查
func (m *Manager) Health() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.started {
		return fmt.Errorf("websocket manager is not running")
	}

	return nil
}
