package websocket

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// BroadcastType 广播类型
type BroadcastType string

const (
	BroadcastToAll     BroadcastType = "all"
	BroadcastToUser    BroadcastType = "user"
	BroadcastToSession BroadcastType = "session"
	BroadcastToRole    BroadcastType = "role"
)

// BroadcastMessage 广播消息
type BroadcastMessage struct {
	Type      BroadcastType
	UserID    uuid.UUID
	SessionID uuid.UUID
	Role      string
	Data      []byte
	Sender    *Client
}

// ClientMessage 客户端消息
type ClientMessage struct {
	Client  *Client
	Message types.WSEvent
	Data    []byte
}

// Hub WebSocket消息中心
type Hub struct {
	// 注册的客户端
	clients map[*Client]bool

	// 用户ID到客户端的映射
	userClients map[uuid.UUID]map[*Client]bool

	// 会话ID到客户端的映射
	sessionClients map[uuid.UUID]map[*Client]bool

	// 广播通道
	broadcast chan *BroadcastMessage

	// 客户端消息通道
	message chan *ClientMessage

	// 注册客户端通道
	register chan *Client

	// 注销客户端通道
	unregister chan *Client

	// 停止通道
	done chan struct{}

	// 读写锁
	mu sync.RWMutex

	// 统计信息
	stats HubStats
}

// HubStats Hub统计信息
type HubStats struct {
	TotalClients  int       `json:"total_clients"`
	TotalUsers    int       `json:"total_users"`
	TotalSessions int       `json:"total_sessions"`
	MessagesTotal int       `json:"messages_total"`
	LastMessageAt time.Time `json:"last_message_at"`
}

// NewHub 创建新的Hub
func NewHub() *Hub {
	return &Hub{
		clients:        make(map[*Client]bool),
		userClients:    make(map[uuid.UUID]map[*Client]bool),
		sessionClients: make(map[uuid.UUID]map[*Client]bool),
		broadcast:      make(chan *BroadcastMessage, 256),
		message:        make(chan *ClientMessage, 256),
		register:       make(chan *Client),
		unregister:     make(chan *Client),
		done:           make(chan struct{}),
	}
}

// Run 启动Hub
func (h *Hub) Run(ctx context.Context) {
	logger.Info("websocket hub started")

	// 启动清理协程
	go h.cleanupRoutine(ctx)

	for {
		select {
		case <-ctx.Done():
			h.shutdown()
			return

		case <-h.done:
			h.shutdown()
			return

		case client := <-h.register:
			h.registerClient(client)

		case client := <-h.unregister:
			h.unregisterClient(client)

		case message := <-h.broadcast:
			h.handleBroadcast(message)

		case clientMsg := <-h.message:
			h.handleClientMessage(clientMsg)
		}
	}
}

// registerClient 注册客户端
func (h *Hub) registerClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 添加到总客户端列表
	h.clients[client] = true

	// 添加到用户客户端映射
	if h.userClients[client.UserID] == nil {
		h.userClients[client.UserID] = make(map[*Client]bool)
	}
	h.userClients[client.UserID][client] = true

	// 更新统计
	h.stats.TotalClients = len(h.clients)
	h.stats.TotalUsers = len(h.userClients)

	logger.Info("websocket client registered",
		zap.String("client_id", client.ID.String()),
		zap.String("user_id", client.UserID.String()),
		zap.Int("total_clients", h.stats.TotalClients),
	)

	// 发送连接成功消息
	welcomeEvent := types.WSEvent{
		Type:    types.WSMessageTypeConnection,
		EventID: uuid.New().String(),
		Time:    time.Now(),
		Data: map[string]interface{}{
			"status":    "connected",
			"client_id": client.ID,
			"timestamp": time.Now(),
		},
	}
	client.SendMessage(welcomeEvent)
}

// unregisterClient 注销客户端
func (h *Hub) unregisterClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.clients[client]; !ok {
		return
	}

	// 从总客户端列表移除
	delete(h.clients, client)

	// 从用户客户端映射移除
	if userClients, exists := h.userClients[client.UserID]; exists {
		delete(userClients, client)
		if len(userClients) == 0 {
			delete(h.userClients, client.UserID)
		}
	}

	// 从会话客户端映射移除
	for sessionID, sessionClients := range h.sessionClients {
		if _, exists := sessionClients[client]; exists {
			delete(sessionClients, client)
			if len(sessionClients) == 0 {
				delete(h.sessionClients, sessionID)
			}
		}
	}

	// 更新统计
	h.stats.TotalClients = len(h.clients)
	h.stats.TotalUsers = len(h.userClients)
	h.stats.TotalSessions = len(h.sessionClients)

	logger.Info("websocket client unregistered",
		zap.String("client_id", client.ID.String()),
		zap.String("user_id", client.UserID.String()),
		zap.Int("total_clients", h.stats.TotalClients),
	)

	// 关闭客户端
	client.Close()
}

// handleBroadcast 处理广播消息
func (h *Hub) handleBroadcast(msg *BroadcastMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	h.stats.MessagesTotal++
	h.stats.LastMessageAt = time.Now()

	switch msg.Type {
	case BroadcastToAll:
		h.broadcastToAll(msg)
	case BroadcastToUser:
		h.broadcastToUser(msg)
	case BroadcastToSession:
		h.broadcastToSession(msg)
	case BroadcastToRole:
		h.broadcastToRole(msg)
	}
}

// broadcastToAll 广播给所有客户端
func (h *Hub) broadcastToAll(msg *BroadcastMessage) {
	for client := range h.clients {
		if client != msg.Sender && client.IsActive() {
			select {
			case client.send <- msg.Data:
			default:
				go h.forceUnregister(client)
			}
		}
	}
}

// broadcastToUser 广播给指定用户
func (h *Hub) broadcastToUser(msg *BroadcastMessage) {
	if userClients, exists := h.userClients[msg.UserID]; exists {
		for client := range userClients {
			if client != msg.Sender && client.IsActive() {
				select {
				case client.send <- msg.Data:
				default:
					go h.forceUnregister(client)
				}
			}
		}
	}
}

// broadcastToSession 广播给会话中的客户端
func (h *Hub) broadcastToSession(msg *BroadcastMessage) {
	if sessionClients, exists := h.sessionClients[msg.SessionID]; exists {
		for client := range sessionClients {
			if client != msg.Sender && client.IsActive() {
				select {
				case client.send <- msg.Data:
				default:
					go h.forceUnregister(client)
				}
			}
		}
	}
}

// broadcastToRole 广播给指定角色的用户
func (h *Hub) broadcastToRole(msg *BroadcastMessage) {
	// TODO: 实现基于角色的广播，需要客户端存储用户角色信息
	logger.Debug("role-based broadcast not implemented",
		zap.String("role", msg.Role))
}

// handleClientMessage 处理客户端消息
func (h *Hub) handleClientMessage(clientMsg *ClientMessage) {
	// 这里可以添加具体的消息处理逻辑
	// 例如：消息持久化、消息转发等

	logger.Debug("received client message",
		zap.String("client_id", clientMsg.Client.ID.String()),
		zap.String("type", string(clientMsg.Message.Type)),
	)

	// 示例：将消息广播给同一用户的其他客户端
	if clientMsg.Message.Type == types.WSMessageTypeMessage {
		h.broadcast <- &BroadcastMessage{
			Type:   BroadcastToUser,
			UserID: clientMsg.Client.UserID,
			Data:   clientMsg.Data,
			Sender: clientMsg.Client,
		}
	}
}

// JoinSession 客户端加入会话
func (h *Hub) JoinSession(client *Client, sessionID uuid.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.sessionClients[sessionID] == nil {
		h.sessionClients[sessionID] = make(map[*Client]bool)
	}
	h.sessionClients[sessionID][client] = true

	h.stats.TotalSessions = len(h.sessionClients)

	// 设置客户端元数据
	client.SetMetadata("current_session", sessionID)

	logger.Info("client joined session",
		zap.String("client_id", client.ID.String()),
		zap.String("session_id", sessionID.String()),
	)
}

// LeaveSession 客户端离开会话
func (h *Hub) LeaveSession(client *Client, sessionID uuid.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if sessionClients, exists := h.sessionClients[sessionID]; exists {
		delete(sessionClients, client)
		if len(sessionClients) == 0 {
			delete(h.sessionClients, sessionID)
		}
	}

	h.stats.TotalSessions = len(h.sessionClients)

	// 清除客户端元数据
	client.SetMetadata("current_session", nil)

	logger.Info("client left session",
		zap.String("client_id", client.ID.String()),
		zap.String("session_id", sessionID.String()),
	)
}

// GetStats 获取统计信息
func (h *Hub) GetStats() HubStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stats
}

// GetClientsByUser 获取用户的所有客户端
func (h *Hub) GetClientsByUser(userID uuid.UUID) []*Client {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var clients []*Client
	if userClients, exists := h.userClients[userID]; exists {
		for client := range userClients {
			if client.IsActive() {
				clients = append(clients, client)
			}
		}
	}
	return clients
}

// forceUnregister 强制注销客户端
func (h *Hub) forceUnregister(client *Client) {
	select {
	case h.unregister <- client:
	default:
		// 通道已满，直接关闭客户端
		client.Close()
	}
}

// cleanupRoutine 清理例程
func (h *Hub) cleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.cleanupInactiveClients()
		}
	}
}

// cleanupInactiveClients 清理不活跃的客户端
func (h *Hub) cleanupInactiveClients() {
	h.mu.RLock()
	var inactiveClients []*Client
	cutoff := time.Now().Add(-5 * time.Minute)

	for client := range h.clients {
		if !client.IsActive() || client.LastPing.Before(cutoff) {
			inactiveClients = append(inactiveClients, client)
		}
	}
	h.mu.RUnlock()

	// 注销不活跃的客户端
	for _, client := range inactiveClients {
		logger.Info("cleaning up inactive client",
			zap.String("client_id", client.ID.String()),
			zap.Time("last_ping", client.LastPing),
		)
		h.forceUnregister(client)
	}
}

// Broadcast 发送广播消息
func (h *Hub) Broadcast(msg *BroadcastMessage) {
	select {
	case h.broadcast <- msg:
	default:
		logger.Warn("broadcast channel is full, message dropped")
	}
}

// SendToUser 发送消息给指定用户
func (h *Hub) SendToUser(userID uuid.UUID, event types.WSEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		logger.Error("failed to marshal event", zap.Error(err))
		return
	}

	h.Broadcast(&BroadcastMessage{
		Type:   BroadcastToUser,
		UserID: userID,
		Data:   data,
	})
}

// SendToSession 发送消息给会话中的所有客户端
func (h *Hub) SendToSession(sessionID uuid.UUID, event types.WSEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		logger.Error("failed to marshal event", zap.Error(err))
		return
	}

	h.Broadcast(&BroadcastMessage{
		Type:      BroadcastToSession,
		SessionID: sessionID,
		Data:      data,
	})
}

// shutdown 关闭Hub
func (h *Hub) shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()

	logger.Info("shutting down websocket hub")

	// 关闭所有客户端
	for client := range h.clients {
		client.Close()
	}

	// 清空所有映射
	h.clients = make(map[*Client]bool)
	h.userClients = make(map[uuid.UUID]map[*Client]bool)
	h.sessionClients = make(map[uuid.UUID]map[*Client]bool)

	logger.Info("websocket hub stopped")
}

// Stop 停止Hub
func (h *Hub) Stop() {
	close(h.done)
}
