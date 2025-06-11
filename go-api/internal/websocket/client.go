package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// Client WebSocket客户端
type Client struct {
	ID       uuid.UUID `json:"id"`
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`

	conn     *websocket.Conn
	hub      *Hub
	send     chan []byte
	done     chan struct{}
	mu       sync.RWMutex
	isActive bool

	// 连接信息
	ConnectedAt time.Time              `json:"connected_at"`
	LastPing    time.Time              `json:"last_ping"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewClient 创建新的WebSocket客户端
func NewClient(conn *websocket.Conn, hub *Hub, userID uuid.UUID, username string) *Client {
	return &Client{
		ID:          uuid.New(),
		UserID:      userID,
		Username:    username,
		conn:        conn,
		hub:         hub,
		send:        make(chan []byte, 256),
		done:        make(chan struct{}),
		isActive:    true,
		ConnectedAt: time.Now(),
		LastPing:    time.Now(),
		Metadata:    make(map[string]interface{}),
	}
}

// Start 启动客户端监听
func (c *Client) Start(ctx context.Context) {
	go c.readPump(ctx)
	go c.writePump(ctx)
}

// readPump 读取消息
func (c *Client) readPump(ctx context.Context) {
	defer func() {
		c.Close()
		c.hub.unregister <- c
	}()

	// 设置读取参数
	c.conn.SetReadLimit(512 * 1024) // 512KB
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.mu.Lock()
		c.LastPing = time.Now()
		c.mu.Unlock()
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		default:
			_, message, err := c.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					logger.Error("websocket read error",
						zap.Error(err),
						zap.String("client_id", c.ID.String()),
					)
				}
				return
			}

			// 处理接收到的消息
			if err := c.handleMessage(message); err != nil {
				logger.Error("failed to handle websocket message",
					zap.Error(err),
					zap.String("client_id", c.ID.String()),
				)
			}
		}
	}
}

// writePump 写入消息
func (c *Client) writePump(ctx context.Context) {
	ticker := time.NewTicker(54 * time.Second) // ping间隔
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				logger.Error("websocket write error",
					zap.Error(err),
					zap.String("client_id", c.ID.String()),
				)
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleMessage 处理接收到的消息
func (c *Client) handleMessage(message []byte) error {
	var wsMsg types.WSEvent
	if err := json.Unmarshal(message, &wsMsg); err != nil {
		return fmt.Errorf("invalid message format: %w", err)
	}

	// 更新事件时间和ID
	wsMsg.Time = time.Now()
	if wsMsg.EventID == "" {
		wsMsg.EventID = uuid.New().String()
	}

	// 根据消息类型处理
	switch wsMsg.Type {
	case types.WSMessageTypeHeartbeat:
		c.handleHeartbeat()
	case types.WSMessageTypeMessage:
		c.hub.broadcast <- &BroadcastMessage{
			Type:   BroadcastToUser,
			UserID: c.UserID,
			Data:   message,
			Sender: c,
		}
	default:
		// 转发给Hub处理
		c.hub.message <- &ClientMessage{
			Client:  c,
			Message: wsMsg,
			Data:    message,
		}
	}

	return nil
}

// handleHeartbeat 处理心跳消息
func (c *Client) handleHeartbeat() {
	c.mu.Lock()
	c.LastPing = time.Now()
	c.mu.Unlock()

	// 发送心跳响应
	response := types.WSEvent{
		Type:    types.WSMessageTypeHeartbeat,
		Data:    map[string]interface{}{"status": "alive"},
		EventID: uuid.New().String(),
		Time:    time.Now(),
	}

	c.SendMessage(response)
}

// SendMessage 发送消息到客户端
func (c *Client) SendMessage(event types.WSEvent) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.isActive {
		return fmt.Errorf("client is not active")
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	select {
	case c.send <- data:
		return nil
	default:
		// 通道已满，关闭客户端
		go c.Close()
		return fmt.Errorf("client send channel is full")
	}
}

// SendError 发送错误消息
func (c *Client) SendError(message string, code int) {
	errorEvent := types.WSEvent{
		Type:    types.WSMessageTypeError,
		EventID: uuid.New().String(),
		Time:    time.Now(),
		Data: map[string]interface{}{
			"message": message,
			"code":    code,
		},
	}
	c.SendMessage(errorEvent)
}

// IsActive 检查客户端是否活跃
func (c *Client) IsActive() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isActive
}

// GetInfo 获取客户端信息
func (c *Client) GetInfo() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"id":           c.ID,
		"user_id":      c.UserID,
		"username":     c.Username,
		"connected_at": c.ConnectedAt,
		"last_ping":    c.LastPing,
		"is_active":    c.isActive,
		"metadata":     c.Metadata,
	}
}

// SetMetadata 设置元数据
func (c *Client) SetMetadata(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Metadata[key] = value
}

// Close 关闭客户端连接
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isActive {
		return
	}

	c.isActive = false
	close(c.done)
	close(c.send)

	if c.conn != nil {
		c.conn.Close()
	}

	logger.Info("websocket client closed",
		zap.String("client_id", c.ID.String()),
		zap.String("user_id", c.UserID.String()),
	)
}
