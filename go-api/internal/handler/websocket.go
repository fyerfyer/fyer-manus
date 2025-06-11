package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/fyerfyer/fyer-manus/go-api/internal/websocket"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// WebSocketHandler WebSocket处理器
type WebSocketHandler struct {
	wsManager      *websocket.Manager
	sessionService *service.SessionService
	messageService *service.MessageService
}

// NewWebSocketHandler 创建WebSocket处理器
func NewWebSocketHandler() *WebSocketHandler {
	return &WebSocketHandler{
		wsManager:      websocket.NewManager(),
		sessionService: service.NewSessionService(),
		messageService: service.NewMessageService(),
	}
}

// Start 启动WebSocket管理器
func (h *WebSocketHandler) Start() {
	h.wsManager.Start()
	logger.Info("websocket handler started")
}

// Stop 停止WebSocket管理器
func (h *WebSocketHandler) Stop() {
	h.wsManager.Stop()
	logger.Info("websocket handler stopped")
}

// HandleWebSocket 处理WebSocket连接
func (h *WebSocketHandler) HandleWebSocket(c *gin.Context) {
	h.wsManager.HandleWebSocket(c)
}

// GetStats 获取WebSocket统计信息
func (h *WebSocketHandler) GetStats(c *gin.Context) {
	stats := h.wsManager.GetStats()
	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "websocket stats retrieved successfully",
		"data":    stats,
	})
}

// GetUserClients 获取用户客户端列表
func (h *WebSocketHandler) GetUserClients(c *gin.Context) {
	userIDStr := c.Param("userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid user ID format",
		})
		return
	}

	clients := h.wsManager.GetUserClients(userID)
	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "user clients retrieved successfully",
		"data":    clients,
	})
}

// DisconnectUser 断开用户连接
func (h *WebSocketHandler) DisconnectUser(c *gin.Context) {
	userIDStr := c.Param("userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid user ID format",
		})
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	h.wsManager.DisconnectUser(userID, req.Reason)

	logger.Info("user disconnected via admin",
		zap.String("user_id", userID.String()),
		zap.String("reason", req.Reason),
	)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "user disconnected successfully",
	})
}

// BroadcastToUser 向指定用户广播消息
func (h *WebSocketHandler) BroadcastToUser(c *gin.Context) {
	userIDStr := c.Param("userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid user ID format",
		})
		return
	}

	var req struct {
		Type string      `json:"type" binding:"required"`
		Data interface{} `json:"data"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	event := types.WSEvent{
		Type:    types.WSMessageType(req.Type),
		Data:    req.Data,
		EventID: uuid.New().String(),
		Time:    time.Now(),
	}

	err = h.wsManager.BroadcastToUser(userID, event)
	if err != nil {
		logger.Error("failed to broadcast to user",
			zap.Error(err),
			zap.String("user_id", userID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": "failed to broadcast message",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "message broadcasted successfully",
	})
}

// BroadcastToSession 向会话广播消息
func (h *WebSocketHandler) BroadcastToSession(c *gin.Context) {
	sessionIDStr := c.Param("sessionId")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid session ID format",
		})
		return
	}

	var req struct {
		Type string      `json:"type" binding:"required"`
		Data interface{} `json:"data"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	event := types.WSEvent{
		Type:    types.WSMessageType(req.Type),
		Data:    req.Data,
		EventID: uuid.New().String(),
		Time:    time.Now(),
	}

	err = h.wsManager.BroadcastToSession(sessionID, event)
	if err != nil {
		logger.Error("failed to broadcast to session",
			zap.Error(err),
			zap.String("session_id", sessionID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": "failed to broadcast message",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "message broadcasted successfully",
	})
}

// JoinSession 用户加入会话
func (h *WebSocketHandler) JoinSession(c *gin.Context) {
	userIDStr := c.Param("userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid user ID format",
		})
		return
	}

	sessionIDStr := c.Param("sessionId")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid session ID format",
		})
		return
	}

	// 验证会话是否存在且用户有权限
	_, err = h.sessionService.GetSession(c.Request.Context(), userID, sessionID)
	if err != nil {
		logger.Error("failed to verify session access",
			zap.Error(err),
			zap.String("user_id", userID.String()),
			zap.String("session_id", sessionID.String()),
		)
		c.JSON(http.StatusForbidden, gin.H{
			"code":    http.StatusForbidden,
			"message": "session access denied",
		})
		return
	}

	h.wsManager.JoinSession(userID, sessionID)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "joined session successfully",
	})
}

// LeaveSession 用户离开会话
func (h *WebSocketHandler) LeaveSession(c *gin.Context) {
	userIDStr := c.Param("userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid user ID format",
		})
		return
	}

	sessionIDStr := c.Param("sessionId")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid session ID format",
		})
		return
	}

	h.wsManager.LeaveSession(userID, sessionID)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "left session successfully",
	})
}

// SendStreamingMessage 发送流式消息
func (h *WebSocketHandler) SendStreamingMessage(userID, sessionID uuid.UUID, content string, done bool) error {
	event := types.WSEvent{
		Type:    types.WSMessageTypeMessage,
		EventID: uuid.New().String(),
		Time:    time.Now(),
		Data: map[string]interface{}{
			"message_id": uuid.New().String(),
			"session_id": sessionID,
			"role":       "assistant",
			"content":    content,
			"done":       done,
			"streaming":  true,
		},
	}

	return h.wsManager.BroadcastToUser(userID, event)
}

// SendTypingIndicator 发送打字指示器
func (h *WebSocketHandler) SendTypingIndicator(userID, sessionID uuid.UUID, typing bool) error {
	event := types.WSEvent{
		Type:    types.WSMessageTypeTyping,
		EventID: uuid.New().String(),
		Time:    time.Now(),
		Data: map[string]interface{}{
			"session_id": sessionID,
			"typing":     typing,
		},
	}

	return h.wsManager.BroadcastToUser(userID, event)
}

// SendError 发送错误消息
func (h *WebSocketHandler) SendError(userID uuid.UUID, message string, code int) error {
	event := types.WSEvent{
		Type:    types.WSMessageTypeError,
		EventID: uuid.New().String(),
		Time:    time.Now(),
		Data: map[string]interface{}{
			"message": message,
			"code":    code,
		},
	}

	return h.wsManager.BroadcastToUser(userID, event)
}

// NotifySessionUpdate 通知会话更新
func (h *WebSocketHandler) NotifySessionUpdate(userID, sessionID uuid.UUID, updateType string, data interface{}) error {
	event := types.WSEvent{
		Type:    types.WSMessageType("session_update"),
		EventID: uuid.New().String(),
		Time:    time.Now(),
		Data: map[string]interface{}{
			"session_id":  sessionID,
			"update_type": updateType,
			"data":        data,
		},
	}

	return h.wsManager.BroadcastToUser(userID, event)
}

// NotifyMessageUpdate 通知消息更新
func (h *WebSocketHandler) NotifyMessageUpdate(userID, sessionID, messageID uuid.UUID, updateType string, data interface{}) error {
	event := types.WSEvent{
		Type:    types.WSMessageType("message_update"),
		EventID: uuid.New().String(),
		Time:    time.Now(),
		Data: map[string]interface{}{
			"session_id":  sessionID,
			"message_id":  messageID,
			"update_type": updateType,
			"data":        data,
		},
	}

	return h.wsManager.BroadcastToUser(userID, event)
}

// Health 健康检查
func (h *WebSocketHandler) Health(c *gin.Context) {
	err := h.wsManager.Health()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"code":    http.StatusServiceUnavailable,
			"message": "websocket service unhealthy",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "websocket service healthy",
	})
}

// HandleMessage 处理具体的WebSocket消息
func (h *WebSocketHandler) HandleMessage(client *websocket.Client, msgType types.WSMessageType, data json.RawMessage) error {
	ctx := context.Background()

	switch msgType {
	case types.WSMessageTypeMessage:
		return h.handleChatMessage(ctx, client, data)
	case types.WSMessageTypeTyping:
		return h.handleTypingMessage(ctx, client, data)
	default:
		logger.Warn("unhandled websocket message type",
			zap.String("type", string(msgType)),
			zap.String("client_id", client.ID.String()),
		)
		return fmt.Errorf("unhandled message type: %s", msgType)
	}
}

// handleChatMessage 处理聊天消息
func (h *WebSocketHandler) handleChatMessage(ctx context.Context, client *websocket.Client, data json.RawMessage) error {
	var req struct {
		SessionID uuid.UUID `json:"session_id"`
		Content   string    `json:"content"`
		Role      string    `json:"role"`
	}

	if err := json.Unmarshal(data, &req); err != nil {
		return fmt.Errorf("invalid chat message format: %w", err)
	}

	// 验证会话权限
	_, err := h.sessionService.GetSession(ctx, client.UserID, req.SessionID)
	if err != nil {
		client.SendError("session access denied", http.StatusForbidden)
		return fmt.Errorf("session access denied: %w", err)
	}

	// 创建消息
	messageReq := model.MessageCreateRequest{
		Role:    types.MessageRole(req.Role),
		Content: req.Content,
	}

	message, err := h.messageService.CreateMessage(ctx, client.UserID, req.SessionID, messageReq)
	if err != nil {
		client.SendError("failed to create message", http.StatusInternalServerError)
		return fmt.Errorf("failed to create message: %w", err)
	}

	// 广播消息更新
	h.NotifyMessageUpdate(client.UserID, req.SessionID, message.ID, "created", message)

	logger.Debug("websocket chat message handled",
		zap.String("client_id", client.ID.String()),
		zap.String("session_id", req.SessionID.String()),
		zap.String("message_id", message.ID.String()),
	)

	return nil
}

// handleTypingMessage 处理打字指示器消息
func (h *WebSocketHandler) handleTypingMessage(ctx context.Context, client *websocket.Client, data json.RawMessage) error {
	var req struct {
		SessionID uuid.UUID `json:"session_id"`
		Typing    bool      `json:"typing"`
	}

	if err := json.Unmarshal(data, &req); err != nil {
		return fmt.Errorf("invalid typing message format: %w", err)
	}

	// 验证会话权限
	_, err := h.sessionService.GetSession(ctx, client.UserID, req.SessionID)
	if err != nil {
		return fmt.Errorf("session access denied: %w", err)
	}

	// 广播打字状态给会话中的其他用户
	h.wsManager.BroadcastToSession(req.SessionID, types.WSEvent{
		Type:    types.WSMessageTypeTyping,
		EventID: uuid.New().String(),
		Time:    time.Now(),
		Data: map[string]interface{}{
			"user_id":    client.UserID,
			"username":   client.Username,
			"session_id": req.SessionID,
			"typing":     req.Typing,
		},
	})

	return nil
}

// GetManager 获取WebSocket管理器
func (h *WebSocketHandler) GetManager() *websocket.Manager {
	return h.wsManager
}
