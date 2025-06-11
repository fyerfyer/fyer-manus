package handler

import (
	"net/http"
	"strconv"

	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/middleware"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SessionHandler 会话处理器
type SessionHandler struct {
	sessionService *service.SessionService
	messageService *service.MessageService
}

// NewSessionHandler 创建会话处理器
func NewSessionHandler() *SessionHandler {
	return &SessionHandler{
		sessionService: service.NewSessionService(),
		messageService: service.NewMessageService(),
	}
}

// CreateSession 创建会话
func (h *SessionHandler) CreateSession(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	var req model.SessionCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("invalid create session request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	session, err := h.sessionService.CreateSession(c.Request.Context(), claims.UserID, req)
	if err != nil {
		logger.Error("failed to create session",
			zap.Error(err),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	logger.Info("session created successfully",
		zap.String("session_id", session.ID.String()),
		zap.String("user_id", claims.UserID.String()),
	)

	c.JSON(http.StatusCreated, gin.H{
		"code":    http.StatusCreated,
		"message": "session created successfully",
		"data":    session,
	})
}

// GetSession 获取会话详情
func (h *SessionHandler) GetSession(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	sessionIDStr := c.Param("id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid session ID format",
		})
		return
	}

	session, err := h.sessionService.GetSession(c.Request.Context(), claims.UserID, sessionID)
	if err != nil {
		logger.Error("failed to get session",
			zap.Error(err),
			zap.String("session_id", sessionID.String()),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusNotFound, gin.H{
			"code":    http.StatusNotFound,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "session retrieved successfully",
		"data":    session,
	})
}

// UpdateSession 更新会话
func (h *SessionHandler) UpdateSession(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	sessionIDStr := c.Param("id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid session ID format",
		})
		return
	}

	var req model.SessionUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("invalid update session request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	session, err := h.sessionService.UpdateSession(c.Request.Context(), claims.UserID, sessionID, req)
	if err != nil {
		logger.Error("failed to update session",
			zap.Error(err),
			zap.String("session_id", sessionID.String()),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	logger.Info("session updated successfully",
		zap.String("session_id", sessionID.String()),
		zap.String("user_id", claims.UserID.String()),
	)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "session updated successfully",
		"data":    session,
	})
}

// DeleteSession 删除会话
func (h *SessionHandler) DeleteSession(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	sessionIDStr := c.Param("id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid session ID format",
		})
		return
	}

	err = h.sessionService.DeleteSession(c.Request.Context(), claims.UserID, sessionID)
	if err != nil {
		logger.Error("failed to delete session",
			zap.Error(err),
			zap.String("session_id", sessionID.String()),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	logger.Info("session deleted successfully",
		zap.String("session_id", sessionID.String()),
		zap.String("user_id", claims.UserID.String()),
	)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "session deleted successfully",
	})
}

// ArchiveSession 归档会话
func (h *SessionHandler) ArchiveSession(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	sessionIDStr := c.Param("id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid session ID format",
		})
		return
	}

	err = h.sessionService.ArchiveSession(c.Request.Context(), claims.UserID, sessionID)
	if err != nil {
		logger.Error("failed to archive session",
			zap.Error(err),
			zap.String("session_id", sessionID.String()),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	logger.Info("session archived successfully",
		zap.String("session_id", sessionID.String()),
		zap.String("user_id", claims.UserID.String()),
	)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "session archived successfully",
	})
}

// ListSessions 获取会话列表
func (h *SessionHandler) ListSessions(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	// 解析查询参数
	var params types.SessionSearchParams
	if err := c.ShouldBindQuery(&params); err != nil {
		logger.Warn("invalid query parameters", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid query parameters",
			"details": err.Error(),
		})
		return
	}

	response, err := h.sessionService.ListSessions(c.Request.Context(), claims.UserID, params)
	if err != nil {
		logger.Error("failed to list sessions",
			zap.Error(err),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":       http.StatusOK,
		"message":    "sessions retrieved successfully",
		"data":       response.Data,
		"pagination": response.Pagination,
	})
}

// CreateMessage 创建消息
func (h *SessionHandler) CreateMessage(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	sessionIDStr := c.Param("id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid session ID format",
		})
		return
	}

	var req model.MessageCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("invalid create message request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	message, err := h.messageService.CreateMessage(c.Request.Context(), claims.UserID, sessionID, req)
	if err != nil {
		logger.Error("failed to create message",
			zap.Error(err),
			zap.String("session_id", sessionID.String()),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	logger.Info("message created successfully",
		zap.String("message_id", message.ID.String()),
		zap.String("session_id", sessionID.String()),
		zap.String("user_id", claims.UserID.String()),
	)

	c.JSON(http.StatusCreated, gin.H{
		"code":    http.StatusCreated,
		"message": "message created successfully",
		"data":    message,
	})
}

// ListMessages 获取消息列表
func (h *SessionHandler) ListMessages(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	sessionIDStr := c.Param("id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid session ID format",
		})
		return
	}

	// 解析查询参数
	var params types.MessageSearchParams
	if err := c.ShouldBindQuery(&params); err != nil {
		logger.Warn("invalid query parameters", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid query parameters",
			"details": err.Error(),
		})
		return
	}

	response, err := h.messageService.ListMessages(c.Request.Context(), claims.UserID, sessionID, params)
	if err != nil {
		logger.Error("failed to list messages",
			zap.Error(err),
			zap.String("session_id", sessionID.String()),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":       http.StatusOK,
		"message":    "messages retrieved successfully",
		"data":       response.Data,
		"pagination": response.Pagination,
	})
}

// GetMessage 获取消息详情
func (h *SessionHandler) GetMessage(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	messageIDStr := c.Param("messageId")
	messageID, err := uuid.Parse(messageIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid message ID format",
		})
		return
	}

	message, err := h.messageService.GetMessage(c.Request.Context(), claims.UserID, messageID)
	if err != nil {
		logger.Error("failed to get message",
			zap.Error(err),
			zap.String("message_id", messageID.String()),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusNotFound, gin.H{
			"code":    http.StatusNotFound,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "message retrieved successfully",
		"data":    message,
	})
}

// GetConversationContext 获取对话上下文
func (h *SessionHandler) GetConversationContext(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	sessionIDStr := c.Param("id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid session ID format",
		})
		return
	}

	// 获取limit参数
	limitStr := c.DefaultQuery("limit", "10")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 10
	}

	context, err := h.messageService.GetConversationContext(c.Request.Context(), claims.UserID, sessionID, limit)
	if err != nil {
		logger.Error("failed to get conversation context",
			zap.Error(err),
			zap.String("session_id", sessionID.String()),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "conversation context retrieved successfully",
		"data":    context,
	})
}

// GetSessionStats 获取会话统计信息
func (h *SessionHandler) GetSessionStats(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	stats, err := h.sessionService.GetSessionStats(c.Request.Context(), claims.UserID)
	if err != nil {
		logger.Error("failed to get session stats",
			zap.Error(err),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "session stats retrieved successfully",
		"data":    stats,
	})
}

// SearchSessions 搜索会话（管理员功能）
func (h *SessionHandler) SearchSessions(c *gin.Context) {
	// 解析查询参数
	var params types.SessionSearchParams
	if err := c.ShouldBindQuery(&params); err != nil {
		logger.Warn("invalid search parameters", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid search parameters",
			"details": err.Error(),
		})
		return
	}

	response, err := h.sessionService.SearchSessions(c.Request.Context(), params)
	if err != nil {
		logger.Error("failed to search sessions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":       http.StatusOK,
		"message":    "sessions search completed successfully",
		"data":       response.Data,
		"pagination": response.Pagination,
	})
}
