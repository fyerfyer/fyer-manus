package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/repository"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// MessageService 消息业务服务
type MessageService struct {
	messageRepo repository.MessageRepository
	sessionRepo repository.SessionRepository
}

// NewMessageService 创建消息服务
func NewMessageService() *MessageService {
	return &MessageService{
		messageRepo: repository.NewMessageRepository(),
		sessionRepo: repository.NewSessionRepository(),
	}
}

// CreateMessage 创建消息
func (s *MessageService) CreateMessage(ctx context.Context, userID, sessionID uuid.UUID, req model.MessageCreateRequest) (*model.MessageResponse, error) {
	// 检查会话是否存在且用户有权限
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("session not found")
		}
		logger.Error("failed to get session", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	if session.UserID != userID {
		return nil, errors.New("access denied")
	}

	if !session.IsActive() {
		return nil, errors.New("session is not active")
	}

	// 检查会话消息数量限制
	if session.MessageCount >= types.MaxMessagesPerSession {
		return nil, fmt.Errorf("maximum messages limit reached (%d)", types.MaxMessagesPerSession)
	}

	// 验证父消息ID
	if req.ParentID != nil {
		parentMessage, err := s.messageRepo.GetByID(ctx, *req.ParentID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, errors.New("parent message not found")
			}
			logger.Error("failed to get parent message", zap.Error(err))
			return nil, errors.New("internal server error")
		}

		if parentMessage.SessionID != sessionID {
			return nil, errors.New("parent message not in same session")
		}
	}

	// 创建消息
	message := &model.Message{
		SessionID:   sessionID,
		ParentID:    req.ParentID,
		Role:        req.Role,
		Content:     req.Content,
		ContentType: req.ContentType,
		Metadata:    req.Metadata,
	}

	if message.ContentType == "" {
		message.ContentType = types.MessageTypeText
	}

	if err := s.messageRepo.Create(ctx, message); err != nil {
		logger.Error("failed to create message", zap.Error(err))
		return nil, errors.New("failed to create message")
	}

	// 更新会话消息计数
	if err := s.sessionRepo.UpdateMessageCount(ctx, sessionID, session.MessageCount+1); err != nil {
		logger.Error("failed to update session message count", zap.Error(err))
		// 不返回错误，消息已创建成功
	}

	logger.Info("message created successfully",
		zap.String("message_id", message.ID.String()),
		zap.String("session_id", sessionID.String()),
		zap.String("role", string(message.Role)),
	)

	response := message.ToResponse()
	return &response, nil
}

// GetMessage 获取消息详情
func (s *MessageService) GetMessage(ctx context.Context, userID, messageID uuid.UUID) (*model.MessageResponse, error) {
	message, err := s.messageRepo.GetByID(ctx, messageID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("message not found")
		}
		logger.Error("failed to get message", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	// 检查会话权限
	session, err := s.sessionRepo.GetByID(ctx, message.SessionID)
	if err != nil {
		logger.Error("failed to get session", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	if session.UserID != userID {
		return nil, errors.New("access denied")
	}

	response := message.ToResponse()
	return &response, nil
}

// UpdateMessage 更新消息
func (s *MessageService) UpdateMessage(ctx context.Context, userID, messageID uuid.UUID, content string, metadata map[string]interface{}) (*model.MessageResponse, error) {
	message, err := s.messageRepo.GetByID(ctx, messageID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("message not found")
		}
		logger.Error("failed to get message", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	// 检查会话权限
	session, err := s.sessionRepo.GetByID(ctx, message.SessionID)
	if err != nil {
		logger.Error("failed to get session", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	if session.UserID != userID {
		return nil, errors.New("access denied")
	}

	// 只允许更新用户消息
	if !message.IsUserMessage() {
		return nil, errors.New("can only update user messages")
	}

	// 更新内容
	if content != "" {
		message.Content = content
	}
	if metadata != nil {
		message.Metadata = metadata
	}

	if err := s.messageRepo.Update(ctx, message); err != nil {
		logger.Error("failed to update message", zap.Error(err))
		return nil, errors.New("failed to update message")
	}

	logger.Info("message updated successfully",
		zap.String("message_id", messageID.String()),
		zap.String("user_id", userID.String()),
	)

	response := message.ToResponse()
	return &response, nil
}

// DeleteMessage 删除消息
func (s *MessageService) DeleteMessage(ctx context.Context, userID, messageID uuid.UUID) error {
	message, err := s.messageRepo.GetByID(ctx, messageID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("message not found")
		}
		logger.Error("failed to get message", zap.Error(err))
		return errors.New("internal server error")
	}

	// 检查会话权限
	session, err := s.sessionRepo.GetByID(ctx, message.SessionID)
	if err != nil {
		logger.Error("failed to get session", zap.Error(err))
		return errors.New("internal server error")
	}

	if session.UserID != userID {
		return errors.New("access denied")
	}

	// 删除消息
	if err := s.messageRepo.Delete(ctx, messageID); err != nil {
		logger.Error("failed to delete message", zap.Error(err))
		return errors.New("failed to delete message")
	}

	// 更新会话消息计数
	count, err := s.messageRepo.CountBySessionID(ctx, message.SessionID)
	if err == nil {
		s.sessionRepo.UpdateMessageCount(ctx, message.SessionID, int(count))
	}

	logger.Info("message deleted successfully",
		zap.String("message_id", messageID.String()),
		zap.String("user_id", userID.String()),
	)

	return nil
}

// ListMessages 获取会话消息列表
func (s *MessageService) ListMessages(ctx context.Context, userID, sessionID uuid.UUID, params types.MessageSearchParams) (*types.PaginatedResponse, error) {
	// 检查会话权限
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("session not found")
		}
		logger.Error("failed to get session", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	if session.UserID != userID {
		return nil, errors.New("access denied")
	}

	// 验证分页参数
	params.Validate()

	messages, total, err := s.messageRepo.GetBySessionID(ctx, sessionID, params)
	if err != nil {
		logger.Error("failed to list messages", zap.Error(err))
		return nil, errors.New("failed to get messages")
	}

	// 转换为响应格式
	messageList := make([]model.MessageListResponse, len(messages))
	for i, message := range messages {
		messageList[i] = message.ToListResponse()
	}

	// 计算分页信息
	totalPage := (total + int64(params.PageSize) - 1) / int64(params.PageSize)

	response := &types.PaginatedResponse{
		Data: messageList,
		Pagination: types.Pagination{
			Page:      params.Page,
			PageSize:  params.PageSize,
			Total:     total,
			TotalPage: totalPage,
		},
	}

	return response, nil
}

// GetConversationContext 获取对话上下文
func (s *MessageService) GetConversationContext(ctx context.Context, userID, sessionID uuid.UUID, limit int) ([]*model.MessageResponse, error) {
	// 检查会话权限
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("session not found")
		}
		logger.Error("failed to get session", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	if session.UserID != userID {
		return nil, errors.New("access denied")
	}

	if limit <= 0 {
		limit = 10
	}

	messages, err := s.messageRepo.GetConversationContext(ctx, sessionID, limit)
	if err != nil {
		logger.Error("failed to get conversation context", zap.Error(err))
		return nil, errors.New("failed to get conversation context")
	}

	// 转换为响应格式
	responses := make([]*model.MessageResponse, len(messages))
	for i, message := range messages {
		response := message.ToResponse()
		responses[i] = &response
	}

	return responses, nil
}

// GetMessageChain 获取消息链
func (s *MessageService) GetMessageChain(ctx context.Context, userID, messageID uuid.UUID) ([]*model.MessageResponse, error) {
	// 检查消息权限
	message, err := s.messageRepo.GetByID(ctx, messageID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("message not found")
		}
		logger.Error("failed to get message", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	// 检查会话权限
	session, err := s.sessionRepo.GetByID(ctx, message.SessionID)
	if err != nil {
		logger.Error("failed to get session", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	if session.UserID != userID {
		return nil, errors.New("access denied")
	}

	chain, err := s.messageRepo.GetMessageChain(ctx, messageID)
	if err != nil {
		logger.Error("failed to get message chain", zap.Error(err))
		return nil, errors.New("failed to get message chain")
	}

	// 转换为响应格式
	responses := make([]*model.MessageResponse, len(chain))
	for i, msg := range chain {
		response := msg.ToResponse()
		responses[i] = &response
	}

	return responses, nil
}

// SearchMessages 搜索消息
func (s *MessageService) SearchMessages(ctx context.Context, params types.MessageSearchParams) (*types.PaginatedResponse, error) {
	// 验证分页参数
	params.Validate()

	messages, total, err := s.messageRepo.Search(ctx, params)
	if err != nil {
		logger.Error("failed to search messages", zap.Error(err))
		return nil, errors.New("failed to search messages")
	}

	// 转换为响应格式
	messageList := make([]model.MessageListResponse, len(messages))
	for i, message := range messages {
		messageList[i] = message.ToListResponse()
	}

	// 计算分页信息
	totalPage := (total + int64(params.PageSize) - 1) / int64(params.PageSize)

	response := &types.PaginatedResponse{
		Data: messageList,
		Pagination: types.Pagination{
			Page:      params.Page,
			PageSize:  params.PageSize,
			Total:     total,
			TotalPage: totalPage,
		},
	}

	return response, nil
}

// CreateAssistantMessage 创建助手消息
func (s *MessageService) CreateAssistantMessage(ctx context.Context, sessionID uuid.UUID, content, modelName string, parentID *uuid.UUID, tokensUsed int, cost float64) (*model.MessageResponse, error) {
	// 检查会话是否存在
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("session not found")
		}
		logger.Error("failed to get session", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	if !session.IsActive() {
		return nil, errors.New("session is not active")
	}

	// 创建助手消息
	message := &model.Message{
		SessionID:   sessionID,
		ParentID:    parentID,
		Role:        types.MessageRoleAssistant,
		Content:     content,
		ContentType: types.MessageTypeText,
		ModelName:   modelName,
		TokensUsed:  tokensUsed,
		Cost:        cost,
		Metadata:    make(map[string]interface{}),
	}

	if err := s.messageRepo.Create(ctx, message); err != nil {
		logger.Error("failed to create assistant message", zap.Error(err))
		return nil, errors.New("failed to create assistant message")
	}

	// 更新会话统计
	s.sessionRepo.UpdateMessageCount(ctx, sessionID, session.MessageCount+1)
	if tokensUsed > 0 {
		s.sessionRepo.AddTokens(ctx, sessionID, tokensUsed)
	}

	logger.Info("assistant message created successfully",
		zap.String("message_id", message.ID.String()),
		zap.String("session_id", sessionID.String()),
		zap.Int("tokens_used", tokensUsed),
	)

	response := message.ToResponse()
	return &response, nil
}

// CreateToolMessage 创建工具消息
func (s *MessageService) CreateToolMessage(ctx context.Context, sessionID uuid.UUID, content, toolCallID string, parentID *uuid.UUID) (*model.MessageResponse, error) {
	// 检查会话是否存在
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return nil, errors.New("session not found")
	}

	if !session.IsActive() {
		return nil, errors.New("session is not active")
	}

	// 创建工具消息
	message := &model.Message{
		SessionID:   sessionID,
		ParentID:    parentID,
		Role:        types.MessageRoleTool,
		Content:     content,
		ContentType: types.MessageTypeText,
		ToolCallID:  toolCallID,
		Metadata:    make(map[string]interface{}),
	}

	if err := s.messageRepo.Create(ctx, message); err != nil {
		logger.Error("failed to create tool message", zap.Error(err))
		return nil, errors.New("failed to create tool message")
	}

	// 更新会话消息计数
	s.sessionRepo.UpdateMessageCount(ctx, sessionID, session.MessageCount+1)

	logger.Info("tool message created successfully",
		zap.String("message_id", message.ID.String()),
		zap.String("session_id", sessionID.String()),
		zap.String("tool_call_id", toolCallID),
	)

	response := message.ToResponse()
	return &response, nil
}
