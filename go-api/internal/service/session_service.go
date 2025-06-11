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

// SessionService 会话业务服务
type SessionService struct {
	sessionRepo repository.SessionRepository
	messageRepo repository.MessageRepository
	userRepo    repository.UserRepository
}

// NewSessionService 创建会话服务
func NewSessionService() *SessionService {
	return &SessionService{
		sessionRepo: repository.NewSessionRepository(),
		messageRepo: repository.NewMessageRepository(),
		userRepo:    repository.NewUserRepository(),
	}
}

// CreateSession 创建会话
func (s *SessionService) CreateSession(ctx context.Context, userID uuid.UUID, req model.SessionCreateRequest) (*model.SessionResponse, error) {
	// 检查用户是否存在
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		logger.Error("failed to get user", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	if !user.IsActive() {
		return nil, errors.New("user is not active")
	}

	// 检查用户活跃会话数量限制
	activeCount, err := s.sessionRepo.GetActiveSessionsCount(ctx, userID)
	if err != nil {
		logger.Error("failed to get active sessions count", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	if activeCount >= types.MaxSessionsPerUser {
		return nil, fmt.Errorf("maximum sessions limit reached (%d)", types.MaxSessionsPerUser)
	}

	// 创建会话
	session := &model.Session{
		UserID:       userID,
		Title:        req.Title,
		ModelName:    req.ModelName,
		SystemPrompt: req.SystemPrompt,
		Metadata:     req.Metadata,
		Status:       types.SessionStatusActive,
	}

	if session.Title == "" {
		session.Title = types.DefaultSessionTitle
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		logger.Error("failed to create session", zap.Error(err))
		return nil, errors.New("failed to create session")
	}

	logger.Info("session created successfully",
		zap.String("session_id", session.ID.String()),
		zap.String("user_id", userID.String()),
	)

	response := session.ToResponse()
	return &response, nil
}

// GetSession 获取会话详情
func (s *SessionService) GetSession(ctx context.Context, userID, sessionID uuid.UUID) (*model.SessionResponse, error) {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("session not found")
		}
		logger.Error("failed to get session", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	// 检查权限
	if session.UserID != userID {
		return nil, errors.New("access denied")
	}

	if !session.CanDelete() {
		return nil, errors.New("session is deleted")
	}

	response := session.ToResponse()
	return &response, nil
}

// UpdateSession 更新会话
func (s *SessionService) UpdateSession(ctx context.Context, userID, sessionID uuid.UUID, req model.SessionUpdateRequest) (*model.SessionResponse, error) {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("session not found")
		}
		logger.Error("failed to get session", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	// 检查权限
	if session.UserID != userID {
		return nil, errors.New("access denied")
	}

	if !session.IsActive() {
		return nil, errors.New("cannot update inactive session")
	}

	// 更新字段
	if req.Title != "" {
		session.Title = req.Title
	}
	if req.SystemPrompt != "" {
		session.SystemPrompt = req.SystemPrompt
	}
	if req.Metadata != nil {
		session.Metadata = req.Metadata
	}

	if err := s.sessionRepo.Update(ctx, session); err != nil {
		logger.Error("failed to update session", zap.Error(err))
		return nil, errors.New("failed to update session")
	}

	logger.Info("session updated successfully",
		zap.String("session_id", sessionID.String()),
		zap.String("user_id", userID.String()),
	)

	response := session.ToResponse()
	return &response, nil
}

// DeleteSession 删除会话
func (s *SessionService) DeleteSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("session not found")
		}
		logger.Error("failed to get session", zap.Error(err))
		return errors.New("internal server error")
	}

	// 检查权限
	if session.UserID != userID {
		return errors.New("access denied")
	}

	if !session.CanDelete() {
		return errors.New("session already deleted")
	}

	// 软删除会话
	if err := s.sessionRepo.Delete(ctx, sessionID); err != nil {
		logger.Error("failed to delete session", zap.Error(err))
		return errors.New("failed to delete session")
	}

	// 删除相关消息
	if err := s.messageRepo.DeleteBySessionID(ctx, sessionID); err != nil {
		logger.Error("failed to delete session messages", zap.Error(err))
		// 不返回错误，因为会话已经删除成功
	}

	logger.Info("session deleted successfully",
		zap.String("session_id", sessionID.String()),
		zap.String("user_id", userID.String()),
	)

	return nil
}

// ArchiveSession 归档会话
func (s *SessionService) ArchiveSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("session not found")
		}
		logger.Error("failed to get session", zap.Error(err))
		return errors.New("internal server error")
	}

	// 检查权限
	if session.UserID != userID {
		return errors.New("access denied")
	}

	if !session.IsActive() {
		return errors.New("session is not active")
	}

	if err := s.sessionRepo.Archive(ctx, sessionID); err != nil {
		logger.Error("failed to archive session", zap.Error(err))
		return errors.New("failed to archive session")
	}

	logger.Info("session archived successfully",
		zap.String("session_id", sessionID.String()),
		zap.String("user_id", userID.String()),
	)

	return nil
}

// ListSessions 获取用户会话列表
func (s *SessionService) ListSessions(ctx context.Context, userID uuid.UUID, params types.SessionSearchParams) (*types.PaginatedResponse, error) {
	// 验证分页参数
	params.Validate()

	sessions, total, err := s.sessionRepo.GetByUserID(ctx, userID, params)
	if err != nil {
		logger.Error("failed to list sessions", zap.Error(err))
		return nil, errors.New("failed to get sessions")
	}

	// 转换为响应格式
	sessionList := make([]model.SessionListResponse, len(sessions))
	for i, session := range sessions {
		sessionList[i] = session.ToListResponse()
	}

	// 计算分页信息
	totalPage := (total + int64(params.PageSize) - 1) / int64(params.PageSize)

	response := &types.PaginatedResponse{
		Data: sessionList,
		Pagination: types.Pagination{
			Page:      params.Page,
			PageSize:  params.PageSize,
			Total:     total,
			TotalPage: totalPage,
		},
	}

	return response, nil
}

// SearchSessions 搜索会话
func (s *SessionService) SearchSessions(ctx context.Context, params types.SessionSearchParams) (*types.PaginatedResponse, error) {
	// 验证分页参数
	params.Validate()

	sessions, total, err := s.sessionRepo.Search(ctx, params)
	if err != nil {
		logger.Error("failed to search sessions", zap.Error(err))
		return nil, errors.New("failed to search sessions")
	}

	// 转换为响应格式
	sessionList := make([]model.SessionListResponse, len(sessions))
	for i, session := range sessions {
		sessionList[i] = session.ToListResponse()
	}

	// 计算分页信息
	totalPage := (total + int64(params.PageSize) - 1) / int64(params.PageSize)

	response := &types.PaginatedResponse{
		Data: sessionList,
		Pagination: types.Pagination{
			Page:      params.Page,
			PageSize:  params.PageSize,
			Total:     total,
			TotalPage: totalPage,
		},
	}

	return response, nil
}

// UpdateMessageCount 更新会话消息计数
func (s *SessionService) UpdateMessageCount(ctx context.Context, sessionID uuid.UUID) error {
	count, err := s.messageRepo.CountBySessionID(ctx, sessionID)
	if err != nil {
		logger.Error("failed to count messages", zap.Error(err))
		return errors.New("failed to update message count")
	}

	if err := s.sessionRepo.UpdateMessageCount(ctx, sessionID, int(count)); err != nil {
		logger.Error("failed to update message count", zap.Error(err))
		return errors.New("failed to update message count")
	}

	return nil
}

// AddTokenUsage 增加token使用量
func (s *SessionService) AddTokenUsage(ctx context.Context, sessionID uuid.UUID, tokens int) error {
	if tokens <= 0 {
		return nil
	}

	if err := s.sessionRepo.AddTokens(ctx, sessionID, tokens); err != nil {
		logger.Error("failed to add token usage", zap.Error(err))
		return errors.New("failed to add token usage")
	}

	return nil
}

// GetSessionStats 获取会话统计信息
func (s *SessionService) GetSessionStats(ctx context.Context, userID uuid.UUID) (map[string]interface{}, error) {
	activeCount, err := s.sessionRepo.GetActiveSessionsCount(ctx, userID)
	if err != nil {
		logger.Error("failed to get active sessions count", zap.Error(err))
		return nil, errors.New("failed to get session stats")
	}

	return map[string]interface{}{
		"active_sessions":    activeCount,
		"max_sessions":       types.MaxSessionsPerUser,
		"remaining_sessions": types.MaxSessionsPerUser - activeCount,
	}, nil
}

// CleanupExpiredSessions 清理过期会话
func (s *SessionService) CleanupExpiredSessions(ctx context.Context) error {
	if err := s.sessionRepo.CleanupExpiredSessions(ctx); err != nil {
		logger.Error("failed to cleanup expired sessions", zap.Error(err))
		return err
	}

	logger.Info("expired sessions cleaned up successfully")
	return nil
}
