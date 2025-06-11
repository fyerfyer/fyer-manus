package repository

import (
	"context"

	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SessionRepository 会话仓储接口
type SessionRepository interface {
	Create(ctx context.Context, session *model.Session) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.Session, error)
	GetByUserID(ctx context.Context, userID uuid.UUID, params types.SessionSearchParams) ([]*model.Session, int64, error)
	Update(ctx context.Context, session *model.Session) error
	Delete(ctx context.Context, id uuid.UUID) error
	Archive(ctx context.Context, id uuid.UUID) error
	UpdateMessageCount(ctx context.Context, sessionID uuid.UUID, count int) error
	AddTokens(ctx context.Context, sessionID uuid.UUID, tokens int) error
	Search(ctx context.Context, params types.SessionSearchParams) ([]*model.Session, int64, error)
	GetActiveSessionsCount(ctx context.Context, userID uuid.UUID) (int64, error)
	CleanupExpiredSessions(ctx context.Context) error
}

// sessionRepository 会话仓储实现
type sessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository 创建会话仓储
func NewSessionRepository() SessionRepository {
	return &sessionRepository{
		db: database.Get(),
	}
}

// Create 创建会话
func (r *sessionRepository) Create(ctx context.Context, session *model.Session) error {
	return r.db.WithContext(ctx).Create(session).Error
}

// GetByID 根据ID获取会话
func (r *sessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Session, error) {
	var session model.Session
	err := r.db.WithContext(ctx).
		Preload("User").
		First(&session, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// GetByUserID 根据用户ID获取会话列表
func (r *sessionRepository) GetByUserID(ctx context.Context, userID uuid.UUID, params types.SessionSearchParams) ([]*model.Session, int64, error) {
	params.Validate()

	query := r.db.WithContext(ctx).Model(&model.Session{}).Where("user_id = ?", userID)

	// 状态过滤
	if params.Status != "" {
		query = query.Where("status = ?", params.Status)
	}

	// 搜索过滤
	if params.Query != "" {
		query = query.Where("title ILIKE ?", "%"+params.Query+"%")
	}

	// 计算总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	var sessions []*model.Session
	err := query.Order("updated_at DESC").
		Offset(params.Offset).
		Limit(params.PageSize).
		Find(&sessions).Error

	return sessions, total, err
}

// Update 更新会话
func (r *sessionRepository) Update(ctx context.Context, session *model.Session) error {
	return r.db.WithContext(ctx).Save(session).Error
}

// Delete 删除会话
func (r *sessionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&model.Session{}).
		Where("id = ?", id).
		Update("status", types.SessionStatusDeleted).Error
}

// Archive 归档会话
func (r *sessionRepository) Archive(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&model.Session{}).
		Where("id = ?", id).
		Update("status", types.SessionStatusArchived).Error
}

// UpdateMessageCount 更新消息计数
func (r *sessionRepository) UpdateMessageCount(ctx context.Context, sessionID uuid.UUID, count int) error {
	return r.db.WithContext(ctx).Model(&model.Session{}).
		Where("id = ?", sessionID).
		Update("message_count", count).Error
}

// AddTokens 增加token计数
func (r *sessionRepository) AddTokens(ctx context.Context, sessionID uuid.UUID, tokens int) error {
	return r.db.WithContext(ctx).Model(&model.Session{}).
		Where("id = ?", sessionID).
		Update("total_tokens", gorm.Expr("total_tokens + ?", tokens)).Error
}

// Search 搜索会话
func (r *sessionRepository) Search(ctx context.Context, params types.SessionSearchParams) ([]*model.Session, int64, error) {
	params.Validate()

	query := r.db.WithContext(ctx).Model(&model.Session{})

	// 用户过滤
	if params.UserID != "" {
		if userID, err := uuid.Parse(params.UserID); err == nil {
			query = query.Where("user_id = ?", userID)
		}
	}

	// 状态过滤
	if params.Status != "" {
		query = query.Where("status = ?", params.Status)
	}

	// 搜索过滤
	if params.Query != "" {
		query = query.Where("title ILIKE ? OR system_prompt ILIKE ?",
			"%"+params.Query+"%", "%"+params.Query+"%")
	}

	// 计算总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	var sessions []*model.Session
	err := query.Order("updated_at DESC").
		Offset(params.Offset).
		Limit(params.PageSize).
		Find(&sessions).Error

	return sessions, total, err
}

// GetActiveSessionsCount 获取用户活跃会话数量
func (r *sessionRepository) GetActiveSessionsCount(ctx context.Context, userID uuid.UUID) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.Session{}).
		Where("user_id = ? AND status = ?", userID, types.SessionStatusActive).
		Count(&count).Error
	return count, err
}

// CleanupExpiredSessions 清理过期会话
func (r *sessionRepository) CleanupExpiredSessions(ctx context.Context) error {
	// 清理超过30天未更新的归档会话
	result := r.db.WithContext(ctx).
		Where("status = ? AND updated_at < ?",
			types.SessionStatusArchived,
			gorm.Expr("NOW() - INTERVAL '30 days'")).
		Delete(&model.Session{})

	if result.Error != nil {
		return result.Error
	}

	return nil
}
