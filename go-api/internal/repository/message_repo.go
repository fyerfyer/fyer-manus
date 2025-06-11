package repository

import (
	"context"

	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// MessageRepository 消息仓储接口
type MessageRepository interface {
	Create(ctx context.Context, message *model.Message) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.Message, error)
	GetBySessionID(ctx context.Context, sessionID uuid.UUID, params types.MessageSearchParams) ([]*model.Message, int64, error)
	Update(ctx context.Context, message *model.Message) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetConversationContext(ctx context.Context, sessionID uuid.UUID, limit int) ([]*model.Message, error)
	GetMessageChain(ctx context.Context, messageID uuid.UUID) ([]*model.Message, error)
	CountBySessionID(ctx context.Context, sessionID uuid.UUID) (int64, error)
	GetLatestBySessionID(ctx context.Context, sessionID uuid.UUID, limit int) ([]*model.Message, error)
	Search(ctx context.Context, params types.MessageSearchParams) ([]*model.Message, int64, error)
	DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) error
}

// messageRepository 消息仓储实现
type messageRepository struct {
	db *gorm.DB
}

// NewMessageRepository 创建消息仓储
func NewMessageRepository() MessageRepository {
	return &messageRepository{
		db: database.Get(),
	}
}

// Create 创建消息
func (r *messageRepository) Create(ctx context.Context, message *model.Message) error {
	return r.db.WithContext(ctx).Create(message).Error
}

// GetByID 根据ID获取消息
func (r *messageRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Message, error) {
	var message model.Message
	err := r.db.WithContext(ctx).
		Preload("Parent").
		Preload("Children").
		First(&message, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &message, nil
}

// GetBySessionID 根据会话ID获取消息列表
func (r *messageRepository) GetBySessionID(ctx context.Context, sessionID uuid.UUID, params types.MessageSearchParams) ([]*model.Message, int64, error) {
	params.Validate()

	query := r.db.WithContext(ctx).Model(&model.Message{}).Where("session_id = ?", sessionID)

	// 角色过滤
	if params.Role != "" {
		query = query.Where("role = ?", params.Role)
	}

	// 搜索过滤
	if params.Query != "" {
		query = query.Where("content ILIKE ?", "%"+params.Query+"%")
	}

	// 计算总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	var messages []*model.Message
	err := query.Order("created_at ASC").
		Offset(params.Offset).
		Limit(params.PageSize).
		Find(&messages).Error

	return messages, total, err
}

// Update 更新消息
func (r *messageRepository) Update(ctx context.Context, message *model.Message) error {
	return r.db.WithContext(ctx).Save(message).Error
}

// Delete 删除消息
func (r *messageRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&model.Message{}, "id = ?", id).Error
}

// GetConversationContext 获取对话上下文
func (r *messageRepository) GetConversationContext(ctx context.Context, sessionID uuid.UUID, limit int) ([]*model.Message, error) {
	if limit <= 0 {
		limit = 10
	}

	var messages []*model.Message
	err := r.db.WithContext(ctx).
		Where("session_id = ?", sessionID).
		Order("created_at DESC").
		Limit(limit).
		Find(&messages).Error

	if err != nil {
		return nil, err
	}

	// 反转顺序，使最新的消息在最后
	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}

	return messages, nil
}

// GetMessageChain 获取消息链（父子关系）
func (r *messageRepository) GetMessageChain(ctx context.Context, messageID uuid.UUID) ([]*model.Message, error) {
	var chain []*model.Message
	var currentID *uuid.UUID = &messageID

	// 向上追溯到根消息
	var rootMessages []*model.Message
	for currentID != nil {
		var message model.Message
		err := r.db.WithContext(ctx).First(&message, "id = ?", *currentID).Error
		if err != nil {
			break
		}
		rootMessages = append([]*model.Message{&message}, rootMessages...)
		currentID = message.ParentID
	}

	// 向下获取子消息
	chain = append(chain, rootMessages...)

	// 递归获取子消息
	if len(rootMessages) > 0 {
		lastMessage := rootMessages[len(rootMessages)-1]
		children, err := r.getChildrenRecursive(ctx, lastMessage.ID)
		if err == nil {
			chain = append(chain, children...)
		}
	}

	return chain, nil
}

// getChildrenRecursive 递归获取子消息
func (r *messageRepository) getChildrenRecursive(ctx context.Context, parentID uuid.UUID) ([]*model.Message, error) {
	var children []*model.Message
	err := r.db.WithContext(ctx).
		Where("parent_id = ?", parentID).
		Order("created_at ASC").
		Find(&children).Error

	if err != nil {
		return nil, err
	}

	var allChildren []*model.Message
	for _, child := range children {
		allChildren = append(allChildren, child)
		grandChildren, err := r.getChildrenRecursive(ctx, child.ID)
		if err == nil {
			allChildren = append(allChildren, grandChildren...)
		}
	}

	return allChildren, nil
}

// CountBySessionID 统计会话消息数量
func (r *messageRepository) CountBySessionID(ctx context.Context, sessionID uuid.UUID) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.Message{}).
		Where("session_id = ?", sessionID).
		Count(&count).Error
	return count, err
}

// GetLatestBySessionID 获取会话最新消息
func (r *messageRepository) GetLatestBySessionID(ctx context.Context, sessionID uuid.UUID, limit int) ([]*model.Message, error) {
	if limit <= 0 {
		limit = 10
	}

	var messages []*model.Message
	err := r.db.WithContext(ctx).
		Where("session_id = ?", sessionID).
		Order("created_at DESC").
		Limit(limit).
		Find(&messages).Error

	return messages, err
}

// Search 搜索消息
func (r *messageRepository) Search(ctx context.Context, params types.MessageSearchParams) ([]*model.Message, int64, error) {
	params.Validate()

	query := r.db.WithContext(ctx).Model(&model.Message{})

	// 会话过滤
	if params.SessionID != "" {
		if sessionID, err := uuid.Parse(params.SessionID); err == nil {
			query = query.Where("session_id = ?", sessionID)
		}
	}

	// 角色过滤
	if params.Role != "" {
		query = query.Where("role = ?", params.Role)
	}

	// 搜索过滤
	if params.Query != "" {
		query = query.Where("content ILIKE ?", "%"+params.Query+"%")
	}

	// 计算总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	var messages []*model.Message
	err := query.Order("created_at DESC").
		Offset(params.Offset).
		Limit(params.PageSize).
		Find(&messages).Error

	return messages, total, err
}

// DeleteBySessionID 删除会话的所有消息
func (r *messageRepository) DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("session_id = ?", sessionID).
		Delete(&model.Message{}).Error
}
