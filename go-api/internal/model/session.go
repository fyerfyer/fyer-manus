package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// JSONMap 自定义类型处理JSONB字段
type JSONMap map[string]interface{}

// Value 实现driver.Valuer接口
func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan 实现sql.Scanner接口
func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = make(map[string]interface{})
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return errors.New("cannot scan into JSONMap")
	}

	if len(bytes) == 0 {
		*j = make(map[string]interface{})
		return nil
	}

	return json.Unmarshal(bytes, j)
}

// Session 会话模型
type Session struct {
	ID           uuid.UUID           `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID       uuid.UUID           `gorm:"type:uuid;not null;index" json:"user_id"`
	Title        string              `gorm:"size:255;default:'New Chat'" json:"title"`
	Status       types.SessionStatus `gorm:"size:20;default:'active';index" json:"status"`
	ModelName    string              `gorm:"size:100" json:"model_name"`
	SystemPrompt string              `gorm:"type:text" json:"system_prompt"`
	Metadata     JSONMap             `gorm:"type:jsonb;default:'{}'" json:"metadata"`
	MessageCount int                 `gorm:"default:0" json:"message_count"`
	TotalTokens  int                 `gorm:"default:0" json:"total_tokens"`
	CreatedAt    time.Time           `gorm:"index" json:"created_at"`
	UpdatedAt    time.Time           `gorm:"index" json:"updated_at"`

	// 关联
	User     User      `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Messages []Message `gorm:"foreignKey:SessionID" json:"messages,omitempty"`
}

// BeforeCreate GORM钩子
func (s *Session) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

// TableName 指定表名
func (Session) TableName() string {
	return "sessions"
}

// IsActive 检查会话是否活跃
func (s *Session) IsActive() bool {
	return s.Status == types.SessionStatusActive
}

// CanDelete 检查是否可以删除
func (s *Session) CanDelete() bool {
	return s.Status != types.SessionStatusDeleted
}

// Archive 归档会话
func (s *Session) Archive() {
	s.Status = types.SessionStatusArchived
}

// Delete 软删除会话
func (s *Session) Delete() {
	s.Status = types.SessionStatusDeleted
}

// UpdateMessageCount 更新消息计数
func (s *Session) UpdateMessageCount(count int) {
	s.MessageCount = count
}

// AddTokens 增加token计数
func (s *Session) AddTokens(tokens int) {
	s.TotalTokens += tokens
}

// SessionCreateRequest 创建会话请求
type SessionCreateRequest struct {
	Title        string                 `json:"title" binding:"max=255"`
	ModelName    string                 `json:"model_name" binding:"max=100"`
	SystemPrompt string                 `json:"system_prompt" binding:"max=10000"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// SessionUpdateRequest 更新会话请求
type SessionUpdateRequest struct {
	Title        string                 `json:"title" binding:"max=255"`
	SystemPrompt string                 `json:"system_prompt" binding:"max=10000"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// SessionResponse 会话响应
type SessionResponse struct {
	ID           uuid.UUID              `json:"id"`
	UserID       uuid.UUID              `json:"user_id"`
	Title        string                 `json:"title"`
	Status       types.SessionStatus    `json:"status"`
	ModelName    string                 `json:"model_name"`
	SystemPrompt string                 `json:"system_prompt"`
	Metadata     map[string]interface{} `json:"metadata"`
	MessageCount int                    `json:"message_count"`
	TotalTokens  int                    `json:"total_tokens"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

// ToResponse 转换为响应格式
func (s *Session) ToResponse() SessionResponse {
	return SessionResponse{
		ID:           s.ID,
		UserID:       s.UserID,
		Title:        s.Title,
		Status:       s.Status,
		ModelName:    s.ModelName,
		SystemPrompt: s.SystemPrompt,
		Metadata:     map[string]interface{}(s.Metadata),
		MessageCount: s.MessageCount,
		TotalTokens:  s.TotalTokens,
		CreatedAt:    s.CreatedAt,
		UpdatedAt:    s.UpdatedAt,
	}
}

// SessionListResponse 会话列表响应
type SessionListResponse struct {
	ID           uuid.UUID           `json:"id"`
	Title        string              `json:"title"`
	Status       types.SessionStatus `json:"status"`
	ModelName    string              `json:"model_name"`
	MessageCount int                 `json:"message_count"`
	TotalTokens  int                 `json:"total_tokens"`
	CreatedAt    time.Time           `json:"created_at"`
	UpdatedAt    time.Time           `json:"updated_at"`
}

// ToListResponse 转换为列表响应格式
func (s *Session) ToListResponse() SessionListResponse {
	return SessionListResponse{
		ID:           s.ID,
		Title:        s.Title,
		Status:       s.Status,
		ModelName:    s.ModelName,
		MessageCount: s.MessageCount,
		TotalTokens:  s.TotalTokens,
		CreatedAt:    s.CreatedAt,
		UpdatedAt:    s.UpdatedAt,
	}
}
