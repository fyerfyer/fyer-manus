package model

import (
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Message 消息模型
type Message struct {
	ID          uuid.UUID              `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	SessionID   uuid.UUID              `gorm:"type:uuid;not null;index" json:"session_id"`
	ParentID    *uuid.UUID             `gorm:"type:uuid;index" json:"parent_id"`
	Role        types.MessageRole      `gorm:"size:20;not null;index" json:"role"`
	Content     string                 `gorm:"type:text;not null" json:"content"`
	ContentType types.MessageType      `gorm:"size:50;default:'text'" json:"content_type"`
	ModelName   string                 `gorm:"size:100" json:"model_name"`
	ToolCalls   []ToolCall             `gorm:"type:jsonb;serializer:json" json:"tool_calls,omitempty"`
	ToolCallID  string                 `gorm:"size:100" json:"tool_call_id,omitempty"`
	Metadata    map[string]interface{} `gorm:"type:jsonb;serializer:json;default:'{}'" json:"metadata"`
	TokensUsed  int                    `gorm:"default:0" json:"tokens_used"`
	Cost        float64                `gorm:"type:decimal(10,6);default:0.00" json:"cost"`
	CreatedAt   time.Time              `gorm:"index" json:"created_at"`

	// 关联
	Session  Session   `gorm:"foreignKey:SessionID" json:"session,omitempty"`
	Parent   *Message  `gorm:"foreignKey:ParentID" json:"parent,omitempty"`
	Children []Message `gorm:"foreignKey:ParentID" json:"children,omitempty"`
}

// ToolCall 工具调用结构
type ToolCall struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Function ToolCallFunction       `json:"function"`
	Result   map[string]interface{} `json:"result,omitempty"`
}

// ToolCallFunction 工具调用函数
type ToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// BeforeCreate GORM钩子
func (m *Message) BeforeCreate(tx *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	return nil
}

// TableName 指定表名
func (Message) TableName() string {
	return "messages"
}

// IsUserMessage 检查是否为用户消息
func (m *Message) IsUserMessage() bool {
	return m.Role == types.MessageRoleUser
}

// IsAssistantMessage 检查是否为助手消息
func (m *Message) IsAssistantMessage() bool {
	return m.Role == types.MessageRoleAssistant
}

// IsSystemMessage 检查是否为系统消息
func (m *Message) IsSystemMessage() bool {
	return m.Role == types.MessageRoleSystem
}

// IsToolMessage 检查是否为工具消息
func (m *Message) IsToolMessage() bool {
	return m.Role == types.MessageRoleTool
}

// HasToolCalls 检查是否包含工具调用
func (m *Message) HasToolCalls() bool {
	return len(m.ToolCalls) > 0
}

// MessageCreateRequest 创建消息请求
type MessageCreateRequest struct {
	Role        types.MessageRole      `json:"role" binding:"required,oneof=user assistant system tool"`
	Content     string                 `json:"content" binding:"required,max=50000"`
	ContentType types.MessageType      `json:"content_type" binding:"omitempty,oneof=text image file code"`
	ParentID    *uuid.UUID             `json:"parent_id"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// MessageResponse 消息响应
type MessageResponse struct {
	ID          uuid.UUID              `json:"id"`
	SessionID   uuid.UUID              `json:"session_id"`
	ParentID    *uuid.UUID             `json:"parent_id"`
	Role        types.MessageRole      `json:"role"`
	Content     string                 `json:"content"`
	ContentType types.MessageType      `json:"content_type"`
	ModelName   string                 `json:"model_name"`
	ToolCalls   []ToolCall             `json:"tool_calls,omitempty"`
	ToolCallID  string                 `json:"tool_call_id,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
	TokensUsed  int                    `json:"tokens_used"`
	Cost        float64                `json:"cost"`
	CreatedAt   time.Time              `json:"created_at"`
}

// ToResponse 转换为响应格式
func (m *Message) ToResponse() MessageResponse {
	return MessageResponse{
		ID:          m.ID,
		SessionID:   m.SessionID,
		ParentID:    m.ParentID,
		Role:        m.Role,
		Content:     m.Content,
		ContentType: m.ContentType,
		ModelName:   m.ModelName,
		ToolCalls:   m.ToolCalls,
		ToolCallID:  m.ToolCallID,
		Metadata:    m.Metadata,
		TokensUsed:  m.TokensUsed,
		Cost:        m.Cost,
		CreatedAt:   m.CreatedAt,
	}
}

// MessageListResponse 消息列表响应
type MessageListResponse struct {
	ID          uuid.UUID         `json:"id"`
	ParentID    *uuid.UUID        `json:"parent_id"`
	Role        types.MessageRole `json:"role"`
	Content     string            `json:"content"`
	ContentType types.MessageType `json:"content_type"`
	ModelName   string            `json:"model_name"`
	TokensUsed  int               `json:"tokens_used"`
	Cost        float64           `json:"cost"`
	CreatedAt   time.Time         `json:"created_at"`
}

// ToListResponse 转换为列表响应格式
func (m *Message) ToListResponse() MessageListResponse {
	return MessageListResponse{
		ID:          m.ID,
		ParentID:    m.ParentID,
		Role:        m.Role,
		Content:     m.Content,
		ContentType: m.ContentType,
		ModelName:   m.ModelName,
		TokensUsed:  m.TokensUsed,
		Cost:        m.Cost,
		CreatedAt:   m.CreatedAt,
	}
}

// StreamingMessage 流式消息
type StreamingMessage struct {
	ID         uuid.UUID         `json:"id"`
	SessionID  uuid.UUID         `json:"session_id"`
	Role       types.MessageRole `json:"role"`
	Content    string            `json:"content"`
	Done       bool              `json:"done"`
	TokensUsed int               `json:"tokens_used,omitempty"`
	Cost       float64           `json:"cost,omitempty"`
}
