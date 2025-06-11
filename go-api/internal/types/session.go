package types

import "time"

// SessionStatus 会话状态
type SessionStatus string

const (
	SessionStatusActive   SessionStatus = "active"
	SessionStatusArchived SessionStatus = "archived"
	SessionStatusDeleted  SessionStatus = "deleted"
)

// MessageRole 消息角色
type MessageRole string

const (
	MessageRoleUser      MessageRole = "user"
	MessageRoleAssistant MessageRole = "assistant"
	MessageRoleSystem    MessageRole = "system"
	MessageRoleTool      MessageRole = "tool"
)

// MessageType 消息内容类型
type MessageType string

const (
	MessageTypeText  MessageType = "text"
	MessageTypeImage MessageType = "image"
	MessageTypeFile  MessageType = "file"
	MessageTypeCode  MessageType = "code"
)

// SessionEvent 会话事件类型
type SessionEvent string

const (
	SessionEventCreated  SessionEvent = "session.created"
	SessionEventUpdated  SessionEvent = "session.updated"
	SessionEventArchived SessionEvent = "session.archived"
	SessionEventDeleted  SessionEvent = "session.deleted"
	SessionEventMessage  SessionEvent = "session.message"
)

// 会话配置常量
const (
	MaxSessionsPerUser      = 100
	MaxMessagesPerSession   = 1000
	SessionTimeoutMinutes   = 30
	DefaultSessionTitle     = "New Chat"
	MaxSessionTitleLength   = 255
	MaxMessageContentLength = 50000
)

// 分页常量
const (
	DefaultPageSize = 20
	MaxPageSize     = 100
)

// 会话元数据键
const (
	MetadataKeyModel       = "model"
	MetadataKeyProvider    = "provider"
	MetadataKeyTemperature = "temperature"
	MetadataKeyMaxTokens   = "max_tokens"
	MetadataKeyPlugins     = "plugins"
)

// WebSocket消息类型
type WSMessageType string

const (
	WSMessageTypeMessage    WSMessageType = "message"
	WSMessageTypeTyping     WSMessageType = "typing"
	WSMessageTypeError      WSMessageType = "error"
	WSMessageTypeConnection WSMessageType = "connection"
	WSMessageTypeHeartbeat  WSMessageType = "heartbeat"
)

// WebSocket事件
type WSEvent struct {
	Type    WSMessageType `json:"type"`
	Data    interface{}   `json:"data"`
	EventID string        `json:"event_id,omitempty"`
	Time    time.Time     `json:"time"`
}

// 分页参数
type PaginationParams struct {
	Page     int `json:"page" form:"page"`
	PageSize int `json:"page_size" form:"page_size"`
	Offset   int `json:"-"`
}

// 验证分页参数
func (p *PaginationParams) Validate() {
	if p.Page <= 0 {
		p.Page = 1
	}
	if p.PageSize <= 0 {
		p.PageSize = DefaultPageSize
	}
	if p.PageSize > MaxPageSize {
		p.PageSize = MaxPageSize
	}
	p.Offset = (p.Page - 1) * p.PageSize
}

// 分页响应
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Pagination Pagination  `json:"pagination"`
}

type Pagination struct {
	Page      int   `json:"page"`
	PageSize  int   `json:"page_size"`
	Total     int64 `json:"total"`
	TotalPage int64 `json:"total_page"`
}

// 会话搜索参数
type SessionSearchParams struct {
	UserID string `json:"user_id" form:"user_id"`
	Status string `json:"status" form:"status"`
	Query  string `json:"query" form:"query"`
	PaginationParams
}

// 消息搜索参数
type MessageSearchParams struct {
	SessionID string `json:"session_id" form:"session_id"`
	Role      string `json:"role" form:"role"`
	Query     string `json:"query" form:"query"`
	PaginationParams
}
