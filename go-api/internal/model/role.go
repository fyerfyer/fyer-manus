package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Role 角色模型
type Role struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name        string    `gorm:"uniqueIndex;size:50;not null" json:"name"`
	Description string    `gorm:"type:text" json:"description"`
	Permissions []string  `gorm:"type:jsonb;serializer:json" json:"permissions"` // 添加 serializer:json
	IsSystem    bool      `gorm:"default:false" json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// 关联关系
	Users []User `gorm:"many2many:user_roles;" json:"-"`
}

// BeforeCreate GORM钩子：创建前设置UUID
func (r *Role) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

// TableName 指定表名
func (Role) TableName() string {
	return "roles"
}

// HasPermission 检查是否有指定权限
func (r *Role) HasPermission(permission string) bool {
	for _, p := range r.Permissions {
		if p == "*" || p == permission {
			return true
		}
	}
	return false
}

// AddPermission 添加权限
func (r *Role) AddPermission(permission string) {
	if !r.HasPermission(permission) {
		r.Permissions = append(r.Permissions, permission)
	}
}

// RemovePermission 移除权限
func (r *Role) RemovePermission(permission string) {
	for i, p := range r.Permissions {
		if p == permission {
			r.Permissions = append(r.Permissions[:i], r.Permissions[i+1:]...)
			break
		}
	}
}

// 预定义权限常量
const (
	PermissionChatCreate    = "chat.create"
	PermissionChatRead      = "chat.read"
	PermissionChatUpdate    = "chat.update"
	PermissionChatDelete    = "chat.delete"
	PermissionPluginExecute = "plugin.execute"
	PermissionUserManage    = "user.manage"
	PermissionSystemAdmin   = "*"
)

// 预定义角色名称
const (
	RoleAdmin  = "admin"
	RoleUser   = "user"
	RoleViewer = "viewer"
)
