package model

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// UserStatus 用户状态枚举
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusInactive  UserStatus = "inactive"
	UserStatusSuspended UserStatus = "suspended"
)

// User 用户模型
type User struct {
	ID            uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Username      string     `gorm:"size:50;not null;uniqueIndex:users_username_key" json:"username"`
	Email         string     `gorm:"size:255;not null;uniqueIndex:users_email_key" json:"email"`
	PasswordHash  string     `gorm:"size:255;not null" json:"-"`
	FullName      string     `gorm:"size:100" json:"full_name"`
	AvatarURL     string     `gorm:"size:500" json:"avatar_url"`
	Status        UserStatus `gorm:"size:20;default:'active'" json:"status"`
	EmailVerified bool       `gorm:"default:false" json:"email_verified"`
	LastLoginAt   *time.Time `json:"last_login_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`

	// 关联关系
	Roles    []Role    `gorm:"many2many:user_roles;" json:"roles,omitempty"`
	Sessions []Session `gorm:"foreignKey:UserID" json:"-"`
}

// BeforeCreate GORM钩子：创建前设置UUID
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// TableName 指定表名
func (User) TableName() string {
	return "users"
}

// SetPassword 设置密码（加密存储）
func (u *User) SetPassword(password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hashedPassword)
	return nil
}

// CheckPassword 验证密码
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

// IsActive 检查用户是否激活
func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}

// HasRole 检查是否有指定角色
func (u *User) HasRole(roleName string) bool {
	for _, role := range u.Roles {
		if role.Name == roleName {
			return true
		}
	}
	return false
}

// HasPermission 检查是否有指定权限
func (u *User) HasPermission(permission string) bool {
	for _, role := range u.Roles {
		if role.HasPermission(permission) {
			return true
		}
	}
	return false
}

// GetPermissions 获取所有权限
func (u *User) GetPermissions() []string {
	permissionSet := make(map[string]bool)
	for _, role := range u.Roles {
		for _, permission := range role.Permissions {
			permissionSet[permission] = true
		}
	}

	permissions := make([]string, 0, len(permissionSet))
	for permission := range permissionSet {
		permissions = append(permissions, permission)
	}
	return permissions
}

// UpdateLastLogin 更新最后登录时间
func (u *User) UpdateLastLogin() {
	now := time.Now()
	u.LastLoginAt = &now
}

// UserProfile 用户信息（去除敏感字段）
type UserProfile struct {
	ID            uuid.UUID  `json:"id"`
	Username      string     `json:"username"`
	Email         string     `json:"email"`
	FullName      string     `json:"full_name"`
	AvatarURL     string     `json:"avatar_url"`
	Status        UserStatus `json:"status"`
	EmailVerified bool       `json:"email_verified"`
	LastLoginAt   *time.Time `json:"last_login_at"`
	CreatedAt     time.Time  `json:"created_at"`
	Roles         []Role     `json:"roles,omitempty"`
}

// ToProfile 转换为用户信息
func (u *User) ToProfile() UserProfile {
	return UserProfile{
		ID:            u.ID,
		Username:      u.Username,
		Email:         u.Email,
		FullName:      u.FullName,
		AvatarURL:     u.AvatarURL,
		Status:        u.Status,
		EmailVerified: u.EmailVerified,
		LastLoginAt:   u.LastLoginAt,
		CreatedAt:     u.CreatedAt,
		Roles:         u.Roles,
	}
}
