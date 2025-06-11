package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims JWT声明结构
type Claims struct {
	UserID      uuid.UUID `json:"user_id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	Roles       []string  `json:"roles"`
	Permissions []string  `json:"permissions"`
	TokenType   string    `json:"token_type"` // access, refresh
	jwt.RegisteredClaims
}

// TokenType 令牌类型
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

// IsAccessToken 检查是否为访问令牌
func (c *Claims) IsAccessToken() bool {
	return c.TokenType == TokenTypeAccess
}

// IsRefreshToken 检查是否为刷新令牌
func (c *Claims) IsRefreshToken() bool {
	return c.TokenType == TokenTypeRefresh
}

// HasRole 检查是否有指定角色
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasPermission 检查是否有指定权限
func (c *Claims) HasPermission(permission string) bool {
	for _, p := range c.Permissions {
		if p == "*" || p == permission {
			return true
		}
	}
	return false
}

// IsAdmin 检查是否为管理员
func (c *Claims) IsAdmin() bool {
	return c.HasRole("admin") || c.HasPermission("*")
}
