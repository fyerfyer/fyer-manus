package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestClaims_IsAccessToken(t *testing.T) {
	// 测试访问令牌
	claims := &Claims{
		TokenType: TokenTypeAccess,
	}
	assert.True(t, claims.IsAccessToken(), "should be access token")

	// 测试刷新令牌
	claims.TokenType = TokenTypeRefresh
	assert.False(t, claims.IsAccessToken(), "should not be access token")

	// 测试无效类型
	claims.TokenType = "invalid"
	assert.False(t, claims.IsAccessToken(), "should not be access token for invalid type")
}

func TestClaims_IsRefreshToken(t *testing.T) {
	// 测试刷新令牌
	claims := &Claims{
		TokenType: TokenTypeRefresh,
	}
	assert.True(t, claims.IsRefreshToken(), "should be refresh token")

	// 测试访问令牌
	claims.TokenType = TokenTypeAccess
	assert.False(t, claims.IsRefreshToken(), "should not be refresh token")

	// 测试无效类型
	claims.TokenType = "invalid"
	assert.False(t, claims.IsRefreshToken(), "should not be refresh token for invalid type")
}

func TestClaims_HasRole(t *testing.T) {
	claims := &Claims{
		Roles: []string{"admin", "user", "editor"},
	}

	// 测试存在的角色
	assert.True(t, claims.HasRole("admin"), "should have admin role")
	assert.True(t, claims.HasRole("user"), "should have user role")
	assert.True(t, claims.HasRole("editor"), "should have editor role")

	// 测试不存在的角色
	assert.False(t, claims.HasRole("manager"), "should not have manager role")
	assert.False(t, claims.HasRole(""), "should not have empty role")

	// 测试空角色列表
	emptyClaims := &Claims{
		Roles: []string{},
	}
	assert.False(t, emptyClaims.HasRole("admin"), "should not have any role when list is empty")

	// 测试nil角色列表
	nilClaims := &Claims{}
	assert.False(t, nilClaims.HasRole("admin"), "should not have any role when list is nil")
}

func TestClaims_HasPermission(t *testing.T) {
	claims := &Claims{
		Permissions: []string{"read", "write", "delete"},
	}

	// 测试存在的权限
	assert.True(t, claims.HasPermission("read"), "should have read permission")
	assert.True(t, claims.HasPermission("write"), "should have write permission")
	assert.True(t, claims.HasPermission("delete"), "should have delete permission")

	// 测试不存在的权限
	assert.False(t, claims.HasPermission("execute"), "should not have execute permission")
	assert.False(t, claims.HasPermission(""), "should not have empty permission")

	// 测试超级权限
	superClaims := &Claims{
		Permissions: []string{"*"},
	}
	assert.True(t, superClaims.HasPermission("any_permission"), "should have any permission with wildcard")
	assert.True(t, superClaims.HasPermission("read"), "should have read permission with wildcard")

	// 测试包含超级权限的混合权限
	mixedClaims := &Claims{
		Permissions: []string{"read", "*", "write"},
	}
	assert.True(t, mixedClaims.HasPermission("any_permission"), "should have any permission with wildcard in mixed list")

	// 测试空权限列表
	emptyClaims := &Claims{
		Permissions: []string{},
	}
	assert.False(t, emptyClaims.HasPermission("read"), "should not have any permission when list is empty")

	// 测试nil权限列表
	nilClaims := &Claims{}
	assert.False(t, nilClaims.HasPermission("read"), "should not have any permission when list is nil")
}

func TestClaims_IsAdmin(t *testing.T) {
	// 测试通过admin角色判断管理员
	adminRoleClaims := &Claims{
		Roles:       []string{"admin", "user"},
		Permissions: []string{"read", "write"},
	}
	assert.True(t, adminRoleClaims.IsAdmin(), "should be admin with admin role")

	// 测试通过超级权限判断管理员
	superPermClaims := &Claims{
		Roles:       []string{"user"},
		Permissions: []string{"*"},
	}
	assert.True(t, superPermClaims.IsAdmin(), "should be admin with super permission")

	// 测试既有admin角色又有超级权限
	bothClaims := &Claims{
		Roles:       []string{"admin"},
		Permissions: []string{"*", "read"},
	}
	assert.True(t, bothClaims.IsAdmin(), "should be admin with both admin role and super permission")

	// 测试普通用户
	userClaims := &Claims{
		Roles:       []string{"user", "editor"},
		Permissions: []string{"read", "write"},
	}
	assert.False(t, userClaims.IsAdmin(), "should not be admin with normal roles and permissions")

	// 测试空权限和角色
	emptyClaims := &Claims{
		Roles:       []string{},
		Permissions: []string{},
	}
	assert.False(t, emptyClaims.IsAdmin(), "should not be admin with empty roles and permissions")

	// 测试nil权限和角色
	nilClaims := &Claims{}
	assert.False(t, nilClaims.IsAdmin(), "should not be admin with nil roles and permissions")
}

func TestClaims_CompleteStructure(t *testing.T) {
	// 测试完整的Claims结构
	userID := uuid.New()
	now := time.Now()

	claims := &Claims{
		UserID:      userID,
		Username:    "testuser",
		Email:       "test@example.com",
		Roles:       []string{"user", "editor"},
		Permissions: []string{"read", "write"},
		TokenType:   TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}

	// 验证基本字段
	assert.Equal(t, userID, claims.UserID, "user id should match")
	assert.Equal(t, "testuser", claims.Username, "username should match")
	assert.Equal(t, "test@example.com", claims.Email, "email should match")
	assert.Equal(t, TokenTypeAccess, claims.TokenType, "token type should match")

	// 验证角色和权限
	assert.True(t, claims.HasRole("user"), "should have user role")
	assert.True(t, claims.HasRole("editor"), "should have editor role")
	assert.True(t, claims.HasPermission("read"), "should have read permission")
	assert.True(t, claims.HasPermission("write"), "should have write permission")

	// 验证令牌类型检查
	assert.True(t, claims.IsAccessToken(), "should be access token")
	assert.False(t, claims.IsRefreshToken(), "should not be refresh token")

	// 验证管理员检查
	assert.False(t, claims.IsAdmin(), "should not be admin")

	// 验证JWT标准字段
	assert.Equal(t, "test-issuer", claims.Issuer, "issuer should match")
	assert.Equal(t, userID.String(), claims.Subject, "subject should match")
	assert.NotEmpty(t, claims.ID, "jti should not be empty")
}

func TestTokenTypeConstants(t *testing.T) {
	// 验证令牌类型常量
	assert.Equal(t, "access", TokenTypeAccess, "access token type constant should be correct")
	assert.Equal(t, "refresh", TokenTypeRefresh, "refresh token type constant should be correct")
}

func TestClaims_EdgeCases(t *testing.T) {
	// 测试边界情况
	claims := &Claims{}

	// 测试空字符串角色和权限
	claims.Roles = []string{"", "user", ""}
	claims.Permissions = []string{"", "read", ""}

	assert.False(t, claims.HasRole(""), "should not match empty role")
	assert.True(t, claims.HasRole("user"), "should match non-empty role")
	assert.False(t, claims.HasPermission(""), "should not match empty permission")
	assert.True(t, claims.HasPermission("read"), "should match non-empty permission")

	// 测试大小写敏感性
	claims.Roles = []string{"Admin"}
	claims.Permissions = []string{"Read"}

	assert.False(t, claims.HasRole("admin"), "role check should be case sensitive")
	assert.False(t, claims.HasPermission("read"), "permission check should be case sensitive")
	assert.True(t, claims.HasRole("Admin"), "should match exact case role")
	assert.True(t, claims.HasPermission("Read"), "should match exact case permission")
}
