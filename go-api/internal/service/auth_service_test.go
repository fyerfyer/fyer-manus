package service

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
)

func TestNewAuthService(t *testing.T) {
	// 初始化数据库
	setupAuthServiceDatabase(t)
	defer database.Close()

	service := NewAuthService()
	assert.NotNil(t, service, "auth service should not be nil")
	assert.NotNil(t, service.jwtManager, "jwt manager should not be nil")
	assert.NotNil(t, service.validator, "validator should not be nil")
}

func TestAuthService_Register(t *testing.T) {
	// 初始化数据库
	setupAuthServiceDatabase(t)
	defer database.Close()

	service := NewAuthService()

	// 测试正常注册
	req := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
		FullName: "Test User",
	}

	response, err := service.Register(req)
	assert.NoError(t, err, "registration should succeed")
	assert.NotNil(t, response, "response should not be nil")
	assert.NotEmpty(t, response.AccessToken, "access token should not be empty")
	assert.NotEmpty(t, response.RefreshToken, "refresh token should not be empty")
	assert.Equal(t, "Bearer", response.TokenType, "token type should be Bearer")
	assert.Equal(t, req.Username, response.User.Username, "username should match")
	assert.Equal(t, req.Email, response.User.Email, "email should match")
	assert.Equal(t, model.UserStatusActive, response.User.Status, "user should be active")

	// 测试重复用户名
	duplicateReq := RegisterRequest{
		Username: "testuser",
		Email:    "another@example.com",
		Password: "password123",
	}

	_, err = service.Register(duplicateReq)
	assert.Error(t, err, "registration with duplicate username should fail")
	assert.Contains(t, err.Error(), "already exists", "error should mention already exists")

	// 测试重复邮箱
	duplicateEmailReq := RegisterRequest{
		Username: "anotheruser",
		Email:    "test@example.com",
		Password: "password123",
	}

	_, err = service.Register(duplicateEmailReq)
	assert.Error(t, err, "registration with duplicate email should fail")
	assert.Contains(t, err.Error(), "already exists", "error should mention already exists")
}

func TestAuthService_Login(t *testing.T) {
	// 初始化数据库
	setupAuthServiceDatabase(t)
	defer database.Close()

	service := NewAuthService()

	// 先注册一个用户
	registerReq := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
		FullName: "Test User",
	}

	_, err := service.Register(registerReq)
	require.NoError(t, err, "registration should succeed")

	// 测试用户名登录
	loginReq := LoginRequest{
		Username: "testuser",
		Password: "password123",
	}

	response, err := service.Login(loginReq)
	assert.NoError(t, err, "login should succeed")
	assert.NotNil(t, response, "response should not be nil")
	assert.NotEmpty(t, response.AccessToken, "access token should not be empty")
	assert.NotEmpty(t, response.RefreshToken, "refresh token should not be empty")
	assert.Equal(t, "testuser", response.User.Username, "username should match")

	// 测试邮箱登录
	emailLoginReq := LoginRequest{
		Username: "test@example.com",
		Password: "password123",
	}

	response, err = service.Login(emailLoginReq)
	assert.NoError(t, err, "email login should succeed")
	assert.Equal(t, "testuser", response.User.Username, "username should match")

	// 测试错误密码
	wrongPasswordReq := LoginRequest{
		Username: "testuser",
		Password: "wrongpassword",
	}

	_, err = service.Login(wrongPasswordReq)
	assert.Error(t, err, "login with wrong password should fail")
	assert.Contains(t, err.Error(), "invalid", "error should mention invalid credentials")

	// 测试不存在的用户
	nonExistentReq := LoginRequest{
		Username: "nonexistent",
		Password: "password123",
	}

	_, err = service.Login(nonExistentReq)
	assert.Error(t, err, "login with non-existent user should fail")
	assert.Contains(t, err.Error(), "invalid", "error should mention invalid credentials")
}

func TestAuthService_RefreshToken(t *testing.T) {
	// 初始化数据库
	setupAuthServiceDatabase(t)
	defer database.Close()

	service := NewAuthService()

	// 先注册并登录用户
	registerReq := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	registerResp, err := service.Register(registerReq)
	require.NoError(t, err, "registration should succeed")

	// 测试刷新令牌
	refreshReq := RefreshTokenRequest{
		RefreshToken: registerResp.RefreshToken,
	}

	response, err := service.RefreshToken(refreshReq)
	assert.NoError(t, err, "refresh token should succeed")
	assert.NotNil(t, response, "response should not be nil")
	assert.NotEmpty(t, response.AccessToken, "new access token should not be empty")
	assert.NotEmpty(t, response.RefreshToken, "new refresh token should not be empty")
	assert.NotEqual(t, registerResp.AccessToken, response.AccessToken, "new access token should be different")

	// 测试无效的刷新令牌
	invalidRefreshReq := RefreshTokenRequest{
		RefreshToken: "invalid.refresh.token",
	}

	_, err = service.RefreshToken(invalidRefreshReq)
	assert.Error(t, err, "refresh with invalid token should fail")
	assert.Contains(t, err.Error(), "invalid", "error should mention invalid token")
}

func TestAuthService_Logout(t *testing.T) {
	// 初始化数据库
	setupAuthServiceDatabase(t)
	defer database.Close()

	service := NewAuthService()

	// 先注册并登录用户
	registerReq := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	registerResp, err := service.Register(registerReq)
	require.NoError(t, err, "registration should succeed")

	// 测试登出
	err = service.Logout(registerResp.AccessToken, registerResp.RefreshToken)
	assert.NoError(t, err, "logout should succeed")

	// 验证令牌被拉黑（尝试使用被拉黑的令牌）
	_, err = service.ValidateToken(registerResp.AccessToken)
	assert.Error(t, err, "using blacklisted token should fail")
}

func TestAuthService_ValidateToken(t *testing.T) {
	// 初始化数据库
	setupAuthServiceDatabase(t)
	defer database.Close()

	service := NewAuthService()

	// 先注册并登录用户
	registerReq := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	registerResp, err := service.Register(registerReq)
	require.NoError(t, err, "registration should succeed")

	// 测试验证有效令牌
	claims, err := service.ValidateToken(registerResp.AccessToken)
	assert.NoError(t, err, "validating valid token should succeed")
	assert.NotNil(t, claims, "claims should not be nil")
	assert.Equal(t, "testuser", claims.Username, "username should match")

	// 测试验证无效令牌
	_, err = service.ValidateToken("invalid.token.here")
	assert.Error(t, err, "validating invalid token should fail")
}

func TestAuthService_ChangePassword(t *testing.T) {
	// 初始化数据库
	setupAuthServiceDatabase(t)
	defer database.Close()

	service := NewAuthService()

	// 先注册用户
	registerReq := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "oldpassword",
	}

	registerResp, err := service.Register(registerReq)
	require.NoError(t, err, "registration should succeed")

	// 测试修改密码
	err = service.ChangePassword(registerResp.User.ID, "oldpassword", "newpassword123")
	assert.NoError(t, err, "change password should succeed")

	// 验证新密码可以登录
	loginReq := LoginRequest{
		Username: "testuser",
		Password: "newpassword123",
	}

	_, err = service.Login(loginReq)
	assert.NoError(t, err, "login with new password should succeed")

	// 验证旧密码不能登录
	oldLoginReq := LoginRequest{
		Username: "testuser",
		Password: "oldpassword",
	}

	_, err = service.Login(oldLoginReq)
	assert.Error(t, err, "login with old password should fail")

	// 测试错误的旧密码
	err = service.ChangePassword(registerResp.User.ID, "wrongoldpassword", "anotherpassword")
	assert.Error(t, err, "change password with wrong old password should fail")
	assert.Contains(t, err.Error(), "invalid", "error should mention invalid old password")

	// 测试不存在的用户
	err = service.ChangePassword(uuid.New(), "oldpassword", "newpassword")
	assert.Error(t, err, "change password for non-existent user should fail")
}

func TestAuthService_GetUserInfo(t *testing.T) {
	// 初始化数据库
	setupAuthServiceDatabase(t)
	defer database.Close()

	service := NewAuthService()

	// 先注册用户
	registerReq := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
		FullName: "Test User",
	}

	registerResp, err := service.Register(registerReq)
	require.NoError(t, err, "registration should succeed")

	// 测试获取用户信息
	userInfo, err := service.GetUserInfo(registerResp.User.ID)
	assert.NoError(t, err, "get user info should succeed")
	assert.NotNil(t, userInfo, "user info should not be nil")
	assert.Equal(t, "testuser", userInfo.Username, "username should match")
	assert.Equal(t, "test@example.com", userInfo.Email, "email should match")
	assert.Equal(t, "Test User", userInfo.FullName, "full name should match")

	// 测试不存在的用户
	_, err = service.GetUserInfo(uuid.New())
	assert.Error(t, err, "get info for non-existent user should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestAuthService_UserStatusHandling(t *testing.T) {
	// 初始化数据库
	setupAuthServiceDatabase(t)
	defer database.Close()

	service := NewAuthService()

	// 注册用户
	registerReq := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	registerResp, err := service.Register(registerReq)
	require.NoError(t, err, "registration should succeed")

	// 手动将用户设置为非活跃状态
	db := database.Get()
	err = db.Model(&model.User{}).
		Where("id = ?", registerResp.User.ID).
		Update("status", model.UserStatusInactive).Error
	require.NoError(t, err, "updating user status should succeed")

	// 测试非活跃用户登录
	loginReq := LoginRequest{
		Username: "testuser",
		Password: "password123",
	}

	_, err = service.Login(loginReq)
	assert.Error(t, err, "login with inactive user should fail")
	assert.Contains(t, err.Error(), "not active", "error should mention user not active")

	// 测试非活跃用户刷新令牌
	refreshReq := RefreshTokenRequest{
		RefreshToken: registerResp.RefreshToken,
	}

	_, err = service.RefreshToken(refreshReq)
	assert.Error(t, err, "refresh token with inactive user should fail")
	assert.Contains(t, err.Error(), "not active", "error should mention user not active")
}

func TestAuthService_TokenExpiry(t *testing.T) {
	// 初始化数据库
	setupAuthServiceDatabase(t)
	defer database.Close()

	service := NewAuthService()

	// 注册用户
	registerReq := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	registerResp, err := service.Register(registerReq)
	require.NoError(t, err, "registration should succeed")

	// 验证令牌有效
	claims, err := service.ValidateToken(registerResp.AccessToken)
	assert.NoError(t, err, "validating fresh token should succeed")
	assert.NotNil(t, claims, "claims should not be nil")

	// 验证令牌过期时间
	assert.True(t, claims.ExpiresAt.After(time.Now()), "token should not be expired")
	assert.True(t, claims.IssuedAt.Before(time.Now().Add(time.Minute)), "issued time should be recent")
}

func TestAuthService_DefaultRoleAssignment(t *testing.T) {
	// 初始化数据库
	setupAuthServiceDatabase(t)
	defer database.Close()

	service := NewAuthService()

	// 创建默认角色
	createTestRole(t, model.RoleUser, "Default user role", []string{
		model.PermissionChatCreate,
		model.PermissionChatRead,
	})

	// 注册用户
	registerReq := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	registerResp, err := service.Register(registerReq)
	require.NoError(t, err, "registration should succeed")

	// 验证用户被分配了默认角色
	userInfo, err := service.GetUserInfo(registerResp.User.ID)
	require.NoError(t, err, "get user info should succeed")

	assert.GreaterOrEqual(t, len(userInfo.Roles), 1, "user should have at least one role")

	// 检查是否有默认用户角色
	hasUserRole := false
	for _, role := range userInfo.Roles {
		if role.Name == model.RoleUser {
			hasUserRole = true
			break
		}
	}
	assert.True(t, hasUserRole, "user should have default user role")
}

func TestAuthService_TokenValidation(t *testing.T) {
	// 初始化数据库
	setupAuthServiceDatabase(t)
	defer database.Close()

	service := NewAuthService()

	// 注册用户
	registerReq := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	registerResp, err := service.Register(registerReq)
	require.NoError(t, err, "registration should succeed")

	// 测试访问令牌验证
	claims, err := service.ValidateToken(registerResp.AccessToken)
	assert.NoError(t, err, "access token validation should succeed")
	assert.Equal(t, "access", claims.TokenType, "should be access token")

	// 测试刷新令牌验证（应该失败，因为ValidateToken只验证访问令牌）
	_, err = service.ValidateToken(registerResp.RefreshToken)
	assert.Error(t, err, "refresh token validation as access token should fail")
}

// setupAuthServiceDatabase 设置测试数据库
func setupAuthServiceDatabase(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	err = database.Init(&cfg.Database)
	require.NoError(t, err, "failed to init database")

	// 自动迁移表结构
	db := database.Get()
	require.NoError(t, err, "failed to migrate tables")

	// 清理测试数据
	db.Exec("TRUNCATE TABLE user_roles CASCADE")
	db.Exec("TRUNCATE TABLE users CASCADE")
	db.Exec("TRUNCATE TABLE roles CASCADE")

	err = cache.Init(&cfg.Redis)
	require.NoError(t, err, "failed to init cache")

	// 设置全局配置（AuthService需要）
	config.LoadForTest()
}

// createTestRole 创建测试角色
func createTestRole(t *testing.T, name, description string, permissions []string) *model.Role {
	db := database.Get()

	role := &model.Role{
		Name:        name,
		Description: description,
		Permissions: permissions,
	}

	err := db.Create(role).Error
	require.NoError(t, err, "creating test role should succeed")

	return role
}
