package auth

import (
	"log"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
)

func TestNewJWTManager(t *testing.T) {
	secretKey := "test-secret-key-32-characters-long"
	accessExpire := time.Hour
	refreshExpire := 24 * time.Hour
	issuer := "test-issuer"

	manager := NewJWTManager(secretKey, accessExpire, refreshExpire, issuer)

	assert.NotNil(t, manager, "jwt manager should not be nil")
	assert.Equal(t, secretKey, manager.secretKey, "secret key should match")
	assert.Equal(t, accessExpire, manager.accessExpire, "access expire should match")
	assert.Equal(t, refreshExpire, manager.refreshExpire, "refresh expire should match")
	assert.Equal(t, issuer, manager.issuer, "issuer should match")
}

func TestJWTManager_GenerateTokens(t *testing.T) {
	// 创建JWT管理器
	manager := createTestJWTManager(t)

	userID := uuid.New()
	username := "testuser"
	email := "test@example.com"
	roles := []string{"user", "editor"}
	permissions := []string{"read", "write"}

	// 生成令牌
	accessToken, refreshToken, err := manager.GenerateTokens(userID, username, email, roles, permissions)

	assert.NoError(t, err, "token generation should succeed")
	assert.NotEmpty(t, accessToken, "access token should not be empty")
	assert.NotEmpty(t, refreshToken, "refresh token should not be empty")
	assert.NotEqual(t, accessToken, refreshToken, "access and refresh tokens should be different")

	// 验证访问令牌
	accessClaims, err := manager.ParseToken(accessToken)
	require.NoError(t, err, "access token parsing should succeed")

	assert.Equal(t, userID, accessClaims.UserID, "access token user id should match")
	assert.Equal(t, username, accessClaims.Username, "access token username should match")
	assert.Equal(t, email, accessClaims.Email, "access token email should match")
	assert.Equal(t, roles, accessClaims.Roles, "access token roles should match")
	assert.Equal(t, permissions, accessClaims.Permissions, "access token permissions should match")
	assert.Equal(t, TokenTypeAccess, accessClaims.TokenType, "should be access token")

	// 验证刷新令牌
	refreshClaims, err := manager.ParseToken(refreshToken)
	require.NoError(t, err, "refresh token parsing should succeed")

	assert.Equal(t, userID, refreshClaims.UserID, "refresh token user id should match")
	assert.Equal(t, TokenTypeRefresh, refreshClaims.TokenType, "should be refresh token")
}

func TestJWTManager_ParseToken(t *testing.T) {
	manager := createTestJWTManager(t)

	userID := uuid.New()
	username := "testuser"
	email := "test@example.com"
	roles := []string{"user"}
	permissions := []string{"read"}

	// 生成有效令牌
	accessToken, _, err := manager.GenerateTokens(userID, username, email, roles, permissions)
	require.NoError(t, err, "token generation should succeed")

	// 解析有效令牌
	claims, err := manager.ParseToken(accessToken)
	assert.NoError(t, err, "parsing valid token should succeed")
	assert.NotNil(t, claims, "claims should not be nil")
	assert.Equal(t, userID, claims.UserID, "user id should match")

	// 测试无效令牌
	_, err = manager.ParseToken("invalid.token.here")
	assert.Error(t, err, "parsing invalid token should fail")

	// 测试空令牌
	_, err = manager.ParseToken("")
	assert.Error(t, err, "parsing empty token should fail")

	// 测试错误签名的令牌
	wrongManager := NewJWTManager("wrong-secret-key", time.Hour, 24*time.Hour, "test")
	_, err = wrongManager.ParseToken(accessToken)
	assert.Error(t, err, "parsing token with wrong secret should fail")
}

func TestJWTManager_VerifyToken(t *testing.T) {
	manager := createTestJWTManager(t)

	userID := uuid.New()
	username := "testuser"
	email := "test@example.com"
	roles := []string{"user"}
	permissions := []string{"read"}

	// 生成有效令牌
	accessToken, _, err := manager.GenerateTokens(userID, username, email, roles, permissions)
	require.NoError(t, err, "token generation should succeed")

	// 验证有效令牌
	claims, err := manager.VerifyToken(accessToken)
	assert.NoError(t, err, "verifying valid token should succeed")
	assert.NotNil(t, claims, "claims should not be nil")

	// 测试过期令牌 - 修复：使用相同的密钥但设置过期时间
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	expiredManager := NewJWTManager(
		cfg.JWT.Secret, // 使用相同的密钥
		-time.Hour,     // 设置为负数，生成已过期的令牌
		24*time.Hour,
		cfg.JWT.Issuer, // 使用相同的发行者
	)
	expiredToken, _, err := expiredManager.GenerateTokens(userID, username, email, roles, permissions)
	require.NoError(t, err, "expired token generation should succeed")

	// 使用原始的manager验证过期令牌
	_, err = manager.VerifyToken(expiredToken)
	assert.Error(t, err, "verifying expired token should fail")
	assert.Contains(t, err.Error(), "expired", "error should mention token expiry")

	// 测试无效令牌
	_, err = manager.VerifyToken("invalid.token")
	assert.Error(t, err, "verifying invalid token should fail")
}

func TestJWTManager_RefreshToken(t *testing.T) {
	manager := createTestJWTManager(t)

	userID := uuid.New()
	username := "testuser"
	email := "test@example.com"
	roles := []string{"user"}
	permissions := []string{"read"}

	// 生成令牌
	accessToken, refreshToken, err := manager.GenerateTokens(userID, username, email, roles, permissions)
	require.NoError(t, err, "token generation should succeed")

	// 使用刷新令牌生成新的访问令牌
	newAccessToken, err := manager.RefreshToken(refreshToken)
	assert.NoError(t, err, "refresh token should succeed")
	assert.NotEmpty(t, newAccessToken, "new access token should not be empty")
	assert.NotEqual(t, accessToken, newAccessToken, "new access token should be different from old one")

	// 验证新的访问令牌
	newClaims, err := manager.VerifyToken(newAccessToken)
	assert.NoError(t, err, "new access token should be valid")
	assert.Equal(t, userID, newClaims.UserID, "user id should match")
	assert.Equal(t, TokenTypeAccess, newClaims.TokenType, "should be access token")

	// 尝试用访问令牌刷新（应该失败）
	_, err = manager.RefreshToken(accessToken)
	assert.Error(t, err, "using access token for refresh should fail")
	assert.Contains(t, err.Error(), "invalid refresh token", "error should mention invalid refresh token")

	// 测试过期的刷新令牌
	expiredManager := NewJWTManager("test-secret-key-32-characters-long", time.Hour, -time.Hour, "test")
	_, expiredRefreshToken, err := expiredManager.GenerateTokens(userID, username, email, roles, permissions)
	require.NoError(t, err, "expired refresh token generation should succeed")

	_, err = manager.RefreshToken(expiredRefreshToken)
	assert.Error(t, err, "using expired refresh token should fail")
}

func TestExtractTokenFromHeader(t *testing.T) {
	// 测试正确的Bearer令牌
	authHeader := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	token := ExtractTokenFromHeader(authHeader)
	assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", token, "should extract token correctly")

	// 测试无Bearer前缀
	authHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	token = ExtractTokenFromHeader(authHeader)
	assert.Equal(t, "", token, "should return empty for header without Bearer")

	// 测试空字符串
	token = ExtractTokenFromHeader("")
	assert.Equal(t, "", token, "should return empty for empty header")

	// 测试只有Bearer
	authHeader = "Bearer"
	token = ExtractTokenFromHeader(authHeader)
	assert.Equal(t, "", token, "should return empty for header with only Bearer")

	// 测试Bearer后面有空格但没有令牌
	authHeader = "Bearer "
	token = ExtractTokenFromHeader(authHeader)
	assert.Equal(t, "", token, "should return empty for Bearer with space but no token")

	// 测试错误的前缀
	authHeader = "Basic eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	token = ExtractTokenFromHeader(authHeader)
	assert.Equal(t, "", token, "should return empty for non-Bearer auth type")

	// 测试大小写敏感
	authHeader = "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	token = ExtractTokenFromHeader(authHeader)
	assert.Equal(t, "", token, "should be case sensitive")
}

func TestJWTManager_GenerateToken_Internal(t *testing.T) {
	manager := createTestJWTManager(t)

	// Add debug logging
	log.Printf("Manager issuer: %s", manager.issuer)

	userID := uuid.New()
	username := "testuser"
	email := "test@example.com"
	roles := []string{"user"}
	permissions := []string{"read"}

	// 测试生成访问令牌
	accessToken, err := manager.generateToken(userID, username, email, roles, permissions, TokenTypeAccess, time.Hour)
	assert.NoError(t, err, "generating access token should succeed")
	assert.NotEmpty(t, accessToken, "access token should not be empty")

	// 验证令牌结构
	parts := strings.Split(accessToken, ".")
	assert.Len(t, parts, 3, "JWT should have 3 parts")

	// 解析并验证内容
	claims, err := manager.ParseToken(accessToken)
	require.NoError(t, err, "parsing generated token should succeed")

	// Add debug logging
	log.Printf("Expected issuer: %s, Actual issuer: %s", manager.issuer, claims.Issuer)
	log.Printf("Token issued at: %v", claims.IssuedAt.Time)
	log.Printf("Token expires at: %v", claims.ExpiresAt.Time)
	log.Printf("Token not before: %v", claims.NotBefore.Time)
	log.Printf("Current time: %v", time.Now())

	assert.Equal(t, TokenTypeAccess, claims.TokenType, "token type should be access")
	assert.Equal(t, userID, claims.UserID, "user id should match")
	assert.Equal(t, username, claims.Username, "username should match")
	assert.Equal(t, email, claims.Email, "email should match")
	assert.Equal(t, roles, claims.Roles, "roles should match")
	assert.Equal(t, permissions, claims.Permissions, "permissions should match")
	assert.Equal(t, manager.issuer, claims.Issuer, "issuer should match") // Use manager.issuer instead of hardcoded value
	assert.Equal(t, userID.String(), claims.Subject, "subject should match user id")
	assert.NotEmpty(t, claims.ID, "jti should not be empty")

	// 验证时间字段
	now := time.Now()
	assert.WithinDuration(t, now, claims.IssuedAt.Time, time.Minute, "issued at should be recent")
	assert.WithinDuration(t, now, claims.NotBefore.Time, time.Minute, "not before should be recent")
	assert.WithinDuration(t, now.Add(time.Hour), claims.ExpiresAt.Time, time.Minute, "expires at should be one hour from now")
}

func TestJWTManager_TokenExpiry(t *testing.T) {
	// 创建短过期时间的管理器 - 增加过期时间以避免时间精度问题
	shortExpireManager := NewJWTManager("test-secret-key-32-characters-long", 2*time.Second, time.Hour, "test")

	userID := uuid.New()
	username := "testuser"
	email := "test@example.com"
	roles := []string{"user"}
	permissions := []string{"read"}

	// Add debug logging
	log.Printf("Creating token with expire duration: %v", 2*time.Second)
	tokenStartTime := time.Now()

	// 生成令牌
	accessToken, _, err := shortExpireManager.GenerateTokens(userID, username, email, roles, permissions)
	require.NoError(t, err, "token generation should succeed")

	tokenGenTime := time.Now()
	log.Printf("Token generated at: %v (took %v)", tokenGenTime, tokenGenTime.Sub(tokenStartTime))

	// Parse token to check expiry time
	claims, err := shortExpireManager.ParseToken(accessToken)
	require.NoError(t, err, "token parsing should succeed")
	log.Printf("Token expires at: %v", claims.ExpiresAt.Time)
	log.Printf("Current time: %v", time.Now())
	log.Printf("Time until expiry: %v", time.Until(claims.ExpiresAt.Time))

	// 立即验证应该成功
	verifyStartTime := time.Now()
	_, err = shortExpireManager.VerifyToken(accessToken)
	verifyEndTime := time.Now()
	log.Printf("Verification at: %v (took %v)", verifyEndTime, verifyEndTime.Sub(verifyStartTime))

	if err != nil {
		log.Printf("Verification error: %v", err)
	}
	assert.NoError(t, err, "newly generated token should be valid")

	// 等待令牌过期 - 增加等待时间
	log.Printf("Waiting for token to expire...")
	time.Sleep(2500 * time.Millisecond) // 等待 2.5 秒，确保令牌过期

	// 验证过期令牌应该失败
	expiredVerifyTime := time.Now()
	log.Printf("Verifying expired token at: %v", expiredVerifyTime)
	_, err = shortExpireManager.VerifyToken(accessToken)
	if err != nil {
		log.Printf("Expected expiry error: %v", err)
	}
	assert.Error(t, err, "expired token should fail verification")
}

func TestJWTManager_EmptyValues(t *testing.T) {
	manager := createTestJWTManager(t)

	userID := uuid.New()

	// 测试空值
	accessToken, refreshToken, err := manager.GenerateTokens(userID, "", "", nil, nil)
	assert.NoError(t, err, "generating tokens with empty values should succeed")
	assert.NotEmpty(t, accessToken, "access token should not be empty")
	assert.NotEmpty(t, refreshToken, "refresh token should not be empty")

	// 验证生成的令牌
	claims, err := manager.ParseToken(accessToken)
	require.NoError(t, err, "parsing token with empty values should succeed")

	assert.Equal(t, userID, claims.UserID, "user id should match")
	assert.Equal(t, "", claims.Username, "username should be empty")
	assert.Equal(t, "", claims.Email, "email should be empty")
	assert.Nil(t, claims.Roles, "roles should be nil")
	assert.Nil(t, claims.Permissions, "permissions should be nil")
}

// createTestJWTManager 创建测试用的JWT管理器
func createTestJWTManager(t *testing.T) *JWTManager {
	// 加载配置
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	return NewJWTManager(
		cfg.JWT.Secret,
		time.Duration(cfg.JWT.ExpireHours)*time.Hour,
		time.Duration(cfg.JWT.RefreshHours)*time.Hour,
		cfg.JWT.Issuer,
	)
}
