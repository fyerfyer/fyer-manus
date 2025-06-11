package auth

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"go.uber.org/zap"
)

// TokenValidator 令牌验证器
type TokenValidator struct {
	jwtManager *JWTManager
	cache      *redis.Client
}

// NewTokenValidator 创建令牌验证器
func NewTokenValidator(jwtManager *JWTManager) *TokenValidator {
	return &TokenValidator{
		jwtManager: jwtManager,
		cache:      cache.Get(),
	}
}

// Validate 验证令牌
func (v *TokenValidator) Validate(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("token is required")
	}

	// 检查令牌是否在黑名单中
	if v.isTokenBlacklisted(tokenString) {
		return nil, errors.New("token is blacklisted")
	}

	// 验证令牌
	claims, err := v.jwtManager.VerifyToken(tokenString)
	if err != nil {
		logger.Error("token validation failed", zap.Error(err))
		return nil, err
	}

	return claims, nil
}

// ValidateAccessToken 验证访问令牌
func (v *TokenValidator) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := v.Validate(tokenString)
	if err != nil {
		return nil, err
	}

	if !claims.IsAccessToken() {
		return nil, errors.New("invalid access token")
	}

	return claims, nil
}

// ValidateRefreshToken 验证刷新令牌
func (v *TokenValidator) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := v.Validate(tokenString)
	if err != nil {
		return nil, err
	}

	if !claims.IsRefreshToken() {
		return nil, errors.New("invalid refresh token")
	}

	return claims, nil
}

// BlacklistToken 将令牌加入黑名单
func (v *TokenValidator) BlacklistToken(tokenString string) error {
	claims, err := v.jwtManager.ParseToken(tokenString)
	if err != nil {
		return err
	}

	// 计算令牌剩余有效期
	var ttl time.Duration
	if claims.ExpiresAt != nil {
		ttl = time.Until(claims.ExpiresAt.Time)
		if ttl <= 0 {
			return nil // 令牌已过期，无需加入黑名单
		}
	} else {
		ttl = 24 * time.Hour // 默认24小时
	}

	// 将令牌加入Redis黑名单
	key := v.getBlacklistKey(tokenString)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = cache.Set(ctx, key, "blacklisted", ttl)
	if err != nil {
		logger.Error("failed to blacklist token", zap.Error(err))
		return err
	}

	logger.Info("token blacklisted", zap.String("token_id", claims.ID))
	return nil
}

// IsTokenBlacklisted 检查令牌是否在黑名单中
func (v *TokenValidator) isTokenBlacklisted(tokenString string) bool {
	key := v.getBlacklistKey(tokenString)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	exists, err := cache.Exists(ctx, key)
	if err != nil {
		logger.Error("failed to check token blacklist", zap.Error(err))
		return false
	}

	return exists > 0
}

// getBlacklistKey 获取黑名单缓存键
func (v *TokenValidator) getBlacklistKey(tokenString string) string {
	// 使用令牌的哈希作为键以节省存储空间
	hash := hashToken(tokenString)
	return "blacklist:token:" + hash
}

// hashToken 计算令牌哈希
func hashToken(token string) string {
	// 简单的哈希方法，生产环境建议使用更安全的哈希算法
	if len(token) > 32 {
		return token[len(token)-32:]
	}
	return token
}

// ValidatePermission 验证权限
func (v *TokenValidator) ValidatePermission(claims *Claims, requiredPermission string) bool {
	if claims == nil {
		return false
	}

	// 检查是否有超级管理员权限
	if claims.HasPermission("*") {
		return true
	}

	// 检查是否有所需权限
	return claims.HasPermission(requiredPermission)
}

// ValidateRole 验证角色
func (v *TokenValidator) ValidateRole(claims *Claims, requiredRole string) bool {
	if claims == nil {
		return false
	}

	return claims.HasRole(requiredRole)
}

// ValidatePermissions 验证多个权限（AND关系）
func (v *TokenValidator) ValidatePermissions(claims *Claims, requiredPermissions []string) bool {
	if claims == nil {
		return false
	}

	// 检查是否有超级管理员权限
	if claims.HasPermission("*") {
		return true
	}

	// 检查是否拥有所有必需权限
	for _, permission := range requiredPermissions {
		if !claims.HasPermission(permission) {
			return false
		}
	}

	return true
}

// ValidateAnyPermission 验证任一权限（OR关系）
func (v *TokenValidator) ValidateAnyPermission(claims *Claims, permissions []string) bool {
	if claims == nil {
		return false
	}

	// 检查是否有超级管理员权限
	if claims.HasPermission("*") {
		return true
	}

	// 检查是否拥有任一权限
	for _, permission := range permissions {
		if claims.HasPermission(permission) {
			return true
		}
	}

	return false
}

// GetUserContext 从令牌中提取用户上下文信息
func (v *TokenValidator) GetUserContext(claims *Claims) map[string]interface{} {
	if claims == nil {
		return nil
	}

	return map[string]interface{}{
		"user_id":     claims.UserID.String(),
		"username":    claims.Username,
		"email":       claims.Email,
		"roles":       claims.Roles,
		"permissions": claims.Permissions,
		"is_admin":    claims.IsAdmin(),
	}
}

// ExtractClaimsFromAuthHeader 从Authorization头中提取claims
func (v *TokenValidator) ExtractClaimsFromAuthHeader(authHeader string) (*Claims, error) {
	token := ExtractTokenFromHeader(authHeader)
	if token == "" {
		return nil, errors.New("invalid authorization header")
	}

	return v.ValidateAccessToken(token)
}

// CleanupExpiredBlacklist 清理过期的黑名单令牌（定期任务）
func (v *TokenValidator) CleanupExpiredBlacklist() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 查找所有黑名单键
	pattern := "blacklist:token:*"
	keys, err := cache.Keys(ctx, pattern)
	if err != nil {
		logger.Error("failed to get blacklist keys", zap.Error(err))
		return err
	}

	if len(keys) == 0 {
		return nil
	}

	// 检查TTL并清理过期键
	var expiredKeys []string
	for _, key := range keys {
		ttl, err := cache.TTL(ctx, key)
		if err != nil {
			continue
		}
		if ttl <= 0 {
			expiredKeys = append(expiredKeys, key)
		}
	}

	if len(expiredKeys) > 0 {
		err = cache.Del(ctx, expiredKeys...)
		if err != nil {
			logger.Error("failed to cleanup expired blacklist tokens", zap.Error(err))
			return err
		}
		logger.Info("cleaned up expired blacklist tokens", zap.Int("count", len(expiredKeys)))
	}

	return nil
}
