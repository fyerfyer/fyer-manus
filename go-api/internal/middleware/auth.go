package middleware

import (
	"net/http"
	"strings"

	"github.com/fyerfyer/fyer-manus/go-api/internal/auth"
	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	AuthHeaderKey    = "Authorization"
	UserContextKey   = "user"
	ClaimsContextKey = "claims"
)

// Auth 认证中间件
func Auth() gin.HandlerFunc {
	authService := service.NewAuthService()
	validator := authService.GetValidator()

	return func(c *gin.Context) {
		// 获取Authorization header
		authHeader := c.GetHeader(AuthHeaderKey)
		if authHeader == "" {
			logger.Warn("missing authorization header",
				zap.String("path", c.Request.URL.Path),
				zap.String("method", c.Request.Method),
			)
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "authorization required",
			})
			c.Abort()
			return
		}

		// 提取token
		token := extractBearerToken(authHeader)
		if token == "" {
			logger.Warn("invalid authorization header format",
				zap.String("header", authHeader),
			)
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "invalid authorization header",
			})
			c.Abort()
			return
		}

		// 验证token
		claims, err := validator.ValidateAccessToken(token)
		if err != nil {
			logger.Warn("token validation failed",
				zap.Error(err),
				zap.String("token", token[:20]+"..."),
			)
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "invalid or expired token",
			})
			c.Abort()
			return
		}

		// 将claims存储到上下文
		c.Set(ClaimsContextKey, claims)

		// 获取用户信息
		userInfo, err := authService.GetUserInfo(claims.UserID)
		if err != nil {
			logger.Error("failed to get user info",
				zap.Error(err),
				zap.String("user_id", claims.UserID.String()),
			)
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":    http.StatusInternalServerError,
				"message": "internal server error",
			})
			c.Abort()
			return
		}

		// 将用户信息存储到上下文
		c.Set(UserContextKey, userInfo)

		logger.Debug("user authenticated successfully",
			zap.String("user_id", claims.UserID.String()),
			zap.String("username", claims.Username),
		)

		c.Next()
	}
}

// OptionalAuth 可选认证中间件
func OptionalAuth() gin.HandlerFunc {
	authService := service.NewAuthService()
	validator := authService.GetValidator()

	return func(c *gin.Context) {
		authHeader := c.GetHeader(AuthHeaderKey)
		if authHeader == "" {
			c.Next()
			return
		}

		token := extractBearerToken(authHeader)
		if token == "" {
			c.Next()
			return
		}

		claims, err := validator.ValidateAccessToken(token)
		if err != nil {
			logger.Debug("optional auth failed", zap.Error(err))
			c.Next()
			return
		}

		// 设置用户上下文
		c.Set(ClaimsContextKey, claims)

		userInfo, err := authService.GetUserInfo(claims.UserID)
		if err == nil {
			c.Set(UserContextKey, userInfo)
		}

		c.Next()
	}
}

// extractBearerToken 从Authorization header中提取Bearer token
func extractBearerToken(authHeader string) string {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// GetCurrentUser 从上下文获取当前用户
func GetCurrentUser(c *gin.Context) (*auth.Claims, bool) {
	claims, exists := c.Get(ClaimsContextKey)
	if !exists {
		return nil, false
	}

	userClaims, ok := claims.(*auth.Claims)
	return userClaims, ok
}

// GetCurrentUserID 从上下文获取当前用户ID
func GetCurrentUserID(c *gin.Context) (string, bool) {
	claims, ok := GetCurrentUser(c)
	if !ok {
		return "", false
	}
	return claims.UserID.String(), true
}

// RequireAuth 确保用户已认证
func RequireAuth(c *gin.Context) (*auth.Claims, bool) {
	claims, ok := GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		c.Abort()
		return nil, false
	}
	return claims, true
}

// AuthenticatedOnly 仅认证用户可访问的中间件组合
func AuthenticatedOnly() gin.HandlerFunc {
	return Auth()
}
