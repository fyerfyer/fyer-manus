package middleware

import (
	"fmt"
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
		logger.Debug("auth middleware: starting authentication check",
			zap.String("path", c.Request.URL.Path),
			zap.String("method", c.Request.Method),
		)

		// 获取Authorization header
		authHeader := c.GetHeader(AuthHeaderKey)
		if authHeader == "" {
			logger.Warn("auth middleware: missing authorization header",
				zap.String("path", c.Request.URL.Path),
				zap.String("method", c.Request.Method),
			)
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "authentication required",
			})
			c.Abort()
			return
		}

		logger.Debug("auth middleware: authorization header found",
			zap.Int("header_length", len(authHeader)),
		)

		// 提取token
		token := extractBearerToken(authHeader)
		if token == "" {
			logger.Warn("auth middleware: invalid authorization header format",
				zap.String("header", authHeader),
				zap.Int("header_length", len(authHeader)),
			)
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "invalid authorization header format",
			})
			c.Abort()
			return
		}

		logger.Debug("auth middleware: bearer token extracted",
			zap.Int("token_length", len(token)),
			zap.String("token_prefix", getTokenPrefix(token)),
		)

		// 验证token
		claims, err := validator.ValidateAccessToken(token)
		if err != nil {
			logger.Warn("auth middleware: token validation failed",
				zap.Error(err),
				zap.Int("token_length", len(token)),
				zap.String("token_prefix", getTokenPrefix(token)),
			)
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "invalid or expired token",
			})
			c.Abort()
			return
		}

		logger.Debug("auth middleware: token validation successful",
			zap.String("user_id", claims.UserID.String()),
			zap.String("username", claims.Username),
		)

		// 将claims存储到上下文
		c.Set(ClaimsContextKey, claims)

		// 获取用户信息
		logger.Debug("auth middleware: attempting to get user info",
			zap.String("user_id", claims.UserID.String()),
		)

		userInfo, err := authService.GetUserInfo(claims.UserID)
		if err != nil {
			logger.Error("auth middleware: failed to get user info",
				zap.Error(err),
				zap.String("user_id", claims.UserID.String()),
				zap.String("error_type", fmt.Sprintf("%T", err)),
			)
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":    http.StatusInternalServerError,
				"message": "internal server error",
			})
			c.Abort()
			return
		}

		logger.Debug("auth middleware: user info retrieved successfully",
			zap.String("user_id", claims.UserID.String()),
			zap.String("username", userInfo.Username),
			zap.String("user_status", string(userInfo.Status)),
		)

		// 检查用户状态
		if userInfo.Status != "active" {
			logger.Error("auth middleware: user account is not active",
				zap.String("user_id", claims.UserID.String()),
				zap.String("username", userInfo.Username),
				zap.String("user_status", string(userInfo.Status)),
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

		logger.Debug("auth middleware: user authenticated successfully",
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
		logger.Debug("optional auth middleware: starting optional authentication check")

		authHeader := c.GetHeader(AuthHeaderKey)
		if authHeader == "" {
			logger.Debug("optional auth middleware: no authorization header, continuing without auth")
			c.Next()
			return
		}

		token := extractBearerToken(authHeader)
		if token == "" {
			logger.Debug("optional auth middleware: invalid bearer token format, continuing without auth")
			c.Next()
			return
		}

		claims, err := validator.ValidateAccessToken(token)
		if err != nil {
			logger.Debug("optional auth middleware: token validation failed, continuing without auth",
				zap.Error(err))
			c.Next()
			return
		}

		// 设置用户上下文
		c.Set(ClaimsContextKey, claims)

		userInfo, err := authService.GetUserInfo(claims.UserID)
		if err == nil {
			c.Set(UserContextKey, userInfo)
			logger.Debug("optional auth middleware: user context set successfully",
				zap.String("user_id", claims.UserID.String()),
			)
		} else {
			logger.Debug("optional auth middleware: failed to get user info, continuing with claims only",
				zap.Error(err),
			)
		}

		c.Next()
	}
}

// extractBearerToken 从Authorization header中提取Bearer token
func extractBearerToken(authHeader string) string {
	logger.Debug("extracting bearer token",
		zap.String("auth_header", authHeader),
		zap.Int("header_length", len(authHeader)),
	)

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		logger.Debug("bearer token extraction failed: invalid parts count",
			zap.Int("parts_count", len(parts)),
			zap.Strings("parts", parts),
		)
		return ""
	}

	if !strings.EqualFold(parts[0], "Bearer") {
		logger.Debug("bearer token extraction failed: invalid token type",
			zap.String("token_type", parts[0]),
		)
		return ""
	}

	logger.Debug("bearer token extracted successfully",
		zap.Int("token_length", len(parts[1])),
	)
	return parts[1]
}

// getTokenPrefix 安全地获取token前缀用于日志
func getTokenPrefix(token string) string {
	if len(token) == 0 {
		return "empty"
	}
	if len(token) <= 10 {
		return token + "..."
	}
	return token[:10] + "..."
}

// GetCurrentUser 从上下文获取当前用户
func GetCurrentUser(c *gin.Context) (*auth.Claims, bool) {
	claims, exists := c.Get(ClaimsContextKey)
	if !exists {
		logger.Debug("get current user: no claims in context")
		return nil, false
	}

	userClaims, ok := claims.(*auth.Claims)
	if !ok {
		logger.Warn("get current user: invalid claims type in context")
		return nil, false
	}

	logger.Debug("get current user: claims retrieved successfully",
		zap.String("user_id", userClaims.UserID.String()),
	)
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
		logger.Debug("require auth: user not authenticated")
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		c.Abort()
		return nil, false
	}
	logger.Debug("require auth: user authentication verified",
		zap.String("user_id", claims.UserID.String()),
	)
	return claims, true
}

// AuthenticatedOnly 仅认证用户可访问的中间件组合
func AuthenticatedOnly() gin.HandlerFunc {
	return Auth()
}
