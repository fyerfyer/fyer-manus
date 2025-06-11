package handler

import (
	"net/http"

	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/middleware"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AuthHandler 认证处理器
type AuthHandler struct {
	authService *service.AuthService
}

// NewAuthHandler 创建认证处理器
func NewAuthHandler() *AuthHandler {
	return &AuthHandler{
		authService: service.NewAuthService(),
	}
}

// Register 用户注册
func (h *AuthHandler) Register(c *gin.Context) {
	var req service.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("invalid register request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	response, err := h.authService.Register(req)
	if err != nil {
		logger.Error("user registration failed",
			zap.Error(err),
			zap.String("username", req.Username),
			zap.String("email", req.Email),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	logger.Info("user registered successfully",
		zap.String("username", req.Username),
		zap.String("user_id", response.User.ID.String()),
	)

	c.JSON(http.StatusCreated, gin.H{
		"code":    http.StatusCreated,
		"message": "user registered successfully",
		"data":    response,
	})
}

// Login 用户登录
func (h *AuthHandler) Login(c *gin.Context) {
	var req service.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("invalid login request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	response, err := h.authService.Login(req)
	if err != nil {
		logger.Warn("user login failed",
			zap.Error(err),
			zap.String("username", req.Username),
		)
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": err.Error(),
		})
		return
	}

	logger.Info("user logged in successfully",
		zap.String("username", req.Username),
		zap.String("user_id", response.User.ID.String()),
	)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "login successful",
		"data":    response,
	})
}

// RefreshToken 刷新令牌
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req service.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("invalid refresh token request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	response, err := h.authService.RefreshToken(req)
	if err != nil {
		logger.Warn("token refresh failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": err.Error(),
		})
		return
	}

	logger.Debug("token refreshed successfully",
		zap.String("user_id", response.User.ID.String()),
	)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "token refreshed successfully",
		"data":    response,
	})
}

// Logout 用户登出
func (h *AuthHandler) Logout(c *gin.Context) {
	// 从请求头获取tokens
	authHeader := c.GetHeader("Authorization")
	accessToken := ""
	if authHeader != "" {
		accessToken = authHeader[7:] // 移除 "Bearer " 前缀
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	c.ShouldBindJSON(&req)

	// 将tokens加入黑名单
	if err := h.authService.Logout(accessToken, req.RefreshToken); err != nil {
		logger.Error("logout failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": "logout failed",
		})
		return
	}

	// 记录登出用户信息
	if claims, ok := middleware.GetCurrentUser(c); ok {
		logger.Info("user logged out",
			zap.String("user_id", claims.UserID.String()),
			zap.String("username", claims.Username),
		)
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "logged out successfully",
	})
}

// GetProfile 获取用户信息
func (h *AuthHandler) GetProfile(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	profile, err := h.authService.GetUserInfo(claims.UserID)
	if err != nil {
		logger.Error("failed to get user profile",
			zap.Error(err),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": "failed to get user profile",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "profile retrieved successfully",
		"data":    profile,
	})
}

// ChangePassword 修改密码
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("invalid change password request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	err := h.authService.ChangePassword(claims.UserID, req.OldPassword, req.NewPassword)
	if err != nil {
		logger.Warn("password change failed",
			zap.Error(err),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	logger.Info("password changed successfully",
		zap.String("user_id", claims.UserID.String()),
	)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "password changed successfully",
	})
}

// ValidateToken 验证令牌
func (h *AuthHandler) ValidateToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "authorization header required",
		})
		return
	}

	token := authHeader[7:] // 移除 "Bearer " 前缀
	claims, err := h.authService.ValidateToken(token)
	if err != nil {
		logger.Debug("token validation failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "invalid token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "token is valid",
		"data": gin.H{
			"user_id":     claims.UserID,
			"username":    claims.Username,
			"email":       claims.Email,
			"roles":       claims.Roles,
			"permissions": claims.Permissions,
			"expires_at":  claims.ExpiresAt.Time,
		},
	})
}

// GetUserByID 根据ID获取用户信息（管理员功能）
func (h *AuthHandler) GetUserByID(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid user ID format",
		})
		return
	}

	profile, err := h.authService.GetUserInfo(userID)
	if err != nil {
		logger.Error("failed to get user by ID",
			zap.Error(err),
			zap.String("target_user_id", userID.String()),
		)
		c.JSON(http.StatusNotFound, gin.H{
			"code":    http.StatusNotFound,
			"message": "user not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "user retrieved successfully",
		"data":    profile,
	})
}

// TestAuth 测试认证状态（开发调试用）
func (h *AuthHandler) TestAuth(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "not authenticated",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "authentication successful",
		"data": gin.H{
			"user_id":     claims.UserID,
			"username":    claims.Username,
			"email":       claims.Email,
			"roles":       claims.Roles,
			"permissions": claims.Permissions,
			"token_type":  claims.TokenType,
		},
	})
}
