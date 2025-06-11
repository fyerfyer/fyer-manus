package handler

import (
	"net/http"
	"strconv"

	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/middleware"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// UserHandler 用户处理器
type UserHandler struct {
	userService *service.UserService
}

// NewUserHandler 创建用户处理器
func NewUserHandler() *UserHandler {
	return &UserHandler{
		userService: service.NewUserService(),
	}
}

// GetProfile 获取用户资料
func (h *UserHandler) GetProfile(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	profile, err := h.userService.GetUserByID(c.Request.Context(), claims.UserID)
	if err != nil {
		logger.Error("failed to get user profile",
			zap.Error(err),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "profile retrieved successfully",
		"data":    profile,
	})
}

// UpdateProfile 更新用户资料
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	var req service.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("invalid update profile request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	profile, err := h.userService.UpdateUser(c.Request.Context(), claims.UserID, req)
	if err != nil {
		logger.Error("failed to update user profile",
			zap.Error(err),
			zap.String("user_id", claims.UserID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	logger.Info("user profile updated successfully",
		zap.String("user_id", claims.UserID.String()),
	)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "profile updated successfully",
		"data":    profile,
	})
}

// ChangePassword 修改密码
func (h *UserHandler) ChangePassword(c *gin.Context) {
	claims, ok := middleware.GetCurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    http.StatusUnauthorized,
			"message": "authentication required",
		})
		return
	}

	var req service.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("invalid change password request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	err := h.userService.ChangePassword(c.Request.Context(), claims.UserID, req)
	if err != nil {
		logger.Error("failed to change password",
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

// GetUserByID 根据ID获取用户信息（管理员）
func (h *UserHandler) GetUserByID(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid user ID format",
		})
		return
	}

	profile, err := h.userService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		logger.Error("failed to get user by ID",
			zap.Error(err),
			zap.String("target_user_id", userID.String()),
		)
		c.JSON(http.StatusNotFound, gin.H{
			"code":    http.StatusNotFound,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "user retrieved successfully",
		"data":    profile,
	})
}

// ListUsers 获取用户列表（管理员）
func (h *UserHandler) ListUsers(c *gin.Context) {
	page := 1
	pageSize := 20

	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if sizeStr := c.Query("page_size"); sizeStr != "" {
		if s, err := strconv.Atoi(sizeStr); err == nil && s > 0 && s <= 100 {
			pageSize = s
		}
	}

	users, total, err := h.userService.ListUsers(c.Request.Context(), page, pageSize)
	if err != nil {
		logger.Error("failed to list users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	totalPage := (total + int64(pageSize) - 1) / int64(pageSize)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "users retrieved successfully",
		"data":    users,
		"pagination": gin.H{
			"page":       page,
			"page_size":  pageSize,
			"total":      total,
			"total_page": totalPage,
		},
	})
}

// SearchUsers 搜索用户（管理员）
func (h *UserHandler) SearchUsers(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "search query is required",
		})
		return
	}

	page := 1
	pageSize := 20

	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if sizeStr := c.Query("page_size"); sizeStr != "" {
		if s, err := strconv.Atoi(sizeStr); err == nil && s > 0 && s <= 100 {
			pageSize = s
		}
	}

	users, total, err := h.userService.SearchUsers(c.Request.Context(), query, page, pageSize)
	if err != nil {
		logger.Error("failed to search users",
			zap.Error(err),
			zap.String("query", query),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	totalPage := (total + int64(pageSize) - 1) / int64(pageSize)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "users search completed successfully",
		"data":    users,
		"pagination": gin.H{
			"page":       page,
			"page_size":  pageSize,
			"total":      total,
			"total_page": totalPage,
		},
	})
}

// UpdateUserStatus 更新用户状态（管理员）
func (h *UserHandler) UpdateUserStatus(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid user ID format",
		})
		return
	}

	var req struct {
		Status string `json:"status" binding:"required,oneof=active inactive suspended"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("invalid update user status request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	err = h.userService.UpdateUserStatus(c.Request.Context(), userID, model.UserStatus(req.Status))
	if err != nil {
		logger.Error("failed to update user status",
			zap.Error(err),
			zap.String("target_user_id", userID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	logger.Info("user status updated successfully",
		zap.String("target_user_id", userID.String()),
		zap.String("status", req.Status),
	)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "user status updated successfully",
	})
}

// AssignRole 分配角色（管理员）
func (h *UserHandler) AssignRole(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid user ID format",
		})
		return
	}

	var req struct {
		RoleID uuid.UUID `json:"role_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("invalid assign role request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	err = h.userService.AssignRole(c.Request.Context(), userID, req.RoleID)
	if err != nil {
		logger.Error("failed to assign role",
			zap.Error(err),
			zap.String("user_id", userID.String()),
			zap.String("role_id", req.RoleID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	logger.Info("role assigned successfully",
		zap.String("user_id", userID.String()),
		zap.String("role_id", req.RoleID.String()),
	)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "role assigned successfully",
	})
}

// RemoveRole 移除角色（管理员）
func (h *UserHandler) RemoveRole(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid user ID format",
		})
		return
	}

	var req struct {
		RoleID uuid.UUID `json:"role_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("invalid remove role request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid request format",
			"details": err.Error(),
		})
		return
	}

	err = h.userService.RemoveRole(c.Request.Context(), userID, req.RoleID)
	if err != nil {
		logger.Error("failed to remove role",
			zap.Error(err),
			zap.String("user_id", userID.String()),
			zap.String("role_id", req.RoleID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	logger.Info("role removed successfully",
		zap.String("user_id", userID.String()),
		zap.String("role_id", req.RoleID.String()),
	)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "role removed successfully",
	})
}

// GetUserRoles 获取用户角色（管理员）
func (h *UserHandler) GetUserRoles(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid user ID format",
		})
		return
	}

	roles, err := h.userService.GetUserRoles(c.Request.Context(), userID)
	if err != nil {
		logger.Error("failed to get user roles",
			zap.Error(err),
			zap.String("user_id", userID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "user roles retrieved successfully",
		"data":    roles,
	})
}

// DeleteUser 删除用户（管理员）
func (h *UserHandler) DeleteUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": "invalid user ID format",
		})
		return
	}

	err = h.userService.DeleteUser(c.Request.Context(), userID)
	if err != nil {
		logger.Error("failed to delete user",
			zap.Error(err),
			zap.String("user_id", userID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	logger.Info("user deleted successfully",
		zap.String("user_id", userID.String()),
	)

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "user deleted successfully",
	})
}

// GetUserStats 获取用户统计信息
func (h *UserHandler) GetUserStats(c *gin.Context) {
	stats, err := h.userService.GetUserStats(c.Request.Context())
	if err != nil {
		logger.Error("failed to get user stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "user stats retrieved successfully",
		"data":    stats,
	})
}
