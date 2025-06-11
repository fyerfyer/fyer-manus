package middleware

import (
	"net/http"

	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RequirePermission 需要指定权限的中间件
func RequirePermission(permission string) gin.HandlerFunc {
	authService := service.NewAuthService()
	validator := authService.GetValidator()

	return func(c *gin.Context) {
		claims, ok := GetCurrentUser(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "authentication required",
			})
			c.Abort()
			return
		}

		if !validator.ValidatePermission(claims, permission) {
			logger.Warn("permission denied",
				zap.String("user_id", claims.UserID.String()),
				zap.String("required_permission", permission),
				zap.Strings("user_permissions", claims.Permissions),
			)
			c.JSON(http.StatusForbidden, gin.H{
				"code":    http.StatusForbidden,
				"message": "insufficient permissions",
			})
			c.Abort()
			return
		}

		logger.Debug("permission granted",
			zap.String("user_id", claims.UserID.String()),
			zap.String("permission", permission),
		)

		c.Next()
	}
}

// RequireRole 需要指定角色的中间件
func RequireRole(role string) gin.HandlerFunc {
	authService := service.NewAuthService()
	validator := authService.GetValidator()

	return func(c *gin.Context) {
		claims, ok := GetCurrentUser(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "authentication required",
			})
			c.Abort()
			return
		}

		if !validator.ValidateRole(claims, role) {
			logger.Warn("role access denied",
				zap.String("user_id", claims.UserID.String()),
				zap.String("required_role", role),
				zap.Strings("user_roles", claims.Roles),
			)
			c.JSON(http.StatusForbidden, gin.H{
				"code":    http.StatusForbidden,
				"message": "insufficient role privileges",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyPermission 需要任一权限的中间件（OR关系）
func RequireAnyPermission(permissions []string) gin.HandlerFunc {
	authService := service.NewAuthService()
	validator := authService.GetValidator()

	return func(c *gin.Context) {
		claims, ok := GetCurrentUser(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "authentication required",
			})
			c.Abort()
			return
		}

		if !validator.ValidateAnyPermission(claims, permissions) {
			logger.Warn("permissions denied",
				zap.String("user_id", claims.UserID.String()),
				zap.Strings("required_permissions", permissions),
				zap.Strings("user_permissions", claims.Permissions),
			)
			c.JSON(http.StatusForbidden, gin.H{
				"code":    http.StatusForbidden,
				"message": "insufficient permissions",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAllPermissions 需要所有权限的中间件（AND关系）
func RequireAllPermissions(permissions []string) gin.HandlerFunc {
	authService := service.NewAuthService()
	validator := authService.GetValidator()

	return func(c *gin.Context) {
		claims, ok := GetCurrentUser(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "authentication required",
			})
			c.Abort()
			return
		}

		if !validator.ValidatePermissions(claims, permissions) {
			logger.Warn("multiple permissions denied",
				zap.String("user_id", claims.UserID.String()),
				zap.Strings("required_permissions", permissions),
				zap.Strings("user_permissions", claims.Permissions),
			)
			c.JSON(http.StatusForbidden, gin.H{
				"code":    http.StatusForbidden,
				"message": "insufficient permissions",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAdmin 需要管理员权限的中间件
func RequireAdmin() gin.HandlerFunc {
	return RequireRole(model.RoleAdmin)
}

// RequireOwnerOrAdmin 需要资源所有者或管理员权限的中间件
func RequireOwnerOrAdmin(getResourceOwnerID func(*gin.Context) (string, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := GetCurrentUser(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "authentication required",
			})
			c.Abort()
			return
		}

		// 检查是否为管理员
		if claims.IsAdmin() {
			c.Next()
			return
		}

		// 检查是否为资源所有者
		ownerID, err := getResourceOwnerID(c)
		if err != nil {
			logger.Error("failed to get resource owner",
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

		if claims.UserID.String() != ownerID {
			logger.Warn("ownership access denied",
				zap.String("user_id", claims.UserID.String()),
				zap.String("resource_owner", ownerID),
			)
			c.JSON(http.StatusForbidden, gin.H{
				"code":    http.StatusForbidden,
				"message": "access denied",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// CheckPermissionDynamic 动态权限检查
func CheckPermissionDynamic(getPermission func(*gin.Context) string) gin.HandlerFunc {
	authService := service.NewAuthService()
	validator := authService.GetValidator()

	return func(c *gin.Context) {
		claims, ok := GetCurrentUser(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "authentication required",
			})
			c.Abort()
			return
		}

		permission := getPermission(c)
		if permission == "" {
			c.Next()
			return
		}

		if !validator.ValidatePermission(claims, permission) {
			logger.Warn("dynamic permission denied",
				zap.String("user_id", claims.UserID.String()),
				zap.String("required_permission", permission),
			)
			c.JSON(http.StatusForbidden, gin.H{
				"code":    http.StatusForbidden,
				"message": "insufficient permissions",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// 预定义的权限中间件
var (
	// 聊天相关权限
	CanCreateChat = RequirePermission(model.PermissionChatCreate)
	CanReadChat   = RequirePermission(model.PermissionChatRead)
	CanUpdateChat = RequirePermission(model.PermissionChatUpdate)
	CanDeleteChat = RequirePermission(model.PermissionChatDelete)

	// 插件相关权限
	CanExecutePlugin = RequirePermission(model.PermissionPluginExecute)

	// 用户管理权限
	CanManageUser = RequirePermission(model.PermissionUserManage)

	// 系统管理员权限
	SystemAdmin = RequirePermission(model.PermissionSystemAdmin)
)

// 便捷的权限组合中间件
func ChatFullAccess() gin.HandlerFunc {
	return RequireAllPermissions([]string{
		model.PermissionChatCreate,
		model.PermissionChatRead,
		model.PermissionChatUpdate,
		model.PermissionChatDelete,
	})
}

func ChatReadOnly() gin.HandlerFunc {
	return RequirePermission(model.PermissionChatRead)
}

func PluginUser() gin.HandlerFunc {
	return RequireAnyPermission([]string{
		model.PermissionPluginExecute,
		model.PermissionSystemAdmin,
	})
}

// BuildResourceOwnerChecker 构建资源所有者检查函数
func BuildResourceOwnerChecker(paramName string) func(*gin.Context) (string, error) {
	return func(c *gin.Context) (string, error) {
		resourceID := c.Param(paramName)
		if resourceID == "" {
			return "", nil
		}

		// 这里应该根据实际业务逻辑查询资源所有者
		// 示例：从数据库查询会话所有者
		// 实际实现时需要注入相应的服务
		return resourceID, nil
	}
}

// ParsePermissionFromPath 从路径解析权限
func ParsePermissionFromPath(c *gin.Context) string {
	path := c.Request.URL.Path
	method := c.Request.Method

	// 简单的路径到权限映射
	switch {
	case containsPath(path, "/chat"):
		switch method {
		case "GET":
			return model.PermissionChatRead
		case "POST":
			return model.PermissionChatCreate
		case "PUT", "PATCH":
			return model.PermissionChatUpdate
		case "DELETE":
			return model.PermissionChatDelete
		}
	case containsPath(path, "/plugin"):
		return model.PermissionPluginExecute
	case containsPath(path, "/admin"):
		return model.PermissionSystemAdmin
	}

	return ""
}

// containsPath 检查路径是否包含指定字符串
func containsPath(path, substr string) bool {
	return len(path) >= len(substr) &&
		(path == substr ||
			(len(path) > len(substr) && path[:len(substr)] == substr && path[len(substr)] == '/'))
}
