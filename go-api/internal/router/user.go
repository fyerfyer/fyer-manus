package router

import (
	"github.com/fyerfyer/fyer-manus/go-api/internal/handler"
	"github.com/fyerfyer/fyer-manus/go-api/internal/middleware"
	"github.com/gin-gonic/gin"
)

func registerUserRoutes(router *gin.Engine) {
	userHandler := handler.NewUserHandler()

	// 用户个人信息管理 - 需要认证
	userProfile := router.Group("/api/v1/users")
	userProfile.Use(middleware.Auth())
	{
		// 获取和更新个人资料
		userProfile.GET("/me", userHandler.GetProfile)
		userProfile.PUT("/me", userHandler.UpdateProfile)

		// 密码管理
		userProfile.PUT("/me/password", userHandler.ChangePassword)
	}

	// 用户管理路由 - 需要用户管理权限
	userManagement := router.Group("/api/v1/users")
	userManagement.Use(middleware.Auth())
	userManagement.Use(middleware.CanManageUser)
	{
		// 用户查询
		userManagement.GET("/:id", userHandler.GetUserByID)
		userManagement.GET("", userHandler.ListUsers)
		userManagement.GET("/search", userHandler.SearchUsers)

		// 用户状态管理
		userManagement.PUT("/:id/status", userHandler.UpdateUserStatus)

		// 用户角色管理
		userManagement.POST("/:id/roles", userHandler.AssignRole)
		userManagement.DELETE("/:id/roles", userHandler.RemoveRole)
		userManagement.GET("/:id/roles", userHandler.GetUserRoles)
	}

	// 管理员专用路由 - 需要管理员权限
	adminUsers := router.Group("/api/v1/admin/users")
	adminUsers.Use(middleware.Auth())
	adminUsers.Use(middleware.RequireAdmin())
	{
		// 用户删除 - 仅管理员
		adminUsers.DELETE("/:id", userHandler.DeleteUser)

		// 用户统计
		adminUsers.GET("/stats", userHandler.GetUserStats)
	}
}
