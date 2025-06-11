package router

import (
	"github.com/fyerfyer/fyer-manus/go-api/internal/handler"
	"github.com/fyerfyer/fyer-manus/go-api/internal/middleware"
	"github.com/gin-gonic/gin"
)

func registerAuthRoutes(router *gin.Engine) {
	authHandler := handler.NewAuthHandler()

	// 认证相关路由组
	auth := router.Group("/api/v1/auth")
	{
		// 公开路由（无需认证）
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/refresh", authHandler.RefreshToken)
		auth.POST("/validate", authHandler.ValidateToken)
	}

	// 需要认证的路由组
	authProtected := router.Group("/api/v1/auth")
	authProtected.Use(middleware.Auth())
	{
		// 用户自己的操作
		authProtected.POST("/logout", authHandler.Logout)
		authProtected.GET("/profile", authHandler.GetProfile)
		authProtected.PUT("/password", authHandler.ChangePassword)
		authProtected.GET("/test", authHandler.TestAuth) // 开发调试用
	}

	// 管理员路由组
	adminAuth := router.Group("/api/v1/admin/users")
	adminAuth.Use(middleware.Auth())
	adminAuth.Use(middleware.RequireAdmin())
	{
		// 管理员操作
		adminAuth.GET("/:id", authHandler.GetUserByID)
	}

	// 用户管理路由组（更细粒度的权限控制）
	userMgmt := router.Group("/api/v1/users")
	userMgmt.Use(middleware.Auth())
	{
		// 获取自己的信息
		userMgmt.GET("/me", authHandler.GetProfile)

		// 修改自己的密码
		userMgmt.PUT("/me/password", authHandler.ChangePassword)

		// 需要用户管理权限的操作
		userMgmt.GET("/:id", middleware.CanManageUser, authHandler.GetUserByID)
	}
}
