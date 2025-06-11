package router

import (
	"github.com/fyerfyer/fyer-manus/go-api/internal/handler"
	"github.com/fyerfyer/fyer-manus/go-api/internal/middleware"
	"github.com/gin-gonic/gin"
)

func registerAuthRoutes(router *gin.Engine) {
	authHandler := handler.NewAuthHandler()

	// 认证相关路由组 - 公开访问
	auth := router.Group("/api/v1/auth")
	{
		// 用户注册和登录
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)

		// token管理
		auth.POST("/refresh", authHandler.RefreshToken)
		auth.POST("/validate", authHandler.ValidateToken)
	}

	// 需要认证的认证路由
	authProtected := router.Group("/api/v1/auth")
	authProtected.Use(middleware.Auth())
	{
		// 登出
		authProtected.POST("/logout", authHandler.Logout)

		// 开发调试接口
		authProtected.GET("/test", authHandler.TestAuth)
	}
}
