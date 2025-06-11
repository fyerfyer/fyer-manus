package router

import (
	"github.com/fyerfyer/fyer-manus/go-api/internal/handler"
	"github.com/fyerfyer/fyer-manus/go-api/internal/middleware"
	"github.com/gin-gonic/gin"
)

func registerSessionRoutes(router *gin.Engine) {
	sessionHandler := handler.NewSessionHandler()
	wsHandler := handler.NewWebSocketHandler()

	// 启动WebSocket管理器
	wsHandler.Start()

	// 会话管理路由组 - 需要认证
	sessions := router.Group("/api/v1/sessions")
	sessions.Use(middleware.Auth())
	{
		// 会话CRUD操作
		sessions.POST("", sessionHandler.CreateSession)
		sessions.GET("", sessionHandler.ListSessions)
		sessions.GET("/:id", sessionHandler.GetSession)
		sessions.PUT("/:id", sessionHandler.UpdateSession)
		sessions.DELETE("/:id", sessionHandler.DeleteSession)
		sessions.POST("/:id/archive", sessionHandler.ArchiveSession)

		// 消息管理
		sessions.POST("/:id/messages", sessionHandler.CreateMessage)
		sessions.GET("/:id/messages", sessionHandler.ListMessages)
		sessions.GET("/:id/context", sessionHandler.GetConversationContext)

		// 消息详情
		sessions.GET("/messages/:messageId", sessionHandler.GetMessage)
	}

	// WebSocket连接路由
	ws := router.Group("/api/v1/ws")
	{
		ws.GET("/chat", wsHandler.HandleWebSocket)
	}

	// WebSocket管理路由 - 需要认证
	wsManagement := router.Group("/api/v1/ws")
	wsManagement.Use(middleware.Auth())
	{
		// 会话WebSocket管理
		wsManagement.POST("/sessions/:sessionId/join", wsHandler.JoinSession)
		wsManagement.POST("/sessions/:sessionId/leave", wsHandler.LeaveSession)

		// 消息广播
		wsManagement.POST("/users/:userId/broadcast", wsHandler.BroadcastToUser)
		wsManagement.POST("/sessions/:sessionId/broadcast", wsHandler.BroadcastToSession)

		// 连接管理
		wsManagement.GET("/users/:userId/clients", wsHandler.GetUserClients)
		wsManagement.POST("/users/:userId/disconnect", wsHandler.DisconnectUser)

		// 健康检查和统计
		wsManagement.GET("/stats", wsHandler.GetStats)
		wsManagement.GET("/health", wsHandler.Health)
	}

	// 用户会话统计 - 需要认证
	userSessions := router.Group("/api/v1/users")
	userSessions.Use(middleware.Auth())
	{
		userSessions.GET("/me/sessions/stats", sessionHandler.GetSessionStats)
	}

	// 管理员路由 - 需要管理员权限
	adminSessions := router.Group("/api/v1/admin/sessions")
	adminSessions.Use(middleware.Auth())
	adminSessions.Use(middleware.RequireAdmin())
	{
		// 搜索所有会话
		adminSessions.GET("", sessionHandler.SearchSessions)

		// WebSocket连接管理
		adminSessions.GET("/ws/stats", wsHandler.GetStats)
		adminSessions.POST("/ws/users/:userId/disconnect", wsHandler.DisconnectUser)
	}
}
