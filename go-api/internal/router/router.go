package router

import (
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/middleware"
	"github.com/gin-gonic/gin"
)

// Setup 创建并配置路由器
func Setup(cfg *config.Config) *gin.Engine {
	// 设置Gin模式
	gin.SetMode(cfg.Server.Mode)

	// 创建路由器
	router := gin.New()

	// 添加中间件
	middleware.Setup(router)

	// 注册路由
	registerHealtRoutes(router)
	registerAuthRoutes(router)
	registerUserRoutes(router)
	registerSessionRoutes(router)

	return router
}
