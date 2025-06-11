package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Server struct {
	httpServer *http.Server
	router     *gin.Engine
	config     *config.Config
}

// New 创建新的服务器实例
func New(cfg *config.Config) *Server {
	return &Server{
		config: cfg,
	}
}

// Init 初始化服务器
func (s *Server) Init() error {
	// 设置Gin模式
	gin.SetMode(s.config.Server.Mode)

	// 创建路由
	s.router = gin.New()

	// 添加中间件
	s.setupMiddleware()

	// 设置路由
	s.setupRoutes()

	// 创建HTTP服务器
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port),
		Handler:      s.router,
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
	}

	return nil
}

// setupMiddleware 设置中间件
func (s *Server) setupMiddleware() {
	// Recovery中间件
	s.router.Use(gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		logger.Error("panic recovered",
			zap.Any("error", recovered),
			zap.String("path", c.Request.URL.Path),
			zap.String("method", c.Request.Method),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "Internal server error",
		})
	}))

	// CORS中间件
	s.router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	// 请求日志中间件
	s.router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		logger.Info("request completed",
			zap.String("method", param.Method),
			zap.String("path", param.Path),
			zap.Int("status", param.StatusCode),
			zap.Duration("latency", param.Latency),
			zap.String("ip", param.ClientIP),
		)
		return ""
	}))
}

// setupRoutes 设置路由
func (s *Server) setupRoutes() {
	// 健康检查
	s.router.GET("/health", s.healthHandler)
	s.router.GET("/ready", s.readinessHandler)

	// API路由组
	api := s.router.Group("/api/v1")
	{
		// 基础路由
		api.GET("/ping", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "pong",
				"time":    time.Now().Unix(),
			})
		})

		// TODO: 添加其他业务路由
		// api.POST("/auth/login", authHandler.Login)
		// api.POST("/sessions", sessionHandler.Create)
		// api.POST("/plugins/execute", pluginHandler.Execute)
	}
}

// healthHandler 健康检查处理器
func (s *Server) healthHandler(c *gin.Context) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
		"checks":    make(map[string]string),
	}

	// 检查数据库连接
	if err := database.Health(); err != nil {
		health["checks"].(map[string]string)["database"] = "unhealthy"
		health["status"] = "unhealthy"
		logger.Error("database health check failed", zap.Error(err))
	} else {
		health["checks"].(map[string]string)["database"] = "healthy"
	}

	// 检查Redis连接
	if err := cache.Health(); err != nil {
		health["checks"].(map[string]string)["redis"] = "unhealthy"
		health["status"] = "unhealthy"
		logger.Error("redis health check failed", zap.Error(err))
	} else {
		health["checks"].(map[string]string)["redis"] = "healthy"
	}

	statusCode := http.StatusOK
	if health["status"] == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, health)
}

// readinessHandler 就绪检查处理器
func (s *Server) readinessHandler(c *gin.Context) {
	ready := map[string]interface{}{
		"status":    "ready",
		"timestamp": time.Now().Unix(),
	}

	// 简单的就绪检查
	if database.Get() == nil || cache.Get() == nil {
		ready["status"] = "not ready"
		c.JSON(http.StatusServiceUnavailable, ready)
		return
	}

	c.JSON(http.StatusOK, ready)
}

// Start 启动服务器
func (s *Server) Start() error {
	logger.Info("starting HTTP server",
		zap.String("addr", s.httpServer.Addr),
		zap.String("mode", s.config.Server.Mode),
	)

	// 启动服务器
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("failed to start server", zap.Error(err))
		}
	}()

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")

	// 优雅关闭
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		logger.Error("server forced to shutdown", zap.Error(err))
		return err
	}

	logger.Info("server stopped")
	return nil
}

// Stop 停止服务器
func (s *Server) Stop() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// GetRouter 获取路由器实例
func (s *Server) GetRouter() *gin.Engine {
	return s.router
}
