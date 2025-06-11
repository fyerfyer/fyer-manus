package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/router"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Server 表示HTTP服务器
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
	// 设置路由器
	s.router = router.Setup(s.config)

	// 创建HTTP服务器
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port),
		Handler:      s.router,
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
	}

	return nil
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
