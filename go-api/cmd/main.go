package main

import (
	"log"
	"os"

	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/server"
	"go.uber.org/zap"
)

func main() {
	// 加载配置
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 初始化日志系统
	if err := logger.Init(&cfg.Log); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() {
		if err := logger.Sync(); err != nil {
			log.Printf("Failed to sync logger: %v", err)
		}
	}()

	logger.Info("Starting AI Agent API Server")
	logger.Info("Configuration loaded successfully")

	// 初始化数据库
	if err := database.Init(&cfg.Database); err != nil {
		logger.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer func() {
		if err := database.Close(); err != nil {
			logger.Error("Failed to close database connection", zap.Error(err))
		}
	}()

	// 初始化Redis
	if err := cache.Init(&cfg.Redis); err != nil {
		logger.Fatal("Failed to initialize cache", zap.Error(err))
	}
	defer func() {
		if err := cache.Close(); err != nil {
			logger.Error("Failed to close cache connection", zap.Error(err))
		}
	}()

	// 创建并初始化服务器
	srv := server.New(cfg)
	if err := srv.Init(); err != nil {
		logger.Fatal("Failed to initialize server", zap.Error(err))
	}

	// 启动服务器
	if err := srv.Start(); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}

	logger.Info("AI Agent API Server stopped")
	os.Exit(0)
}
