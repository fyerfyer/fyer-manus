package handler

import (
	"net/http"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Health 健康检查处理器
func Health(c *gin.Context) {
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

// Readiness 就绪检查处理器
func Readiness(c *gin.Context) {
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
