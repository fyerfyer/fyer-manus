package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/monitor"
	"github.com/gin-gonic/gin"
)

var healthChecker *monitor.HealthChecker

// init 初始化健康检查器
func init() {
	healthChecker = monitor.NewHealthChecker()

	// 启动定期健康检查（可选）
	healthChecker.StartPeriodicCheck(30 * time.Second)
}

// Health 完整健康检查处理器
func Health(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	health := healthChecker.Check(ctx)

	statusCode := http.StatusOK
	if health.Status != monitor.HealthStatusHealthy {
		statusCode = http.StatusServiceUnavailable
	}

	// 设置响应头
	c.Header("Content-Type", "application/json")

	// 对于 HEAD 请求，只返回状态码和响应头，不返回响应体
	if c.Request.Method == http.MethodHead {
		c.Status(statusCode)
		return
	}

	c.JSON(statusCode, health)
}

// Readiness 就绪检查处理器（快速检查）
func Readiness(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	health := healthChecker.QuickCheck(ctx)

	statusCode := http.StatusOK
	if health.Status != monitor.HealthStatusHealthy {
		statusCode = http.StatusServiceUnavailable
	}

	// 设置响应头
	c.Header("Content-Type", "application/json")

	// 对于 HEAD 请求，只返回状态码和响应头，不返回响应体
	if c.Request.Method == http.MethodHead {
		c.Status(statusCode)
		return
	}

	c.JSON(statusCode, health)
}

// Liveness 存活检查处理器（最简单检查）
func Liveness(c *gin.Context) {
	response := gin.H{
		"status":    "alive",
		"timestamp": time.Now().Unix(),
		"uptime":    healthChecker.GetUptime().Seconds(),
	}

	// 设置响应头
	c.Header("Content-Type", "application/json")

	// 对于 HEAD 请求，只返回状态码和响应头，不返回响应体
	if c.Request.Method == http.MethodHead {
		c.Status(http.StatusOK)
		return
	}

	c.JSON(http.StatusOK, response)
}

// ComponentHealth 单个组件健康检查
func ComponentHealth(c *gin.Context) {
	componentName := c.Param("component")

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	health, err := healthChecker.GetComponentHealth(ctx, componentName)
	if err != nil {
		errorResponse := gin.H{
			"code":      http.StatusNotFound,
			"message":   "component not found",
			"component": componentName,
		}

		// 设置响应头
		c.Header("Content-Type", "application/json")

		// 对于 HEAD 请求，只返回状态码和响应头，不返回响应体
		if c.Request.Method == http.MethodHead {
			c.Status(http.StatusNotFound)
			return
		}

		c.JSON(http.StatusNotFound, errorResponse)
		return
	}

	statusCode := http.StatusOK
	if health.Status != monitor.HealthStatusHealthy {
		statusCode = http.StatusServiceUnavailable
	}

	// 设置响应头
	c.Header("Content-Type", "application/json")

	// 对于 HEAD 请求，只返回状态码和响应头，不返回响应体
	if c.Request.Method == http.MethodHead {
		c.Status(statusCode)
		return
	}

	c.JSON(statusCode, health)
}
