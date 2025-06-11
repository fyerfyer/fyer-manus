package middleware

import (
	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Logger 返回请求日志中间件
func Logger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		logger.Info("request completed",
			zap.String("method", param.Method),
			zap.String("path", param.Path),
			zap.Int("status", param.StatusCode),
			zap.Duration("latency", param.Latency),
			zap.String("ip", param.ClientIP),
		)
		return ""
	})
}
