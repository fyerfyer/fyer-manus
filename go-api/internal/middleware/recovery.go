package middleware

import (
	"net/http"

	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Recovery 返回自定义恢复中间件
func Recovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		logger.Error("panic recovered",
			zap.Any("error", recovered),
			zap.String("path", c.Request.URL.Path),
			zap.String("method", c.Request.Method),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "Internal server error",
		})
	})
}
