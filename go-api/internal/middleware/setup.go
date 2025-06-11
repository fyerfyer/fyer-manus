package middleware

import "github.com/gin-gonic/gin"

func Setup(gin *gin.Engine) {
	// 添加日志中间件
	gin.Use(Logger())

	// 添加恢复中间件
	gin.Use(Recovery())

	// 添加跨域中间件
	gin.Use(CORS())
}
