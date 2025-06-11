package router

import (
	"github.com/fyerfyer/fyer-manus/go-api/internal/handler"
	"github.com/gin-gonic/gin"
)

func registerHealtRoutes(router *gin.Engine) {
	router.GET("/health", handler.Health)
	router.GET("/ready", handler.Readiness)
}
