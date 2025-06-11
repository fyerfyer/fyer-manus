package middleware

import (
	"strings"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/monitor"
	"github.com/gin-gonic/gin"
)

// Metrics 指标收集中间件
func Metrics() gin.HandlerFunc {
	return monitor.MetricsMiddleware()
}

// DetailedMetrics 详细指标收集中间件
func DetailedMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}

		// 记录请求开始
		c.Next()

		// 请求完成后记录指标
		duration := time.Since(start)
		status := c.Writer.Status()
		method := c.Request.Method

		// 记录HTTP指标
		monitor.RecordDBQuery(method, duration)

		// 记录认证指标
		if isAuthEndpoint(path) {
			success := status >= 200 && status < 300
			monitor.RecordAuthentication(success)

			if success && (method == "POST" && path == "/api/v1/auth/login") {
				monitor.RecordTokenGeneration()
			}
		}

		// 记录业务指标
		recordBusinessMetrics(c, path, method, status)

		// 记录用户活动
		if claims, ok := GetCurrentUser(c); ok {
			recordUserActivity(claims.UserID.String(), path, method)
		}
	}
}

// AuthMetrics 认证相关指标中间件
func AuthMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.FullPath()
		method := c.Request.Method

		c.Next()

		status := c.Writer.Status()

		// 只记录认证相关端点
		if isAuthEndpoint(path) {
			success := status >= 200 && status < 300
			monitor.RecordAuthentication(success)

			// 记录token生成
			if success && method == "POST" {
				switch path {
				case "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/refresh":
					monitor.RecordTokenGeneration()
				}
			}
		}
	}
}

// UserActivityMetrics 用户活动指标中间件
func UserActivityMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// 只有认证用户才记录活动
		if claims, ok := GetCurrentUser(c); ok {
			path := c.FullPath()
			method := c.Request.Method
			status := c.Writer.Status()

			// 记录用户活动
			recordUserActivity(claims.UserID.String(), path, method)

			// 记录成功的API调用
			if status >= 200 && status < 300 {
				recordAPIUsage(claims.UserID.String(), path, method)
			}
		}
	}
}

// DatabaseMetrics 数据库操作指标中间件
func DatabaseMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start)
		path := c.FullPath()
		method := c.Request.Method

		// 根据HTTP方法推断数据库操作类型
		var operation string
		switch method {
		case "GET":
			operation = "select"
		case "POST":
			operation = "insert"
		case "PUT", "PATCH":
			operation = "update"
		case "DELETE":
			operation = "delete"
		default:
			operation = "unknown"
		}

		// 记录数据库查询指标
		monitor.RecordDBQuery(operation, duration)

		// 记录慢查询
		if duration > 500*time.Millisecond {
			recordSlowQuery(path, method, duration)
		}
	}
}

// isAuthEndpoint 检查是否为认证端点
func isAuthEndpoint(path string) bool {
	authPaths := []string{
		"/api/v1/auth/login",
		"/api/v1/auth/register",
		"/api/v1/auth/logout",
		"/api/v1/auth/refresh",
		"/api/v1/auth/validate",
	}

	for _, authPath := range authPaths {
		if path == authPath {
			return true
		}
	}
	return false
}

// recordBusinessMetrics 记录业务指标
func recordBusinessMetrics(c *gin.Context, path, method string, status int) {
	// 记录聊天相关指标
	if isChatEndpoint(path) && status >= 200 && status < 300 {
		switch method {
		case "POST":
			if path == "/api/v1/sessions" {
				// 新会话创建
				recordSessionCreation()
			} else if strings.Contains(path, "/messages") {
				// 消息发送
				recordMessageSent()
			}
		}
	}

	// 记录插件相关指标
	if isPluginEndpoint(path) && status >= 200 && status < 300 {
		if method == "POST" && strings.Contains(path, "/execute") {
			recordPluginExecution(extractPluginName(path))
		}
	}
}

// recordUserActivity 记录用户活动
func recordUserActivity(userID, path, method string) {
	// TODO: 扩展更详细的用户行为分析
	// 例如：活跃时间、使用频率、功能偏好等
}

// recordAPIUsage 记录API使用情况
func recordAPIUsage(userID, path, method string) {
	// TODO: 记录用户API使用统计
}

// recordSlowQuery 记录慢查询
func recordSlowQuery(path, method string, duration time.Duration) {
	// TODO: 记录慢查询日志，用于性能优化
}

// recordSessionCreation 记录会话创建
func recordSessionCreation() {
	// TODO: 记录会话创建指标
}

// recordMessageSent 记录消息发送
func recordMessageSent() {
	monitor.RecordMessage("user")
}

// recordPluginExecution 记录插件执行
func recordPluginExecution(pluginName string) {
	// TODO: 扩展记录具体插件的使用统计
}

// isChatEndpoint 检查是否为聊天端点
func isChatEndpoint(path string) bool {
	return strings.HasPrefix(path, "/api/v1/sessions") ||
		strings.HasPrefix(path, "/api/v1/chat")
}

// isPluginEndpoint 检查是否为插件端点
func isPluginEndpoint(path string) bool {
	return strings.HasPrefix(path, "/api/v1/plugins")
}

// extractPluginName 从路径中提取插件名称
func extractPluginName(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "plugins" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return "unknown"
}

// CustomMetrics 自定义指标中间件
func CustomMetrics(metricName string, labelExtractor func(*gin.Context) map[string]string) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start)
		labels := labelExtractor(c)

		// TODO: 扩展自定义指标记录逻辑
		_ = metricName
		_ = labels
		_ = duration
	}
}
