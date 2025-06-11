package middleware

import (
	"net/http"
	"strings"

	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/monitor"
	"github.com/fyerfyer/fyer-manus/go-api/internal/ratelimit"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RateLimit 限流中间件
func RateLimit() gin.HandlerFunc {
	limiter := ratelimit.NewLimiter()

	return func(c *gin.Context) {
		// 获取客户端标识
		identifier := getClientIdentifier(c)
		if identifier == "" {
			c.Next()
			return
		}

		// 获取请求头信息用于规则匹配
		headers := make(map[string]string)
		for key, values := range c.Request.Header {
			if len(values) > 0 {
				headers[key] = values[0]
			}
		}

		// 检查限流
		result, err := limiter.CheckByPath(
			c.Request.URL.Path,
			c.Request.Method,
			identifier,
			headers,
		)

		if err != nil {
			logger.Error("rate limit check failed",
				zap.Error(err),
				zap.String("path", c.Request.URL.Path),
				zap.String("identifier", identifier),
			)
			c.Next()
			return
		}

		// 设置限流响应头
		setRateLimitHeaders(c, result)

		// 记录限流指标
		monitor.RecordRateLimit("api", result.Allowed)

		if !result.Allowed {
			logger.Warn("rate limit exceeded",
				zap.String("identifier", identifier),
				zap.String("path", c.Request.URL.Path),
				zap.String("method", c.Request.Method),
				zap.Duration("retry_after", result.RetryAfter),
			)

			c.JSON(http.StatusTooManyRequests, gin.H{
				"code":        http.StatusTooManyRequests,
				"message":     "rate limit exceeded",
				"retry_after": int(result.RetryAfter.Seconds()),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitByUser 基于用户的限流中间件
func RateLimitByUser() gin.HandlerFunc {
	limiter := ratelimit.NewLimiter()
	limiter.SetKeyGenerator(&ratelimit.UserKeyGenerator{})

	return func(c *gin.Context) {
		// 需要先经过认证中间件
		claims, ok := GetCurrentUser(c)
		if !ok {
			c.Next()
			return
		}

		identifier := claims.UserID.String()
		headers := make(map[string]string)
		for key, values := range c.Request.Header {
			if len(values) > 0 {
				headers[key] = values[0]
			}
		}

		result, err := limiter.CheckByPath(
			c.Request.URL.Path,
			c.Request.Method,
			identifier,
			headers,
		)

		if err != nil {
			logger.Error("user rate limit check failed",
				zap.Error(err),
				zap.String("user_id", identifier),
			)
			c.Next()
			return
		}

		setRateLimitHeaders(c, result)
		monitor.RecordRateLimit("user", result.Allowed)

		if !result.Allowed {
			logger.Warn("user rate limit exceeded",
				zap.String("user_id", identifier),
				zap.String("path", c.Request.URL.Path),
			)

			c.JSON(http.StatusTooManyRequests, gin.H{
				"code":        http.StatusTooManyRequests,
				"message":     "user rate limit exceeded",
				"retry_after": int(result.RetryAfter.Seconds()),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitByIP IP限流中间件
func RateLimitByIP() gin.HandlerFunc {
	limiter := ratelimit.NewLimiter()
	limiter.SetKeyGenerator(&ratelimit.IPKeyGenerator{})

	return func(c *gin.Context) {
		ip := getClientIP(c)
		if ip == "" {
			c.Next()
			return
		}

		headers := make(map[string]string)
		for key, values := range c.Request.Header {
			if len(values) > 0 {
				headers[key] = values[0]
			}
		}

		result, err := limiter.CheckByPath(
			c.Request.URL.Path,
			c.Request.Method,
			ip,
			headers,
		)

		if err != nil {
			logger.Error("IP rate limit check failed",
				zap.Error(err),
				zap.String("ip", ip),
			)
			c.Next()
			return
		}

		setRateLimitHeaders(c, result)
		monitor.RecordRateLimit("ip", result.Allowed)

		if !result.Allowed {
			logger.Warn("IP rate limit exceeded",
				zap.String("ip", ip),
				zap.String("path", c.Request.URL.Path),
			)

			c.JSON(http.StatusTooManyRequests, gin.H{
				"code":        http.StatusTooManyRequests,
				"message":     "IP rate limit exceeded",
				"retry_after": int(result.RetryAfter.Seconds()),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// getClientIdentifier 获取客户端标识符
func getClientIdentifier(c *gin.Context) string {
	// 优先使用用户ID
	if claims, ok := GetCurrentUser(c); ok {
		return "user:" + claims.UserID.String()
	}

	// 其次使用API Key
	if apiKey := c.GetHeader("X-API-Key"); apiKey != "" {
		return "api:" + apiKey
	}

	// 最后使用IP地址
	if ip := getClientIP(c); ip != "" {
		return "ip:" + ip
	}

	return ""
}

// getClientIP 获取客户端IP地址
func getClientIP(c *gin.Context) string {
	// 优先检查X-Forwarded-For
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For可能包含多个IP，取第一个
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 检查X-Real-IP
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		return xri
	}

	// 使用RemoteAddr
	return c.ClientIP()
}

// setRateLimitHeaders 设置限流相关的响应头
func setRateLimitHeaders(c *gin.Context, result *ratelimit.Result) {
	c.Header("X-RateLimit-Remaining", string(rune(result.Remaining)))
	c.Header("X-RateLimit-Reset", string(rune(result.ResetTime.Unix())))

	if !result.Allowed {
		c.Header("Retry-After", string(rune(int(result.RetryAfter.Seconds()))))
	}
}

// CustomRateLimit 自定义限流中间件
func CustomRateLimit(rule ratelimit.Rule) gin.HandlerFunc {
	limiter := ratelimit.NewLimiter()
	err := limiter.AddRule(rule)
	if err != nil {
		logger.Error("failed to add custom rate limit rule",
			zap.Error(err),
			zap.String("rule_name", rule.Name),
		)
		// 返回空中间件
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		identifier := getClientIdentifier(c)
		if identifier == "" {
			c.Next()
			return
		}

		result, err := limiter.Check(rule, identifier)
		if err != nil {
			logger.Error("custom rate limit check failed",
				zap.Error(err),
				zap.String("rule", rule.Name),
			)
			c.Next()
			return
		}

		setRateLimitHeaders(c, result)
		monitor.RecordRateLimit(rule.Name, result.Allowed)

		if !result.Allowed {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"code":        http.StatusTooManyRequests,
				"message":     "rate limit exceeded",
				"rule":        rule.Name,
				"retry_after": int(result.RetryAfter.Seconds()),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
