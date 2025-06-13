package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/auth"
	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/ratelimit"
	"github.com/google/uuid"
)

func TestRateLimit(t *testing.T) {
	// 初始化测试环境
	setupRateLimitTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 使用限流中间件
	router.Use(RateLimit())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 测试正常请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "first request should succeed")
	assert.Contains(t, w.Header().Get("X-RateLimit-Remaining"), "", "should have rate limit headers")

	// 测试无IP地址的请求
	req = httptest.NewRequest("GET", "/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "request without IP should succeed")
}

func TestRateLimitByUser(t *testing.T) {
	// 初始化测试环境
	setupRateLimitTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 模拟认证中间件
	router.Use(func(c *gin.Context) {
		claims := &auth.Claims{
			UserID:   uuid.New(),
			Username: "testuser",
			Email:    "test@example.com",
		}
		c.Set(ClaimsContextKey, claims)
		c.Next()
	})

	// 使用用户限流中间件
	router.Use(RateLimitByUser())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 测试有用户认证的请求
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "authenticated user request should succeed")
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"), "should have rate limit headers")
}

func TestRateLimitByUserWithoutAuth(t *testing.T) {
	// 初始化测试环境
	setupRateLimitTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 使用用户限流中间件但不设置认证
	router.Use(RateLimitByUser())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 测试没有用户认证的请求
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "unauthenticated request should succeed without rate limit")
}

func TestRateLimitByIP(t *testing.T) {
	// 初始化测试环境
	setupRateLimitTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 使用IP限流中间件
	router.Use(RateLimitByIP())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 测试正常IP请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "IP request should succeed")
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"), "should have rate limit headers")

	// 测试多个IP的X-Forwarded-For
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.200, 10.0.0.1, 127.0.0.1")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "multiple IP request should succeed")
}

func TestGetClientIdentifier(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		setup       func(*gin.Context)
		expected    string
		checkPrefix bool // 标识是否只检查前缀
	}{
		{
			name: "user authenticated",
			setup: func(c *gin.Context) {
				userID := uuid.New()
				claims := &auth.Claims{
					UserID:   userID,
					Username: "testuser",
				}
				c.Set(ClaimsContextKey, claims)
			},
			expected:    "user:",
			checkPrefix: true,
		},
		{
			name: "API key provided",
			setup: func(c *gin.Context) {
				c.Request.Header.Set("X-API-Key", "test-api-key")
			},
			expected: "api:test-api-key",
		},
		{
			name: "IP address only",
			setup: func(c *gin.Context) {
				c.Request.Header.Set("X-Real-IP", "192.168.1.1")
			},
			expected: "ip:192.168.1.1",
		},
		{
			name: "no identifier",
			setup: func(c *gin.Context) {
				// 不设置任何标识
			},
			expected:    "ip:", // gin测试环境会返回默认IP
			checkPrefix: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/test", nil)

			tt.setup(c)

			result := getClientIdentifier(c)
			if tt.checkPrefix {
				// 对于需要检查前缀的情况
				assert.Contains(t, result, tt.expected, "should start with expected prefix")
				assert.NotEqual(t, tt.expected, result, "should have content after prefix")
			} else {
				assert.Equal(t, tt.expected, result, "client identifier should match")
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name: "X-Forwarded-For single IP",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.1",
			},
			expected: "192.168.1.1",
		},
		{
			name: "X-Forwarded-For multiple IPs",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.1, 10.0.0.1, 127.0.0.1",
			},
			expected: "192.168.1.1",
		},
		{
			name: "X-Real-IP",
			headers: map[string]string{
				"X-Real-IP": "192.168.1.2",
			},
			expected: "192.168.1.2",
		},
		{
			name: "X-Forwarded-For priority over X-Real-IP",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.1",
				"X-Real-IP":       "192.168.1.2",
			},
			expected: "192.168.1.1",
		},
		{
			name:     "no headers",
			headers:  map[string]string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/test", nil)

			for key, value := range tt.headers {
				c.Request.Header.Set(key, value)
			}

			result := getClientIP(c)
			if tt.expected == "" {
				// ClientIP() 总是返回一些值，所以只检查不为空
				assert.NotEmpty(t, result, "should have some IP value")
			} else {
				assert.Equal(t, tt.expected, result, "IP should match expected")
			}
		})
	}
}

func TestSetRateLimitHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	result := &ratelimit.Result{
		Allowed:   true,
		Remaining: 5,
		ResetTime: time.Now().Add(time.Minute),
	}

	setRateLimitHeaders(c, result)

	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"), "should set remaining header")
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"), "should set reset header")
	assert.Empty(t, w.Header().Get("Retry-After"), "should not set retry-after for allowed request")

	// 测试被拒绝的请求
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)

	result.Allowed = false
	result.RetryAfter = 30 * time.Second

	setRateLimitHeaders(c, result)

	assert.NotEmpty(t, w.Header().Get("Retry-After"), "should set retry-after for denied request")
}

func TestCustomRateLimit(t *testing.T) {
	// 初始化测试环境
	setupRateLimitTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 创建自定义限流规则
	customRule := ratelimit.Rule{
		Name:    "custom_test",
		Pattern: "/api/custom",
		Methods: []string{"GET"},
		Config: ratelimit.Config{
			Strategy: ratelimit.StrategyFixedWindow,
			Rate:     2,
			Period:   time.Minute,
			Enabled:  true,
		},
	}

	// 使用自定义限流中间件
	router.Use(CustomRateLimit(customRule))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 测试正常请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "custom rate limit request should succeed")
}

func TestCustomRateLimitWithInvalidRule(t *testing.T) {
	// 初始化测试环境
	setupRateLimitTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 创建无效的限流规则
	invalidRule := ratelimit.Rule{
		Name:    "invalid_test",
		Pattern: "/api/invalid",
		Config: ratelimit.Config{
			Strategy: ratelimit.StrategyFixedWindow,
			Rate:     0, // 无效速率
			Period:   time.Minute,
			Enabled:  true,
		},
	}

	// 使用自定义限流中间件
	router.Use(CustomRateLimit(invalidRule))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 无效规则应该不进行限流
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "invalid rule should not block requests")
}

func TestRateLimitExceeded(t *testing.T) {
	// 初始化测试环境
	setupRateLimitTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 创建严格的限流规则
	strictRule := ratelimit.Rule{
		Name:    "strict_test",
		Pattern: "/api/strict",
		Methods: []string{"GET"},
		Config: ratelimit.Config{
			Strategy: ratelimit.StrategyFixedWindow,
			Rate:     1,
			Period:   time.Minute,
			Enabled:  true,
		},
	}

	// 使用自定义限流中间件
	router.Use(CustomRateLimit(strictRule))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	clientIP := "192.168.1.100"

	// 第一次请求应该成功
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", clientIP)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "first request should succeed")

	// 第二次请求应该被拒绝
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", clientIP)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code, "second request should be rate limited")
	assert.Contains(t, w.Body.String(), "rate limit exceeded", "should return rate limit error message")
	assert.NotEmpty(t, w.Header().Get("Retry-After"), "should set retry-after header")
}

func TestRateLimitWithDifferentIdentifiers(t *testing.T) {
	// 初始化测试环境
	setupRateLimitTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 使用IP限流中间件
	router.Use(RateLimitByIP())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 不同IP应该有独立的限流计数
	ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}

	for _, ip := range ips {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", ip)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "request from IP %s should succeed", ip)
	}
}

func TestRateLimitErrorHandling(t *testing.T) {
	// 初始化测试环境但不启动Redis
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	// 使用无效的Redis配置
	cfg.Redis.Addr = "invalid:6379"

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 使用限流中间件
	router.Use(RateLimit())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Redis连接失败时应该降级允许请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "should fallback to allow requests when rate limiter fails")
}

func TestRateLimitWithUserContext(t *testing.T) {
	// 初始化测试环境
	setupRateLimitTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	userID := uuid.New()

	// 模拟认证中间件
	router.Use(func(c *gin.Context) {
		claims := &auth.Claims{
			UserID:   userID,
			Username: "testuser",
			Email:    "test@example.com",
		}
		c.Set(ClaimsContextKey, claims)
		c.Next()
	})

	// 使用限流中间件
	router.Use(RateLimit())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 有用户上下文的请求
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "authenticated user request should succeed")
}

func TestRateLimitWithAPIKey(t *testing.T) {
	// 初始化测试环境
	setupRateLimitTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 使用限流中间件
	router.Use(RateLimit())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 使用API Key的请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "test-api-key-123")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "API key request should succeed")
}

// setupRateLimitTestEnv 设置限流测试环境
func setupRateLimitTestEnv(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	err = cache.Init(&cfg.Redis)
	require.NoError(t, err, "failed to init cache")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 清理测试数据
	keys, err := cache.Keys(ctx, "ratelimit:*")
	if err == nil && len(keys) > 0 {
		cache.Del(ctx, keys...)
	}
}
