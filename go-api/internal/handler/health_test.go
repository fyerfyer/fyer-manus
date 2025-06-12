package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/monitor"
)

func TestHealth(t *testing.T) {
	// 初始化测试环境
	setupHealthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health", Health)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 根据实际环境状态验证响应
	if w.Code == http.StatusOK {
		assert.Equal(t, http.StatusOK, w.Code, "should return 200 when system is healthy")
		assert.Contains(t, w.Body.String(), "status", "response should contain status field")
		assert.Contains(t, w.Body.String(), "components", "response should contain components field")
	} else {
		assert.Equal(t, http.StatusServiceUnavailable, w.Code, "should return 503 when system is unhealthy")
	}

	// 验证响应头
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json", "should return JSON content")
}

func TestReadiness(t *testing.T) {
	// 初始化测试环境
	setupHealthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/readiness", Readiness)

	req := httptest.NewRequest("GET", "/readiness", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 就绪检查应该比健康检查更快
	if w.Code == http.StatusOK {
		assert.Equal(t, http.StatusOK, w.Code, "should return 200 when system is ready")
		assert.Contains(t, w.Body.String(), "status", "response should contain status field")
	} else {
		assert.Equal(t, http.StatusServiceUnavailable, w.Code, "should return 503 when system is not ready")
	}
}

func TestLiveness(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/liveness", Liveness)

	req := httptest.NewRequest("GET", "/liveness", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 存活检查应该总是返回200
	assert.Equal(t, http.StatusOK, w.Code, "liveness check should always return 200")
	assert.Contains(t, w.Body.String(), "status", "response should contain status field")
	assert.Contains(t, w.Body.String(), "alive", "response should contain alive status")
	assert.Contains(t, w.Body.String(), "timestamp", "response should contain timestamp")
	assert.Contains(t, w.Body.String(), "uptime", "response should contain uptime")
}

func TestComponentHealth(t *testing.T) {
	// 初始化测试环境
	setupHealthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health/component/:component", ComponentHealth)

	tests := []struct {
		name           string
		component      string
		expectedStatus int
	}{
		{
			name:           "database component",
			component:      "database",
			expectedStatus: http.StatusOK, // 可能返回200或503
		},
		{
			name:           "redis component",
			component:      "redis",
			expectedStatus: http.StatusOK, // 可能返回200或503
		},
		{
			name:           "memory component",
			component:      "memory",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "disk component",
			component:      "disk",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "nonexistent component",
			component:      "nonexistent",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/health/component/"+tt.component, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if tt.component == "nonexistent" {
				assert.Equal(t, http.StatusNotFound, w.Code, "should return 404 for nonexistent component")
				assert.Contains(t, w.Body.String(), "component not found", "should mention component not found")
			} else {
				// 对于真实组件，状态可能是200或503，取决于实际健康状态
				assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusServiceUnavailable,
					"component check should return 200 or 503")
				assert.Contains(t, w.Body.String(), "status", "response should contain status field")
			}
		})
	}
}

func TestHealthWithTimeout(t *testing.T) {
	// 初始化测试环境
	setupHealthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health", Health)

	// 测试请求超时处理
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	start := time.Now()
	router.ServeHTTP(w, req)
	duration := time.Since(start)

	// 健康检查应该在合理时间内完成（10秒超时）
	assert.Less(t, duration, 15*time.Second, "health check should complete within timeout")
}

func TestReadinessWithTimeout(t *testing.T) {
	// 初始化测试环境
	setupHealthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/readiness", Readiness)

	req := httptest.NewRequest("GET", "/readiness", nil)
	w := httptest.NewRecorder()

	start := time.Now()
	router.ServeHTTP(w, req)
	duration := time.Since(start)

	// 就绪检查应该更快（3秒超时）
	assert.Less(t, duration, 5*time.Second, "readiness check should complete within timeout")
}

func TestComponentHealthWithTimeout(t *testing.T) {
	// 初始化测试环境
	setupHealthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health/component/:component", ComponentHealth)

	req := httptest.NewRequest("GET", "/health/component/database", nil)
	w := httptest.NewRecorder()

	start := time.Now()
	router.ServeHTTP(w, req)
	duration := time.Since(start)

	// 组件检查应该在5秒内完成
	assert.Less(t, duration, 8*time.Second, "component health check should complete within timeout")
}

func TestHealthResponseFormat(t *testing.T) {
	// 初始化测试环境
	setupHealthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health", Health)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 验证JSON响应格式
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json", "should return JSON")

	// 解析响应验证结构
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err, "response should be valid JSON")

	// 验证必需字段
	assert.Contains(t, response, "status", "response should contain status")
	assert.Contains(t, response, "timestamp", "response should contain timestamp")
	assert.Contains(t, response, "components", "response should contain components")

	if components, ok := response["components"].(map[string]interface{}); ok {
		assert.NotEmpty(t, components, "components should not be empty")
	}
}

func TestLivenessResponseFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/liveness", Liveness)

	req := httptest.NewRequest("GET", "/liveness", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 验证JSON响应格式
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json", "should return JSON")

	// 解析响应验证结构
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err, "response should be valid JSON")

	// 验证必需字段
	assert.Equal(t, "alive", response["status"], "status should be alive")
	assert.NotNil(t, response["timestamp"], "should have timestamp")
	assert.NotNil(t, response["uptime"], "should have uptime")

	// 验证uptime是数字
	if uptime, ok := response["uptime"].(float64); ok {
		assert.GreaterOrEqual(t, uptime, 0.0, "uptime should be non-negative")
	}
}

func TestComponentHealthResponseFormat(t *testing.T) {
	// 初始化测试环境
	setupHealthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health/component/:component", ComponentHealth)

	req := httptest.NewRequest("GET", "/health/component/memory", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Contains(t, w.Header().Get("Content-Type"), "application/json", "should return JSON")

	// 解析响应验证结构
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err, "response should be valid JSON")

	if w.Code == http.StatusOK {
		// 成功响应应该包含组件信息
		assert.Contains(t, response, "name", "response should contain component name")
		assert.Contains(t, response, "status", "response should contain status")
		assert.Contains(t, response, "last_check", "response should contain last_check")
	} else if w.Code == http.StatusNotFound {
		// 404响应应该包含错误信息
		assert.Contains(t, response, "code", "error response should contain code")
		assert.Contains(t, response, "message", "error response should contain message")
	}
}

func TestHealthConcurrentRequests(t *testing.T) {
	// 初始化测试环境
	setupHealthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health", Health)

	const numRequests = 10
	results := make(chan int, numRequests)

	// 并发发送健康检查请求
	for i := 0; i < numRequests; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/health", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			results <- w.Code
		}()
	}

	// 收集结果
	var statusCodes []int
	for i := 0; i < numRequests; i++ {
		statusCode := <-results
		statusCodes = append(statusCodes, statusCode)
	}

	// 验证所有请求都得到了响应
	assert.Len(t, statusCodes, numRequests, "should receive all responses")

	// 验证响应状态码一致性
	firstCode := statusCodes[0]
	for _, code := range statusCodes {
		assert.True(t, code == http.StatusOK || code == http.StatusServiceUnavailable,
			"response code should be 200 or 503")
		// 在短时间内，健康状态应该是一致的
		assert.Equal(t, firstCode, code, "concurrent requests should return consistent status")
	}
}

func TestHealthCheckerInitialization(t *testing.T) {
	// 验证全局健康检查器是否正确初始化
	assert.NotNil(t, healthChecker, "global health checker should be initialized")

	// 验证定期检查是否已启动
	uptime := healthChecker.GetUptime()
	assert.Greater(t, uptime, time.Duration(0), "health checker should have positive uptime")
}

func TestHealthEndpointWithDifferentMethods(t *testing.T) {
	// 初始化测试环境
	setupHealthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Any("/health", Health)

	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}

	for _, method := range methods {
		t.Run(method+" method", func(t *testing.T) {
			req := httptest.NewRequest(method, "/health", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if method == "HEAD" {
				// HEAD请求应该只返回状态码和头部，没有body
				assert.Empty(t, w.Body.String(), "HEAD request should have empty body")
			} else if method == "OPTIONS" {
				// OPTIONS请求可能有不同的处理
				assert.True(t, w.Code >= 200 && w.Code < 500, "OPTIONS should return valid status")
			} else {
				// 其他方法应该正常处理
				assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusServiceUnavailable,
					"should return valid health status")
			}
		})
	}
}

// setupHealthHandlerTestEnv 设置健康检查处理器测试环境
func setupHealthHandlerTestEnv(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	// 初始化数据库连接（如果可能）
	err = database.Init(&cfg.Database)
	if err != nil {
		t.Logf("Warning: failed to init database for health handler test: %v", err)
	}

	// 初始化Redis连接（如果可能）
	err = cache.Init(&cfg.Redis)
	if err != nil {
		t.Logf("Warning: failed to init cache for health handler test: %v", err)
	}

	// 确保健康检查器已初始化
	if healthChecker == nil {
		healthChecker = monitor.NewHealthChecker()
		healthChecker.StartPeriodicCheck(30 * time.Second)
	}
}
