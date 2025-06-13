package monitor

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestNewPrometheusManager(t *testing.T) {
	manager := NewPrometheusManager()
	assert.NotNil(t, manager, "prometheus manager should not be nil")
	assert.NotNil(t, manager.registry, "registry should not be nil")
}

func TestMetricsMiddleware(t *testing.T) {
	// 重置指标
	resetAllMetrics()

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 使用指标中间件
	router.Use(MetricsMiddleware())
	router.GET("/test/:id", func(c *gin.Context) {
		// 模拟一些处理时间
		time.Sleep(10 * time.Millisecond)
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	router.POST("/api/users", func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{"message": "created"})
	})

	// 测试GET请求
	req := httptest.NewRequest("GET", "/test/123", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "GET request should succeed")

	// 测试POST请求
	req = httptest.NewRequest("POST", "/api/users", strings.NewReader(`{"name":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code, "POST request should succeed")

	// 验证指标被记录
	manager := NewPrometheusManager()
	metrics, err := manager.GetMetrics()
	assert.NoError(t, err, "should get metrics without error")
	assert.NotEmpty(t, metrics, "metrics should not be empty")

	// 检查是否记录了HTTP请求指标
	foundHTTPRequestsTotal := false
	foundHTTPRequestDuration := false

	for metricName := range metrics {
		if strings.Contains(metricName, "http_requests_total") {
			foundHTTPRequestsTotal = true
		}
		if strings.Contains(metricName, "http_request_duration_seconds") {
			foundHTTPRequestDuration = true
		}
	}

	assert.True(t, foundHTTPRequestsTotal, "should record http_requests_total metric")
	assert.True(t, foundHTTPRequestDuration, "should record http_request_duration_seconds metric")
}

func TestPrometheusHandler(t *testing.T) {
	manager := NewPrometheusManager()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/metrics", manager.Handler())

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "metrics endpoint should return 200")
	assert.Contains(t, w.Header().Get("Content-Type"), "text/plain", "should return prometheus format")
	assert.NotEmpty(t, w.Body.String(), "metrics response should not be empty")
}

func TestRecordAuthentication(t *testing.T) {
	// 重置指标
	resetAllMetrics()

	// 记录成功认证
	RecordAuthentication(true)
	RecordAuthentication(true)

	// 记录失败认证
	RecordAuthentication(false)

	// 验证指标
	manager := NewPrometheusManager()
	metrics, err := manager.GetMetrics()
	assert.NoError(t, err, "should get metrics without error")

	// 检查认证指标
	successCount := 0.0
	failureCount := 0.0

	for metricName, value := range metrics {
		if strings.Contains(metricName, "authentication_total") {
			if strings.Contains(metricName, "success") {
				successCount = value
			} else if strings.Contains(metricName, "failure") {
				failureCount = value
			}
		}
	}

	assert.Equal(t, 2.0, successCount, "should record 2 successful authentications")
	assert.Equal(t, 1.0, failureCount, "should record 1 failed authentication")
}

func TestRecordTokenGeneration(t *testing.T) {
	// 重置指标
	resetAllMetrics()

	// 记录token生成
	RecordTokenGeneration()
	RecordTokenGeneration()
	RecordTokenGeneration()

	// 验证指标
	manager := NewPrometheusManager()
	metrics, err := manager.GetMetrics()
	assert.NoError(t, err, "should get metrics without error")

	// 检查token生成指标
	var tokenCount float64
	for metricName, value := range metrics {
		if strings.Contains(metricName, "token_generation_total") {
			tokenCount = value
			break
		}
	}

	assert.Equal(t, 3.0, tokenCount, "should record 3 token generations")
}

func TestRecordRateLimit(t *testing.T) {
	// 重置指标
	resetAllMetrics()

	// 记录限流事件
	RecordRateLimit("api_global", true)
	RecordRateLimit("api_global", true)
	RecordRateLimit("api_global", false)
	RecordRateLimit("auth_strict", false)

	// 验证指标
	manager := NewPrometheusManager()
	metrics, err := manager.GetMetrics()
	assert.NoError(t, err, "should get metrics without error")

	allowedCount := 0.0
	blockedCount := 0.0

	for metricName, value := range metrics {
		if strings.Contains(metricName, "rate_limit_hits_total") {
			if strings.Contains(metricName, "allowed") {
				allowedCount += value
			} else if strings.Contains(metricName, "blocked") {
				blockedCount += value
			}
		}
	}

	assert.Equal(t, 2.0, allowedCount, "should record 2 allowed requests")
	assert.Equal(t, 2.0, blockedCount, "should record 2 blocked requests")
}

func TestRecordDBConnection(t *testing.T) {
	// 重置指标
	resetAllMetrics()

	// 记录数据库连接数
	RecordDBConnection(10)
	RecordDBConnection(15)

	// 验证指标（Gauge类型会被最新值覆盖）
	manager := NewPrometheusManager()
	metrics, err := manager.GetMetrics()
	assert.NoError(t, err, "should get metrics without error")

	var dbConnections float64
	for metricName, value := range metrics {
		if strings.Contains(metricName, "db_connections_active") {
			dbConnections = value
			break
		}
	}

	assert.Equal(t, 15.0, dbConnections, "should record latest DB connection count")
}

func TestRecordDBQuery(t *testing.T) {
	// 重置指标
	resetAllMetrics()

	// 记录数据库查询
	RecordDBQuery("select", 50*time.Millisecond)
	RecordDBQuery("select", 30*time.Millisecond)
	RecordDBQuery("insert", 100*time.Millisecond)

	// 验证指标
	manager := NewPrometheusManager()
	metrics, err := manager.GetMetrics()
	assert.NoError(t, err, "should get metrics without error")

	selectCount := 0.0
	insertCount := 0.0

	for metricName, value := range metrics {
		if strings.Contains(metricName, "db_queries_total") {
			if strings.Contains(metricName, "select") {
				selectCount = value
			} else if strings.Contains(metricName, "insert") {
				insertCount = value
			}
		}
	}

	assert.Equal(t, 2.0, selectCount, "should record 2 select queries")
	assert.Equal(t, 1.0, insertCount, "should record 1 insert query")
}

func TestRecordRedisConnection(t *testing.T) {
	// 重置指标
	resetAllMetrics()

	// 记录Redis连接数
	RecordRedisConnection(5)
	RecordRedisConnection(8)

	// 验证指标
	manager := NewPrometheusManager()
	metrics, err := manager.GetMetrics()
	assert.NoError(t, err, "should get metrics without error")

	var redisConnections float64
	for metricName, value := range metrics {
		if strings.Contains(metricName, "redis_connections_active") {
			redisConnections = value
			break
		}
	}

	assert.Equal(t, 8.0, redisConnections, "should record latest Redis connection count")
}

func TestRecordRedisOperation(t *testing.T) {
	// 重置指标
	resetAllMetrics()

	// 记录Redis操作
	RecordRedisOperation("get", true)
	RecordRedisOperation("get", true)
	RecordRedisOperation("set", true)
	RecordRedisOperation("get", false)

	// 验证指标
	manager := NewPrometheusManager()
	metrics, err := manager.GetMetrics()
	assert.NoError(t, err, "should get metrics without error")

	successCount := 0.0
	errorCount := 0.0

	for metricName, value := range metrics {
		if strings.Contains(metricName, "redis_operations_total") {
			if strings.Contains(metricName, "success") {
				successCount += value
			} else if strings.Contains(metricName, "error") {
				errorCount += value
			}
		}
	}

	assert.Equal(t, 3.0, successCount, "should record 3 successful operations")
	assert.Equal(t, 1.0, errorCount, "should record 1 error operation")
}

func TestRecordActiveSessions(t *testing.T) {
	// 重置指标
	resetAllMetrics()

	// 记录活跃会话数
	RecordActiveSessions(50)
	RecordActiveSessions(75)

	// 验证指标
	manager := NewPrometheusManager()
	metrics, err := manager.GetMetrics()
	assert.NoError(t, err, "should get metrics without error")

	var activeSessions float64
	for metricName, value := range metrics {
		if strings.Contains(metricName, "active_sessions_total") {
			activeSessions = value
			break
		}
	}

	assert.Equal(t, 75.0, activeSessions, "should record latest active sessions count")
}

func TestRecordMessage(t *testing.T) {
	// 重置指标
	resetAllMetrics()

	// 记录消息处理
	RecordMessage("user")
	RecordMessage("user")
	RecordMessage("assistant")
	RecordMessage("system")

	// 验证指标
	manager := NewPrometheusManager()
	metrics, err := manager.GetMetrics()
	assert.NoError(t, err, "should get metrics without error")

	userMessages := 0.0
	assistantMessages := 0.0
	systemMessages := 0.0

	for metricName, value := range metrics {
		if strings.Contains(metricName, "messages_total") {
			if strings.Contains(metricName, "user") {
				userMessages = value
			} else if strings.Contains(metricName, "assistant") {
				assistantMessages = value
			} else if strings.Contains(metricName, "system") {
				systemMessages = value
			}
		}
	}

	assert.Equal(t, 2.0, userMessages, "should record 2 user messages")
	assert.Equal(t, 1.0, assistantMessages, "should record 1 assistant message")
	assert.Equal(t, 1.0, systemMessages, "should record 1 system message")
}

func TestRecordGoroutines(t *testing.T) {
	// 重置指标
	resetAllMetrics()

	// 记录协程数量
	RecordGoroutines(100)
	RecordGoroutines(120)

	// 验证指标
	manager := NewPrometheusManager()
	metrics, err := manager.GetMetrics()
	assert.NoError(t, err, "should get metrics without error")

	var goroutines float64
	for metricName, value := range metrics {
		if strings.Contains(metricName, "goroutines_active") {
			goroutines = value
			break
		}
	}

	assert.Equal(t, 120.0, goroutines, "should record latest goroutines count")
}

func TestGetMetrics(t *testing.T) {
	// 重置指标
	resetAllMetrics()

	manager := NewPrometheusManager()

	// 记录一些指标
	RecordAuthentication(true)
	RecordTokenGeneration()
	RecordRateLimit("test", false)

	// 获取指标
	metrics, err := manager.GetMetrics()
	assert.NoError(t, err, "should get metrics without error")
	assert.NotEmpty(t, metrics, "metrics should not be empty")

	// 验证指标格式
	for metricName, value := range metrics {
		assert.NotEmpty(t, metricName, "metric name should not be empty")
		assert.GreaterOrEqual(t, value, 0.0, "metric value should be non-negative")
	}
}

func TestConcurrentMetricsRecording(t *testing.T) {
	// 重置指标
	resetAllMetrics()

	// 并发记录指标
	const numGoroutines = 10
	const numRecordsPerGoroutine = 5

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < numRecordsPerGoroutine; j++ {
				RecordAuthentication(true)
				RecordTokenGeneration()
				RecordMessage("user")
			}
		}()
	}

	// 等待所有goroutine完成
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// 验证指标
	manager := NewPrometheusManager()
	metrics, err := manager.GetMetrics()
	assert.NoError(t, err, "should get metrics without error")

	expectedCount := float64(numGoroutines * numRecordsPerGoroutine)

	authCount := 0.0
	tokenCount := 0.0
	messageCount := 0.0

	for metricName, value := range metrics {
		if metricName == "authentication_total{status=success}" {
			authCount = value
		} else if metricName == "token_generation_total" {
			tokenCount = value
		} else if metricName == "messages_total{type=user}" {
			messageCount = value
		}
	}

	assert.Equal(t, expectedCount, authCount, "should record correct auth count")
	assert.Equal(t, expectedCount, tokenCount, "should record correct token count")
	assert.Equal(t, expectedCount, messageCount, "should record correct message count")
}

// resetAllMetrics 重置所有指标
func resetAllMetrics() {
	manager := NewPrometheusManager()
	manager.ResetMetrics()
}
