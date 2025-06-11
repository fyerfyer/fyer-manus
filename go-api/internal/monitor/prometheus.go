package monitor

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// HTTP请求指标
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// 认证指标
	authenticationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authentication_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"status"}, // success, failure
	)

	tokenGenerationTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "token_generation_total",
			Help: "Total number of JWT tokens generated",
		},
	)

	// 限流指标
	rateLimitHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rate_limit_hits_total",
			Help: "Total number of rate limit hits",
		},
		[]string{"rule", "action"}, // action: allowed, blocked
	)

	// 数据库指标
	dbConnectionsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "db_connections_active",
			Help: "Number of active database connections",
		},
	)

	dbQueriesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "db_queries_total",
			Help: "Total number of database queries",
		},
		[]string{"operation"}, // select, insert, update, delete
	)

	dbQueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "db_query_duration_seconds",
			Help:    "Database query duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
		},
		[]string{"operation"},
	)

	// Redis指标
	redisConnectionsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "redis_connections_active",
			Help: "Number of active Redis connections",
		},
	)

	redisOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "redis_operations_total",
			Help: "Total number of Redis operations",
		},
		[]string{"operation", "status"}, // operation: get, set, del; status: success, error
	)

	// 业务指标
	activeSessionsTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_sessions_total",
			Help: "Number of active user sessions",
		},
	)

	messagesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "messages_total",
			Help: "Total number of messages processed",
		},
		[]string{"type"}, // user, assistant, system
	)

	// 系统指标
	goroutinesActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "goroutines_active",
			Help: "Number of active goroutines",
		},
	)
)

// PrometheusManager Prometheus指标管理器
type PrometheusManager struct {
	registry *prometheus.Registry
}

// NewPrometheusManager 创建Prometheus管理器
func NewPrometheusManager() *PrometheusManager {
	return &PrometheusManager{
		registry: prometheus.DefaultRegisterer.(*prometheus.Registry),
	}
}

// MetricsMiddleware HTTP指标收集中间件
func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}

		c.Next()

		duration := time.Since(start)
		status := strconv.Itoa(c.Writer.Status())

		httpRequestsTotal.WithLabelValues(c.Request.Method, path, status).Inc()
		httpRequestDuration.WithLabelValues(c.Request.Method, path).Observe(duration.Seconds())
	}
}

// Handler 返回Prometheus指标处理器
func (pm *PrometheusManager) Handler() gin.HandlerFunc {
	return gin.WrapH(promhttp.Handler())
}

// RecordAuthentication 记录认证事件
func RecordAuthentication(success bool) {
	status := "failure"
	if success {
		status = "success"
	}
	authenticationTotal.WithLabelValues(status).Inc()
}

// RecordTokenGeneration 记录Token生成
func RecordTokenGeneration() {
	tokenGenerationTotal.Inc()
}

// RecordRateLimit 记录限流事件
func RecordRateLimit(rule string, allowed bool) {
	action := "blocked"
	if allowed {
		action = "allowed"
	}
	rateLimitHitsTotal.WithLabelValues(rule, action).Inc()
}

// RecordDBConnection 记录数据库连接数
func RecordDBConnection(active int) {
	dbConnectionsActive.Set(float64(active))
}

// RecordDBQuery 记录数据库查询
func RecordDBQuery(operation string, duration time.Duration) {
	dbQueriesTotal.WithLabelValues(operation).Inc()
	dbQueryDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// RecordRedisConnection 记录Redis连接数
func RecordRedisConnection(active int) {
	redisConnectionsActive.Set(float64(active))
}

// RecordRedisOperation 记录Redis操作
func RecordRedisOperation(operation string, success bool) {
	status := "error"
	if success {
		status = "success"
	}
	redisOperationsTotal.WithLabelValues(operation, status).Inc()
}

// RecordActiveSessions 记录活跃会话数
func RecordActiveSessions(count int) {
	activeSessionsTotal.Set(float64(count))
}

// RecordMessage 记录消息处理
func RecordMessage(messageType string) {
	messagesTotal.WithLabelValues(messageType).Inc()
}

// RecordGoroutines 记录协程数量
func RecordGoroutines(count int) {
	goroutinesActive.Set(float64(count))
}

// GetMetrics 获取所有指标的当前值
func (pm *PrometheusManager) GetMetrics() (map[string]float64, error) {
	metricFamilies, err := pm.registry.Gather()
	if err != nil {
		return nil, err
	}

	metrics := make(map[string]float64)
	for _, mf := range metricFamilies {
		for _, m := range mf.GetMetric() {
			name := mf.GetName()
			if len(m.GetLabel()) > 0 {
				labels := ""
				for _, label := range m.GetLabel() {
					if labels != "" {
						labels += ","
					}
					labels += label.GetName() + "=" + label.GetValue()
				}
				name = name + "{" + labels + "}"
			}

			var value float64
			if m.GetCounter() != nil {
				value = m.GetCounter().GetValue()
			} else if m.GetGauge() != nil {
				value = m.GetGauge().GetValue()
			} else if m.GetHistogram() != nil {
				value = m.GetHistogram().GetSampleSum()
			}

			metrics[name] = value
		}
	}

	return metrics, nil
}

// ResetMetrics 重置指定指标（测试用）
func (pm *PrometheusManager) ResetMetrics() {
	httpRequestsTotal.Reset()
	httpRequestDuration.Reset()
	authenticationTotal.Reset()
	rateLimitHitsTotal.Reset()
	dbQueriesTotal.Reset()
	dbQueryDuration.Reset()
	redisOperationsTotal.Reset()
	messagesTotal.Reset()
}
