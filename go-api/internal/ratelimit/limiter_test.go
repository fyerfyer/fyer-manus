package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
)

func TestNewLimiter(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()
	assert.NotNil(t, limiter, "limiter should not be nil")
	assert.NotNil(t, limiter.redis, "redis client should not be nil")
	assert.NotNil(t, limiter.manager, "strategy manager should not be nil")
	assert.NotNil(t, limiter.buckets, "token buckets should not be nil")

	// 验证策略已注册
	manager := limiter.GetManager()
	assert.NotNil(t, manager.strategies[StrategyFixedWindow], "fixed window strategy should be registered")
	assert.NotNil(t, manager.strategies[StrategySlidingWindow], "sliding window strategy should be registered")
	assert.NotNil(t, manager.strategies[StrategyTokenBucket], "token bucket strategy should be registered")
	assert.NotNil(t, manager.strategies[StrategyLeakyBucket], "leaky bucket strategy should be registered")
}

func TestLimiter_FixedWindowStrategy(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	// 创建固定窗口规则
	rule := Rule{
		Name:    "test_fixed_window",
		Pattern: "/api/test",
		Config: Config{
			Strategy: StrategyFixedWindow,
			Rate:     5,
			Period:   time.Minute,
			Enabled:  true,
		},
	}

	identifier := "test_user_1"

	// 测试正常请求
	for i := 0; i < 5; i++ {
		result, err := limiter.Check(rule, identifier)
		assert.NoError(t, err, "check should succeed")
		assert.True(t, result.Allowed, "request should be allowed")
		assert.Equal(t, 5-i-1, result.Remaining, "remaining count should be correct")
	}

	// 测试超限请求
	result, err := limiter.Check(rule, identifier)
	assert.NoError(t, err, "check should succeed")
	assert.False(t, result.Allowed, "request should be denied")
	assert.Equal(t, 0, result.Remaining, "remaining should be 0")
	assert.True(t, result.RetryAfter > 0, "retry after should be positive")
}

func TestLimiter_SlidingWindowStrategy(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	// 创建滑动窗口规则
	rule := Rule{
		Name:    "test_sliding_window",
		Pattern: "/api/test",
		Config: Config{
			Strategy: StrategySlidingWindow,
			Rate:     3,
			Period:   5 * time.Second,
			Enabled:  true,
		},
	}

	identifier := "test_user_2"

	// 测试正常请求
	for i := 0; i < 3; i++ {
		result, err := limiter.Check(rule, identifier)
		assert.NoError(t, err, "check should succeed")
		assert.True(t, result.Allowed, "request should be allowed")
	}

	// 测试超限请求
	result, err := limiter.Check(rule, identifier)
	assert.NoError(t, err, "check should succeed")
	assert.False(t, result.Allowed, "request should be denied")

	// 等待一段时间后重试
	time.Sleep(2 * time.Second)
	result, err = limiter.Check(rule, identifier)
	assert.NoError(t, err, "check should succeed")
	// 滑动窗口中仍有部分请求，可能仍被拒绝
}

func TestLimiter_TokenBucketStrategy(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	// 创建令牌桶规则
	rule := Rule{
		Name:    "test_token_bucket",
		Pattern: "/api/test",
		Config: Config{
			Strategy: StrategyTokenBucket,
			Rate:     10, // 每秒10个令牌
			Period:   time.Second,
			Burst:    5, // 桶容量5
			Enabled:  true,
		},
	}

	identifier := "test_user_3"

	// 测试突发流量
	allowedCount := 0
	for i := 0; i < 10; i++ {
		result, err := limiter.Check(rule, identifier)
		assert.NoError(t, err, "check should succeed")
		if result.Allowed {
			allowedCount++
		}
	}

	assert.GreaterOrEqual(t, allowedCount, 5, "at least burst capacity should be allowed")
	assert.LessOrEqual(t, allowedCount, 10, "should not exceed total requests")
}

func TestLimiter_LeakyBucketStrategy(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	// 创建漏桶规则
	rule := Rule{
		Name:    "test_leaky_bucket",
		Pattern: "/api/test",
		Config: Config{
			Strategy: StrategyLeakyBucket,
			Rate:     2, // 每秒漏出2个
			Period:   time.Second,
			Burst:    5, // 桶容量5
			Enabled:  true,
		},
	}

	identifier := "test_user_4"

	// 测试正常请求
	allowedCount := 0
	for i := 0; i < 7; i++ {
		result, err := limiter.Check(rule, identifier)
		assert.NoError(t, err, "check should succeed")
		if result.Allowed {
			allowedCount++
		}
	}

	assert.GreaterOrEqual(t, allowedCount, 5, "at least bucket capacity should be allowed")
	assert.LessOrEqual(t, allowedCount, 7, "should not exceed total requests")
}

func TestLimiter_CheckByPath(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	identifier := "test_user_5"
	headers := map[string]string{}

	tests := []struct {
		name           string
		path           string
		method         string
		expectedRule   bool
		expectedResult bool
	}{
		{
			name:           "api global match",
			path:           "/api/v1/test",
			method:         "GET",
			expectedRule:   true,
			expectedResult: true,
		},
		{
			name:           "auth strict match",
			path:           "/api/v1/auth/login",
			method:         "POST",
			expectedRule:   true,
			expectedResult: true,
		},
		{
			name:           "chat normal match",
			path:           "/api/v1/chat/sessions",
			method:         "POST",
			expectedRule:   true,
			expectedResult: true,
		},
		{
			name:           "no rule match",
			path:           "/public/health",
			method:         "GET",
			expectedRule:   false,
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := limiter.CheckByPath(tt.path, tt.method, identifier, headers)
			assert.NoError(t, err, "check by path should succeed")
			assert.Equal(t, tt.expectedResult, result.Allowed, "result should match expected")
		})
	}
}

func TestLimiter_AddRule(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	// 测试添加有效规则
	validRule := Rule{
		Name:    "custom_rule",
		Pattern: "/api/custom",
		Config: Config{
			Strategy: StrategyFixedWindow,
			Rate:     100,
			Period:   time.Minute,
			Enabled:  true,
		},
	}

	err := limiter.AddRule(validRule)
	assert.NoError(t, err, "adding valid rule should succeed")

	// 测试添加无效规则
	invalidRule := Rule{
		Name:    "invalid_rule",
		Pattern: "/api/invalid",
		Config: Config{
			Strategy: StrategyFixedWindow,
			Rate:     0, // 无效速率
			Period:   time.Minute,
			Enabled:  true,
		},
	}

	err = limiter.AddRule(invalidRule)
	assert.Error(t, err, "adding invalid rule should fail")
	assert.Contains(t, err.Error(), "invalid rule config", "error should mention invalid config")
}

func TestLimiter_ExceptionHandling(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	// 创建带例外的规则
	rule := Rule{
		Name:    "test_with_exceptions",
		Pattern: "/api/test",
		Config: Config{
			Strategy: StrategyFixedWindow,
			Rate:     1,
			Period:   time.Minute,
			Enabled:  true,
		},
		Exceptions: []string{"admin_user", "192.168.1.1"},
	}

	// 测试例外用户
	result, err := limiter.Check(rule, "admin_user")
	assert.NoError(t, err, "check should succeed")
	assert.True(t, result.Allowed, "exception user should always be allowed")

	// 测试例外IP
	result, err = limiter.Check(rule, "192.168.1.1")
	assert.NoError(t, err, "check should succeed")
	assert.True(t, result.Allowed, "exception IP should always be allowed")

	// 测试普通用户
	result, err = limiter.Check(rule, "normal_user")
	assert.NoError(t, err, "check should succeed")
	assert.True(t, result.Allowed, "first request should be allowed")

	// 第二次请求应该被拒绝
	result, err = limiter.Check(rule, "normal_user")
	assert.NoError(t, err, "check should succeed")
	assert.False(t, result.Allowed, "second request should be denied")
}

func TestLimiter_DisabledRule(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	// 创建禁用的规则
	rule := Rule{
		Name:    "disabled_rule",
		Pattern: "/api/test",
		Config: Config{
			Strategy: StrategyFixedWindow,
			Rate:     1,
			Period:   time.Minute,
			Enabled:  false, // 禁用
		},
	}

	identifier := "test_user_6"

	// 即使规则很严格，禁用状态下应该都允许
	for i := 0; i < 5; i++ {
		result, err := limiter.Check(rule, identifier)
		assert.NoError(t, err, "check should succeed")
		assert.True(t, result.Allowed, "disabled rule should always allow")
	}
}

func TestLimiter_GetStats(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	// 创建测试规则
	rule := Rule{
		Name:    "stats_test",
		Pattern: "/api/stats",
		Config: Config{
			Strategy: StrategyFixedWindow,
			Rate:     5,
			Period:   time.Minute,
			Enabled:  true,
		},
	}

	identifier := "stats_user"

	// 执行几次请求
	for i := 0; i < 3; i++ {
		_, err := limiter.Check(rule, identifier)
		require.NoError(t, err, "check should succeed")
	}

	// 获取统计信息
	key := "ratelimit:stats_test:" + identifier
	stats, err := limiter.GetStats(key)
	assert.NoError(t, err, "getting stats should succeed")
	assert.NotNil(t, stats, "stats should not be nil")
}

func TestLimiter_Reset(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	// 创建测试规则
	rule := Rule{
		Name:    "reset_test",
		Pattern: "/api/reset",
		Config: Config{
			Strategy: StrategyFixedWindow,
			Rate:     2,
			Period:   time.Minute,
			Enabled:  true,
		},
	}

	identifier := "reset_user"

	// 执行请求直到限制
	for i := 0; i < 2; i++ {
		result, err := limiter.Check(rule, identifier)
		require.NoError(t, err, "check should succeed")
		assert.True(t, result.Allowed, "request should be allowed")
	}

	// 验证已达到限制
	result, err := limiter.Check(rule, identifier)
	require.NoError(t, err, "check should succeed")
	assert.False(t, result.Allowed, "request should be denied")

	// 重置限流状态
	key := "ratelimit:reset_test:" + identifier
	err = limiter.Reset(key)
	assert.NoError(t, err, "reset should succeed")

	// 验证重置后可以正常请求
	result, err = limiter.Check(rule, identifier)
	assert.NoError(t, err, "check should succeed")
	assert.True(t, result.Allowed, "request should be allowed after reset")
}

func TestLimiter_SetKeyGenerator(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	// 设置自定义键生成器
	customKeyGen := &IPKeyGenerator{}
	limiter.SetKeyGenerator(customKeyGen)

	// 验证键生成器已设置
	manager := limiter.GetManager()
	assert.Equal(t, customKeyGen, manager.keyGen, "key generator should be set")
}

func TestLimiter_ConcurrentAccess(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	// 创建测试规则
	rule := Rule{
		Name:    "concurrent_test",
		Pattern: "/api/concurrent",
		Config: Config{
			Strategy: StrategyFixedWindow,
			Rate:     10,
			Period:   time.Minute,
			Enabled:  true,
		},
	}

	identifier := "concurrent_user"

	// 并发测试
	const numGoroutines = 5
	const requestsPerGoroutine = 4

	allowedChan := make(chan bool, numGoroutines*requestsPerGoroutine)
	doneChan := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer func() { doneChan <- true }()
			for j := 0; j < requestsPerGoroutine; j++ {
				result, err := limiter.Check(rule, identifier)
				if err == nil {
					allowedChan <- result.Allowed
				}
			}
		}()
	}

	// 等待所有goroutine完成
	for i := 0; i < numGoroutines; i++ {
		<-doneChan
	}
	close(allowedChan)

	// 统计允许的请求数
	allowedCount := 0
	for allowed := range allowedChan {
		if allowed {
			allowedCount++
		}
	}

	// 验证结果合理性
	assert.LessOrEqual(t, allowedCount, 10, "should not exceed rate limit")
	assert.GreaterOrEqual(t, allowedCount, 1, "at least some requests should be allowed")
}

func TestLimiter_RedisFailure(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	// 创建测试规则
	rule := Rule{
		Name:    "redis_failure_test",
		Pattern: "/api/failure",
		Config: Config{
			Strategy: StrategyFixedWindow,
			Rate:     5,
			Period:   time.Minute,
			Enabled:  true,
		},
	}

	identifier := "failure_user"

	// 在Redis连接正常时应该能工作
	result, err := limiter.Check(rule, identifier)
	assert.NoError(t, err, "check should succeed with healthy redis")
	assert.True(t, result.Allowed, "request should be allowed")

	// 注意：实际测试Redis故障需要模拟Redis服务器故障
	// 这里只是演示测试结构，实际实现中限流器应该有降级策略
}

func TestLimiter_DifferentIdentifiers(t *testing.T) {
	// 初始化测试环境
	setupLimiterTestEnv(t)

	limiter := NewLimiter()

	// 创建测试规则
	rule := Rule{
		Name:    "multi_user_test",
		Pattern: "/api/multi",
		Config: Config{
			Strategy: StrategyFixedWindow,
			Rate:     2,
			Period:   time.Minute,
			Enabled:  true,
		},
	}

	// 测试不同用户的独立限流
	users := []string{"user1", "user2", "user3"}

	for _, user := range users {
		// 每个用户都应该有独立的限流计数
		for i := 0; i < 2; i++ {
			result, err := limiter.Check(rule, user)
			assert.NoError(t, err, "check should succeed")
			assert.True(t, result.Allowed, "request should be allowed for %s", user)
		}

		// 第三次请求应该被拒绝
		result, err := limiter.Check(rule, user)
		assert.NoError(t, err, "check should succeed")
		assert.False(t, result.Allowed, "third request should be denied for %s", user)
	}
}

// setupLimiterTestEnv 设置限流器测试环境
func setupLimiterTestEnv(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	err = cache.Init(&cfg.Redis)
	require.NoError(t, err, "failed to init cache")

	// 清理测试数据
	ctx := context.Background()
	keys, err := cache.Keys(ctx, "ratelimit:*")
	if err == nil && len(keys) > 0 {
		cache.Del(ctx, keys...)
	}
}
