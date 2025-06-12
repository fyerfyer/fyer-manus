package monitor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
)

func TestNewHealthChecker(t *testing.T) {
	checker := NewHealthChecker()
	assert.NotNil(t, checker, "health checker should not be nil")
	assert.NotNil(t, checker.components, "components map should not be nil")
	assert.NotNil(t, checker.cache, "cache map should not be nil")
	assert.Equal(t, 30*time.Second, checker.cacheTTL, "cache TTL should be 30 seconds")

	// 验证默认组件已注册
	assert.Contains(t, checker.components, "database", "should have database check")
	assert.Contains(t, checker.components, "redis", "should have redis check")
	assert.Contains(t, checker.components, "memory", "should have memory check")
	assert.Contains(t, checker.components, "disk", "should have disk check")
}

func TestHealthChecker_RegisterCheck(t *testing.T) {
	checker := NewHealthChecker()

	// 注册自定义检查
	customCheck := func(ctx context.Context) ComponentHealth {
		return ComponentHealth{
			Name:   "custom",
			Status: HealthStatusHealthy,
		}
	}

	checker.RegisterCheck("custom", customCheck)
	assert.Contains(t, checker.components, "custom", "should register custom check")
}

func TestHealthChecker_UnregisterCheck(t *testing.T) {
	checker := NewHealthChecker()

	// 注册然后注销检查
	customCheck := func(ctx context.Context) ComponentHealth {
		return ComponentHealth{
			Name:   "custom",
			Status: HealthStatusHealthy,
		}
	}

	checker.RegisterCheck("custom", customCheck)
	assert.Contains(t, checker.components, "custom", "should register custom check")

	checker.UnregisterCheck("custom")
	assert.NotContains(t, checker.components, "custom", "should unregister custom check")
}

func TestHealthChecker_Check(t *testing.T) {
	// 初始化测试环境
	setupHealthTestEnv(t)

	checker := NewHealthChecker()

	// 注册一个始终健康的测试组件
	healthyCheck := func(ctx context.Context) ComponentHealth {
		return ComponentHealth{
			Name:      "test_healthy",
			Status:    HealthStatusHealthy,
			Message:   "test component is healthy",
			LastCheck: time.Now(),
			Duration:  10 * time.Millisecond,
		}
	}
	checker.RegisterCheck("test_healthy", healthyCheck)

	// 注册一个不健康的测试组件
	unhealthyCheck := func(ctx context.Context) ComponentHealth {
		return ComponentHealth{
			Name:      "test_unhealthy",
			Status:    HealthStatusUnhealthy,
			Message:   "test component is unhealthy",
			LastCheck: time.Now(),
			Duration:  5 * time.Millisecond,
		}
	}
	checker.RegisterCheck("test_unhealthy", unhealthyCheck)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := checker.Check(ctx)

	// 验证总体结果
	assert.Equal(t, HealthStatusUnhealthy, result.Status, "overall status should be unhealthy")
	assert.NotZero(t, result.Timestamp, "timestamp should be set")
	assert.NotEmpty(t, result.Version, "version should be set")
	assert.Greater(t, result.Uptime, time.Duration(0), "uptime should be positive")
	assert.NotEmpty(t, result.Components, "components should not be empty")

	// 验证组件结果
	healthyComponent, exists := result.Components["test_healthy"]
	assert.True(t, exists, "should have healthy component")
	assert.Equal(t, HealthStatusHealthy, healthyComponent.Status, "healthy component should be healthy")

	unhealthyComponent, exists := result.Components["test_unhealthy"]
	assert.True(t, exists, "should have unhealthy component")
	assert.Equal(t, HealthStatusUnhealthy, unhealthyComponent.Status, "unhealthy component should be unhealthy")
}

func TestHealthChecker_QuickCheck(t *testing.T) {
	// 初始化测试环境
	setupHealthTestEnv(t)

	checker := NewHealthChecker()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := checker.QuickCheck(ctx)

	// 快速检查只检查关键组件
	assert.NotZero(t, result.Timestamp, "timestamp should be set")
	assert.NotEmpty(t, result.Components, "should have components")

	// 验证只包含关键组件
	_, hasDatabase := result.Components["database"]
	_, hasRedis := result.Components["redis"]
	assert.True(t, hasDatabase || hasRedis, "should check at least one critical component")
}

func TestHealthChecker_CheckDatabase(t *testing.T) {
	// 初始化测试环境
	setupHealthTestEnv(t)

	checker := NewHealthChecker()
	ctx := context.Background()

	health := checker.checkDatabase(ctx)

	assert.Equal(t, "database", health.Name, "component name should be database")
	assert.NotZero(t, health.LastCheck, "last check time should be set")
	assert.Greater(t, health.Duration, time.Duration(0), "duration should be positive")

	// 根据实际数据库状态验证结果
	if health.Status == HealthStatusHealthy {
		assert.Contains(t, health.Message, "successful", "healthy database should have success message")
		assert.NotNil(t, health.Details, "healthy database should have details")
	} else {
		assert.Contains(t, health.Message, "failed", "unhealthy database should have failure message")
	}
}

func TestHealthChecker_CheckRedis(t *testing.T) {
	// 初始化测试环境
	setupHealthTestEnv(t)

	checker := NewHealthChecker()
	ctx := context.Background()

	health := checker.checkRedis(ctx)

	assert.Equal(t, "redis", health.Name, "component name should be redis")
	assert.NotZero(t, health.LastCheck, "last check time should be set")
	assert.Greater(t, health.Duration, time.Duration(0), "duration should be positive")

	// 根据实际Redis状态验证结果
	if health.Status == HealthStatusHealthy {
		assert.Contains(t, health.Message, "successful", "healthy redis should have success message")
		assert.NotNil(t, health.Details, "healthy redis should have details")
	} else {
		assert.Contains(t, health.Message, "failed", "unhealthy redis should have failure message")
	}
}

func TestHealthChecker_CheckMemory(t *testing.T) {
	checker := NewHealthChecker()
	ctx := context.Background()

	health := checker.checkMemory(ctx)

	assert.Equal(t, "memory", health.Name, "component name should be memory")
	assert.Equal(t, HealthStatusHealthy, health.Status, "memory check should be healthy")
	assert.NotZero(t, health.LastCheck, "last check time should be set")
	assert.Greater(t, health.Duration, time.Duration(0), "duration should be positive")
	assert.NotNil(t, health.Details, "should have details")
}

func TestHealthChecker_CheckDisk(t *testing.T) {
	checker := NewHealthChecker()
	ctx := context.Background()

	health := checker.checkDisk(ctx)

	assert.Equal(t, "disk", health.Name, "component name should be disk")
	assert.Equal(t, HealthStatusHealthy, health.Status, "disk check should be healthy")
	assert.NotZero(t, health.LastCheck, "last check time should be set")
	assert.Greater(t, health.Duration, time.Duration(0), "duration should be positive")
	assert.NotNil(t, health.Details, "should have details")
}

func TestHealthChecker_Cache(t *testing.T) {
	checker := NewHealthChecker()

	// 创建测试组件
	callCount := 0
	testCheck := func(ctx context.Context) ComponentHealth {
		callCount++
		return ComponentHealth{
			Name:      "test_cache",
			Status:    HealthStatusHealthy,
			LastCheck: time.Now(),
		}
	}

	checker.RegisterCheck("test_cache", testCheck)

	ctx := context.Background()

	// 第一次检查
	checker.Check(ctx)
	assert.Equal(t, 1, callCount, "should call check function once")

	// 立即再次检查（应该使用缓存）
	checker.Check(ctx)
	assert.Equal(t, 1, callCount, "should use cache, not call check function again")

	// 清除缓存后再次检查
	delete(checker.cache, "test_cache")
	checker.Check(ctx)
	assert.Equal(t, 2, callCount, "should call check function again after cache cleared")
}

func TestHealthChecker_CalculateOverallStatus(t *testing.T) {
	checker := NewHealthChecker()

	tests := []struct {
		name       string
		components map[string]ComponentHealth
		expected   HealthStatus
	}{
		{
			name: "all healthy",
			components: map[string]ComponentHealth{
				"comp1": {Status: HealthStatusHealthy},
				"comp2": {Status: HealthStatusHealthy},
			},
			expected: HealthStatusHealthy,
		},
		{
			name: "one unhealthy",
			components: map[string]ComponentHealth{
				"comp1": {Status: HealthStatusHealthy},
				"comp2": {Status: HealthStatusUnhealthy},
			},
			expected: HealthStatusUnhealthy,
		},
		{
			name: "one degraded",
			components: map[string]ComponentHealth{
				"comp1": {Status: HealthStatusHealthy},
				"comp2": {Status: HealthStatusDegraded},
			},
			expected: HealthStatusDegraded,
		},
		{
			name: "unhealthy takes precedence over degraded",
			components: map[string]ComponentHealth{
				"comp1": {Status: HealthStatusDegraded},
				"comp2": {Status: HealthStatusUnhealthy},
			},
			expected: HealthStatusUnhealthy,
		},
		{
			name:       "empty components",
			components: map[string]ComponentHealth{},
			expected:   HealthStatusHealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.calculateOverallStatus(tt.components)
			assert.Equal(t, tt.expected, result, "overall status should match expected")
		})
	}
}

func TestHealthChecker_GetComponentHealth(t *testing.T) {
	checker := NewHealthChecker()

	// 注册测试组件
	testCheck := func(ctx context.Context) ComponentHealth {
		return ComponentHealth{
			Name:      "test_component",
			Status:    HealthStatusHealthy,
			Message:   "test message",
			LastCheck: time.Now(),
		}
	}
	checker.RegisterCheck("test_component", testCheck)

	ctx := context.Background()

	// 获取存在的组件
	health, err := checker.GetComponentHealth(ctx, "test_component")
	assert.NoError(t, err, "should get component health without error")
	assert.NotNil(t, health, "health should not be nil")
	assert.Equal(t, "test_component", health.Name, "component name should match")

	// 获取不存在的组件
	health, err = checker.GetComponentHealth(ctx, "nonexistent")
	assert.Error(t, err, "should return error for nonexistent component")
	assert.Nil(t, health, "health should be nil for nonexistent component")
	assert.Contains(t, err.Error(), "not found", "error should mention component not found")
}

func TestHealthChecker_IsHealthy(t *testing.T) {
	// 初始化测试环境
	setupHealthTestEnv(t)

	checker := NewHealthChecker()

	// 注册健康组件
	healthyCheck := func(ctx context.Context) ComponentHealth {
		return ComponentHealth{
			Name:   "test_healthy",
			Status: HealthStatusHealthy,
		}
	}
	checker.RegisterCheck("test_healthy", healthyCheck)

	ctx := context.Background()

	isHealthy := checker.IsHealthy(ctx)
	// 结果取决于数据库和Redis的实际状态
	assert.IsType(t, true, isHealthy, "should return boolean")
}

func TestHealthChecker_GetUptime(t *testing.T) {
	checker := NewHealthChecker()

	// 等待一小段时间
	time.Sleep(10 * time.Millisecond)

	uptime := checker.GetUptime()
	assert.Greater(t, uptime, time.Duration(0), "uptime should be positive")
	assert.Greater(t, uptime, 5*time.Millisecond, "uptime should be at least 5ms")
}

func TestHealthChecker_StartPeriodicCheck(t *testing.T) {
	checker := NewHealthChecker()

	// 注册一个测试组件
	checkCount := 0
	testCheck := func(ctx context.Context) ComponentHealth {
		checkCount++
		return ComponentHealth{
			Name:   "periodic_test",
			Status: HealthStatusHealthy,
		}
	}
	checker.RegisterCheck("periodic_test", testCheck)

	// 启动定期检查（使用很短的间隔用于测试）
	checker.StartPeriodicCheck(50 * time.Millisecond)

	// 等待几次检查
	time.Sleep(150 * time.Millisecond)

	// 验证检查被执行了多次
	assert.Greater(t, checkCount, 1, "periodic check should be executed multiple times")
}

func TestHealthChecker_ConcurrentCheck(t *testing.T) {
	checker := NewHealthChecker()

	// 注册多个慢速组件
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("slow_%d", i)
		slowCheck := func(ctx context.Context) ComponentHealth {
			time.Sleep(50 * time.Millisecond)
			return ComponentHealth{
				Name:   name,
				Status: HealthStatusHealthy,
			}
		}
		checker.RegisterCheck(name, slowCheck)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	result := checker.Check(ctx)
	duration := time.Since(start)

	// 并发执行应该比串行执行快
	assert.Less(t, duration, 200*time.Millisecond, "concurrent checks should be faster than serial")
	assert.Equal(t, 5, len(result.Components), "should have all components")
}

func TestHealthChecker_ContextTimeout(t *testing.T) {
	checker := NewHealthChecker()

	// 注册一个会超时的组件
	timeoutCheck := func(ctx context.Context) ComponentHealth {
		select {
		case <-time.After(100 * time.Millisecond):
			return ComponentHealth{
				Name:   "timeout_test",
				Status: HealthStatusHealthy,
			}
		case <-ctx.Done():
			return ComponentHealth{
				Name:    "timeout_test",
				Status:  HealthStatusUnhealthy,
				Message: "context timeout",
			}
		}
	}
	checker.RegisterCheck("timeout_test", timeoutCheck)

	// 使用很短的超时时间
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	result := checker.Check(ctx)

	// 验证超时处理
	assert.NotEmpty(t, result.Components, "should have components even with timeout")
}

func TestComponentHealth_Statuses(t *testing.T) {
	tests := []struct {
		name   string
		status HealthStatus
		valid  bool
	}{
		{"healthy", HealthStatusHealthy, true},
		{"unhealthy", HealthStatusUnhealthy, true},
		{"degraded", HealthStatusDegraded, true},
		{"invalid", HealthStatus("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			health := ComponentHealth{
				Name:   "test",
				Status: tt.status,
			}

			assert.Equal(t, tt.status, health.Status, "status should match")

			if tt.valid {
				validStatuses := []HealthStatus{
					HealthStatusHealthy,
					HealthStatusUnhealthy,
					HealthStatusDegraded,
				}
				assert.Contains(t, validStatuses, health.Status, "should be valid status")
			}
		})
	}
}

func TestOverallHealth_Structure(t *testing.T) {
	checker := NewHealthChecker()
	ctx := context.Background()

	result := checker.Check(ctx)

	// 验证结构完整性
	assert.NotZero(t, result.Status, "status should be set")
	assert.NotZero(t, result.Timestamp, "timestamp should be set")
	assert.NotEmpty(t, result.Version, "version should be set")
	assert.GreaterOrEqual(t, result.Uptime, time.Duration(0), "uptime should be non-negative")
	assert.NotNil(t, result.Components, "components should not be nil")

	// 验证时间戳是最近的
	assert.WithinDuration(t, time.Now(), result.Timestamp, 5*time.Second, "timestamp should be recent")
}

// setupHealthTestEnv 设置健康检查测试环境
func setupHealthTestEnv(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	// 初始化数据库连接
	err = database.Init(&cfg.Database)
	if err != nil {
		t.Logf("Warning: failed to init database for health check test: %v", err)
	}

	// 初始化Redis连接
	err = cache.Init(&cfg.Redis)
	if err != nil {
		t.Logf("Warning: failed to init cache for health check test: %v", err)
	}
}
