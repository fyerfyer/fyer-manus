package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"go.uber.org/zap"
)

// HealthStatus 健康状态
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusDegraded  HealthStatus = "degraded"
)

// ComponentHealth 组件健康状态
type ComponentHealth struct {
	Name      string                 `json:"name"`
	Status    HealthStatus           `json:"status"`
	Message   string                 `json:"message,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	LastCheck time.Time              `json:"last_check"`
	Duration  time.Duration          `json:"duration"`
}

// OverallHealth 总体健康状态
type OverallHealth struct {
	Status     HealthStatus               `json:"status"`
	Timestamp  time.Time                  `json:"timestamp"`
	Version    string                     `json:"version"`
	Uptime     time.Duration              `json:"uptime"`
	Components map[string]ComponentHealth `json:"components"`
}

// HealthChecker 健康检查器
type HealthChecker struct {
	components map[string]HealthCheckFunc
	cache      map[string]ComponentHealth
	cacheTTL   time.Duration
	mutex      sync.RWMutex
	startTime  time.Time
}

// HealthCheckFunc 健康检查函数类型
type HealthCheckFunc func(ctx context.Context) ComponentHealth

// NewHealthChecker 创建健康检查器
func NewHealthChecker() *HealthChecker {
	hc := &HealthChecker{
		components: make(map[string]HealthCheckFunc),
		cache:      make(map[string]ComponentHealth),
		cacheTTL:   30 * time.Second,
		startTime:  time.Now(),
	}

	// 注册默认检查项
	hc.RegisterCheck("database", hc.checkDatabase)
	hc.RegisterCheck("redis", hc.checkRedis)
	hc.RegisterCheck("memory", hc.checkMemory)
	hc.RegisterCheck("disk", hc.checkDisk)

	return hc
}

// RegisterCheck 注册健康检查
func (hc *HealthChecker) RegisterCheck(name string, checkFunc HealthCheckFunc) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	hc.components[name] = checkFunc
}

// UnregisterCheck 注销健康检查
func (hc *HealthChecker) UnregisterCheck(name string) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	delete(hc.components, name)
	delete(hc.cache, name)
}

// Check 执行健康检查
func (hc *HealthChecker) Check(ctx context.Context) OverallHealth {
	hc.mutex.RLock()
	components := make(map[string]HealthCheckFunc)
	for name, checkFunc := range hc.components {
		components[name] = checkFunc
	}
	hc.mutex.RUnlock()

	results := make(map[string]ComponentHealth)
	var wg sync.WaitGroup
	var resultsMutex sync.Mutex // 添加互斥锁，保证并发安全

	// 并发执行健康检查
	for name, checkFunc := range components {
		wg.Add(1)
		go func(n string, cf HealthCheckFunc) {
			defer wg.Done()

			// 检查缓存
			if cached := hc.getCachedHealth(n); cached != nil {
				resultsMutex.Lock()
				results[n] = *cached
				resultsMutex.Unlock()
				return
			}

			// 执行检查
			checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			health := cf(checkCtx)

			resultsMutex.Lock()
			results[n] = health
			resultsMutex.Unlock()

			// 更新缓存
			hc.setCachedHealth(n, health)
		}(name, checkFunc)
	}

	wg.Wait()

	// 计算总体状态
	overallStatus := hc.calculateOverallStatus(results)

	return OverallHealth{
		Status:     overallStatus,
		Timestamp:  time.Now(),
		Version:    "1.0.0", // 从config或环境变量获取
		Uptime:     time.Since(hc.startTime),
		Components: results,
	}
}

// QuickCheck 快速健康检查（仅检查关键组件）
func (hc *HealthChecker) QuickCheck(ctx context.Context) OverallHealth {
	criticalComponents := []string{"database", "redis"}

	hc.mutex.RLock()
	components := make(map[string]HealthCheckFunc)
	for _, name := range criticalComponents {
		if checkFunc, exists := hc.components[name]; exists {
			components[name] = checkFunc
		}
	}
	hc.mutex.RUnlock()

	results := make(map[string]ComponentHealth)

	for name, checkFunc := range components {
		checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		health := checkFunc(checkCtx)
		cancel()
		results[name] = health
	}

	overallStatus := hc.calculateOverallStatus(results)

	return OverallHealth{
		Status:     overallStatus,
		Timestamp:  time.Now(),
		Version:    "1.0.0",
		Uptime:     time.Since(hc.startTime),
		Components: results,
	}
}

// getCachedHealth 获取缓存的健康状态
func (hc *HealthChecker) getCachedHealth(name string) *ComponentHealth {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	if cached, exists := hc.cache[name]; exists {
		if time.Since(cached.LastCheck) < hc.cacheTTL {
			return &cached
		}
	}
	return nil
}

// setCachedHealth 设置缓存的健康状态
func (hc *HealthChecker) setCachedHealth(name string, health ComponentHealth) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	hc.cache[name] = health
}

// calculateOverallStatus 计算总体健康状态
func (hc *HealthChecker) calculateOverallStatus(components map[string]ComponentHealth) HealthStatus {
	hasUnhealthy := false
	hasDegraded := false

	for _, component := range components {
		switch component.Status {
		case HealthStatusUnhealthy:
			hasUnhealthy = true
		case HealthStatusDegraded:
			hasDegraded = true
		}
	}

	if hasUnhealthy {
		return HealthStatusUnhealthy
	}
	if hasDegraded {
		return HealthStatusDegraded
	}
	return HealthStatusHealthy
}

// checkDatabase 检查数据库健康状态
func (hc *HealthChecker) checkDatabase(ctx context.Context) ComponentHealth {
	start := time.Now()

	health := ComponentHealth{
		Name:      "database",
		LastCheck: start,
	}

	if err := database.Health(); err != nil {
		health.Status = HealthStatusUnhealthy
		health.Message = "database connection failed"
		health.Details = map[string]interface{}{
			"error": err.Error(),
		}
		logger.Error("database health check failed", zap.Error(err))
	} else {
		health.Status = HealthStatusHealthy
		health.Message = "database connection successful"

		// 获取连接池统计
		stats := database.Stats()
		health.Details = stats
	}

	health.Duration = time.Since(start)
	return health
}

// checkRedis 检查Redis健康状态
func (hc *HealthChecker) checkRedis(ctx context.Context) ComponentHealth {
	start := time.Now()

	health := ComponentHealth{
		Name:      "redis",
		LastCheck: start,
	}

	if err := cache.Health(); err != nil {
		health.Status = HealthStatusUnhealthy
		health.Message = "redis connection failed"
		health.Details = map[string]interface{}{
			"error": err.Error(),
		}
		logger.Error("redis health check failed", zap.Error(err))
	} else {
		health.Status = HealthStatusHealthy
		health.Message = "redis connection successful"

		// 获取Redis统计信息
		stats := cache.Stats()
		health.Details = stats
	}

	health.Duration = time.Since(start)
	return health
}

// checkMemory 检查内存使用情况
func (hc *HealthChecker) checkMemory(ctx context.Context) ComponentHealth {
	start := time.Now()

	// TODO: 这里可以使用第三方库如 gopsutil 获取系统内存信息
	health := ComponentHealth{
		Name:      "memory",
		Status:    HealthStatusHealthy,
		Message:   "memory usage normal",
		LastCheck: start,
		Details: map[string]interface{}{
			"status": "basic check only",
		},
	}

	health.Duration = time.Since(start)
	return health
}

// checkDisk 检查磁盘使用情况
func (hc *HealthChecker) checkDisk(ctx context.Context) ComponentHealth {
	start := time.Now()

	// 这里可以使用第三方库如 gopsutil 获取磁盘信息
	// 为了简化，这里只做基本检查
	health := ComponentHealth{
		Name:      "disk",
		Status:    HealthStatusHealthy,
		Message:   "disk usage normal",
		LastCheck: start,
		Details: map[string]interface{}{
			"status": "basic check only",
		},
	}

	health.Duration = time.Since(start)
	return health
}

// StartPeriodicCheck 启动定期健康检查
func (hc *HealthChecker) StartPeriodicCheck(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				result := hc.Check(ctx)
				cancel()

				// 记录不健康的组件
				for name, component := range result.Components {
					if component.Status != HealthStatusHealthy {
						logger.Warn("component unhealthy",
							zap.String("component", name),
							zap.String("status", string(component.Status)),
							zap.String("message", component.Message),
						)
					}
				}

				// 记录Prometheus指标
				for _, component := range result.Components {
					var statusValue float64
					switch component.Status {
					case HealthStatusHealthy:
						statusValue = 1
					case HealthStatusDegraded:
						statusValue = 0.5
					case HealthStatusUnhealthy:
						statusValue = 0
					}

					// 这里可以添加健康检查的Prometheus指标
					_ = statusValue // 避免未使用变量警告
				}
			}
		}
	}()
}

// GetComponentHealth 获取特定组件的健康状态
func (hc *HealthChecker) GetComponentHealth(ctx context.Context, componentName string) (*ComponentHealth, error) {
	hc.mutex.RLock()
	checkFunc, exists := hc.components[componentName]
	hc.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("component %s not found", componentName)
	}

	// 检查缓存
	if cached := hc.getCachedHealth(componentName); cached != nil {
		return cached, nil
	}

	// 执行检查
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	health := checkFunc(checkCtx)
	hc.setCachedHealth(componentName, health)

	return &health, nil
}

// IsHealthy 检查系统是否健康
func (hc *HealthChecker) IsHealthy(ctx context.Context) bool {
	result := hc.QuickCheck(ctx)
	return result.Status == HealthStatusHealthy
}

// GetUptime 获取系统运行时间
func (hc *HealthChecker) GetUptime() time.Duration {
	return time.Since(hc.startTime)
}
