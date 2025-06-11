package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// Limiter 限流器
type Limiter struct {
	redis   *redis.Client
	manager *StrategyManager
	buckets map[string]*rate.Limiter // 本地令牌桶缓存
}

// NewLimiter 创建限流器
func NewLimiter() *Limiter {
	manager := NewStrategyManager()
	limiter := &Limiter{
		redis:   cache.Get(),
		manager: manager,
		buckets: make(map[string]*rate.Limiter),
	}

	// 注册策略实现
	limiter.manager.RegisterStrategy(&FixedWindowStrategy{redis: limiter.redis})
	limiter.manager.RegisterStrategy(&SlidingWindowStrategy{redis: limiter.redis})
	limiter.manager.RegisterStrategy(&TokenBucketStrategy{redis: limiter.redis, buckets: limiter.buckets})
	limiter.manager.RegisterStrategy(&LeakyBucketStrategy{redis: limiter.redis})

	// 加载默认规则
	for _, rule := range GetDefaultRules() {
		limiter.manager.AddRule(rule)
	}

	return limiter
}

// Check 检查是否超过限流
func (l *Limiter) Check(rule Rule, identifier string) (*Result, error) {
	// 检查是否为例外
	if l.manager.IsException(rule, identifier) {
		return &Result{Allowed: true}, nil
	}

	return l.manager.Check(rule, identifier)
}

// CheckByPath 根据路径检查限流
func (l *Limiter) CheckByPath(path, method, identifier string, headers map[string]string) (*Result, error) {
	rule := l.manager.FindMatchingRule(path, method, headers)
	if rule == nil {
		return &Result{Allowed: true}, nil
	}

	return l.Check(*rule, identifier)
}

// AddRule 添加限流规则
func (l *Limiter) AddRule(rule Rule) error {
	if err := ValidateConfig(rule.Config); err != nil {
		return fmt.Errorf("invalid rule config: %w", err)
	}
	l.manager.AddRule(rule)
	return nil
}

// FixedWindowStrategy 固定窗口策略
type FixedWindowStrategy struct {
	redis *redis.Client
}

func (s *FixedWindowStrategy) Name() Strategy {
	return StrategyFixedWindow
}

func (s *FixedWindowStrategy) Check(key string, config Config) (*Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 计算当前窗口
	now := time.Now()
	window := now.Truncate(config.Period).Unix()
	windowKey := fmt.Sprintf("%s:%d", key, window)

	// Lua脚本实现原子操作
	script := `
        local key = KEYS[1]
        local limit = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local current = redis.call('GET', key)
        
        if current == false then
            current = 0
        else
            current = tonumber(current)
        end
        
        if current < limit then
            redis.call('INCR', key)
            redis.call('EXPIRE', key, window)
            return {1, limit - current - 1, current + 1}
        else
            return {0, 0, current}
        end
    `

	windowDuration := int(config.Period.Seconds())
	result, err := s.redis.Eval(ctx, script, []string{windowKey}, config.Rate, windowDuration).Result()
	if err != nil {
		logger.Error("fixed window rate limit failed", zap.Error(err), zap.String("key", key))
		return &Result{Allowed: true}, nil // 降级策略：限流失败时允许请求
	}

	values := result.([]interface{})
	allowed := values[0].(int64) == 1
	remaining := int(values[1].(int64))
	totalRequests := int(values[2].(int64))

	resetTime := now.Truncate(config.Period).Add(config.Period)
	retryAfter := time.Duration(0)
	if !allowed {
		retryAfter = time.Until(resetTime)
	}

	return &Result{
		Allowed:       allowed,
		Remaining:     remaining,
		RetryAfter:    retryAfter,
		ResetTime:     resetTime,
		TotalRequests: totalRequests,
	}, nil
}

// SlidingWindowStrategy 滑动窗口策略
type SlidingWindowStrategy struct {
	redis *redis.Client
}

func (s *SlidingWindowStrategy) Name() Strategy {
	return StrategySlidingWindow
}

func (s *SlidingWindowStrategy) Check(key string, config Config) (*Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	now := time.Now()
	windowStart := now.Add(-config.Period).UnixNano()

	// 使用Lua脚本实现滑动窗口
	script := `
        local key = KEYS[1]
        local limit = tonumber(ARGV[1])
        local window_start = tonumber(ARGV[2])
        local current_time = tonumber(ARGV[3])
        
        -- 清理过期记录
        redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
        
        -- 获取当前窗口内的请求数
        local current_count = redis.call('ZCARD', key)
        
        if current_count < limit then
            -- 添加当前请求
            redis.call('ZADD', key, current_time, current_time)
            redis.call('EXPIRE', key, 3600) -- 1小时过期
            return {1, limit - current_count - 1, current_count + 1}
        else
            return {0, 0, current_count}
        end
    `

	result, err := s.redis.Eval(ctx, script, []string{key},
		config.Rate, windowStart, now.UnixNano()).Result()
	if err != nil {
		logger.Error("sliding window rate limit failed", zap.Error(err), zap.String("key", key))
		return &Result{Allowed: true}, nil
	}

	values := result.([]interface{})
	allowed := values[0].(int64) == 1
	remaining := int(values[1].(int64))
	totalRequests := int(values[2].(int64))

	return &Result{
		Allowed:       allowed,
		Remaining:     remaining,
		RetryAfter:    time.Second, // 滑动窗口建议1秒后重试
		ResetTime:     now.Add(config.Period),
		TotalRequests: totalRequests,
	}, nil
}

// TokenBucketStrategy 令牌桶策略
type TokenBucketStrategy struct {
	redis   *redis.Client
	buckets map[string]*rate.Limiter
}

func (s *TokenBucketStrategy) Name() Strategy {
	return StrategyTokenBucket
}

func (s *TokenBucketStrategy) Check(key string, config Config) (*Result, error) {
	// 使用golang.org/x/time/rate的本地令牌桶
	limiter, exists := s.buckets[key]
	if !exists {
		burst := config.Burst
		if burst <= 0 {
			burst = config.Rate
		}

		// 计算每秒令牌数
		tokensPerSecond := float64(config.Rate) / config.Period.Seconds()
		limiter = rate.NewLimiter(rate.Limit(tokensPerSecond), burst)
		s.buckets[key] = limiter
	}

	allowed := limiter.Allow()
	remaining := limiter.Tokens()

	retryAfter := time.Duration(0)
	if !allowed {
		retryAfter = limiter.Reserve().Delay()
	}

	return &Result{
		Allowed:       allowed,
		Remaining:     int(remaining),
		RetryAfter:    retryAfter,
		ResetTime:     time.Now().Add(retryAfter),
		TotalRequests: config.Rate - int(remaining),
	}, nil
}

// LeakyBucketStrategy 漏桶策略
type LeakyBucketStrategy struct {
	redis *redis.Client
}

func (s *LeakyBucketStrategy) Name() Strategy {
	return StrategyLeakyBucket
}

func (s *LeakyBucketStrategy) Check(key string, config Config) (*Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	now := time.Now().UnixNano()
	bucketKey := key + ":leaky"

	// 漏桶算法Lua脚本
	script := `
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local rate = tonumber(ARGV[2])
        local period_ns = tonumber(ARGV[3])
        local current_time = tonumber(ARGV[4])
        
        local bucket = redis.call('HMGET', key, 'volume', 'last_leak')
        local volume = tonumber(bucket[1]) or 0
        local last_leak = tonumber(bucket[2]) or current_time
        
        -- 计算漏出的水量
        local time_passed = current_time - last_leak
        local leaked = time_passed * rate / period_ns
        
        -- 更新桶中水量
        volume = math.max(0, volume - leaked)
        
        if volume < capacity then
            volume = volume + 1
            redis.call('HMSET', key, 'volume', volume, 'last_leak', current_time)
            redis.call('EXPIRE', key, 3600)
            return {1, capacity - volume, volume}
        else
            redis.call('HMSET', key, 'volume', volume, 'last_leak', current_time)
            redis.call('EXPIRE', key, 3600)
            return {0, 0, volume}
        end
    `

	capacity := config.Burst
	if capacity <= 0 {
		capacity = config.Rate
	}

	result, err := s.redis.Eval(ctx, script, []string{bucketKey},
		capacity, config.Rate, config.Period.Nanoseconds(), now).Result()
	if err != nil {
		logger.Error("leaky bucket rate limit failed", zap.Error(err), zap.String("key", key))
		return &Result{Allowed: true}, nil
	}

	values := result.([]interface{})
	allowed := values[0].(int64) == 1
	remaining := int(values[1].(int64))
	totalRequests := int(values[2].(int64))

	retryAfter := time.Duration(0)
	if !allowed {
		// 计算桶不满时的等待时间
		retryAfter = config.Period / time.Duration(config.Rate)
	}

	return &Result{
		Allowed:       allowed,
		Remaining:     remaining,
		RetryAfter:    retryAfter,
		ResetTime:     time.Now().Add(retryAfter),
		TotalRequests: totalRequests,
	}, nil
}

// GetStats 获取限流统计信息
func (l *Limiter) GetStats(key string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stats := make(map[string]interface{})

	// 获取所有相关键
	pattern := key + "*"
	keys, err := l.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		switch {
		case strings.Contains(k, ":bucket"):
			// 令牌桶统计
			bucket, err := l.redis.HMGet(ctx, k, "tokens", "last_refill").Result()
			if err == nil {
				stats[k] = map[string]interface{}{
					"tokens":      bucket[0],
					"last_refill": bucket[1],
				}
			}
		case strings.Contains(k, ":leaky"):
			// 漏桶统计
			bucket, err := l.redis.HMGet(ctx, k, "volume", "last_leak").Result()
			if err == nil {
				stats[k] = map[string]interface{}{
					"volume":    bucket[0],
					"last_leak": bucket[1],
				}
			}
		default:
			// 窗口计数
			val, err := l.redis.Get(ctx, k).Result()
			if err == nil {
				count, _ := strconv.Atoi(val)
				stats[k] = count
			}
		}
	}

	return stats, nil
}

// Reset 重置限流状态
func (l *Limiter) Reset(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pattern := key + "*"
	keys, err := l.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return l.redis.Del(ctx, keys...).Err()
	}

	return nil
}

// SetKeyGenerator 设置键生成器
func (l *Limiter) SetKeyGenerator(keyGen KeyGenerator) {
	l.manager.SetKeyGenerator(keyGen)
}

// GetManager 获取策略管理器
func (l *Limiter) GetManager() *StrategyManager {
	return l.manager
}
