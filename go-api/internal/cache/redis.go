package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
)

var globalClient *redis.Client

// Init 初始化Redis连接
func Init(cfg *config.RedisConfig) error {
	client := redis.NewClient(&redis.Options{
		Addr:            cfg.Addr,
		Password:        cfg.Password,
		DB:              cfg.DB,
		PoolSize:        cfg.PoolSize,
		MinIdleConns:    cfg.MinIdleConns,
		DialTimeout:     cfg.DialTimeout,
		ReadTimeout:     cfg.ReadTimeout,
		WriteTimeout:    cfg.WriteTimeout,
		MaxRetries:      3,
		MaxRetryBackoff: time.Millisecond * 100,
	})

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to connect redis: %w", err)
	}

	globalClient = client
	logger.Info("Redis connected successfully")
	return nil
}

// Get 获取Redis客户端
func Get() *redis.Client {
	return globalClient
}

// Close 关闭Redis连接
func Close() error {
	if globalClient != nil {
		return globalClient.Close()
	}
	return nil
}

// Health 检查Redis连接健康状态
func Health() error {
	if globalClient == nil {
		return fmt.Errorf("redis not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := globalClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}

	return nil
}

// Set 设置键值对
func Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return globalClient.Set(ctx, key, value, expiration).Err()
}

// GetValue 获取值
func GetValue(ctx context.Context, key string) (string, error) {
	return globalClient.Get(ctx, key).Result()
}

// Del 删除键
func Del(ctx context.Context, keys ...string) error {
	return globalClient.Del(ctx, keys...).Err()
}

// Exists 检查键是否存在
func Exists(ctx context.Context, keys ...string) (int64, error) {
	return globalClient.Exists(ctx, keys...).Result()
}

// TTL 获取键的过期时间
func TTL(ctx context.Context, key string) (time.Duration, error) {
	return globalClient.TTL(ctx, key).Result()
}

// Expire 设置键的过期时间
func Expire(ctx context.Context, key string, expiration time.Duration) error {
	return globalClient.Expire(ctx, key, expiration).Err()
}

// HSet 设置哈希字段
func HSet(ctx context.Context, key string, values ...interface{}) error {
	return globalClient.HSet(ctx, key, values...).Err()
}

// HGet 获取哈希字段值
func HGet(ctx context.Context, key, field string) (string, error) {
	return globalClient.HGet(ctx, key, field).Result()
}

// HGetAll 获取哈希所有字段
func HGetAll(ctx context.Context, key string) (map[string]string, error) {
	return globalClient.HGetAll(ctx, key).Result()
}

// HDel 删除哈希字段
func HDel(ctx context.Context, key string, fields ...string) error {
	return globalClient.HDel(ctx, key, fields...).Err()
}

// Incr 递增计数器
func Incr(ctx context.Context, key string) (int64, error) {
	return globalClient.Incr(ctx, key).Result()
}

// IncrBy 按指定值递增
func IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	return globalClient.IncrBy(ctx, key, value).Result()
}

// LPush 向列表头部添加元素
func LPush(ctx context.Context, key string, values ...interface{}) error {
	return globalClient.LPush(ctx, key, values...).Err()
}

// RPop 从列表尾部弹出元素
func RPop(ctx context.Context, key string) (string, error) {
	return globalClient.RPop(ctx, key).Result()
}

// LLen 获取列表长度
func LLen(ctx context.Context, key string) (int64, error) {
	return globalClient.LLen(ctx, key).Result()
}

// SAdd 向集合添加成员
func SAdd(ctx context.Context, key string, members ...interface{}) error {
	return globalClient.SAdd(ctx, key, members...).Err()
}

// SMembers 获取集合所有成员
func SMembers(ctx context.Context, key string) ([]string, error) {
	return globalClient.SMembers(ctx, key).Result()
}

// SRem 从集合移除成员
func SRem(ctx context.Context, key string, members ...interface{}) error {
	return globalClient.SRem(ctx, key, members...).Err()
}

// Keys 获取匹配模式的键
func Keys(ctx context.Context, pattern string) ([]string, error) {
	return globalClient.Keys(ctx, pattern).Result()
}

// FlushDB 清空当前数据库
func FlushDB(ctx context.Context) error {
	return globalClient.FlushDB(ctx).Err()
}

// Stats 获取Redis统计信息
func Stats() map[string]interface{} {
	if globalClient == nil {
		return map[string]interface{}{"status": "not_initialized"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	info, err := globalClient.Info(ctx, "stats").Result()
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	poolStats := globalClient.PoolStats()

	return map[string]interface{}{
		"hits":        poolStats.Hits,
		"misses":      poolStats.Misses,
		"timeouts":    poolStats.Timeouts,
		"total_conns": poolStats.TotalConns,
		"idle_conns":  poolStats.IdleConns,
		"stale_conns": poolStats.StaleConns,
		"info":        info,
	}
}
