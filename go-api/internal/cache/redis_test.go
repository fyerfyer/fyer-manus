package cache

import (
	"context"
	"testing"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInit(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	// 测试Redis初始化
	err = Init(&cfg.Redis)
	assert.NoError(t, err, "redis init should succeed")

	// 验证全局客户端不为空
	client := Get()
	assert.NotNil(t, client, "global client should not be nil")

	// 清理
	defer func() {
		err := Close()
		assert.NoError(t, err, "redis close should succeed")
	}()
}

func TestHealth(t *testing.T) {
	// 加载配置并初始化Redis
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Redis)
	require.NoError(t, err, "redis init should succeed")

	// 测试健康检查
	err = Health()
	assert.NoError(t, err, "health check should pass")

	// 清理
	defer func() {
		err := Close()
		assert.NoError(t, err, "redis close should succeed")
	}()
}

func TestHealthWithoutInit(t *testing.T) {
	// 重置全局客户端
	originalClient := globalClient
	globalClient = nil

	// 测试未初始化时的健康检查
	err := Health()
	assert.Error(t, err, "health check should fail when not initialized")
	assert.Contains(t, err.Error(), "not initialized")

	// 恢复全局客户端
	globalClient = originalClient
}

func TestSetAndGet(t *testing.T) {
	// 初始化Redis
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Redis)
	require.NoError(t, err, "redis init should succeed")

	ctx := context.Background()
	testKey := "test:key"
	testValue := "test_value"

	// 测试设置值
	err = Set(ctx, testKey, testValue, time.Minute)
	assert.NoError(t, err, "set should succeed")

	// 测试获取值
	value, err := GetValue(ctx, testKey)
	assert.NoError(t, err, "get should succeed")
	assert.Equal(t, testValue, value, "value should match")

	// 清理测试数据
	err = Del(ctx, testKey)
	assert.NoError(t, err, "delete should succeed")

	// 清理
	defer func() {
		err := Close()
		assert.NoError(t, err, "redis close should succeed")
	}()
}

func TestExists(t *testing.T) {
	// 初始化Redis
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Redis)
	require.NoError(t, err, "redis init should succeed")

	ctx := context.Background()
	testKey := "test:exists"

	// 测试不存在的键
	count, err := Exists(ctx, testKey)
	assert.NoError(t, err, "exists check should succeed")
	assert.Equal(t, int64(0), count, "key should not exist")

	// 设置键
	err = Set(ctx, testKey, "value", time.Minute)
	require.NoError(t, err, "set should succeed")

	// 测试存在的键
	count, err = Exists(ctx, testKey)
	assert.NoError(t, err, "exists check should succeed")
	assert.Equal(t, int64(1), count, "key should exist")

	// 清理
	err = Del(ctx, testKey)
	assert.NoError(t, err, "delete should succeed")

	defer func() {
		err := Close()
		assert.NoError(t, err, "redis close should succeed")
	}()
}

func TestTTLAndExpire(t *testing.T) {
	// 初始化Redis
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Redis)
	require.NoError(t, err, "redis init should succeed")

	ctx := context.Background()
	testKey := "test:ttl"

	// 设置带过期时间的键
	err = Set(ctx, testKey, "value", time.Minute)
	require.NoError(t, err, "set should succeed")

	// 检查TTL
	ttl, err := TTL(ctx, testKey)
	assert.NoError(t, err, "ttl check should succeed")
	assert.Greater(t, ttl, time.Duration(0), "ttl should be positive")

	// 更新过期时间
	err = Expire(ctx, testKey, 2*time.Minute)
	assert.NoError(t, err, "expire should succeed")

	// 再次检查TTL
	newTTL, err := TTL(ctx, testKey)
	assert.NoError(t, err, "ttl check should succeed")
	assert.Greater(t, newTTL, ttl, "new ttl should be greater")

	// 清理
	err = Del(ctx, testKey)
	assert.NoError(t, err, "delete should succeed")

	defer func() {
		err := Close()
		assert.NoError(t, err, "redis close should succeed")
	}()
}

func TestHashOperations(t *testing.T) {
	// 初始化Redis
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Redis)
	require.NoError(t, err, "redis init should succeed")

	ctx := context.Background()
	hashKey := "test:hash"

	// 设置哈希字段
	err = HSet(ctx, hashKey, "field1", "value1", "field2", "value2")
	assert.NoError(t, err, "hset should succeed")

	// 获取单个字段
	value, err := HGet(ctx, hashKey, "field1")
	assert.NoError(t, err, "hget should succeed")
	assert.Equal(t, "value1", value, "hash value should match")

	// 获取所有字段
	all, err := HGetAll(ctx, hashKey)
	assert.NoError(t, err, "hgetall should succeed")
	assert.Equal(t, "value1", all["field1"], "hash field1 should match")
	assert.Equal(t, "value2", all["field2"], "hash field2 should match")

	// 删除字段
	err = HDel(ctx, hashKey, "field1")
	assert.NoError(t, err, "hdel should succeed")

	// 验证字段被删除
	_, err = HGet(ctx, hashKey, "field1")
	assert.Error(t, err, "hget should fail for deleted field")

	// 清理
	err = Del(ctx, hashKey)
	assert.NoError(t, err, "delete should succeed")

	defer func() {
		err := Close()
		assert.NoError(t, err, "redis close should succeed")
	}()
}

func TestCounterOperations(t *testing.T) {
	// 初始化Redis
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Redis)
	require.NoError(t, err, "redis init should succeed")

	ctx := context.Background()
	counterKey := "test:counter"

	// 递增计数器
	count, err := Incr(ctx, counterKey)
	assert.NoError(t, err, "incr should succeed")
	assert.Equal(t, int64(1), count, "counter should be 1")

	// 按指定值递增
	count, err = IncrBy(ctx, counterKey, 5)
	assert.NoError(t, err, "incrby should succeed")
	assert.Equal(t, int64(6), count, "counter should be 6")

	// 清理
	err = Del(ctx, counterKey)
	assert.NoError(t, err, "delete should succeed")

	defer func() {
		err := Close()
		assert.NoError(t, err, "redis close should succeed")
	}()
}

func TestListOperations(t *testing.T) {
	// 初始化Redis
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Redis)
	require.NoError(t, err, "redis init should succeed")

	ctx := context.Background()
	listKey := "test:list"

	// 向列表添加元素
	err = LPush(ctx, listKey, "item1", "item2")
	assert.NoError(t, err, "lpush should succeed")

	// 获取列表长度
	length, err := LLen(ctx, listKey)
	assert.NoError(t, err, "llen should succeed")
	assert.Equal(t, int64(2), length, "list length should be 2")

	// 弹出元素
	item, err := RPop(ctx, listKey)
	assert.NoError(t, err, "rpop should succeed")
	assert.Equal(t, "item1", item, "popped item should match")

	// 清理
	err = Del(ctx, listKey)
	assert.NoError(t, err, "delete should succeed")

	defer func() {
		err := Close()
		assert.NoError(t, err, "redis close should succeed")
	}()
}

func TestSetOperations(t *testing.T) {
	// 初始化Redis
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Redis)
	require.NoError(t, err, "redis init should succeed")

	ctx := context.Background()
	setKey := "test:set"

	// 向集合添加成员
	err = SAdd(ctx, setKey, "member1", "member2")
	assert.NoError(t, err, "sadd should succeed")

	// 获取集合成员
	members, err := SMembers(ctx, setKey)
	assert.NoError(t, err, "smembers should succeed")
	assert.Len(t, members, 2, "set should have 2 members")

	// 移除成员
	err = SRem(ctx, setKey, "member1")
	assert.NoError(t, err, "srem should succeed")

	// 验证成员被移除
	members, err = SMembers(ctx, setKey)
	assert.NoError(t, err, "smembers should succeed")
	assert.Len(t, members, 1, "set should have 1 member")

	// 清理
	err = Del(ctx, setKey)
	assert.NoError(t, err, "delete should succeed")

	defer func() {
		err := Close()
		assert.NoError(t, err, "redis close should succeed")
	}()
}

func TestStats(t *testing.T) {
	// 初始化Redis
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Redis)
	require.NoError(t, err, "redis init should succeed")

	// 获取统计信息
	stats := Stats()
	assert.NotNil(t, stats, "stats should not be nil")

	// 验证基本统计字段存在
	assert.Contains(t, stats, "hits")
	assert.Contains(t, stats, "misses")
	assert.Contains(t, stats, "total_conns")

	t.Logf("Redis stats: %+v", stats)

	// 清理
	defer func() {
		err := Close()
		assert.NoError(t, err, "redis close should succeed")
	}()
}

func TestStatsWithoutInit(t *testing.T) {
	// 重置全局客户端
	originalClient := globalClient
	globalClient = nil

	// 测试未初始化时的统计信息
	stats := Stats()
	assert.Equal(t, "not_initialized", stats["status"])

	// 恢复全局客户端
	globalClient = originalClient
}

func TestKeys(t *testing.T) {
	// 初始化Redis
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Redis)
	require.NoError(t, err, "redis init should succeed")

	ctx := context.Background()

	// 设置测试键
	testKeys := []string{"test:keys:1", "test:keys:2", "other:key"}
	for _, key := range testKeys {
		err = Set(ctx, key, "value", time.Minute)
		require.NoError(t, err, "set should succeed")
	}

	// 查找匹配的键
	keys, err := Keys(ctx, "test:keys:*")
	assert.NoError(t, err, "keys should succeed")
	assert.Len(t, keys, 2, "should find 2 matching keys")

	// 清理
	for _, key := range testKeys {
		err = Del(ctx, key)
		assert.NoError(t, err, "delete should succeed")
	}

	defer func() {
		err := Close()
		assert.NoError(t, err, "redis close should succeed")
	}()
}

func TestClose(t *testing.T) {
	// 初始化Redis
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Redis)
	require.NoError(t, err, "redis init should succeed")

	// 测试关闭
	err = Close()
	assert.NoError(t, err, "redis close should succeed")

	// 重置全局客户端为nil，测试重复关闭
	globalClient = nil
	err = Close()
	assert.NoError(t, err, "closing nil client should not error")
}

func TestGet(t *testing.T) {
	// 测试未初始化时获取客户端
	originalClient := globalClient
	globalClient = nil

	client := Get()
	assert.Nil(t, client, "should return nil when not initialized")

	// 恢复全局客户端
	globalClient = originalClient
}
