package database

import (
	"context"
	"testing"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestInit(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	// 测试数据库初始化
	err = Init(&cfg.Database)
	assert.NoError(t, err, "database init should succeed")

	// 验证全局DB对象不为空
	db := Get()
	assert.NotNil(t, db, "global db should not be nil")

	// 清理
	defer func() {
		err := Close()
		assert.NoError(t, err, "database close should succeed")
	}()
}

func TestHealth(t *testing.T) {
	// 加载配置并初始化数据库
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Database)
	require.NoError(t, err, "database init should succeed")

	// 测试健康检查
	err = Health()
	assert.NoError(t, err, "health check should pass")

	// 清理
	defer func() {
		err := Close()
		assert.NoError(t, err, "database close should succeed")
	}()
}

func TestHealthWithoutInit(t *testing.T) {
	// 重置全局DB
	originalDB := globalDB
	globalDB = nil

	// 测试未初始化时的健康检查
	err := Health()
	assert.Error(t, err, "health check should fail when not initialized")
	assert.Contains(t, err.Error(), "not initialized")

	// 恢复全局DB
	globalDB = originalDB
}

func TestStats(t *testing.T) {
	// 加载配置并初始化数据库
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Database)
	require.NoError(t, err, "database init should succeed")

	// 测试统计信息
	stats := Stats()
	assert.NotNil(t, stats, "stats should not be nil")

	// 验证基本统计字段存在
	assert.Contains(t, stats, "max_open_connections")
	assert.Contains(t, stats, "open_connections")
	assert.Contains(t, stats, "in_use")
	assert.Contains(t, stats, "idle")

	t.Logf("Database stats: %+v", stats)

	// 清理
	defer func() {
		err := Close()
		assert.NoError(t, err, "database close should succeed")
	}()
}

func TestStatsWithoutInit(t *testing.T) {
	// 重置全局DB
	originalDB := globalDB
	globalDB = nil

	// 测试未初始化时的统计信息
	stats := Stats()
	assert.Equal(t, "not_initialized", stats["status"])

	// 恢复全局DB
	globalDB = originalDB
}

func TestTransaction(t *testing.T) {
	// 加载配置并初始化数据库
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Database)
	require.NoError(t, err, "database init should succeed")

	// 测试成功的事务
	err = Transaction(func(tx *gorm.DB) error {
		// 执行一个简单的查询
		var result int
		return tx.Raw("SELECT 1").Scan(&result).Error
	})
	assert.NoError(t, err, "transaction should succeed")

	// 测试失败的事务
	err = Transaction(func(tx *gorm.DB) error {
		// 故意返回错误来测试回滚
		return assert.AnError
	})
	assert.Error(t, err, "transaction should fail and rollback")

	// 清理
	defer func() {
		err := Close()
		assert.NoError(t, err, "database close should succeed")
	}()
}

func TestClose(t *testing.T) {
	// 加载配置并初始化数据库
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Database)
	require.NoError(t, err, "database init should succeed")

	// 测试关闭数据库
	err = Close()
	assert.NoError(t, err, "database close should succeed")

	// 重置全局DB为nil，测试重复关闭
	globalDB = nil
	err = Close()
	assert.NoError(t, err, "closing nil db should not error")
}

func TestConnectionPool(t *testing.T) {
	// 加载配置并初始化数据库
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load config")

	err = Init(&cfg.Database)
	require.NoError(t, err, "database init should succeed")

	// 获取连接池信息
	stats := Stats()
	maxOpen := stats["max_open_connections"]

	t.Logf("Max open connections: %v", maxOpen)
	assert.NotNil(t, maxOpen, "max open connections should be set")

	// 验证连接池配置生效
	db := Get()
	sqlDB, err := db.DB()
	require.NoError(t, err, "should get sql.DB")

	// 测试ping多次以验证连接池
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		err = sqlDB.PingContext(ctx)
		cancel()
		assert.NoError(t, err, "ping should succeed")
	}

	// 清理
	defer func() {
		err := Close()
		assert.NoError(t, err, "database close should succeed")
	}()
}

func TestGet(t *testing.T) {
	// 测试未初始化时获取DB
	originalDB := globalDB
	globalDB = nil

	db := Get()
	assert.Nil(t, db, "should return nil when not initialized")

	// 恢复全局DB
	globalDB = originalDB
}

func TestGormLogger(t *testing.T) {
	// 测试GORM日志适配器
	logger := &gormLogger{}

	// 测试Printf方法不会panic
	assert.NotPanics(t, func() {
		logger.Printf("test log: %s", "message")
	}, "gorm logger printf should not panic")
}
