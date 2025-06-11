package database

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	appLogger "github.com/fyerfyer/fyer-manus/go-api/internal/logger"
)

var globalDB *gorm.DB

// Init 初始化PostgreSQL连接
func Init(cfg *config.DatabaseConfig) error {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)

	// GORM配置
	gormConfig := &gorm.Config{
		Logger: logger.New(
			&gormLogger{},
			logger.Config{
				SlowThreshold:             200 * time.Millisecond,
				LogLevel:                  logger.Warn,
				IgnoreRecordNotFoundError: true,
				Colorful:                  false,
			},
		),
		NowFunc: func() time.Time {
			return time.Now().Local()
		},
	}

	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return fmt.Errorf("failed to connect database: %w", err)
	}

	// 获取底层sql.DB对象进行连接池配置
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get sql.DB: %w", err)
	}

	// 配置连接池
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	// 测试连接
	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	globalDB = db
	appLogger.Info("Database connected successfully")
	return nil
}

// Get 获取数据库连接
func Get() *gorm.DB {
	return globalDB
}

// Close 关闭数据库连接
func Close() error {
	if globalDB != nil {
		sqlDB, err := globalDB.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}

// Health 检查数据库连接健康状态
func Health() error {
	if globalDB == nil {
		return fmt.Errorf("database not initialized")
	}

	sqlDB, err := globalDB.DB()
	if err != nil {
		return fmt.Errorf("failed to get sql.DB: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	return nil
}

// Stats 获取数据库连接池统计信息
func Stats() map[string]interface{} {
	if globalDB == nil {
		return map[string]interface{}{"status": "not_initialized"}
	}

	sqlDB, err := globalDB.DB()
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	stats := sqlDB.Stats()
	return map[string]interface{}{
		"max_open_connections": stats.MaxOpenConnections,
		"open_connections":     stats.OpenConnections,
		"in_use":               stats.InUse,
		"idle":                 stats.Idle,
		"wait_count":           stats.WaitCount,
		"wait_duration":        stats.WaitDuration.String(),
		"max_idle_closed":      stats.MaxIdleClosed,
		"max_idle_time_closed": stats.MaxIdleTimeClosed,
		"max_lifetime_closed":  stats.MaxLifetimeClosed,
	}
}

// Transaction 执行数据库事务
func Transaction(fn func(*gorm.DB) error) error {
	return globalDB.Transaction(fn)
}

// gormLogger 适配器，将GORM日志转发到应用日志系统
type gormLogger struct{}

func (l *gormLogger) Printf(format string, args ...interface{}) {
	appLogger.Info(fmt.Sprintf(format, args...))
}
