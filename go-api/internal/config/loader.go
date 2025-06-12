package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

var globalConfig *Config

// Load 加载配置文件
func Load() (*Config, error) {
	// 首先加载.env文件
	if err := loadEnvFile(); err != nil {
		// .env文件不存在不是致命错误，继续执行
		fmt.Printf("Warning: %v\n", err)
	}

	v := viper.New()

	// 设置配置文件
	v.SetConfigName("config")
	v.SetConfigType("yaml")

	// 添加多个配置文件搜索路径
	v.AddConfigPath("./configs")
	v.AddConfigPath("../configs")
	v.AddConfigPath("../../configs") // 从go-api目录向上两级找
	v.AddConfigPath(".")
	v.AddConfigPath("..")

	// 读取配置文件
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// 环境变量支持
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// 绑定关键环境变量
	bindCriticalEnvVars(v)

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// 处理敏感信息的环境变量覆盖
	if err := overrideSensitiveConfig(&config); err != nil {
		return nil, fmt.Errorf("failed to override sensitive config: %w", err)
	}

	// 验证配置
	if err := validate(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	globalConfig = &config
	return &config, nil
}

// LoadForTest 为测试加载配置，使用测试默认值
func LoadForTest() (*Config, error) {
	config := &Config{
		Server: ServerConfig{
			Host:         "localhost",
			Port:         8080,
			Mode:         "test",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Database: DatabaseConfig{
			Host:            "localhost",
			Port:            5432,
			User:            "postgres",
			Password:        "password",
			DBName:          "ai_agent", // 修改为与docker-compose一致
			SSLMode:         "disable",
			MaxOpenConns:    10,
			MaxIdleConns:    5,
			ConnMaxLifetime: time.Hour,
			ConnMaxIdleTime: 10 * time.Minute,
		},
		Redis: RedisConfig{
			Addr:         "localhost:6379",
			Password:     "",
			DB:           0, // 修改为与docker-compose一致
			PoolSize:     10,
			MinIdleConns: 5,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
		},
		JWT: JWTConfig{
			Secret:       "test-jwt-secret-key-for-testing-only-32-chars-minimum",
			ExpireHours:  24,
			RefreshHours: 168,
			Issuer:       "ai-agent-test",
		},
		AI: AIConfig{
			BaseURL:          "http://localhost:8000",
			Timeout:          30 * time.Second,
			RetryAttempts:    3,
			DefaultModel:     "gpt-3.5-turbo",
			MaxTokens:        4096,
			TemperatureLimit: 2.0,
		},
		Plugin: PluginConfig{
			RegistryURL:    "http://localhost:8080/api/v1/plugins",
			SandboxEnabled: true,
			CPULimit:       "100m",
			MemoryLimit:    "128Mi",
			Timeout:        30 * time.Second,
			MaxConcurrent:  10,
		},
		Log: LogConfig{
			Level:      "debug",
			Format:     "console",
			Output:     "stdout",
			FilePath:   "./logs/test.log",
			MaxSize:    100,
			MaxBackups: 10,
			MaxAge:     30,
			Compress:   true,
		},
	}

	// 尝试从环境变量覆盖一些配置
	if redisAddr := os.Getenv("REDIS_ADDR"); redisAddr != "" {
		config.Redis.Addr = redisAddr
	}
	if dbHost := os.Getenv("DB_HOST"); dbHost != "" {
		config.Database.Host = dbHost
	}
	if dbPassword := os.Getenv("DB_PASSWORD"); dbPassword != "" {
		config.Database.Password = dbPassword
	}
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		config.JWT.Secret = jwtSecret
	}

	globalConfig = config
	return config, nil
}

// loadEnvFile 加载.env文件
func loadEnvFile() error {
	// 尝试多个可能的.env文件位置
	envPaths := []string{
		".env",
		"../.env",
		"../../.env",
	}

	var envFile string
	for _, path := range envPaths {
		if absPath, err := filepath.Abs(path); err == nil {
			if _, err := os.Stat(absPath); err == nil {
				envFile = absPath
				break
			}
		}
	}

	if envFile == "" {
		return fmt.Errorf(".env file not found in any of the expected locations")
	}

	if err := godotenv.Load(envFile); err != nil {
		return fmt.Errorf("failed to load .env file from %s: %w", envFile, err)
	}

	fmt.Printf("Loaded .env file from: %s\n", envFile)
	return nil
}

// bindCriticalEnvVars 绑定关键的环境变量
func bindCriticalEnvVars(v *viper.Viper) {
	// 敏感信息
	v.BindEnv("database.password", "DB_PASSWORD")
	v.BindEnv("redis.password", "REDIS_PASSWORD")
	v.BindEnv("jwt.secret", "JWT_SECRET")

	// 可能需要环境差异的配置
	v.BindEnv("server.mode", "SERVER_MODE")
	v.BindEnv("server.port", "SERVER_PORT")
	v.BindEnv("log.level", "LOG_LEVEL")
	v.BindEnv("log.output", "LOG_OUTPUT")
	v.BindEnv("database.host", "DB_HOST")
	v.BindEnv("database.port", "DB_PORT")
	v.BindEnv("database.user", "DB_USER")
	v.BindEnv("database.dbname", "DB_NAME")
	v.BindEnv("redis.addr", "REDIS_ADDR")
}

// Get 获取全局配置
func Get() *Config {
	return globalConfig
}

// overrideSensitiveConfig 覆盖敏感配置
func overrideSensitiveConfig(config *Config) error {
	// 数据库密码
	if dbPassword := os.Getenv("DB_PASSWORD"); dbPassword != "" {
		config.Database.Password = dbPassword
	}

	// Redis密码
	if redisPassword := os.Getenv("REDIS_PASSWORD"); redisPassword != "" {
		config.Redis.Password = redisPassword
	}

	// JWT密钥
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		config.JWT.Secret = jwtSecret
	}

	// 其他可能的环境变量覆盖
	if serverMode := os.Getenv("SERVER_MODE"); serverMode != "" {
		config.Server.Mode = serverMode
	}

	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.Log.Level = logLevel
	}

	return nil
}

// validate 验证配置
func validate(config *Config) error {
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	if config.Database.Host == "" {
		return fmt.Errorf("database host cannot be empty")
	}

	if config.Redis.Addr == "" {
		return fmt.Errorf("redis address cannot be empty")
	}

	if config.JWT.Secret == "" {
		return fmt.Errorf("JWT secret cannot be empty")
	}

	if len(config.JWT.Secret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters long")
	}

	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLogLevels[config.Log.Level] {
		return fmt.Errorf("invalid log level: %s", config.Log.Level)
	}

	validLogFormats := map[string]bool{
		"json": true, "console": true,
	}
	if !validLogFormats[config.Log.Format] {
		return fmt.Errorf("invalid log format: %s", config.Log.Format)
	}

	return nil
}
