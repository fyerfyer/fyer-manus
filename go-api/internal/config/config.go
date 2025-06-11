package config

import "time"

// Config 应用配置结构
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	AI       AIConfig       `mapstructure:"ai"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Plugin   PluginConfig   `mapstructure:"plugin"`
	Log      LogConfig      `mapstructure:"log"`
}

// ServerConfig HTTP服务器配置
type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	Mode         string        `mapstructure:"mode"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	DBName          string        `mapstructure:"dbname"`
	SSLMode         string        `mapstructure:"sslmode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
}

// RedisConfig Redis配置
type RedisConfig struct {
	Addr         string        `mapstructure:"addr"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// AIConfig AI服务配置
type AIConfig struct {
	BaseURL          string        `mapstructure:"base_url"`
	Timeout          time.Duration `mapstructure:"timeout"`
	RetryAttempts    int           `mapstructure:"retry_attempts"`
	DefaultModel     string        `mapstructure:"default_model"`
	MaxTokens        int           `mapstructure:"max_tokens"`
	TemperatureLimit float64       `mapstructure:"temperature_limit"`
}

// JWTConfig JWT配置
type JWTConfig struct {
	Secret       string `mapstructure:"secret"`
	ExpireHours  int    `mapstructure:"expire_hours"`
	RefreshHours int    `mapstructure:"refresh_hours"`
	Issuer       string `mapstructure:"issuer"`
}

// PluginConfig 插件配置
type PluginConfig struct {
	RegistryURL    string        `mapstructure:"registry_url"`
	SandboxEnabled bool          `mapstructure:"sandbox_enabled"`
	CPULimit       string        `mapstructure:"cpu_limit"`
	MemoryLimit    string        `mapstructure:"memory_limit"`
	Timeout        time.Duration `mapstructure:"timeout"`
	MaxConcurrent  int           `mapstructure:"max_concurrent"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	FilePath   string `mapstructure:"file_path"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
	Compress   bool   `mapstructure:"compress"`
}
