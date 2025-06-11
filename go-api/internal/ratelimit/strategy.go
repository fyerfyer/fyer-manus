package ratelimit

import (
	"fmt"
	"time"
)

// Strategy 限流策略类型
type Strategy string

const (
	StrategyFixedWindow   Strategy = "fixed_window"   // 固定窗口
	StrategySlidingWindow Strategy = "sliding_window" // 滑动窗口
	StrategyTokenBucket   Strategy = "token_bucket"   // 令牌桶
	StrategyLeakyBucket   Strategy = "leaky_bucket"   // 漏桶
)

// Config 限流配置
type Config struct {
	Strategy  Strategy      `yaml:"strategy" json:"strategy"`
	Rate      int           `yaml:"rate" json:"rate"`             // 限制速率
	Period    time.Duration `yaml:"period" json:"period"`         // 时间窗口
	Burst     int           `yaml:"burst" json:"burst"`           // 突发容量
	KeyPrefix string        `yaml:"key_prefix" json:"key_prefix"` // Redis键前缀
	Enabled   bool          `yaml:"enabled" json:"enabled"`       // 是否启用
}

// Rule 限流规则
type Rule struct {
	Name       string            `yaml:"name" json:"name"`
	Pattern    string            `yaml:"pattern" json:"pattern"` // 路径匹配模式
	Methods    []string          `yaml:"methods" json:"methods"` // HTTP方法
	Config     Config            `yaml:"config" json:"config"`
	Headers    map[string]string `yaml:"headers" json:"headers"`       // 头部匹配
	UserTypes  []string          `yaml:"user_types" json:"user_types"` // 用户类型
	Exceptions []string          `yaml:"exceptions" json:"exceptions"` // 例外IP/用户
}

// KeyGenerator 键生成器接口
type KeyGenerator interface {
	GenerateKey(identifier string, rule Rule) string
}

// DefaultKeyGenerator 默认键生成器
type DefaultKeyGenerator struct{}

// GenerateKey 生成Redis键
func (g *DefaultKeyGenerator) GenerateKey(identifier string, rule Rule) string {
	prefix := rule.Config.KeyPrefix
	if prefix == "" {
		prefix = "ratelimit"
	}
	return fmt.Sprintf("%s:%s:%s", prefix, rule.Name, identifier)
}

// IPKeyGenerator IP地址键生成器
type IPKeyGenerator struct{}

func (g *IPKeyGenerator) GenerateKey(identifier string, rule Rule) string {
	prefix := rule.Config.KeyPrefix
	if prefix == "" {
		prefix = "ratelimit:ip"
	}
	return fmt.Sprintf("%s:%s:%s", prefix, rule.Name, identifier)
}

// UserKeyGenerator 用户键生成器
type UserKeyGenerator struct{}

func (g *UserKeyGenerator) GenerateKey(identifier string, rule Rule) string {
	prefix := rule.Config.KeyPrefix
	if prefix == "" {
		prefix = "ratelimit:user"
	}
	return fmt.Sprintf("%s:%s:%s", prefix, rule.Name, identifier)
}

// APIKeyGenerator API键生成器
type APIKeyGenerator struct{}

func (g *APIKeyGenerator) GenerateKey(identifier string, rule Rule) string {
	prefix := rule.Config.KeyPrefix
	if prefix == "" {
		prefix = "ratelimit:api"
	}
	return fmt.Sprintf("%s:%s:%s", prefix, rule.Name, identifier)
}

// Result 限流结果
type Result struct {
	Allowed       bool          `json:"allowed"`        // 是否允许
	Remaining     int           `json:"remaining"`      // 剩余次数
	RetryAfter    time.Duration `json:"retry_after"`    // 重试间隔
	ResetTime     time.Time     `json:"reset_time"`     // 重置时间
	TotalRequests int           `json:"total_requests"` // 总请求数
}

// StrategyManager 策略管理器
type StrategyManager struct {
	rules      []Rule
	keyGen     KeyGenerator
	strategies map[Strategy]StrategyImpl
}

// StrategyImpl 策略实现接口
type StrategyImpl interface {
	Check(key string, config Config) (*Result, error)
	Name() Strategy
}

// NewStrategyManager 创建策略管理器
func NewStrategyManager() *StrategyManager {
	return &StrategyManager{
		rules:      make([]Rule, 0),
		keyGen:     &DefaultKeyGenerator{},
		strategies: make(map[Strategy]StrategyImpl),
	}
}

// AddRule 添加限流规则
func (sm *StrategyManager) AddRule(rule Rule) {
	sm.rules = append(sm.rules, rule)
}

// SetKeyGenerator 设置键生成器
func (sm *StrategyManager) SetKeyGenerator(keyGen KeyGenerator) {
	sm.keyGen = keyGen
}

// RegisterStrategy 注册策略实现
func (sm *StrategyManager) RegisterStrategy(strategy StrategyImpl) {
	sm.strategies[strategy.Name()] = strategy
}

// FindMatchingRule 查找匹配的规则
func (sm *StrategyManager) FindMatchingRule(path, method string, headers map[string]string) *Rule {
	for _, rule := range sm.rules {
		if sm.ruleMatches(rule, path, method, headers) {
			return &rule
		}
	}
	return nil
}

// ruleMatches 检查规则是否匹配
func (sm *StrategyManager) ruleMatches(rule Rule, path, method string, headers map[string]string) bool {
	// 检查路径模式匹配
	if !sm.pathMatches(rule.Pattern, path) {
		return false
	}

	// 检查HTTP方法
	if len(rule.Methods) > 0 {
		methodMatch := false
		for _, m := range rule.Methods {
			if m == method {
				methodMatch = true
				break
			}
		}
		if !methodMatch {
			return false
		}
	}

	// 检查头部匹配
	if len(rule.Headers) > 0 {
		for key, value := range rule.Headers {
			if headers[key] != value {
				return false
			}
		}
	}

	return true
}

// pathMatches 路径匹配检查
func (sm *StrategyManager) pathMatches(pattern, path string) bool {
	// 简单的模式匹配，支持通配符*
	if pattern == "*" {
		return true
	}
	if pattern == path {
		return true
	}

	// 前缀匹配
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix
	}

	return false
}

// Check 执行限流检查
func (sm *StrategyManager) Check(rule Rule, identifier string) (*Result, error) {
	if !rule.Config.Enabled {
		return &Result{Allowed: true}, nil
	}

	strategy, exists := sm.strategies[rule.Config.Strategy]
	if !exists {
		return nil, fmt.Errorf("unknown rate limit strategy: %s", rule.Config.Strategy)
	}

	key := sm.keyGen.GenerateKey(identifier, rule)
	return strategy.Check(key, rule.Config)
}

// IsException 检查是否为例外
func (sm *StrategyManager) IsException(rule Rule, identifier string) bool {
	for _, exception := range rule.Exceptions {
		if exception == identifier {
			return true
		}
	}
	return false
}

// GetDefaultRules 获取默认限流规则
func GetDefaultRules() []Rule {
	return []Rule{
		{
			Name:    "api_global",
			Pattern: "/api/*",
			Methods: []string{"GET", "POST", "PUT", "DELETE"},
			Config: Config{
				Strategy: StrategyFixedWindow,
				Rate:     1000,
				Period:   time.Minute,
				Enabled:  true,
			},
		},
		{
			Name:    "auth_strict",
			Pattern: "/api/v1/auth/*",
			Methods: []string{"POST"},
			Config: Config{
				Strategy: StrategySlidingWindow,
				Rate:     10,
				Period:   time.Minute,
				Enabled:  true,
			},
		},
		{
			Name:    "chat_normal",
			Pattern: "/api/v1/chat/*",
			Methods: []string{"POST"},
			Config: Config{
				Strategy: StrategyTokenBucket,
				Rate:     100,
				Period:   time.Minute,
				Burst:    20,
				Enabled:  true,
			},
		},
		{
			Name:    "plugin_execute",
			Pattern: "/api/v1/plugins/*/execute",
			Methods: []string{"POST"},
			Config: Config{
				Strategy: StrategyLeakyBucket,
				Rate:     50,
				Period:   time.Minute,
				Burst:    10,
				Enabled:  true,
			},
		},
	}
}

// ParseStrategy 解析策略字符串
func ParseStrategy(s string) (Strategy, error) {
	switch s {
	case "fixed_window":
		return StrategyFixedWindow, nil
	case "sliding_window":
		return StrategySlidingWindow, nil
	case "token_bucket":
		return StrategyTokenBucket, nil
	case "leaky_bucket":
		return StrategyLeakyBucket, nil
	default:
		return "", fmt.Errorf("invalid strategy: %s", s)
	}
}

// ValidateConfig 验证限流配置
func ValidateConfig(config Config) error {
	if config.Rate <= 0 {
		return fmt.Errorf("rate must be positive")
	}
	if config.Period <= 0 {
		return fmt.Errorf("period must be positive")
	}
	if config.Burst < 0 {
		return fmt.Errorf("burst cannot be negative")
	}

	validStrategies := map[Strategy]bool{
		StrategyFixedWindow:   true,
		StrategySlidingWindow: true,
		StrategyTokenBucket:   true,
		StrategyLeakyBucket:   true,
	}

	if !validStrategies[config.Strategy] {
		return fmt.Errorf("invalid strategy: %s", config.Strategy)
	}

	return nil
}
