package ratelimit

import (
	"fmt"
	"strings"
	"sync"
	"time"

	iradix "github.com/hashicorp/go-immutable-radix"
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

// RouteRule 路由规则
type RouteRule struct {
	Rule     Rule              `json:"rule"`
	Methods  map[string]bool   `json:"methods"`  // 支持的HTTP方法
	Headers  map[string]string `json:"headers"`  // 头部匹配
	Priority int               `json:"priority"` // 优先级，数字越小优先级越高
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
	routeTree  *iradix.Tree              // 路由规则树
	keyGen     KeyGenerator              // 键生成器
	strategies map[Strategy]StrategyImpl // 策略实现
	mutex      sync.RWMutex              // 读写锁
}

// StrategyImpl 策略实现接口
type StrategyImpl interface {
	Check(key string, config Config) (*Result, error)
	Name() Strategy
}

// NewStrategyManager 创建策略管理器
func NewStrategyManager() *StrategyManager {
	return &StrategyManager{
		routeTree:  iradix.New(),
		keyGen:     &DefaultKeyGenerator{},
		strategies: make(map[Strategy]StrategyImpl),
	}
}

// AddRule 添加限流规则
func (sm *StrategyManager) AddRule(rule Rule) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// 构建路由规则
	routeRule := &RouteRule{
		Rule:     rule,
		Methods:  make(map[string]bool),
		Headers:  rule.Headers,
		Priority: sm.calculatePriority(rule.Pattern),
	}

	// 设置支持的HTTP方法
	if len(rule.Methods) == 0 {
		// 如果没有指定方法，默认支持所有方法
		routeRule.Methods["*"] = true
	} else {
		for _, method := range rule.Methods {
			routeRule.Methods[strings.ToUpper(method)] = true
		}
	}

	// 将规则插入radix树
	// 使用规则名称和模式组合作为键，确保唯一性
	key := sm.buildRouteKey(rule.Pattern, rule.Name)
	sm.routeTree, _, _ = sm.routeTree.Insert([]byte(key), routeRule)
}

// buildRouteKey 构建路由键
func (sm *StrategyManager) buildRouteKey(pattern, name string) string {
	// 使用完整的模式和名称构建唯一键
	key := fmt.Sprintf("%s#%s", pattern, name)
	return key
}

// calculatePriority 计算规则优先级
func (sm *StrategyManager) calculatePriority(pattern string) int {
	// 具体路径优先级高于通配符路径
	if pattern == "*" {
		return 1000 // 最低优先级
	}
	if strings.HasSuffix(pattern, "*") {
		// 前缀越长，优先级越高
		return 500 - len(strings.TrimSuffix(pattern, "*"))
	}
	// 精确匹配优先级最高
	return 100 - len(pattern)
}

// SetKeyGenerator 设置键生成器
func (sm *StrategyManager) SetKeyGenerator(keyGen KeyGenerator) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.keyGen = keyGen
}

// RegisterStrategy 注册策略实现
func (sm *StrategyManager) RegisterStrategy(strategy StrategyImpl) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.strategies[strategy.Name()] = strategy
}

// FindMatchingRule 查找匹配的规则
func (sm *StrategyManager) FindMatchingRule(path, method string, headers map[string]string) *Rule {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	method = strings.ToUpper(method)
	var bestMatch *RouteRule
	var bestMatchLength int

	// 遍历所有规则找到最佳匹配
	sm.routeTree.Root().Walk(func(key []byte, value interface{}) bool {
		routeRule := value.(*RouteRule)

		// 检查路径是否匹配
		if !sm.pathMatches(routeRule.Rule.Pattern, path) {
			return false // 继续遍历
		}

		// 检查HTTP方法
		if !routeRule.Methods["*"] && !routeRule.Methods[method] {
			return false // 继续遍历
		}

		// 检查头部匹配
		if !sm.headersMatch(routeRule.Headers, headers) {
			return false // 继续遍历
		}

		// 计算匹配长度（用于选择最佳匹配）
		var matchLength int
		if routeRule.Rule.Pattern == "*" {
			matchLength = 0 // 通配符优先级最低
		} else if strings.HasSuffix(routeRule.Rule.Pattern, "*") {
			// 前缀匹配的长度是去掉*后的长度
			matchLength = len(strings.TrimSuffix(routeRule.Rule.Pattern, "*"))
		} else {
			// 精确匹配的长度是完整长度
			matchLength = len(routeRule.Rule.Pattern)
		}

		// 选择最佳匹配（最长匹配优先，如果长度相同则优先级高的优先）
		if bestMatch == nil || matchLength > bestMatchLength ||
			(matchLength == bestMatchLength && routeRule.Priority < bestMatch.Priority) {
			bestMatch = routeRule
			bestMatchLength = matchLength
		}

		return false // 继续遍历所有规则
	})

	if bestMatch != nil {
		return &bestMatch.Rule
	}

	return nil
}

// headersMatch 检查头部是否匹配
func (sm *StrategyManager) headersMatch(ruleHeaders, requestHeaders map[string]string) bool {
	if len(ruleHeaders) == 0 {
		return true
	}

	for key, expectedValue := range ruleHeaders {
		if actualValue, exists := requestHeaders[key]; !exists || actualValue != expectedValue {
			return false
		}
	}
	return true
}

// pathMatches 路径匹配检查
func (sm *StrategyManager) pathMatches(pattern, path string) bool {
	// 完全匹配
	if pattern == "*" {
		return true
	}
	if pattern == path {
		return true
	}

	// 前缀匹配
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		result := strings.HasPrefix(path, prefix)
		return result
	}

	return false
}

// Check 执行限流检查
func (sm *StrategyManager) Check(rule Rule, identifier string) (*Result, error) {
	if !rule.Config.Enabled {
		return &Result{Allowed: true}, nil
	}

	sm.mutex.RLock()
	strategy, exists := sm.strategies[rule.Config.Strategy]
	keyGen := sm.keyGen
	sm.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unknown rate limit strategy: %s", rule.Config.Strategy)
	}

	key := keyGen.GenerateKey(identifier, rule)
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

// GetStats 获取路由统计信息
func (sm *StrategyManager) GetStats() map[string]interface{} {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_rules": sm.routeTree.Len(),
		"rules":       make([]map[string]interface{}, 0),
	}

	rules := make([]map[string]interface{}, 0)
	sm.routeTree.Root().Walk(func(key []byte, value interface{}) bool {
		routeRule := value.(*RouteRule)
		ruleStats := map[string]interface{}{
			"name":     routeRule.Rule.Name,
			"pattern":  routeRule.Rule.Pattern,
			"methods":  routeRule.Rule.Methods,
			"priority": routeRule.Priority,
			"enabled":  routeRule.Rule.Config.Enabled,
			"key":      string(key),
		}
		rules = append(rules, ruleStats)
		return false // 继续遍历
	})

	stats["rules"] = rules
	return stats
}

// DeleteRule 删除规则
func (sm *StrategyManager) DeleteRule(pattern, name string) bool {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	key := sm.buildRouteKey(pattern, name)
	newTree, _, existed := sm.routeTree.Delete([]byte(key))
	if existed {
		sm.routeTree = newTree
	}
	return existed
}

// UpdateRule 更新规则
func (sm *StrategyManager) UpdateRule(rule Rule) bool {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	key := sm.buildRouteKey(rule.Pattern, rule.Name)

	// 检查规则是否存在
	if _, exists := sm.routeTree.Get([]byte(key)); !exists {
		return false
	}

	// 构建新的路由规则
	routeRule := &RouteRule{
		Rule:     rule,
		Methods:  make(map[string]bool),
		Headers:  rule.Headers,
		Priority: sm.calculatePriority(rule.Pattern),
	}

	// 设置支持的HTTP方法
	if len(rule.Methods) == 0 {
		routeRule.Methods["*"] = true
	} else {
		for _, method := range rule.Methods {
			routeRule.Methods[strings.ToUpper(method)] = true
		}
	}

	// 更新规则
	sm.routeTree, _, _ = sm.routeTree.Insert([]byte(key), routeRule)
	return true
}

// GetDefaultRules 获取默认限流规则
func GetDefaultRules() []Rule {
	return []Rule{
		{
			Name:    "api_global",
			Pattern: "/api/",
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
			Pattern: "/api/v1/auth/",
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
			Pattern: "/api/v1/chat/",
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
			Pattern: "/api/v1/plugins/",
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
