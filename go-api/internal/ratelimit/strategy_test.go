package ratelimit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewStrategyManager(t *testing.T) {
	manager := NewStrategyManager()
	assert.NotNil(t, manager, "strategy manager should not be nil")
	assert.NotNil(t, manager.rules, "rules slice should not be nil")
	assert.NotNil(t, manager.keyGen, "key generator should not be nil")
	assert.NotNil(t, manager.strategies, "strategies map should not be nil")
}

func TestStrategyManager_AddRule(t *testing.T) {
	manager := NewStrategyManager()

	rule := Rule{
		Name:    "test_rule",
		Pattern: "/api/test",
		Config: Config{
			Strategy: StrategyFixedWindow,
			Rate:     10,
			Period:   time.Minute,
			Enabled:  true,
		},
	}

	// 添加规则前
	assert.Len(t, manager.rules, 0, "should start with no rules")

	manager.AddRule(rule)

	// 添加规则后
	assert.Len(t, manager.rules, 1, "should have one rule after adding")
	assert.Equal(t, rule.Name, manager.rules[0].Name, "rule name should match")
}

func TestStrategyManager_SetKeyGenerator(t *testing.T) {
	manager := NewStrategyManager()

	// 默认键生成器
	assert.IsType(t, &DefaultKeyGenerator{}, manager.keyGen, "should start with default key generator")

	// 设置IP键生成器
	ipKeyGen := &IPKeyGenerator{}
	manager.SetKeyGenerator(ipKeyGen)
	assert.Equal(t, ipKeyGen, manager.keyGen, "key generator should be updated")

	// 设置用户键生成器
	userKeyGen := &UserKeyGenerator{}
	manager.SetKeyGenerator(userKeyGen)
	assert.Equal(t, userKeyGen, manager.keyGen, "key generator should be updated again")
}

func TestStrategyManager_RegisterStrategy(t *testing.T) {
	manager := NewStrategyManager()

	// 创建模拟策略
	mockStrategy := &mockStrategyImpl{
		name: StrategyFixedWindow,
	}

	manager.RegisterStrategy(mockStrategy)

	strategy, exists := manager.strategies[StrategyFixedWindow]
	assert.True(t, exists, "strategy should be registered")
	assert.Equal(t, mockStrategy, strategy, "registered strategy should match")
}

func TestStrategyManager_FindMatchingRule(t *testing.T) {
	manager := NewStrategyManager()

	// 添加测试规则
	rules := []Rule{
		{
			Name:    "exact_match",
			Pattern: "/api/exact",
			Methods: []string{"GET"},
		},
		{
			Name:    "wildcard_match",
			Pattern: "/api/*",
			Methods: []string{"POST", "PUT"},
		},
		{
			Name:    "prefix_match",
			Pattern: "/admin/*",
			Methods: []string{"GET", "POST"},
		},
		{
			Name:    "with_headers",
			Pattern: "/api/headers",
			Methods: []string{"POST"},
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		},
		{
			Name:    "any_path",
			Pattern: "*",
		},
	}

	for _, rule := range rules {
		manager.AddRule(rule)
	}

	tests := []struct {
		name         string
		path         string
		method       string
		headers      map[string]string
		expectedRule string
		shouldMatch  bool
	}{
		{
			name:         "exact path match",
			path:         "/api/exact",
			method:       "GET",
			expectedRule: "exact_match",
			shouldMatch:  true,
		},
		{
			name:         "wildcard match",
			path:         "/api/users",
			method:       "POST",
			expectedRule: "wildcard_match",
			shouldMatch:  true,
		},
		{
			name:         "prefix match",
			path:         "/admin/users",
			method:       "GET",
			expectedRule: "prefix_match",
			shouldMatch:  true,
		},
		{
			name:         "header match",
			path:         "/api/headers",
			method:       "POST",
			headers:      map[string]string{"Content-Type": "application/json"},
			expectedRule: "with_headers",
			shouldMatch:  true,
		},
		{
			name:         "header mismatch",
			path:         "/api/headers",
			method:       "POST",
			headers:      map[string]string{"Content-Type": "text/plain"},
			expectedRule: "any_path",
			shouldMatch:  true,
		},
		{
			name:         "method mismatch",
			path:         "/api/exact",
			method:       "POST",
			expectedRule: "any_path",
			shouldMatch:  true,
		},
		{
			name:         "fallback to wildcard",
			path:         "/other/path",
			method:       "GET",
			expectedRule: "any_path",
			shouldMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.headers == nil {
				tt.headers = make(map[string]string)
			}

			rule := manager.FindMatchingRule(tt.path, tt.method, tt.headers)

			if tt.shouldMatch {
				assert.NotNil(t, rule, "should find a matching rule")
				assert.Equal(t, tt.expectedRule, rule.Name, "should match expected rule")
			} else {
				assert.Nil(t, rule, "should not find a matching rule")
			}
		})
	}
}

func TestStrategyManager_PathMatches(t *testing.T) {
	manager := NewStrategyManager()

	tests := []struct {
		name     string
		pattern  string
		path     string
		expected bool
	}{
		{
			name:     "exact match",
			pattern:  "/api/users",
			path:     "/api/users",
			expected: true,
		},
		{
			name:     "exact mismatch",
			pattern:  "/api/users",
			path:     "/api/posts",
			expected: false,
		},
		{
			name:     "wildcard match all",
			pattern:  "*",
			path:     "/any/path",
			expected: true,
		},
		{
			name:     "prefix wildcard match",
			pattern:  "/api/*",
			path:     "/api/users",
			expected: true,
		},
		{
			name:     "prefix wildcard match long path",
			pattern:  "/api/*",
			path:     "/api/users/123/posts",
			expected: true,
		},
		{
			name:     "prefix wildcard mismatch",
			pattern:  "/api/*",
			path:     "/admin/users",
			expected: false,
		},
		{
			name:     "prefix wildcard exact prefix",
			pattern:  "/api/*",
			path:     "/api/",
			expected: true,
		},
		{
			name:     "prefix wildcard shorter path",
			pattern:  "/api/v1/*",
			path:     "/api",
			expected: false,
		},
		{
			name:     "empty pattern",
			pattern:  "",
			path:     "/any/path",
			expected: false,
		},
		{
			name:     "pattern longer than path",
			pattern:  "/very/long/pattern",
			path:     "/short",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.pathMatches(tt.pattern, tt.path)
			assert.Equal(t, tt.expected, result, "path match result should be correct")
		})
	}
}

func TestStrategyManager_Check(t *testing.T) {
	manager := NewStrategyManager()

	// 注册模拟策略
	mockStrategy := &mockStrategyImpl{
		name: StrategyFixedWindow,
		checkResult: &Result{
			Allowed:   true,
			Remaining: 5,
		},
	}
	manager.RegisterStrategy(mockStrategy)

	rule := Rule{
		Name:    "test_check",
		Pattern: "/api/test",
		Config: Config{
			Strategy: StrategyFixedWindow,
			Rate:     10,
			Period:   time.Minute,
			Enabled:  true,
		},
	}

	identifier := "test_user"

	// 测试启用的规则
	result, err := manager.Check(rule, identifier)
	assert.NoError(t, err, "check should succeed")
	assert.NotNil(t, result, "result should not be nil")
	assert.True(t, result.Allowed, "request should be allowed")
	assert.Equal(t, 5, result.Remaining, "remaining should match")

	// 测试禁用的规则
	rule.Config.Enabled = false
	result, err = manager.Check(rule, identifier)
	assert.NoError(t, err, "check should succeed")
	assert.True(t, result.Allowed, "disabled rule should allow")

	// 测试未知策略
	rule.Config.Enabled = true
	rule.Config.Strategy = "unknown_strategy"
	result, err = manager.Check(rule, identifier)
	assert.Error(t, err, "unknown strategy should cause error")
	assert.Nil(t, result, "result should be nil for error")
	assert.Contains(t, err.Error(), "unknown rate limit strategy", "error should mention unknown strategy")
}

func TestStrategyManager_IsException(t *testing.T) {
	manager := NewStrategyManager()

	rule := Rule{
		Name:       "exception_test",
		Pattern:    "/api/test",
		Exceptions: []string{"admin", "192.168.1.1", "special_user"},
	}

	tests := []struct {
		name       string
		identifier string
		expected   bool
	}{
		{
			name:       "admin exception",
			identifier: "admin",
			expected:   true,
		},
		{
			name:       "IP exception",
			identifier: "192.168.1.1",
			expected:   true,
		},
		{
			name:       "special user exception",
			identifier: "special_user",
			expected:   true,
		},
		{
			name:       "normal user",
			identifier: "normal_user",
			expected:   false,
		},
		{
			name:       "partial match",
			identifier: "admin_user",
			expected:   false,
		},
		{
			name:       "empty identifier",
			identifier: "",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.IsException(rule, tt.identifier)
			assert.Equal(t, tt.expected, result, "exception check result should be correct")
		})
	}
}

func TestGetDefaultRules(t *testing.T) {
	rules := GetDefaultRules()
	assert.Greater(t, len(rules), 0, "should have default rules")

	expectedRules := map[string]bool{
		"api_global":     false,
		"auth_strict":    false,
		"chat_normal":    false,
		"plugin_execute": false,
	}

	for _, rule := range rules {
		if _, exists := expectedRules[rule.Name]; exists {
			expectedRules[rule.Name] = true
		}

		// 验证规则配置
		assert.NotEmpty(t, rule.Name, "rule should have name")
		assert.NotEmpty(t, rule.Pattern, "rule should have pattern")
		assert.True(t, rule.Config.Enabled, "default rules should be enabled")
		assert.Greater(t, rule.Config.Rate, 0, "rate should be positive")
		assert.Greater(t, rule.Config.Period, time.Duration(0), "period should be positive")
	}

	// 验证所有预期规则都存在
	for ruleName, found := range expectedRules {
		assert.True(t, found, "should have default rule: %s", ruleName)
	}
}

func TestParseStrategy(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    Strategy
		shouldError bool
	}{
		{
			name:     "fixed window",
			input:    "fixed_window",
			expected: StrategyFixedWindow,
		},
		{
			name:     "sliding window",
			input:    "sliding_window",
			expected: StrategySlidingWindow,
		},
		{
			name:     "token bucket",
			input:    "token_bucket",
			expected: StrategyTokenBucket,
		},
		{
			name:     "leaky bucket",
			input:    "leaky_bucket",
			expected: StrategyLeakyBucket,
		},
		{
			name:        "invalid strategy",
			input:       "invalid_strategy",
			shouldError: true,
		},
		{
			name:        "empty string",
			input:       "",
			shouldError: true,
		},
		{
			name:        "case sensitive",
			input:       "Fixed_Window",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseStrategy(tt.input)

			if tt.shouldError {
				assert.Error(t, err, "should return error for invalid input")
				assert.Contains(t, err.Error(), "invalid strategy", "error should mention invalid strategy")
			} else {
				assert.NoError(t, err, "should not return error for valid input")
				assert.Equal(t, tt.expected, result, "parsed strategy should match expected")
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		shouldError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: Config{
				Strategy: StrategyFixedWindow,
				Rate:     10,
				Period:   time.Minute,
				Burst:    5,
			},
			shouldError: false,
		},
		{
			name: "zero rate",
			config: Config{
				Strategy: StrategyFixedWindow,
				Rate:     0,
				Period:   time.Minute,
				Burst:    5,
			},
			shouldError: true,
			errorMsg:    "rate must be positive",
		},
		{
			name: "negative rate",
			config: Config{
				Strategy: StrategyFixedWindow,
				Rate:     -1,
				Period:   time.Minute,
				Burst:    5,
			},
			shouldError: true,
			errorMsg:    "rate must be positive",
		},
		{
			name: "zero period",
			config: Config{
				Strategy: StrategyFixedWindow,
				Rate:     10,
				Period:   0,
				Burst:    5,
			},
			shouldError: true,
			errorMsg:    "period must be positive",
		},
		{
			name: "negative period",
			config: Config{
				Strategy: StrategyFixedWindow,
				Rate:     10,
				Period:   -time.Second,
				Burst:    5,
			},
			shouldError: true,
			errorMsg:    "period must be positive",
		},
		{
			name: "negative burst",
			config: Config{
				Strategy: StrategyFixedWindow,
				Rate:     10,
				Period:   time.Minute,
				Burst:    -1,
			},
			shouldError: true,
			errorMsg:    "burst cannot be negative",
		},
		{
			name: "zero burst (allowed)",
			config: Config{
				Strategy: StrategyFixedWindow,
				Rate:     10,
				Period:   time.Minute,
				Burst:    0,
			},
			shouldError: false,
		},
		{
			name: "invalid strategy",
			config: Config{
				Strategy: "invalid_strategy",
				Rate:     10,
				Period:   time.Minute,
				Burst:    5,
			},
			shouldError: true,
			errorMsg:    "invalid strategy",
		},
		{
			name: "empty strategy",
			config: Config{
				Strategy: "",
				Rate:     10,
				Period:   time.Minute,
				Burst:    5,
			},
			shouldError: true,
			errorMsg:    "invalid strategy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)

			if tt.shouldError {
				assert.Error(t, err, "should return error for invalid config")
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg, "error message should contain expected text")
				}
			} else {
				assert.NoError(t, err, "should not return error for valid config")
			}
		})
	}
}

func TestKeyGenerators(t *testing.T) {
	rule := Rule{
		Name: "test_rule",
		Config: Config{
			KeyPrefix: "custom",
		},
	}
	identifier := "test_id"

	tests := []struct {
		name      string
		generator KeyGenerator
		expected  string
	}{
		{
			name:      "default key generator",
			generator: &DefaultKeyGenerator{},
			expected:  "custom:test_rule:test_id",
		},
		{
			name:      "IP key generator",
			generator: &IPKeyGenerator{},
			expected:  "custom:test_rule:test_id",
		},
		{
			name:      "user key generator",
			generator: &UserKeyGenerator{},
			expected:  "custom:test_rule:test_id",
		},
		{
			name:      "API key generator",
			generator: &APIKeyGenerator{},
			expected:  "custom:test_rule:test_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.generator.GenerateKey(identifier, rule)
			assert.Equal(t, tt.expected, result, "generated key should match expected")
		})
	}

	// 测试默认前缀
	ruleWithoutPrefix := Rule{
		Name:   "test_rule",
		Config: Config{},
	}

	defaultGen := &DefaultKeyGenerator{}
	result := defaultGen.GenerateKey(identifier, ruleWithoutPrefix)
	assert.Equal(t, "ratelimit:test_rule:test_id", result, "should use default prefix")

	ipGen := &IPKeyGenerator{}
	result = ipGen.GenerateKey(identifier, ruleWithoutPrefix)
	assert.Equal(t, "ratelimit:ip:test_rule:test_id", result, "should use IP default prefix")

	userGen := &UserKeyGenerator{}
	result = userGen.GenerateKey(identifier, ruleWithoutPrefix)
	assert.Equal(t, "ratelimit:user:test_rule:test_id", result, "should use user default prefix")

	apiGen := &APIKeyGenerator{}
	result = apiGen.GenerateKey(identifier, ruleWithoutPrefix)
	assert.Equal(t, "ratelimit:api:test_rule:test_id", result, "should use API default prefix")
}

func TestResult(t *testing.T) {
	result := &Result{
		Allowed:       true,
		Remaining:     5,
		RetryAfter:    30 * time.Second,
		ResetTime:     time.Now().Add(time.Minute),
		TotalRequests: 15,
	}

	assert.True(t, result.Allowed, "result should be allowed")
	assert.Equal(t, 5, result.Remaining, "remaining should be 5")
	assert.Equal(t, 30*time.Second, result.RetryAfter, "retry after should be 30 seconds")
	assert.Equal(t, 15, result.TotalRequests, "total requests should be 15")
	assert.True(t, result.ResetTime.After(time.Now()), "reset time should be in future")
}

// mockStrategyImpl 模拟策略实现，用于测试
type mockStrategyImpl struct {
	name        Strategy
	checkResult *Result
	checkError  error
}

func (m *mockStrategyImpl) Name() Strategy {
	return m.name
}

func (m *mockStrategyImpl) Check(key string, config Config) (*Result, error) {
	if m.checkError != nil {
		return nil, m.checkError
	}
	return m.checkResult, nil
}
