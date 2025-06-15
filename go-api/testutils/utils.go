package testutils

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// SetupTestEnv 设置测试环境的通用函数
func SetupTestEnv(t *testing.T) *TestDBManager {
	manager := NewTestDBManager(t)

	// 在每个测试前清理数据
	t.Cleanup(func() {
		manager.CleanupTestData(t)
	})

	return manager
}

// GenerateTestUsername 生成测试用用户名
func GenerateTestUsername(t *testing.T) string {
	// 添加时间戳确保唯一性
	return fmt.Sprintf("testuser_%s_%d", uuid.New().String()[:8], time.Now().UnixNano())
}

// GenerateTestEmail 生成测试用邮箱
func GenerateTestEmail(t *testing.T) string {
	// 添加时间戳确保唯一性
	return fmt.Sprintf("test_%s_%d@example.com", uuid.New().String()[:8], time.Now().UnixNano())
}

// CreateLongString 创建指定长度的字符串
func CreateLongString(length int) string {
	if length <= 0 {
		return ""
	}
	return strings.Repeat("a", length)
}
