package testutils

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/google/uuid"
)

// TestDBManager 测试数据库管理器
type TestDBManager struct {
	db *gorm.DB
}

// NewTestDBManager 创建测试数据库管理器
func NewTestDBManager(t *testing.T) *TestDBManager {
	// 确保数据库已初始化
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	if database.Get() == nil {
		err = database.Init(&cfg.Database)
		require.NoError(t, err, "failed to init database")
	}

	if cache.Get() == nil {
		err = cache.Init(&cfg.Redis)
		require.NoError(t, err, "failed to init cache")
	}

	return &TestDBManager{
		db: database.Get(),
	}
}

// CleanupTestData 清理测试数据
func (m *TestDBManager) CleanupTestData(t *testing.T) {
	// 需要按照外键依赖顺序清理
	cleanupTables := []string{
		"user_roles", // 先删除关联表
		"messages",   // 再删除依赖sessions的表
		"sessions",   // 再删除依赖users的表
		"users",      // 最后删除主表
		"roles",      // 角色表
	}

	// 临时禁用外键约束检查
	err := m.db.Exec("SET CONSTRAINTS ALL DEFERRED").Error
	if err != nil {
		t.Logf("Warning: failed to defer constraints: %v", err)
	}

	for _, table := range cleanupTables {
		if m.tableExists(table) {
			// 使用 DELETE 而不是 TRUNCATE，避免权限问题
			err := m.db.Exec("DELETE FROM " + table).Error
			if err != nil {
				t.Logf("Warning: failed to delete from table %s: %v", table, err)
			}
		}
	}

	// 重新启用外键约束检查
	err = m.db.Exec("SET CONSTRAINTS ALL IMMEDIATE").Error
	if err != nil {
		t.Logf("Warning: failed to restore constraints: %v", err)
	}

	// 清理Redis缓存
	if cache.Get() != nil {
		ctx := context.Background()
		err := cache.FlushDB(ctx)
		if err != nil {
			t.Logf("Warning: failed to flush Redis: %v", err)
		}
	}
}

// tableExists 检查表是否存在
func (m *TestDBManager) tableExists(tableName string) bool {
	var count int64
	err := m.db.Raw("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?", tableName).Scan(&count).Error
	return err == nil && count > 0
}

// CleanupUser 清理指定用户数据
func (m *TestDBManager) CleanupUser(t *testing.T, userID uuid.UUID) {
	// 只删除存在的表的数据
	if m.tableExists("user_roles") {
		m.db.Exec("DELETE FROM user_roles WHERE user_id = ?", userID)
	}
	if m.tableExists("messages") {
		m.db.Exec("DELETE FROM messages WHERE session_id IN (SELECT id FROM sessions WHERE user_id = ?)", userID)
	}
	if m.tableExists("sessions") {
		m.db.Exec("DELETE FROM sessions WHERE user_id = ?", userID)
	}
	if m.tableExists("users") {
		m.db.Exec("DELETE FROM users WHERE id = ?", userID)
	}
}

// CleanupSession 清理指定会话数据
func (m *TestDBManager) CleanupSession(t *testing.T, sessionID uuid.UUID) {
	if m.tableExists("messages") {
		m.db.Exec("DELETE FROM messages WHERE session_id = ?", sessionID)
	}
	if m.tableExists("sessions") {
		m.db.Exec("DELETE FROM sessions WHERE id = ?", sessionID)
	}
}

// CreateTestUser 创建测试用户（简单版本，避免循环依赖）
func (m *TestDBManager) CreateTestUser(t *testing.T, username, email string) uuid.UUID {
	userID := uuid.New()

	// 确保用户名和邮箱唯一
	if username == "" {
		username = GenerateTestUsername(t)
	}
	if email == "" {
		email = GenerateTestEmail(t)
	}

	// 生成正确的密码哈希
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	require.NoError(t, err, "failed to generate password hash")

	// 直接使用GORM创建用户，避免依赖service层
	user := map[string]interface{}{
		"id":             userID,
		"username":       username,
		"email":          email,
		"password_hash":  string(passwordHash),
		"full_name":      "Test User",
		"status":         "active",
		"email_verified": false,
		"created_at":     time.Now(),
		"updated_at":     time.Now(),
	}

	err = m.db.Table("users").Create(user).Error
	require.NoError(t, err, "failed to create test user")

	return userID
}

// CreateTestSession 创建测试会话
func (m *TestDBManager) CreateTestSession(t *testing.T, userID uuid.UUID, title string) uuid.UUID {
	sessionID := uuid.New()

	session := map[string]interface{}{
		"id":            sessionID,
		"user_id":       userID,
		"title":         title,
		"status":        "active",
		"model_name":    "gpt-3.5-turbo",
		"system_prompt": "You are a helpful assistant",
		"metadata":      "{}",
		"message_count": 0,
		"total_tokens":  0,
	}

	err := m.db.Table("sessions").Create(session).Error
	require.NoError(t, err, "failed to create test session")

	return sessionID
}

// CreateTestRole 创建测试角色
func (m *TestDBManager) CreateTestRole(t *testing.T, name, description string, permissions []string) uuid.UUID {
	roleID := uuid.New()

	// 将permissions转换为JSON字符串
	permissionsJSON := `["` + strings.Join(permissions, `","`) + `"]`

	role := map[string]interface{}{
		"id":          roleID,
		"name":        name,
		"description": description,
		"permissions": permissionsJSON,
		"is_system":   false,
	}

	err := m.db.Table("roles").Create(role).Error
	require.NoError(t, err, "failed to create test role")

	return roleID
}
