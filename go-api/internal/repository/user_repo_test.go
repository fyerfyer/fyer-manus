package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
)

func TestNewUserRepository(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	assert.NotNil(t, repo, "user repository should not be nil")
}

func TestUserRepository_Create(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 测试创建用户
	user := &model.User{
		Username: "testuser",
		Email:    "test@example.com",
		FullName: "Test User",
		Status:   model.UserStatusActive,
	}

	err := user.SetPassword("password123")
	require.NoError(t, err, "setting password should succeed")

	err = repo.Create(ctx, user)
	assert.NoError(t, err, "creating user should succeed")
	assert.NotEqual(t, uuid.Nil, user.ID, "user id should be set")

	// 测试重复用户名
	duplicateUser := &model.User{
		Username: "testuser",
		Email:    "another@example.com",
	}
	err = repo.Create(ctx, duplicateUser)
	assert.Error(t, err, "creating user with duplicate username should fail")

	// 测试重复邮箱
	duplicateEmailUser := &model.User{
		Username: "anotheruser",
		Email:    "test@example.com",
	}
	err = repo.Create(ctx, duplicateEmailUser)
	assert.Error(t, err, "creating user with duplicate email should fail")
}

func TestUserRepository_GetByID(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUser(t, repo, "testuser", "test@example.com")

	// 获取用户
	foundUser, err := repo.GetByID(ctx, user.ID)
	assert.NoError(t, err, "getting user by id should succeed")
	assert.NotNil(t, foundUser, "found user should not be nil")
	assert.Equal(t, user.ID, foundUser.ID, "user id should match")
	assert.Equal(t, user.Username, foundUser.Username, "username should match")

	// 测试不存在的用户
	_, err = repo.GetByID(ctx, uuid.New())
	assert.Error(t, err, "getting non-existent user should fail")
}

func TestUserRepository_GetByUsername(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUser(t, repo, "testuser", "test@example.com")

	// 通过用户名获取用户
	foundUser, err := repo.GetByUsername(ctx, user.Username)
	assert.NoError(t, err, "getting user by username should succeed")
	assert.NotNil(t, foundUser, "found user should not be nil")
	assert.Equal(t, user.ID, foundUser.ID, "user id should match")
	assert.Equal(t, user.Username, foundUser.Username, "username should match")

	// 测试不存在的用户名
	_, err = repo.GetByUsername(ctx, "nonexistent")
	assert.Error(t, err, "getting non-existent user should fail")
}

func TestUserRepository_GetByEmail(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUser(t, repo, "testuser", "test@example.com")

	// 通过邮箱获取用户
	foundUser, err := repo.GetByEmail(ctx, user.Email)
	assert.NoError(t, err, "getting user by email should succeed")
	assert.NotNil(t, foundUser, "found user should not be nil")
	assert.Equal(t, user.ID, foundUser.ID, "user id should match")
	assert.Equal(t, user.Email, foundUser.Email, "email should match")

	// 测试不存在的邮箱
	_, err = repo.GetByEmail(ctx, "nonexistent@example.com")
	assert.Error(t, err, "getting non-existent user should fail")
}

func TestUserRepository_Update(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUser(t, repo, "testuser", "test@example.com")

	// 更新用户信息
	user.FullName = "Updated Name"
	user.Status = model.UserStatusInactive

	err := repo.Update(ctx, user)
	assert.NoError(t, err, "updating user should succeed")

	// 验证更新
	updatedUser, err := repo.GetByID(ctx, user.ID)
	require.NoError(t, err, "getting updated user should succeed")
	assert.Equal(t, "Updated Name", updatedUser.FullName, "full name should be updated")
	assert.Equal(t, model.UserStatusInactive, updatedUser.Status, "status should be updated")
}

func TestUserRepository_Delete(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUser(t, repo, "testuser", "test@example.com")

	// 删除用户
	err := repo.Delete(ctx, user.ID)
	assert.NoError(t, err, "deleting user should succeed")

	// 验证用户已删除
	_, err = repo.GetByID(ctx, user.ID)
	assert.Error(t, err, "getting deleted user should fail")
}

func TestUserRepository_UpdateLastLogin(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUser(t, repo, "testuser", "test@example.com")

	// 更新最后登录时间
	err := repo.UpdateLastLogin(ctx, user.ID)
	assert.NoError(t, err, "updating last login should succeed")

	// 验证更新
	updatedUser, err := repo.GetByID(ctx, user.ID)
	require.NoError(t, err, "getting updated user should succeed")
	assert.NotNil(t, updatedUser.LastLoginAt, "last login time should be set")
}

func TestUserRepository_UpdatePassword(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUser(t, repo, "testuser", "test@example.com")
	originalHash := user.PasswordHash

	// 更新密码
	newPasswordHash := "newhash123"
	err := repo.UpdatePassword(ctx, user.ID, newPasswordHash)
	assert.NoError(t, err, "updating password should succeed")

	// 验证更新
	updatedUser, err := repo.GetByID(ctx, user.ID)
	require.NoError(t, err, "getting updated user should succeed")
	assert.Equal(t, newPasswordHash, updatedUser.PasswordHash, "password hash should be updated")
	assert.NotEqual(t, originalHash, updatedUser.PasswordHash, "password hash should be different")
}

func TestUserRepository_UpdateStatus(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUser(t, repo, "testuser", "test@example.com")

	// 更新状态
	err := repo.UpdateStatus(ctx, user.ID, model.UserStatusSuspended)
	assert.NoError(t, err, "updating status should succeed")

	// 验证更新
	updatedUser, err := repo.GetByID(ctx, user.ID)
	require.NoError(t, err, "getting updated user should succeed")
	assert.Equal(t, model.UserStatusSuspended, updatedUser.Status, "status should be updated")
}

func TestUserRepository_ExistsByUsername(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUser(t, repo, "testuser", "test@example.com")

	// 测试存在的用户名
	exists, err := repo.ExistsByUsername(ctx, user.Username)
	assert.NoError(t, err, "checking username existence should succeed")
	assert.True(t, exists, "username should exist")

	// 测试不存在的用户名
	exists, err = repo.ExistsByUsername(ctx, "nonexistent")
	assert.NoError(t, err, "checking username existence should succeed")
	assert.False(t, exists, "username should not exist")
}

func TestUserRepository_ExistsByEmail(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUser(t, repo, "testuser", "test@example.com")

	// 测试存在的邮箱
	exists, err := repo.ExistsByEmail(ctx, user.Email)
	assert.NoError(t, err, "checking email existence should succeed")
	assert.True(t, exists, "email should exist")

	// 测试不存在的邮箱
	exists, err = repo.ExistsByEmail(ctx, "nonexistent@example.com")
	assert.NoError(t, err, "checking email existence should succeed")
	assert.False(t, exists, "email should not exist")
}

func TestUserRepository_List(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建多个测试用户
	for i := 0; i < 5; i++ {
		username := "testuser" + string(rune('0'+i))
		email := "test" + string(rune('0'+i)) + "@example.com"
		createTestUser(t, repo, username, email)
	}

	// 测试分页列表
	users, total, err := repo.List(ctx, 0, 3)
	assert.NoError(t, err, "listing users should succeed")
	assert.Len(t, users, 3, "should return 3 users")
	assert.GreaterOrEqual(t, total, int64(5), "total should be at least 5")

	// 测试第二页
	users, total, err = repo.List(ctx, 3, 3)
	assert.NoError(t, err, "listing users should succeed")
	assert.GreaterOrEqual(t, len(users), 2, "should return at least 2 users")
	assert.GreaterOrEqual(t, total, int64(5), "total should be at least 5")
}

func TestUserRepository_Search(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户
	createTestUser(t, repo, "searchuser", "search@example.com")
	createTestUser(t, repo, "anotheruser", "another@example.com")

	// 搜索用户名
	users, total, err := repo.Search(ctx, "search", 0, 10)
	assert.NoError(t, err, "searching users should succeed")
	assert.Greater(t, len(users), 0, "should find users")
	assert.Greater(t, total, int64(0), "total should be greater than 0")

	// 搜索邮箱
	users, total, err = repo.Search(ctx, "search@", 0, 10)
	assert.NoError(t, err, "searching users should succeed")
	assert.Greater(t, len(users), 0, "should find users")

	// 搜索不存在的内容
	users, total, err = repo.Search(ctx, "nonexistent", 0, 10)
	assert.NoError(t, err, "searching users should succeed")
	assert.Equal(t, 0, len(users), "should not find users")
	assert.Equal(t, int64(0), total, "total should be 0")
}

func TestUserRepository_AssignRole(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户和角色
	user := createTestUser(t, repo, "testuser", "test@example.com")
	role := createTestRole(t, "testrole", "Test Role")

	// 分配角色
	err := repo.AssignRole(ctx, user.ID, role.ID)
	assert.NoError(t, err, "assigning role should succeed")

	// 验证角色分配
	roles, err := repo.GetUserRoles(ctx, user.ID)
	assert.NoError(t, err, "getting user roles should succeed")
	assert.Greater(t, len(roles), 0, "user should have roles")

	// 验证具体角色
	hasRole := false
	for _, r := range roles {
		if r.ID == role.ID {
			hasRole = true
			break
		}
	}
	assert.True(t, hasRole, "user should have the assigned role")

	// 测试重复分配（应该不出错）
	err = repo.AssignRole(ctx, user.ID, role.ID)
	assert.NoError(t, err, "reassigning same role should not error")
}

func TestUserRepository_RemoveRole(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户和角色
	user := createTestUser(t, repo, "testuser", "test@example.com")
	role := createTestRole(t, "testrole", "Test Role")

	// 先分配角色
	err := repo.AssignRole(ctx, user.ID, role.ID)
	require.NoError(t, err, "assigning role should succeed")

	// 移除角色
	err = repo.RemoveRole(ctx, user.ID, role.ID)
	assert.NoError(t, err, "removing role should succeed")

	// 验证角色移除
	roles, err := repo.GetUserRoles(ctx, user.ID)
	assert.NoError(t, err, "getting user roles should succeed")

	// 检查角色是否已移除
	hasRole := false
	for _, r := range roles {
		if r.ID == role.ID {
			hasRole = true
			break
		}
	}
	assert.False(t, hasRole, "role should be removed")
}

func TestUserRepository_GetUserRoles(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 创建测试用户和角色
	user := createTestUser(t, repo, "testuser", "test@example.com")
	role1 := createTestRole(t, "role1", "Role 1")
	role2 := createTestRole(t, "role2", "Role 2")

	// 分配多个角色
	err := repo.AssignRole(ctx, user.ID, role1.ID)
	require.NoError(t, err, "assigning role1 should succeed")

	err = repo.AssignRole(ctx, user.ID, role2.ID)
	require.NoError(t, err, "assigning role2 should succeed")

	// 获取用户角色
	roles, err := repo.GetUserRoles(ctx, user.ID)
	assert.NoError(t, err, "getting user roles should succeed")
	assert.GreaterOrEqual(t, len(roles), 2, "user should have at least 2 roles")

	// 验证角色内容
	roleIDs := make(map[uuid.UUID]bool)
	for _, role := range roles {
		roleIDs[role.ID] = true
	}
	assert.True(t, roleIDs[role1.ID], "should have role1")
	assert.True(t, roleIDs[role2.ID], "should have role2")
}

func TestUserRepository_ErrorHandling(t *testing.T) {
	// 初始化数据库
	setupDatabase(t)
	defer database.Close()

	repo := NewUserRepository()
	ctx := context.Background()

	// 测试创建无效用户（空用户名）
	invalidUser := &model.User{
		Username:     "", // 空用户名
		Email:        "test@example.com",
		PasswordHash: "valid_password_hash",
	}
	err := repo.Create(ctx, invalidUser)
	assert.Error(t, err, "creating user with empty username should fail")

	// 测试创建无效用户（空邮箱）
	invalidUser2 := &model.User{
		Username:     "testuser",
		Email:        "", // 空邮箱
		PasswordHash: "valid_password_hash",
	}
	err = repo.Create(ctx, invalidUser2)
	assert.Error(t, err, "creating user with empty email should fail")

	// 测试创建无效用户（缺少密码）- 这个测试需要修改
	// 因为 PasswordHash 字段有 NOT NULL 约束，空字符串仍然不违反 CHECK 约束
	invalidUser3 := &model.User{
		Username: "testuser2",
		Email:    "test2@example.com",
	}
	err = repo.Create(ctx, invalidUser3)
	assert.Error(t, err, "creating user without password should fail")
}

// setupDatabase 设置测试数据库
func setupDatabase(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	err = database.Init(&cfg.Database)
	require.NoError(t, err, "failed to init database")

	db := database.Get()

	// 清理测试数据
	db.Exec("TRUNCATE TABLE user_roles CASCADE")
	db.Exec("TRUNCATE TABLE users CASCADE")
	db.Exec("TRUNCATE TABLE roles CASCADE")
}

// createTestUser 创建测试用户
func createTestUser(t *testing.T, repo UserRepository, username, email string) *model.User {
	ctx := context.Background()

	user := &model.User{
		Username: username,
		Email:    email,
		FullName: "Test User",
		Status:   model.UserStatusActive,
	}

	err := user.SetPassword("password123")
	require.NoError(t, err, "setting password should succeed")

	err = repo.Create(ctx, user)
	require.NoError(t, err, "creating test user should succeed")

	return user
}

// createTestRole 创建测试角色
func createTestRole(t *testing.T, name, description string) *model.Role {
	db := database.Get()

	role := &model.Role{
		Name:        name,
		Description: description,
		Permissions: []string{"read", "write"},
	}

	err := db.Create(role).Error
	require.NoError(t, err, "creating test role should succeed")

	return role
}
