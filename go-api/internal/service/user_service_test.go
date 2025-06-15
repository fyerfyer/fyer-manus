package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/testutils"
)

func TestNewUserService(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	assert.NotNil(t, service, "user service should not be nil")
	assert.NotNil(t, service.userRepo, "user repository should not be nil")
}

func TestUserService_CreateUser(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 测试正常创建用户
	req := CreateUserRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
		FullName: "Test User",
	}

	profile, err := service.CreateUser(ctx, req)
	assert.NoError(t, err, "creating user should succeed")
	assert.NotNil(t, profile, "profile should not be nil")
	assert.Equal(t, req.Username, profile.Username, "username should match")
	assert.Equal(t, req.Email, profile.Email, "email should match")
	assert.Equal(t, req.FullName, profile.FullName, "full name should match")
	assert.Equal(t, model.UserStatusActive, profile.Status, "user should be active")

	// 测试重复用户名
	duplicateReq := CreateUserRequest{
		Username: "testuser",
		Email:    "another@example.com",
		Password: "password123",
	}

	_, err = service.CreateUser(ctx, duplicateReq)
	assert.Error(t, err, "creating user with duplicate username should fail")
	assert.Contains(t, err.Error(), "already exists", "error should mention already exists")

	// 测试重复邮箱
	duplicateEmailReq := CreateUserRequest{
		Username: "anotheruser",
		Email:    "test@example.com",
		Password: "password123",
	}

	_, err = service.CreateUser(ctx, duplicateEmailReq)
	assert.Error(t, err, "creating user with duplicate email should fail")
	assert.Contains(t, err.Error(), "already exists", "error should mention already exists")
}

func TestUserService_GetUserByID(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUserForService(t, "testuser", "test@example.com")

	// 测试获取用户
	profile, err := service.GetUserByID(ctx, user.ID)
	assert.NoError(t, err, "getting user by id should succeed")
	assert.NotNil(t, profile, "profile should not be nil")
	assert.Equal(t, user.ID, profile.ID, "user id should match")
	assert.Equal(t, user.Username, profile.Username, "username should match")

	// 测试不存在的用户
	_, err = service.GetUserByID(ctx, uuid.New())
	assert.Error(t, err, "getting non-existent user should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestUserService_GetUserByUsername(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUserForService(t, "testuser", "test@example.com")

	// 测试通过用户名获取用户
	profile, err := service.GetUserByUsername(ctx, user.Username)
	assert.NoError(t, err, "getting user by username should succeed")
	assert.NotNil(t, profile, "profile should not be nil")
	assert.Equal(t, user.ID, profile.ID, "user id should match")
	assert.Equal(t, user.Username, profile.Username, "username should match")

	// 测试不存在的用户名
	_, err = service.GetUserByUsername(ctx, "nonexistent")
	assert.Error(t, err, "getting non-existent user should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestUserService_GetUserByEmail(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUserForService(t, "testuser", "test@example.com")

	// 测试通过邮箱获取用户
	profile, err := service.GetUserByEmail(ctx, user.Email)
	assert.NoError(t, err, "getting user by email should succeed")
	assert.NotNil(t, profile, "profile should not be nil")
	assert.Equal(t, user.ID, profile.ID, "user id should match")
	assert.Equal(t, user.Email, profile.Email, "email should match")

	// 测试不存在的邮箱
	_, err = service.GetUserByEmail(ctx, "nonexistent@example.com")
	assert.Error(t, err, "getting non-existent user should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestUserService_UpdateUser(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUserForService(t, "testuser", "test@example.com")

	// 测试更新用户信息
	req := UpdateUserRequest{
		FullName:  "Updated Name",
		AvatarURL: "https://example.com/avatar.jpg",
	}

	profile, err := service.UpdateUser(ctx, user.ID, req)
	assert.NoError(t, err, "updating user should succeed")
	assert.NotNil(t, profile, "profile should not be nil")
	assert.Equal(t, req.FullName, profile.FullName, "full name should be updated")
	assert.Equal(t, req.AvatarURL, profile.AvatarURL, "avatar url should be updated")

	// 测试部分更新
	partialReq := UpdateUserRequest{
		FullName: "Partially Updated Name",
	}

	profile, err = service.UpdateUser(ctx, user.ID, partialReq)
	assert.NoError(t, err, "partial update should succeed")
	assert.Equal(t, partialReq.FullName, profile.FullName, "full name should be updated")
	assert.Equal(t, req.AvatarURL, profile.AvatarURL, "avatar url should remain unchanged")

	// 测试更新不存在的用户
	_, err = service.UpdateUser(ctx, uuid.New(), req)
	assert.Error(t, err, "updating non-existent user should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestUserService_ChangePassword(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUserForService(t, "testuser", "test@example.com")

	// 测试修改密码
	req := ChangePasswordRequest{
		OldPassword: "password123",
		NewPassword: "newpassword456",
	}

	err := service.ChangePassword(ctx, user.ID, req)
	assert.NoError(t, err, "changing password should succeed")

	// 验证新密码（通过重新获取用户并检查密码）
	updatedUser, err := service.ValidateUser(ctx, user.Username, req.NewPassword)
	assert.NoError(t, err, "login with new password should succeed")
	assert.Equal(t, user.ID, updatedUser.ID, "user id should match")

	// 验证旧密码不再有效
	_, err = service.ValidateUser(ctx, user.Username, req.OldPassword)
	assert.Error(t, err, "login with old password should fail")

	// 测试错误的旧密码
	wrongReq := ChangePasswordRequest{
		OldPassword: "wrongpassword",
		NewPassword: "anotherpassword",
	}

	err = service.ChangePassword(ctx, user.ID, wrongReq)
	assert.Error(t, err, "changing password with wrong old password should fail")
	assert.Contains(t, err.Error(), "invalid", "error should mention invalid old password")

	// 测试不存在的用户
	err = service.ChangePassword(ctx, uuid.New(), req)
	assert.Error(t, err, "changing password for non-existent user should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestUserService_UpdateUserStatus(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUserForService(t, "testuser", "test@example.com")

	// 测试更新用户状态
	err := service.UpdateUserStatus(ctx, user.ID, model.UserStatusSuspended)
	assert.NoError(t, err, "updating user status should succeed")

	// 验证状态更新
	profile, err := service.GetUserByID(ctx, user.ID)
	require.NoError(t, err, "getting updated user should succeed")
	assert.Equal(t, model.UserStatusSuspended, profile.Status, "status should be updated")

	// 测试更新不存在的用户状态
	err = service.UpdateUserStatus(ctx, uuid.New(), model.UserStatusActive)
	assert.Error(t, err, "updating status for non-existent user should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestUserService_DeleteUser(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUserForService(t, "testuser", "test@example.com")

	// 测试删除用户
	err := service.DeleteUser(ctx, user.ID)
	assert.NoError(t, err, "deleting user should succeed")

	// 验证用户被删除
	_, err = service.GetUserByID(ctx, user.ID)
	assert.Error(t, err, "getting deleted user should fail")

	// 测试删除不存在的用户
	err = service.DeleteUser(ctx, uuid.New())
	assert.Error(t, err, "deleting non-existent user should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestUserService_ListUsers(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 创建多个测试用户
	for i := 0; i < 5; i++ {
		username := "testuser" + string(rune('0'+i))
		email := "test" + string(rune('0'+i)) + "@example.com"
		createTestUserForService(t, username, email)
	}

	// 测试列表用户
	profiles, total, err := service.ListUsers(ctx, 1, 3)
	assert.NoError(t, err, "listing users should succeed")
	assert.Len(t, profiles, 3, "should return 3 users")
	assert.GreaterOrEqual(t, total, int64(5), "total should be at least 5")

	// 测试第二页
	profiles, total, err = service.ListUsers(ctx, 2, 3)
	assert.NoError(t, err, "listing second page should succeed")
	assert.GreaterOrEqual(t, len(profiles), 2, "should return at least 2 users")
	assert.GreaterOrEqual(t, total, int64(5), "total should be at least 5")

	// 测试默认参数
	profiles, total, err = service.ListUsers(ctx, 0, 0)
	assert.NoError(t, err, "listing with default params should succeed")
	assert.GreaterOrEqual(t, len(profiles), 5, "should return at least 5 users")
	assert.GreaterOrEqual(t, total, int64(5), "total should be at least 5")

	// 测试超大页面大小限制
	profiles, _, err = service.ListUsers(ctx, 1, 200)
	assert.NoError(t, err, "listing with large page size should succeed")
	assert.LessOrEqual(t, len(profiles), 100, "should not exceed max page size of 100")
}

func TestUserService_SearchUsers(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 创建测试用户
	createTestUserForService(t, "searchuser", "search@example.com")
	createTestUserForService(t, "anotheruser", "another@example.com")
	createTestUserForService(t, "testuser", "test@search.com")

	// 测试搜索用户名
	profiles, total, err := service.SearchUsers(ctx, "search", 1, 10)
	assert.NoError(t, err, "searching users should succeed")
	assert.GreaterOrEqual(t, len(profiles), 2, "should find at least 2 users")
	assert.GreaterOrEqual(t, total, int64(2), "total should be at least 2")

	// 验证搜索结果
	searchFound := false
	testFound := false
	for _, profile := range profiles {
		if profile.Username == "searchuser" || profile.Email == "search@example.com" {
			searchFound = true
		}
		if profile.Username == "testuser" || profile.Email == "test@search.com" {
			testFound = true
		}
	}
	assert.True(t, searchFound, "should find searchuser")
	assert.True(t, testFound, "should find testuser with search in email")

	// 测试搜索不存在的内容
	profiles, total, err = service.SearchUsers(ctx, "nonexistent", 1, 10)
	assert.NoError(t, err, "searching non-existent should succeed")
	assert.Equal(t, 0, len(profiles), "should find no users")
	assert.Equal(t, int64(0), total, "total should be 0")

	// 测试空搜索（应该返回所有用户）
	profiles, total, err = service.SearchUsers(ctx, "", 1, 10)
	assert.NoError(t, err, "empty search should succeed")
	assert.GreaterOrEqual(t, len(profiles), 3, "should return at least 3 users")
	assert.GreaterOrEqual(t, total, int64(3), "total should be at least 3")
}

func TestUserService_AssignRole(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 创建测试用户和角色
	user := createTestUserForService(t, "testuser", "test@example.com")
	role := createTestRoleForService(t, "testrole", "Test Role")

	// 测试分配角色
	err := service.AssignRole(ctx, user.ID, role.ID)
	assert.NoError(t, err, "assigning role should succeed")

	// 验证角色分配
	roles, err := service.GetUserRoles(ctx, user.ID)
	assert.NoError(t, err, "getting user roles should succeed")
	assert.GreaterOrEqual(t, len(roles), 1, "user should have at least 1 role")

	// 验证具体角色
	roleFound := false
	for _, r := range roles {
		if r.ID == role.ID {
			roleFound = true
			break
		}
	}
	assert.True(t, roleFound, "user should have the assigned role")

	// 测试分配角色给不存在的用户
	err = service.AssignRole(ctx, uuid.New(), role.ID)
	assert.Error(t, err, "assigning role to non-existent user should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestUserService_RemoveRole(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 创建测试用户和角色
	user := createTestUserForService(t, "testuser", "test@example.com")
	role := createTestRoleForService(t, "testrole", "Test Role")

	// 先分配角色
	err := service.AssignRole(ctx, user.ID, role.ID)
	require.NoError(t, err, "assigning role should succeed")

	// 测试移除角色
	err = service.RemoveRole(ctx, user.ID, role.ID)
	assert.NoError(t, err, "removing role should succeed")

	// 验证角色移除
	roles, err := service.GetUserRoles(ctx, user.ID)
	assert.NoError(t, err, "getting user roles should succeed")

	// 检查角色是否已移除
	roleFound := false
	for _, r := range roles {
		if r.ID == role.ID {
			roleFound = true
			break
		}
	}
	assert.False(t, roleFound, "role should be removed")

	// 测试从不存在的用户移除角色
	err = service.RemoveRole(ctx, uuid.New(), role.ID)
	assert.Error(t, err, "removing role from non-existent user should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestUserService_GetUserRoles(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 创建测试用户和角色
	user := createTestUserForService(t, "testuser", "test@example.com")
	role1 := createTestRoleForService(t, "role1", "Role 1")
	role2 := createTestRoleForService(t, "role2", "Role 2")

	// 分配多个角色
	err := service.AssignRole(ctx, user.ID, role1.ID)
	require.NoError(t, err, "assigning role1 should succeed")

	err = service.AssignRole(ctx, user.ID, role2.ID)
	require.NoError(t, err, "assigning role2 should succeed")

	// 测试获取用户角色
	roles, err := service.GetUserRoles(ctx, user.ID)
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

func TestUserService_ValidateUser(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUserForService(t, "testuser", "test@example.com")

	// 测试验证用户
	validatedUser, err := service.ValidateUser(ctx, "testuser", "password123")
	assert.NoError(t, err, "validating user should succeed")
	assert.NotNil(t, validatedUser, "validated user should not be nil")
	assert.Equal(t, user.ID, validatedUser.ID, "user id should match")

	// 测试错误密码
	_, err = service.ValidateUser(ctx, "testuser", "wrongpassword")
	assert.Error(t, err, "validating with wrong password should fail")
	assert.Contains(t, err.Error(), "invalid", "error should mention invalid credentials")

	// 测试不存在的用户
	_, err = service.ValidateUser(ctx, "nonexistent", "password123")
	assert.Error(t, err, "validating non-existent user should fail")
	assert.Contains(t, err.Error(), "invalid", "error should mention invalid credentials")

	// 测试非活跃用户
	err = service.UpdateUserStatus(ctx, user.ID, model.UserStatusInactive)
	require.NoError(t, err, "updating user status should succeed")

	_, err = service.ValidateUser(ctx, "testuser", "password123")
	assert.Error(t, err, "validating inactive user should fail")
	assert.Contains(t, err.Error(), "not active", "error should mention user not active")
}

func TestUserService_GetUserStats(t *testing.T) {
	// 初始化数据库
	setupUserServiceDatabase(t)

	service := NewUserService()
	ctx := context.Background()

	// 测试获取用户统计信息
	stats, err := service.GetUserStats(ctx)
	assert.NoError(t, err, "getting user stats should succeed")
	assert.NotNil(t, stats, "stats should not be nil")
	assert.NotEmpty(t, stats, "stats should not be empty")
}

// setupUserServiceDatabase 设置测试数据库
func setupUserServiceDatabase(t *testing.T) {
	testutils.SetupTestEnv(t)
}

// createTestUserForService 创建测试用户
func createTestUserForService(t *testing.T, username, email string) *model.User {
	manager := testutils.NewTestDBManager(t)
	userID := manager.CreateTestUser(t, username, email)

	// 获取创建的用户
	db := database.Get()
	var user model.User
	err := db.First(&user, "id = ?", userID).Error
	require.NoError(t, err, "getting created user should succeed")

	return &user
}

// createTestRoleForService 创建测试角色
func createTestRoleForService(t *testing.T, name, description string) *model.Role {
	manager := testutils.NewTestDBManager(t)
	roleID := manager.CreateTestRole(t, name, description, []string{"read", "write"})

	// 获取创建的角色
	db := database.Get()
	var role model.Role
	err := db.First(&role, "id = ?", roleID).Error
	require.NoError(t, err, "getting created role should succeed")

	return &role
}
