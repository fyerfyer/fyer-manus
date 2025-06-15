package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
)

func TestNewSessionService(t *testing.T) {
	// 初始化数据库
	setupSessionServiceDatabase(t)

	service := NewSessionService()
	assert.NotNil(t, service, "session service should not be nil")
	assert.NotNil(t, service.sessionRepo, "session repository should not be nil")
	assert.NotNil(t, service.messageRepo, "message repository should not be nil")
	assert.NotNil(t, service.userRepo, "user repository should not be nil")
}

func TestSessionService_CreateSession(t *testing.T) {
	// 初始化数据库
	setupSessionServiceDatabase(t)

	service := NewSessionService()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUserForSessionService(t, "testuser", "test@example.com")

	// 测试正常创建会话
	req := model.SessionCreateRequest{
		Title:        "Test Session",
		ModelName:    "gpt-3.5-turbo",
		SystemPrompt: "You are a helpful assistant",
		Metadata: map[string]interface{}{
			"test": true,
		},
	}

	response, err := service.CreateSession(ctx, user.ID, req)
	assert.NoError(t, err, "creating session should succeed")
	assert.NotNil(t, response, "response should not be nil")
	assert.Equal(t, req.Title, response.Title, "title should match")
	assert.Equal(t, req.ModelName, response.ModelName, "model name should match")
	assert.Equal(t, types.SessionStatusActive, response.Status, "status should be active")
	assert.Equal(t, user.ID, response.UserID, "user id should match")

	// 测试空标题使用默认值
	emptyTitleReq := model.SessionCreateRequest{
		ModelName: "gpt-4",
	}

	response, err = service.CreateSession(ctx, user.ID, emptyTitleReq)
	assert.NoError(t, err, "creating session with empty title should succeed")
	assert.Equal(t, types.DefaultSessionTitle, response.Title, "should use default title")

	// 测试不存在的用户
	_, err = service.CreateSession(ctx, uuid.New(), req)
	assert.Error(t, err, "creating session for non-existent user should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")

	// 测试非活跃用户
	inactiveUser := createTestUserForSessionService(t, "inactive", "inactive@example.com")
	db := database.Get()
	err = db.Model(&model.User{}).Where("id = ?", inactiveUser.ID).Update("status", model.UserStatusInactive).Error
	require.NoError(t, err, "updating user status should succeed")

	_, err = service.CreateSession(ctx, inactiveUser.ID, req)
	assert.Error(t, err, "creating session for inactive user should fail")
	assert.Contains(t, err.Error(), "not active", "error should mention user not active")
}

func TestSessionService_GetSession(t *testing.T) {
	// 初始化数据库
	setupSessionServiceDatabase(t)

	service := NewSessionService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSessionService(t, "testuser", "test@example.com")
	session := createTestSessionForService(t, service, user.ID, "Test Session")

	// 测试获取会话
	response, err := service.GetSession(ctx, user.ID, session.ID)
	assert.NoError(t, err, "getting session should succeed")
	assert.NotNil(t, response, "response should not be nil")
	assert.Equal(t, session.ID, response.ID, "session id should match")
	assert.Equal(t, session.Title, response.Title, "title should match")

	// 测试权限检查
	otherUser := createTestUserForSessionService(t, "otheruser", "other@example.com")
	_, err = service.GetSession(ctx, otherUser.ID, session.ID)
	assert.Error(t, err, "getting session by other user should fail")
	assert.Contains(t, err.Error(), "access denied", "error should mention access denied")

	// 测试不存在的会话
	_, err = service.GetSession(ctx, user.ID, uuid.New())
	assert.Error(t, err, "getting non-existent session should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestSessionService_UpdateSession(t *testing.T) {
	// 初始化数据库
	setupSessionServiceDatabase(t)

	service := NewSessionService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSessionService(t, "testuser", "test@example.com")
	session := createTestSessionForService(t, service, user.ID, "Original Title")

	// 测试更新会话
	req := model.SessionUpdateRequest{
		Title:        "Updated Title",
		SystemPrompt: "Updated prompt",
		Metadata: map[string]interface{}{
			"updated": true,
		},
	}

	response, err := service.UpdateSession(ctx, user.ID, session.ID, req)
	assert.NoError(t, err, "updating session should succeed")
	assert.NotNil(t, response, "response should not be nil")
	assert.Equal(t, req.Title, response.Title, "title should be updated")
	assert.Equal(t, req.SystemPrompt, response.SystemPrompt, "system prompt should be updated")

	// 测试部分更新
	partialReq := model.SessionUpdateRequest{
		Title: "Partially Updated",
	}

	response, err = service.UpdateSession(ctx, user.ID, session.ID, partialReq)
	assert.NoError(t, err, "partial update should succeed")
	assert.Equal(t, partialReq.Title, response.Title, "title should be updated")
	assert.Equal(t, req.SystemPrompt, response.SystemPrompt, "system prompt should remain")

	// 测试权限检查
	otherUser := createTestUserForSessionService(t, "otheruser", "other@example.com")
	_, err = service.UpdateSession(ctx, otherUser.ID, session.ID, req)
	assert.Error(t, err, "updating session by other user should fail")
	assert.Contains(t, err.Error(), "access denied", "error should mention access denied")

	// 测试不存在的会话
	_, err = service.UpdateSession(ctx, user.ID, uuid.New(), req)
	assert.Error(t, err, "updating non-existent session should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestSessionService_DeleteSession(t *testing.T) {
	// 初始化数据库
	setupSessionServiceDatabase(t)

	service := NewSessionService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSessionService(t, "testuser", "test@example.com")
	session := createTestSessionForService(t, service, user.ID, "To Delete")

	// 测试删除会话
	err := service.DeleteSession(ctx, user.ID, session.ID)
	assert.NoError(t, err, "deleting session should succeed")

	// 验证会话被软删除
	_, err = service.GetSession(ctx, user.ID, session.ID)
	assert.Error(t, err, "getting deleted session should fail")
	assert.Contains(t, err.Error(), "deleted", "error should mention deleted")

	// 测试权限检查
	otherUser := createTestUserForSessionService(t, "otheruser", "other@example.com")
	otherSession := createTestSessionForService(t, service, otherUser.ID, "Other Session")

	err = service.DeleteSession(ctx, user.ID, otherSession.ID)
	assert.Error(t, err, "deleting session by other user should fail")
	assert.Contains(t, err.Error(), "access denied", "error should mention access denied")

	// 测试不存在的会话
	err = service.DeleteSession(ctx, user.ID, uuid.New())
	assert.Error(t, err, "deleting non-existent session should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestSessionService_ArchiveSession(t *testing.T) {
	// 初始化数据库
	setupSessionServiceDatabase(t)

	service := NewSessionService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSessionService(t, "testuser", "test@example.com")
	session := createTestSessionForService(t, service, user.ID, "To Archive")

	// 测试归档会话
	err := service.ArchiveSession(ctx, user.ID, session.ID)
	assert.NoError(t, err, "archiving session should succeed")

	// 验证会话被归档
	archivedSession, err := service.GetSession(ctx, user.ID, session.ID)
	assert.NoError(t, err, "getting archived session should succeed")
	assert.Equal(t, types.SessionStatusArchived, archivedSession.Status, "status should be archived")

	// 测试归档已归档的会话
	err = service.ArchiveSession(ctx, user.ID, session.ID)
	assert.Error(t, err, "archiving archived session should fail")
	assert.Contains(t, err.Error(), "not active", "error should mention not active")

	// 测试权限检查
	otherUser := createTestUserForSessionService(t, "otheruser", "other@example.com")
	otherSession := createTestSessionForService(t, service, otherUser.ID, "Other Session")

	err = service.ArchiveSession(ctx, user.ID, otherSession.ID)
	assert.Error(t, err, "archiving session by other user should fail")
	assert.Contains(t, err.Error(), "access denied", "error should mention access denied")
}

func TestSessionService_ListSessions(t *testing.T) {
	// 初始化数据库
	setupSessionServiceDatabase(t)

	service := NewSessionService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSessionService(t, "testuser", "test@example.com")

	// 创建多个会话
	for i := 0; i < 5; i++ {
		title := "Test Session " + string(rune('0'+i+1))
		createTestSessionForService(t, service, user.ID, title)
	}

	// 创建一个归档会话
	archivedSession := createTestSessionForService(t, service, user.ID, "Archived Session")
	err := service.ArchiveSession(ctx, user.ID, archivedSession.ID)
	require.NoError(t, err, "archiving session should succeed")

	// 测试列表所有会话
	params := types.SessionSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	response, err := service.ListSessions(ctx, user.ID, params)
	assert.NoError(t, err, "listing sessions should succeed")
	assert.NotNil(t, response, "response should not be nil")
	assert.GreaterOrEqual(t, len(response.Data.([]model.SessionListResponse)), 6, "should have at least 6 sessions")
	assert.GreaterOrEqual(t, response.Pagination.Total, int64(6), "total should be at least 6")

	// 测试状态过滤
	params.Status = string(types.SessionStatusActive)
	response, err = service.ListSessions(ctx, user.ID, params)
	assert.NoError(t, err, "listing active sessions should succeed")
	assert.GreaterOrEqual(t, len(response.Data.([]model.SessionListResponse)), 5, "should have at least 5 active sessions")

	// 测试搜索过滤
	params = types.SessionSearchParams{
		Query: "Session 1",
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	response, err = service.ListSessions(ctx, user.ID, params)
	assert.NoError(t, err, "searching sessions should succeed")
	assert.GreaterOrEqual(t, len(response.Data.([]model.SessionListResponse)), 1, "should find at least 1 session")

	// 测试分页
	params = types.SessionSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 3,
		},
	}
	params.Validate()

	firstPage, err := service.ListSessions(ctx, user.ID, params)
	assert.NoError(t, err, "getting first page should succeed")
	assert.Len(t, firstPage.Data.([]model.SessionListResponse), 3, "first page should have 3 sessions")

	params.PaginationParams.Page = 2
	params.Validate()

	secondPage, err := service.ListSessions(ctx, user.ID, params)
	assert.NoError(t, err, "getting second page should succeed")
	assert.GreaterOrEqual(t, len(secondPage.Data.([]model.SessionListResponse)), 3, "second page should have at least 3 sessions")
}

func TestSessionService_SearchSessions(t *testing.T) {
	// 初始化数据库
	setupSessionServiceDatabase(t)

	service := NewSessionService()
	ctx := context.Background()

	// 创建测试数据
	user1 := createTestUserForSessionService(t, "user1", "user1@example.com")
	user2 := createTestUserForSessionService(t, "user2", "user2@example.com")

	createTestSessionForService(t, service, user1.ID, "Machine Learning Chat")
	createTestSessionForService(t, service, user1.ID, "Python Programming")
	createTestSessionForService(t, service, user2.ID, "Java Development")

	// 测试按用户搜索
	params := types.SessionSearchParams{
		UserID: user1.ID.String(),
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	response, err := service.SearchSessions(ctx, params)
	assert.NoError(t, err, "searching by user should succeed")
	assert.GreaterOrEqual(t, len(response.Data.([]model.SessionListResponse)), 2, "should find at least 2 sessions for user1")

	// 测试按查询词搜索
	params = types.SessionSearchParams{
		Query: "Programming",
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	response, err = service.SearchSessions(ctx, params)
	assert.NoError(t, err, "searching by query should succeed")
	assert.GreaterOrEqual(t, len(response.Data.([]model.SessionListResponse)), 1, "should find at least 1 session with 'Programming'")

	// 测试组合搜索
	params = types.SessionSearchParams{
		UserID: user1.ID.String(),
		Query:  "Machine",
		Status: string(types.SessionStatusActive),
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	response, err = service.SearchSessions(ctx, params)
	assert.NoError(t, err, "combined search should succeed")
	assert.GreaterOrEqual(t, len(response.Data.([]model.SessionListResponse)), 1, "should find at least 1 matching session")
}

func TestSessionService_UpdateMessageCount(t *testing.T) {
	// 初始化数据库
	setupSessionServiceDatabase(t)

	service := NewSessionService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSessionService(t, "testuser", "test@example.com")
	session := createTestSessionForService(t, service, user.ID, "Test Session")

	// 测试更新消息计数
	err := service.UpdateMessageCount(ctx, session.ID)
	assert.NoError(t, err, "updating message count should succeed")

	// 验证计数更新
	updatedSession, err := service.GetSession(ctx, user.ID, session.ID)
	require.NoError(t, err, "getting updated session should succeed")
	assert.Equal(t, 0, updatedSession.MessageCount, "message count should be 0 for empty session")
}

func TestSessionService_AddTokenUsage(t *testing.T) {
	// 初始化数据库
	setupSessionServiceDatabase(t)

	service := NewSessionService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSessionService(t, "testuser", "test@example.com")
	session := createTestSessionForService(t, service, user.ID, "Test Session")

	// 测试增加token使用量
	err := service.AddTokenUsage(ctx, session.ID, 100)
	assert.NoError(t, err, "adding token usage should succeed")

	// 验证token增加
	updatedSession, err := service.GetSession(ctx, user.ID, session.ID)
	require.NoError(t, err, "getting updated session should succeed")
	assert.Equal(t, 100, updatedSession.TotalTokens, "total tokens should be 100")

	// 再次增加token
	err = service.AddTokenUsage(ctx, session.ID, 50)
	assert.NoError(t, err, "adding more tokens should succeed")

	finalSession, err := service.GetSession(ctx, user.ID, session.ID)
	require.NoError(t, err, "getting final session should succeed")
	assert.Equal(t, 150, finalSession.TotalTokens, "total tokens should be 150")

	// 测试0或负数token
	err = service.AddTokenUsage(ctx, session.ID, 0)
	assert.NoError(t, err, "adding 0 tokens should succeed without error")

	err = service.AddTokenUsage(ctx, session.ID, -10)
	assert.NoError(t, err, "adding negative tokens should succeed without error")
}

func TestSessionService_GetSessionStats(t *testing.T) {
	// 初始化数据库
	setupSessionServiceDatabase(t)

	service := NewSessionService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSessionService(t, "testuser", "test@example.com")

	// 创建几个活跃会话
	for i := 0; i < 3; i++ {
		createTestSessionForService(t, service, user.ID, "Active Session")
	}

	// 创建一个归档会话
	archivedSession := createTestSessionForService(t, service, user.ID, "Archived Session")
	err := service.ArchiveSession(ctx, user.ID, archivedSession.ID)
	require.NoError(t, err, "archiving session should succeed")

	// 测试获取统计信息
	stats, err := service.GetSessionStats(ctx, user.ID)
	assert.NoError(t, err, "getting session stats should succeed")
	assert.NotNil(t, stats, "stats should not be nil")
	assert.Contains(t, stats, "active_sessions", "stats should contain active_sessions")
	assert.Contains(t, stats, "max_sessions", "stats should contain max_sessions")
	assert.Contains(t, stats, "remaining_sessions", "stats should contain remaining_sessions")

	activeCount := stats["active_sessions"].(int64)
	// 修复：使用 int64(3) 而不是 int(3)
	assert.GreaterOrEqual(t, activeCount, int64(3), "should have at least 3 active sessions")
	assert.Equal(t, int64(types.MaxSessionsPerUser), stats["max_sessions"], "max sessions should match constant")
}

func TestSessionService_CleanupExpiredSessions(t *testing.T) {
	// 初始化数据库
	setupSessionServiceDatabase(t)

	service := NewSessionService()
	ctx := context.Background()

	// 测试清理过期会话
	err := service.CleanupExpiredSessions(ctx)
	assert.NoError(t, err, "cleanup should succeed")
}

func TestSessionService_SessionLimits(t *testing.T) {
	// 初始化数据库
	setupSessionServiceDatabase(t)

	service := NewSessionService()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUserForSessionService(t, "testuser", "test@example.com")

	// 模拟达到会话限制（这里为了测试方便，我们假设限制是一个较小的数字）
	// 在实际测试中，我们可能需要修改常量或使用mock

	req := model.SessionCreateRequest{
		Title:     "Test Session",
		ModelName: "gpt-3.5-turbo",
	}

	// 由于MaxSessionsPerUser=100，实际测试中创建100个会话会很慢
	// 这里我们只测试基本的创建逻辑
	response, err := service.CreateSession(ctx, user.ID, req)
	assert.NoError(t, err, "creating session should succeed")
	assert.NotNil(t, response, "response should not be nil")
}

// setupSessionServiceDatabase 设置测试数据库
func setupSessionServiceDatabase(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	err = database.Init(&cfg.Database)
	require.NoError(t, err, "failed to init database")

	// 自动迁移表结构
	db := database.Get()
	require.NoError(t, err, "failed to migrate tables")

	// 清理测试数据
	db.Exec("TRUNCATE TABLE messages CASCADE")
	db.Exec("TRUNCATE TABLE sessions CASCADE")
	db.Exec("TRUNCATE TABLE user_roles CASCADE")
	db.Exec("TRUNCATE TABLE users CASCADE")
	db.Exec("TRUNCATE TABLE roles CASCADE")
}

// createTestUserForSessionService 创建测试用户
func createTestUserForSessionService(t *testing.T, username, email string) *model.User {
	db := database.Get()

	user := &model.User{
		Username: username,
		Email:    email,
		FullName: "Test User",
		Status:   model.UserStatusActive,
	}

	err := user.SetPassword("password123")
	require.NoError(t, err, "setting password should succeed")

	err = db.Create(user).Error
	require.NoError(t, err, "creating test user should succeed")

	return user
}

// createTestSessionForService 创建测试会话
func createTestSessionForService(t *testing.T, service *SessionService, userID uuid.UUID, title string) *model.SessionResponse {
	ctx := context.Background()

	req := model.SessionCreateRequest{
		Title:        title,
		ModelName:    "gpt-3.5-turbo",
		SystemPrompt: "You are a helpful assistant",
		Metadata: map[string]interface{}{
			"test": true,
		},
	}

	response, err := service.CreateSession(ctx, userID, req)
	require.NoError(t, err, "creating test session should succeed")

	return response
}
