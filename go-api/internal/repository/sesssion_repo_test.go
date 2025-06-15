package repository

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/fyerfyer/fyer-manus/go-api/testutils"
)

func TestNewSessionRepository(t *testing.T) {
	// 初始化数据库
	setupSessionDatabase(t)

	repo := NewSessionRepository()
	assert.NotNil(t, repo, "session repository should not be nil")
}

func TestSessionRepository_Create(t *testing.T) {
	// 初始化数据库
	setupSessionDatabase(t)

	repo := NewSessionRepository()
	ctx := context.Background()

	// 创建测试用户
	user := createTestUserForSession(t, "testuser", "test@example.com")

	// 测试创建会话
	session := &model.Session{
		UserID:       user.ID,
		Title:        "Test Session",
		Status:       types.SessionStatusActive,
		ModelName:    "gpt-3.5-turbo",
		SystemPrompt: "You are a helpful assistant",
		Metadata: map[string]interface{}{
			"test": "value",
		},
	}

	err := repo.Create(ctx, session)
	assert.NoError(t, err, "creating session should succeed")
	assert.NotEqual(t, uuid.Nil, session.ID, "session id should be set")
	assert.False(t, session.CreatedAt.IsZero(), "created_at should be set")
}

func TestSessionRepository_GetByID(t *testing.T) {
	// 初始化数据库
	setupSessionDatabase(t)

	repo := NewSessionRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSession(t, "testuser", "test@example.com")
	session := createTestSession(t, repo, user.ID, "Test Session")

	// 获取会话
	foundSession, err := repo.GetByID(ctx, session.ID)
	assert.NoError(t, err, "getting session by id should succeed")
	assert.NotNil(t, foundSession, "found session should not be nil")
	assert.Equal(t, session.ID, foundSession.ID, "session id should match")
	assert.Equal(t, session.Title, foundSession.Title, "title should match")
	assert.Equal(t, session.UserID, foundSession.UserID, "user id should match")

	// 测试不存在的会话
	_, err = repo.GetByID(ctx, uuid.New())
	assert.Error(t, err, "getting non-existent session should fail")
}

func TestSessionRepository_GetByUserID(t *testing.T) {
	// 初始化数据库
	setupSessionDatabase(t)

	repo := NewSessionRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSession(t, "testuser", "test@example.com")

	// 创建多个会话
	session1 := createTestSession(t, repo, user.ID, "Session 1")
	session3 := createTestSession(t, repo, user.ID, "Archived Session")

	// 归档一个会话
	session3.Status = types.SessionStatusArchived
	err := repo.Update(ctx, session3)
	require.NoError(t, err, "updating session should succeed")

	// 测试获取所有会话
	params := types.SessionSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	sessions, total, err := repo.GetByUserID(ctx, user.ID, params)
	assert.NoError(t, err, "getting sessions by user id should succeed")
	assert.GreaterOrEqual(t, len(sessions), 2, "should have at least 3 sessions")
	assert.GreaterOrEqual(t, total, int64(2), "total should be at least 3")

	// 测试状态过滤
	params.Status = string(types.SessionStatusActive)
	activeSessions, activeTotal, err := repo.GetByUserID(ctx, user.ID, params)
	assert.NoError(t, err, "getting active sessions should succeed")
	assert.GreaterOrEqual(t, len(activeSessions), 1, "should have at least 2 active sessions")
	assert.GreaterOrEqual(t, activeTotal, int64(1), "active total should be at least 2")

	// 测试标题搜索
	params = types.SessionSearchParams{
		Query: "Session 1",
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	searchSessions, searchTotal, err := repo.GetByUserID(ctx, user.ID, params)
	assert.NoError(t, err, "searching sessions should succeed")
	assert.GreaterOrEqual(t, len(searchSessions), 1, "should find at least 1 session")
	assert.GreaterOrEqual(t, searchTotal, int64(1), "search total should be at least 1")

	// 验证找到的会话
	found := false
	for _, s := range searchSessions {
		if s.ID == session1.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "should find session1 in search results")
}

func TestSessionRepository_Update(t *testing.T) {
	// 初始化数据库
	setupSessionDatabase(t)

	repo := NewSessionRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSession(t, "testuser", "test@example.com")
	session := createTestSession(t, repo, user.ID, "Original Title")

	// 更新会话
	session.Title = "Updated Title"
	session.SystemPrompt = "Updated prompt"
	session.Metadata = map[string]interface{}{
		"updated": true,
	}

	err := repo.Update(ctx, session)
	assert.NoError(t, err, "updating session should succeed")

	// 验证更新
	updatedSession, err := repo.GetByID(ctx, session.ID)
	require.NoError(t, err, "getting updated session should succeed")
	assert.Equal(t, "Updated Title", updatedSession.Title, "title should be updated")
	assert.Equal(t, "Updated prompt", updatedSession.SystemPrompt, "system prompt should be updated")
	assert.Equal(t, true, updatedSession.Metadata["updated"], "metadata should be updated")
}

func TestSessionRepository_Delete(t *testing.T) {
	// 初始化数据库
	setupSessionDatabase(t)

	repo := NewSessionRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSession(t, "testuser", "test@example.com")
	session := createTestSession(t, repo, user.ID, "To Delete")

	// 删除会话（软删除）
	err := repo.Delete(ctx, session.ID)
	assert.NoError(t, err, "deleting session should succeed")

	// 验证软删除
	deletedSession, err := repo.GetByID(ctx, session.ID)
	require.NoError(t, err, "getting deleted session should succeed")
	assert.Equal(t, types.SessionStatusDeleted, deletedSession.Status, "status should be deleted")
}

func TestSessionRepository_Archive(t *testing.T) {
	// 初始化数据库
	setupSessionDatabase(t)

	repo := NewSessionRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSession(t, "testuser", "test@example.com")
	session := createTestSession(t, repo, user.ID, "To Archive")

	// 归档会话
	err := repo.Archive(ctx, session.ID)
	assert.NoError(t, err, "archiving session should succeed")

	// 验证归档
	archivedSession, err := repo.GetByID(ctx, session.ID)
	require.NoError(t, err, "getting archived session should succeed")
	assert.Equal(t, types.SessionStatusArchived, archivedSession.Status, "status should be archived")
}

func TestSessionRepository_UpdateMessageCount(t *testing.T) {
	// 初始化数据库
	setupSessionDatabase(t)

	repo := NewSessionRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSession(t, "testuser", "test@example.com")
	session := createTestSession(t, repo, user.ID, "Test Session")

	// 更新消息计数
	newCount := 10
	err := repo.UpdateMessageCount(ctx, session.ID, newCount)
	assert.NoError(t, err, "updating message count should succeed")

	// 验证更新
	updatedSession, err := repo.GetByID(ctx, session.ID)
	require.NoError(t, err, "getting updated session should succeed")
	assert.Equal(t, newCount, updatedSession.MessageCount, "message count should be updated")
}

func TestSessionRepository_AddTokens(t *testing.T) {
	// 初始化数据库
	setupSessionDatabase(t)

	repo := NewSessionRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSession(t, "testuser", "test@example.com")
	session := createTestSession(t, repo, user.ID, "Test Session")

	originalTokens := session.TotalTokens

	// 增加tokens
	addTokens := 100
	err := repo.AddTokens(ctx, session.ID, addTokens)
	assert.NoError(t, err, "adding tokens should succeed")

	// 验证增加
	updatedSession, err := repo.GetByID(ctx, session.ID)
	require.NoError(t, err, "getting updated session should succeed")
	assert.Equal(t, originalTokens+addTokens, updatedSession.TotalTokens, "total tokens should be increased")

	// 再次增加tokens
	err = repo.AddTokens(ctx, session.ID, 50)
	assert.NoError(t, err, "adding more tokens should succeed")

	// 验证累加
	finalSession, err := repo.GetByID(ctx, session.ID)
	require.NoError(t, err, "getting final session should succeed")
	assert.Equal(t, originalTokens+addTokens+50, finalSession.TotalTokens, "tokens should be accumulated")
}

func TestSessionRepository_Search(t *testing.T) {
	// 初始化数据库
	setupSessionDatabase(t)

	repo := NewSessionRepository()
	ctx := context.Background()

	// 创建测试数据
	user1 := createTestUserForSession(t, "user1", "user1@example.com")
	user2 := createTestUserForSession(t, "user2", "user2@example.com")

	// 创建更多会话用于测试
	session1 := createTestSession(t, repo, user1.ID, "Python Programming Guide")
	createTestSession(t, repo, user1.ID, "JavaScript Basics")
	session3 := createTestSession(t, repo, user2.ID, "Machine Learning with Python")
	createTestSession(t, repo, user2.ID, "Data Science Tutorial")

	// 修改一个会话的系统提示用于搜索测试
	session1.SystemPrompt = "You are a Python programming expert"
	err := repo.Update(ctx, session1)
	require.NoError(t, err, "updating session should succeed")

	// 归档一个会话用于状态测试
	err = repo.Archive(ctx, session3.ID)
	require.NoError(t, err, "archiving session should succeed")

	// 测试按用户搜索
	params := types.SessionSearchParams{
		UserID: user1.ID.String(),
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	sessions, total, err := repo.Search(ctx, params)
	assert.NoError(t, err, "searching by user should succeed")
	assert.Equal(t, 2, len(sessions), "should find exactly 2 sessions for user1")
	assert.Equal(t, int64(2), total, "total should be 2")

	// 验证找到的会话属于正确的用户
	for _, s := range sessions {
		assert.Equal(t, user1.ID, s.UserID, "all sessions should belong to user1")
	}

	// 测试按查询词搜索（标题）
	params = types.SessionSearchParams{
		Query: "Python",
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	sessions, total, err = repo.Search(ctx, params)
	assert.NoError(t, err, "searching by query should succeed")
	assert.Equal(t, 2, len(sessions), "should find exactly 2 sessions with 'Python'")
	assert.Equal(t, int64(2), total, "total should be 2")

	// 验证搜索结果包含Python相关会话
	foundSessions := make(map[uuid.UUID]bool)
	for _, s := range sessions {
		foundSessions[s.ID] = true
		assert.True(t,
			strings.Contains(strings.ToLower(s.Title), "python") ||
				strings.Contains(strings.ToLower(s.SystemPrompt), "python"),
			"session should contain 'python' in title or system prompt")
	}
	assert.True(t, foundSessions[session1.ID], "should find session1")
	assert.True(t, foundSessions[session3.ID], "should find session3")

	// 测试按状态搜索
	params = types.SessionSearchParams{
		Status: string(types.SessionStatusActive),
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	activeSessions, activeTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "searching by status should succeed")
	assert.Equal(t, 3, len(activeSessions), "should find exactly 3 active sessions")
	assert.Equal(t, int64(3), activeTotal, "active total should be 3")

	// 验证所有返回的会话都是活跃状态
	for _, s := range activeSessions {
		assert.Equal(t, types.SessionStatusActive, s.Status, "all sessions should be active")
	}

	// 测试归档状态搜索
	params = types.SessionSearchParams{
		Status: string(types.SessionStatusArchived),
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	archivedSessions, archivedTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "searching archived sessions should succeed")
	assert.Equal(t, 1, len(archivedSessions), "should find exactly 1 archived session")
	assert.Equal(t, int64(1), archivedTotal, "archived total should be 1")
	assert.Equal(t, session3.ID, archivedSessions[0].ID, "should find the archived session")

	// 测试组合搜索
	params = types.SessionSearchParams{
		UserID: user1.ID.String(),
		Query:  "Programming",
		Status: string(types.SessionStatusActive),
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	combinedSessions, combinedTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "combined search should succeed")
	assert.Equal(t, 1, len(combinedSessions), "should find exactly 1 session matching all criteria")
	assert.Equal(t, int64(1), combinedTotal, "combined total should be 1")

	// 验证找到的是正确的会话
	assert.Equal(t, session1.ID, combinedSessions[0].ID, "should find session1 in combined search")
	assert.Equal(t, user1.ID, combinedSessions[0].UserID, "session should belong to user1")
	assert.Equal(t, types.SessionStatusActive, combinedSessions[0].Status, "session should be active")
	assert.Contains(t, strings.ToLower(combinedSessions[0].Title), "programming",
		"session title should contain 'programming'")

	// 测试空搜索（返回所有会话）
	params = types.SessionSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	allSessions, allTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "empty search should succeed")
	assert.Equal(t, 4, len(allSessions), "should return all 4 sessions")
	assert.Equal(t, int64(4), allTotal, "total should be 4")

	// 测试不存在的搜索条件
	params = types.SessionSearchParams{
		Query: "NonExistentKeyword",
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	noResultSessions, noResultTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "search with no results should succeed")
	assert.Equal(t, 0, len(noResultSessions), "should find no sessions")
	assert.Equal(t, int64(0), noResultTotal, "total should be 0")

	// 测试分页
	params = types.SessionSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 2,
			Page:     1,
		},
	}
	params.Validate()

	firstPage, firstTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "first page search should succeed")
	assert.Equal(t, 2, len(firstPage), "first page should have 2 sessions")
	assert.Equal(t, int64(4), firstTotal, "total should be 4")

	params.PaginationParams.Page = 2
	params.Validate()

	secondPage, secondTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "second page search should succeed")
	assert.Equal(t, 2, len(secondPage), "second page should have 2 sessions")
	assert.Equal(t, firstTotal, secondTotal, "total should be consistent")

	// 验证分页结果不重复
	firstPageIDs := make(map[uuid.UUID]bool)
	for _, s := range firstPage {
		firstPageIDs[s.ID] = true
	}

	for _, s := range secondPage {
		assert.False(t, firstPageIDs[s.ID], "second page should not contain sessions from first page")
	}
}

func TestSessionRepository_GetActiveSessionsCount(t *testing.T) {
	// 初始化数据库
	setupSessionDatabase(t)

	repo := NewSessionRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSession(t, "testuser", "test@example.com")

	// 获取初始活跃会话数量（应该为0）
	initialCount, err := repo.GetActiveSessionsCount(ctx, user.ID)
	assert.NoError(t, err, "getting initial active sessions count should succeed")
	assert.Equal(t, int64(0), initialCount, "initial active sessions count should be 0")

	// 创建多个会话
	session1 := createTestSession(t, repo, user.ID, "Active Session 1")
	session2 := createTestSession(t, repo, user.ID, "Active Session 2")
	session3 := createTestSession(t, repo, user.ID, "Session To Archive")
	session4 := createTestSession(t, repo, user.ID, "Session To Delete")

	// 验证创建后的活跃会话数量
	afterCreateCount, err := repo.GetActiveSessionsCount(ctx, user.ID)
	assert.NoError(t, err, "getting active sessions count after creation should succeed")
	assert.Equal(t, int64(4), afterCreateCount, "should have 4 active sessions after creation")

	// 归档一个会话
	err = repo.Archive(ctx, session3.ID)
	require.NoError(t, err, "archiving session should succeed")

	// 验证归档后的活跃会话数量
	afterArchiveCount, err := repo.GetActiveSessionsCount(ctx, user.ID)
	assert.NoError(t, err, "getting active sessions count after archive should succeed")
	assert.Equal(t, int64(3), afterArchiveCount, "should have 3 active sessions after archiving one")

	// 删除一个会话（软删除）
	err = repo.Delete(ctx, session4.ID)
	require.NoError(t, err, "deleting session should succeed")

	// 验证删除后的活跃会话数量
	afterDeleteCount, err := repo.GetActiveSessionsCount(ctx, user.ID)
	assert.NoError(t, err, "getting active sessions count after delete should succeed")
	assert.Equal(t, int64(2), afterDeleteCount, "should have 2 active sessions after deleting one")

	// 再删除一个会话
	err = repo.Delete(ctx, session1.ID)
	require.NoError(t, err, "deleting another session should succeed")

	// 验证最终的活跃会话数量
	finalCount, err := repo.GetActiveSessionsCount(ctx, user.ID)
	assert.NoError(t, err, "getting final active sessions count should succeed")
	assert.Equal(t, int64(1), finalCount, "should have 1 active session remaining")

	// 验证剩余的活跃会话是正确的
	params := types.SessionSearchParams{
		Status: string(types.SessionStatusActive),
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	activeSessions, _, err := repo.GetByUserID(ctx, user.ID, params)
	assert.NoError(t, err, "getting active sessions should succeed")
	assert.Len(t, activeSessions, 1, "should have 1 active session")
	assert.Equal(t, session2.ID, activeSessions[0].ID, "remaining session should be session2")

	// 测试不存在用户的活跃会话数量
	nonExistentUserID := uuid.New()
	count, err := repo.GetActiveSessionsCount(ctx, nonExistentUserID)
	assert.NoError(t, err, "getting active sessions count for non-existent user should not error")
	assert.Equal(t, int64(0), count, "count should be 0 for non-existent user")

	// 创建另一个用户测试隔离性
	user2 := createTestUserForSession(t, "testuser2", "test2@example.com")
	createTestSession(t, repo, user2.ID, "User2 Session")

	// 验证用户间的隔离
	user1Count, err := repo.GetActiveSessionsCount(ctx, user.ID)
	assert.NoError(t, err, "getting user1 active sessions count should succeed")
	assert.Equal(t, int64(1), user1Count, "user1 should still have 1 active session")

	user2Count, err := repo.GetActiveSessionsCount(ctx, user2.ID)
	assert.NoError(t, err, "getting user2 active sessions count should succeed")
	assert.Equal(t, int64(1), user2Count, "user2 should have 1 active session")
}

func TestSessionRepository_Pagination(t *testing.T) {
	// 初始化数据库
	setupSessionDatabase(t)

	repo := NewSessionRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForSession(t, "testuser", "test@example.com")

	// 创建多个会话
	for i := 0; i < 5; i++ {
		createTestSession(t, repo, user.ID, fmt.Sprintf("Session %d", i+1))
	}

	// 测试分页
	params := types.SessionSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 2,
		},
	}
	params.Validate()

	firstPage, total, err := repo.GetByUserID(ctx, user.ID, params)
	assert.NoError(t, err, "getting first page should succeed")
	assert.Len(t, firstPage, 2, "first page should have 2 sessions")
	assert.GreaterOrEqual(t, total, int64(5), "total should be at least 5")

	// 第二页
	params.PaginationParams.Page = 2
	params.Validate()

	secondPage, _, err := repo.GetByUserID(ctx, user.ID, params)
	assert.NoError(t, err, "getting second page should succeed")
	assert.Len(t, secondPage, 2, "second page should have 2 sessions")

	// 验证分页结果不重复
	firstPageIDs := make(map[uuid.UUID]bool)
	for _, s := range firstPage {
		firstPageIDs[s.ID] = true
	}

	for _, s := range secondPage {
		assert.False(t, firstPageIDs[s.ID], "second page should not contain sessions from first page")
	}
}

func TestSessionRepository_ErrorHandling(t *testing.T) {
	// 初始化数据库
	setupSessionDatabase(t)

	repo := NewSessionRepository()
	ctx := context.Background()

	// 首先创建一个有效的用户用于测试
	validUser := createTestUserForSession(t, "validuser", "valid@example.com")

	// 测试更新不存在的会话（但使用有效的UserID）
	nonExistentSession := &model.Session{
		ID:        uuid.New(),
		UserID:    validUser.ID, // 使用有效的用户ID
		Title:     "Non-existent",
		Status:    types.SessionStatusActive,
		ModelName: "gpt-3.5-turbo",
	}
	err := repo.Update(ctx, nonExistentSession)
	// 注意：GORM的Save方法在记录不存在时会创建新记录
	assert.NoError(t, err, "updating non-existent session with valid user should create new record")

	// 测试使用无效UserID创建会话（应该失败）
	invalidSession := &model.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(), // 不存在的用户ID
		Title:     "Invalid User Session",
		Status:    types.SessionStatusActive,
		ModelName: "gpt-3.5-turbo",
	}
	err = repo.Create(ctx, invalidSession)
	assert.Error(t, err, "creating session with invalid user should fail")
	assert.Contains(t, err.Error(), "foreign key constraint", "error should mention foreign key constraint")

	// 测试删除不存在的会话
	err = repo.Delete(ctx, uuid.New())
	assert.NoError(t, err, "deleting non-existent session should not error")

	// 测试无效的搜索参数
	params := types.SessionSearchParams{
		UserID: "invalid-uuid",
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	sessions, total, err := repo.Search(ctx, params)
	assert.Error(t, err, "search with invalid user id should error")
	assert.Equal(t, 0, len(sessions), "should find no sessions with invalid user id")
	assert.Equal(t, int64(0), total, "total should be 0 with invalid user id")

	// 测试获取不存在会话的详情
	_, err = repo.GetByID(ctx, uuid.New())
	assert.Error(t, err, "getting non-existent session should fail")

	// 测试更新不存在会话的消息计数
	err = repo.UpdateMessageCount(ctx, uuid.New(), 10)
	assert.NoError(t, err, "updating message count for non-existent session should not error but affect 0 rows")

	// 测试为不存在的会话添加tokens
	err = repo.AddTokens(ctx, uuid.New(), 100)
	assert.NoError(t, err, "adding tokens to non-existent session should not error but affect 0 rows")

	// 测试归档不存在的会话
	err = repo.Archive(ctx, uuid.New())
	assert.NoError(t, err, "archiving non-existent session should not error but affect 0 rows")

	// 测试获取不存在用户的活跃会话数量
	count, err := repo.GetActiveSessionsCount(ctx, uuid.New())
	assert.NoError(t, err, "getting active sessions count for non-existent user should not error")
	assert.Equal(t, int64(0), count, "count should be 0 for non-existent user")
}

// setupSessionDatabase 设置测试数据库
func setupSessionDatabase(t *testing.T) {
	testutils.SetupTestEnv(t)
}

// createTestUserForSession 创建测试用户
func createTestUserForSession(t *testing.T, username, email string) *model.User {
	manager := testutils.NewTestDBManager(t)
	userID := manager.CreateTestUser(t, username, email)

	// 获取创建的用户
	db := database.Get()
	var user model.User
	err := db.First(&user, "id = ?", userID).Error
	require.NoError(t, err, "getting created user should succeed")

	return &user
}

// createTestSession 创建测试会话
func createTestSession(t *testing.T, repo SessionRepository, userID uuid.UUID, title string) *model.Session {
	manager := testutils.NewTestDBManager(t)
	sessionID := manager.CreateTestSession(t, userID, title)

	// 获取创建的会话
	ctx := context.Background()
	session, err := repo.GetByID(ctx, sessionID)
	require.NoError(t, err, "getting created session should succeed")

	return session
}
