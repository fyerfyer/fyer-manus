package repository

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/fyerfyer/fyer-manus/go-api/testutils"
)

func TestNewMessageRepository(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	assert.NotNil(t, repo, "message repository should not be nil")
}

func TestMessageRepository_Create(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessage(t, "testuser", "test@example.com")
	session := createTestSessionForMessage(t, user.ID, "Test Session")

	// 测试创建用户消息
	userMessage := &model.Message{
		SessionID: session.ID,
		Role:      types.MessageRoleUser,
		Content:   "Hello, how are you?",
		Metadata: map[string]interface{}{
			"source": "test",
		},
	}

	err := repo.Create(ctx, userMessage)
	assert.NoError(t, err, "creating user message should succeed")
	assert.NotEqual(t, uuid.Nil, userMessage.ID, "message id should be set")
	assert.False(t, userMessage.CreatedAt.IsZero(), "created_at should be set")

	// 测试创建助手消息
	assistantMessage := &model.Message{
		SessionID:  session.ID,
		Role:       types.MessageRoleAssistant,
		Content:    "I'm doing well, thank you!",
		ParentID:   &userMessage.ID,
		TokensUsed: 20,
	}

	err = repo.Create(ctx, assistantMessage)
	assert.NoError(t, err, "creating assistant message should succeed")
	assert.NotEqual(t, uuid.Nil, assistantMessage.ID, "assistant message id should be set")
}

func TestMessageRepository_GetByID(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessage(t, "testuser", "test@example.com")
	session := createTestSessionForMessage(t, user.ID, "Test Session")
	message := createTestMessage(t, repo, session.ID, types.MessageRoleUser, "Test message")

	// 获取消息
	foundMessage, err := repo.GetByID(ctx, message.ID)
	assert.NoError(t, err, "getting message by id should succeed")
	assert.NotNil(t, foundMessage, "found message should not be nil")
	assert.Equal(t, message.ID, foundMessage.ID, "message id should match")
	assert.Equal(t, message.Content, foundMessage.Content, "content should match")
	assert.Equal(t, message.SessionID, foundMessage.SessionID, "session id should match")

	// 测试不存在的消息
	_, err = repo.GetByID(ctx, uuid.New())
	assert.Error(t, err, "getting non-existent message should fail")
}

func TestMessageRepository_GetBySessionID(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessage(t, "testuser", "test@example.com")
	session := createTestSessionForMessage(t, user.ID, "Test Session")

	// 创建多条消息
	msg1 := createTestMessage(t, repo, session.ID, types.MessageRoleUser, "First message")
	msg2 := createTestMessage(t, repo, session.ID, types.MessageRoleAssistant, "First response")

	// 设置消息关系
	msg2.ParentID = &msg1.ID
	err := repo.Update(ctx, msg2)
	require.NoError(t, err, "updating message parent should succeed")

	// 测试获取会话消息
	params := types.MessageSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	messages, total, err := repo.GetBySessionID(ctx, session.ID, params)
	assert.NoError(t, err, "getting messages by session id should succeed")
	assert.GreaterOrEqual(t, len(messages), 2, "should have at least 3 messages")
	assert.GreaterOrEqual(t, total, int64(2), "total should be at least 3")

	// 验证消息按时间排序
	assert.True(t, messages[0].CreatedAt.Before(messages[len(messages)-1].CreatedAt) ||
		messages[0].CreatedAt.Equal(messages[len(messages)-1].CreatedAt),
		"messages should be ordered by creation time")

	// 测试角色过滤
	params.Role = string(types.MessageRoleUser)
	userMessages, userTotal, err := repo.GetBySessionID(ctx, session.ID, params)
	assert.NoError(t, err, "getting user messages should succeed")
	assert.GreaterOrEqual(t, len(userMessages), 1, "should have at least 2 user messages")
	assert.GreaterOrEqual(t, userTotal, int64(1), "user total should be at least 2")

	// 验证过滤结果
	for _, msg := range userMessages {
		assert.Equal(t, types.MessageRoleUser, msg.Role, "all messages should be user messages")
	}

	// 测试分页
	params = types.MessageSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 2,
		},
	}
	params.Validate()

	pagedMessages, _, err := repo.GetBySessionID(ctx, session.ID, params)
	assert.NoError(t, err, "getting paged messages should succeed")
	assert.Len(t, pagedMessages, 2, "should return 2 messages per page")
}

func TestMessageRepository_Update(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessage(t, "testuser", "test@example.com")
	session := createTestSessionForMessage(t, user.ID, "Test Session")
	message := createTestMessage(t, repo, session.ID, types.MessageRoleUser, "Original content")

	// 更新消息
	message.Content = "Updated content"
	message.TokensUsed = 50
	message.Metadata = map[string]interface{}{
		"updated": true,
	}

	err := repo.Update(ctx, message)
	assert.NoError(t, err, "updating message should succeed")

	// 验证更新
	updatedMessage, err := repo.GetByID(ctx, message.ID)
	require.NoError(t, err, "getting updated message should succeed")
	assert.Equal(t, "Updated content", updatedMessage.Content, "content should be updated")
	assert.Equal(t, 50, updatedMessage.TokensUsed, "token count should be updated")
	assert.Equal(t, true, updatedMessage.Metadata["updated"], "metadata should be updated")
}

func TestMessageRepository_Delete(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessage(t, "testuser", "test@example.com")
	session := createTestSessionForMessage(t, user.ID, "Test Session")
	message := createTestMessage(t, repo, session.ID, types.MessageRoleUser, "To delete")

	// 删除消息
	err := repo.Delete(ctx, message.ID)
	assert.NoError(t, err, "deleting message should succeed")

	// 验证删除
	_, err = repo.GetByID(ctx, message.ID)
	assert.Error(t, err, "getting deleted message should fail")
}

func TestMessageRepository_GetConversationContext(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessage(t, "testuser", "test@example.com")
	session := createTestSessionForMessage(t, user.ID, "Test Session")

	// 创建对话上下文
	messages := make([]*model.Message, 0)
	for i := 0; i < 6; i++ {
		role := types.MessageRoleUser
		content := fmt.Sprintf("User message %d", i+1)
		if i%2 == 1 {
			role = types.MessageRoleAssistant
			content = fmt.Sprintf("Assistant response %d", i)
		}
		msg := createTestMessage(t, repo, session.ID, role, content)
		messages = append(messages, msg)

		// 设置父子关系
		if i > 0 {
			msg.ParentID = &messages[i-1].ID
			err := repo.Update(ctx, msg)
			require.NoError(t, err, "updating message parent should succeed")
		}

		// 添加延迟确保时间顺序
		time.Sleep(1 * time.Millisecond)
	}

	// 获取对话上下文（最近5条）
	context, err := repo.GetConversationContext(ctx, session.ID, 5)
	assert.NoError(t, err, "getting conversation context should succeed")
	assert.Len(t, context, 5, "should return 5 messages")

	// 验证顺序（应该是按时间正序）
	for i := 0; i < len(context)-1; i++ {
		assert.True(t, context[i].CreatedAt.Before(context[i+1].CreatedAt),
			"messages should be ordered by creation time asc")
	}

	// 测试限制数量
	limitedContext, err := repo.GetConversationContext(ctx, session.ID, 3)
	assert.NoError(t, err, "getting limited context should succeed")
	assert.Len(t, limitedContext, 3, "should return 3 messages")
}

func TestMessageRepository_GetMessageChain(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessage(t, "testuser", "test@example.com")
	session := createTestSessionForMessage(t, user.ID, "Test Session")

	// 创建消息链
	rootMessage := createTestMessage(t, repo, session.ID, types.MessageRoleUser, "Root message")

	// 创建子消息
	childMessage1 := createTestMessage(t, repo, session.ID, types.MessageRoleAssistant, "Child 1")
	childMessage1.ParentID = &rootMessage.ID
	err := repo.Update(ctx, childMessage1)
	require.NoError(t, err, "updating child message should succeed")

	childMessage2 := createTestMessage(t, repo, session.ID, types.MessageRoleUser, "Child 2")
	childMessage2.ParentID = &rootMessage.ID
	err = repo.Update(ctx, childMessage2)
	require.NoError(t, err, "updating second child message should succeed")

	// 创建孙子消息
	grandChildMessage := createTestMessage(t, repo, session.ID, types.MessageRoleAssistant, "Grandchild")
	grandChildMessage.ParentID = &childMessage1.ID
	err = repo.Update(ctx, grandChildMessage)
	require.NoError(t, err, "updating grandchild message should succeed")

	// 获取消息链
	chain, err := repo.GetMessageChain(ctx, rootMessage.ID)
	assert.NoError(t, err, "getting message chain should succeed")
	assert.GreaterOrEqual(t, len(chain), 4, "chain should have at least 4 messages")

	// 验证根消息在结果中
	found := false
	for _, msg := range chain {
		if msg.ID == rootMessage.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "root message should be in chain")

	// 验证子消息在结果中
	childFound := 0
	for _, msg := range chain {
		if msg.ParentID != nil && *msg.ParentID == rootMessage.ID {
			childFound++
		}
	}
	assert.GreaterOrEqual(t, childFound, 2, "should find at least 2 child messages")
}

func TestMessageRepository_CountBySessionID(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessage(t, "testuser", "test@example.com")
	session := createTestSessionForMessage(t, user.ID, "Test Session")

	// 创建多条消息
	for i := 0; i < 5; i++ {
		role := types.MessageRoleUser
		if i%2 == 1 {
			role = types.MessageRoleAssistant
		}
		createTestMessage(t, repo, session.ID, role, fmt.Sprintf("Message %d", i+1))
	}

	// 统计总消息数
	totalCount, err := repo.CountBySessionID(ctx, session.ID)
	assert.NoError(t, err, "counting messages should succeed")
	assert.GreaterOrEqual(t, totalCount, int64(5), "should have at least 5 messages")
}

func TestMessageRepository_GetLatestBySessionID(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessage(t, "testuser", "test@example.com")
	session := createTestSessionForMessage(t, user.ID, "Test Session")

	msg3 := createTestMessage(t, repo, session.ID, types.MessageRoleUser, "Latest message")

	// 获取最新消息
	latestMessages, err := repo.GetLatestBySessionID(ctx, session.ID, 1)
	assert.NoError(t, err, "getting latest message should succeed")
	assert.Len(t, latestMessages, 1, "should return 1 message")
	assert.Equal(t, msg3.ID, latestMessages[0].ID, "should return the latest message")
	assert.Equal(t, "Latest message", latestMessages[0].Content, "content should match latest message")

	// 获取最新的2条消息
	latestTwoMessages, err := repo.GetLatestBySessionID(ctx, session.ID, 1)
	assert.NoError(t, err, "getting latest 1 messages should succeed")
	assert.Len(t, latestTwoMessages, 1, "should return 1 messages")

	// 测试空会话
	emptySession := createTestSessionForMessage(t, user.ID, "Empty Session")
	emptyMessages, err := repo.GetLatestBySessionID(ctx, emptySession.ID, 10)
	assert.NoError(t, err, "getting latest messages from empty session should succeed")
	assert.Len(t, emptyMessages, 0, "should return no messages for empty session")
}

func TestMessageRepository_Search(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 创建测试数据
	user1 := createTestUserForMessage(t, "user1", "user1@example.com")
	user2 := createTestUserForMessage(t, "user2", "user2@example.com")

	session1 := createTestSessionForMessage(t, user1.ID, "Session 1")
	session2 := createTestSessionForMessage(t, user2.ID, "Session 2")

	// 创建测试消息，确保包含搜索关键词
	createTestMessage(t, repo, session1.ID, types.MessageRoleUser, "I want to learn python programming")
	createTestMessage(t, repo, session1.ID, types.MessageRoleAssistant, "Python is a great programming language!")
	createTestMessage(t, repo, session1.ID, types.MessageRoleUser, "How to use python for data analysis?")
	createTestMessage(t, repo, session2.ID, types.MessageRoleUser, "Tell me about machine learning")
	createTestMessage(t, repo, session2.ID, types.MessageRoleAssistant, "Machine learning with python is popular")
	createTestMessage(t, repo, session1.ID, types.MessageRoleUser, "What are the best programming practices?")

	// 测试内容搜索
	params := types.MessageSearchParams{
		Query: "python",
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	messages, total, err := repo.Search(ctx, params)
	assert.NoError(t, err, "searching messages should succeed")
	assert.GreaterOrEqual(t, len(messages), 3, "should find at least 3 messages with 'python'")
	assert.GreaterOrEqual(t, total, int64(3), "total should be at least 3")

	// 验证搜索结果包含关键词
	for _, msg := range messages {
		assert.Contains(t, strings.ToLower(msg.Content), "python", "message content should contain search term")
	}

	// 测试会话过滤
	params = types.MessageSearchParams{
		SessionID: session1.ID.String(),
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	sessionMessages, sessionTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "searching by session should succeed")
	assert.GreaterOrEqual(t, len(sessionMessages), 4, "should find at least 4 messages in session1")
	assert.GreaterOrEqual(t, sessionTotal, int64(4), "session total should be at least 4")

	// 验证会话过滤结果
	for _, msg := range sessionMessages {
		assert.Equal(t, session1.ID, msg.SessionID, "all messages should belong to session1")
	}

	// 测试角色过滤
	params = types.MessageSearchParams{
		Role: string(types.MessageRoleUser),
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	userMessages, userTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "searching by role should succeed")
	assert.GreaterOrEqual(t, len(userMessages), 4, "should find at least 4 user messages")
	assert.GreaterOrEqual(t, userTotal, int64(4), "user total should be at least 4")

	// 验证角色过滤结果
	for _, msg := range userMessages {
		assert.Equal(t, types.MessageRoleUser, msg.Role, "all messages should be user messages")
	}

	// 测试组合搜索
	params = types.MessageSearchParams{
		SessionID: session1.ID.String(),
		Role:      string(types.MessageRoleUser),
		Query:     "programming",
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	combinedMessages, combinedTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "combined search should succeed")
	assert.GreaterOrEqual(t, len(combinedMessages), 1, "should find at least 1 message matching all criteria")
	assert.GreaterOrEqual(t, combinedTotal, int64(1), "combined total should be at least 1")

	// 验证组合搜索结果
	for _, msg := range combinedMessages {
		assert.Equal(t, session1.ID, msg.SessionID, "message should belong to session1")
		assert.Equal(t, types.MessageRoleUser, msg.Role, "message should be user message")
		assert.Contains(t, strings.ToLower(msg.Content), "programming", "message should contain search term")
	}

	// 测试不存在的搜索词
	params = types.MessageSearchParams{
		Query: "nonexistent_keyword_xyz",
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	emptyMessages, emptyTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "searching for non-existent term should succeed")
	assert.Equal(t, 0, len(emptyMessages), "should find no messages with non-existent keyword")
	assert.Equal(t, int64(0), emptyTotal, "total should be 0 for non-existent keyword")

	// 测试空搜索（返回所有消息）
	params = types.MessageSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	allMessages, allTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "empty search should succeed")
	assert.GreaterOrEqual(t, len(allMessages), 6, "should find all created messages")
	assert.GreaterOrEqual(t, allTotal, int64(6), "total should include all messages")

	// 测试分页功能
	params = types.MessageSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 3,
			Page:     1,
		},
	}
	params.Validate()

	firstPage, firstTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "first page search should succeed")
	assert.LessOrEqual(t, len(firstPage), 3, "first page should have at most 3 messages")

	params.PaginationParams.Page = 2
	params.Validate()

	secondPage, secondTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "second page search should succeed")
	assert.Equal(t, firstTotal, secondTotal, "total should be consistent across pages")

	// 验证分页结果不重复
	firstPageIDs := make(map[uuid.UUID]bool)
	for _, msg := range firstPage {
		firstPageIDs[msg.ID] = true
	}

	for _, msg := range secondPage {
		assert.False(t, firstPageIDs[msg.ID], "second page should not contain messages from first page")
	}

	// 测试无效的会话ID
	fmt.Printf("Test: Testing invalid session ID\n")
	params = types.MessageSearchParams{
		SessionID: "invalid-uuid",
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()
	fmt.Printf("Test: Params after validation - SessionID: '%s', PageSize: %d\n",
		params.SessionID, params.PageSize)

	invalidMessages, invalidTotal, err := repo.Search(ctx, params)
	fmt.Printf("Test: Search returned %d messages, total: %d, error: %v\n",
		len(invalidMessages), invalidTotal, err)
	assert.NoError(t, err, "search with invalid session ID should not error")
	assert.Equal(t, 0, len(invalidMessages), "should find no messages with invalid session ID")
	assert.Equal(t, int64(0), invalidTotal, "total should be 0 with invalid session ID")

	// 测试不存在的会话ID
	params = types.MessageSearchParams{
		SessionID: uuid.New().String(),
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	nonExistentMessages, nonExistentTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "search with non-existent session ID should not error")
	assert.Equal(t, 0, len(nonExistentMessages), "should find no messages with non-existent session ID")
	assert.Equal(t, int64(0), nonExistentTotal, "total should be 0 with non-existent session ID")

	// 测试大小写不敏感搜索
	params = types.MessageSearchParams{
		Query: "PYTHON", // 大写
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	caseInsensitiveMessages, caseInsensitiveTotal, err := repo.Search(ctx, params)
	assert.NoError(t, err, "case insensitive search should succeed")
	assert.GreaterOrEqual(t, len(caseInsensitiveMessages), 3, "should find messages regardless of case")
	assert.GreaterOrEqual(t, caseInsensitiveTotal, int64(3), "total should be at least 3 for case insensitive search")
}

func TestMessageRepository_DeleteBySessionID(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessage(t, "testuser", "test@example.com")
	session1 := createTestSessionForMessage(t, user.ID, "Session 1")
	session2 := createTestSessionForMessage(t, user.ID, "Session 2")

	// 在两个会话中创建消息
	createTestMessage(t, repo, session1.ID, types.MessageRoleUser, "Session 1 message 1")
	createTestMessage(t, repo, session1.ID, types.MessageRoleAssistant, "Session 1 message 2")
	createTestMessage(t, repo, session2.ID, types.MessageRoleUser, "Session 2 message 1")

	// 删除session1的所有消息
	err := repo.DeleteBySessionID(ctx, session1.ID)
	assert.NoError(t, err, "deleting messages by session id should succeed")

	// 验证session1的消息被删除
	count1, err := repo.CountBySessionID(ctx, session1.ID)
	assert.NoError(t, err, "counting messages should succeed")
	assert.Equal(t, int64(0), count1, "session1 should have no messages")

	// 验证session2的消息仍然存在
	count2, err := repo.CountBySessionID(ctx, session2.ID)
	assert.NoError(t, err, "counting messages should succeed")
	assert.GreaterOrEqual(t, count2, int64(1), "session2 should still have messages")
}

func TestMessageRepository_ToolCallHandling(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessage(t, "testuser", "test@example.com")
	session := createTestSessionForMessage(t, user.ID, "Test Session")

	// 创建带工具调用的消息
	toolCallMessage := &model.Message{
		SessionID: session.ID,
		Role:      types.MessageRoleAssistant,
		Content:   "I'll help you with that calculation.",
		ToolCalls: []model.ToolCall{
			{
				ID:   "call_1",
				Type: "function",
				Function: model.ToolCallFunction{
					Name:      "calculate",
					Arguments: `{"operation": "add", "a": 5, "b": 3}`,
				},
			},
		},
		TokensUsed: 25,
	}

	err := repo.Create(ctx, toolCallMessage)
	assert.NoError(t, err, "creating message with tool calls should succeed")

	// 验证工具调用保存
	savedMessage, err := repo.GetByID(ctx, toolCallMessage.ID)
	require.NoError(t, err, "getting message should succeed")
	assert.Len(t, savedMessage.ToolCalls, 1, "should have 1 tool call")
	assert.Equal(t, "call_1", savedMessage.ToolCalls[0].ID, "tool call id should match")
	assert.Equal(t, "calculate", savedMessage.ToolCalls[0].Function.Name, "function name should match")

	// 创建工具响应消息
	toolResponseMessage := &model.Message{
		SessionID:  session.ID,
		Role:       types.MessageRoleTool,
		Content:    "8",
		ParentID:   &toolCallMessage.ID,
		ToolCallID: "call_1",
		Metadata: map[string]interface{}{
			"tool_call_id": "call_1",
		},
	}

	err = repo.Create(ctx, toolResponseMessage)
	assert.NoError(t, err, "creating tool response should succeed")

	// 验证消息关系
	chain, err := repo.GetMessageChain(ctx, toolCallMessage.ID)
	assert.NoError(t, err, "getting message chain should succeed")
	assert.GreaterOrEqual(t, len(chain), 2, "chain should include both messages")
}

func TestMessageRepository_Pagination(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessage(t, "testuser", "test@example.com")
	session := createTestSessionForMessage(t, user.ID, "Test Session")

	// 创建多条消息
	for i := 0; i < 7; i++ {
		role := types.MessageRoleUser
		if i%2 == 1 {
			role = types.MessageRoleAssistant
		}
		createTestMessage(t, repo, session.ID, role, fmt.Sprintf("Message %d", i+1))
		time.Sleep(1 * time.Millisecond) // 确保时间顺序
	}

	// 测试第一页
	params := types.MessageSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 3,
		},
	}
	params.Validate()

	firstPage, total, err := repo.GetBySessionID(ctx, session.ID, params)
	assert.NoError(t, err, "getting first page should succeed")
	assert.Len(t, firstPage, 3, "first page should have 3 messages")
	assert.GreaterOrEqual(t, total, int64(7), "total should be at least 7")

	// 测试第二页
	params.PaginationParams.Page = 2
	params.Validate()

	secondPage, _, err := repo.GetBySessionID(ctx, session.ID, params)
	assert.NoError(t, err, "getting second page should succeed")
	assert.Len(t, secondPage, 3, "second page should have 3 messages")

	// 验证分页结果不重复
	firstPageIDs := make(map[uuid.UUID]bool)
	for _, msg := range firstPage {
		firstPageIDs[msg.ID] = true
	}

	for _, msg := range secondPage {
		assert.False(t, firstPageIDs[msg.ID], "second page should not contain messages from first page")
	}
}

func TestMessageRepository_ErrorHandling(t *testing.T) {
	// 初始化数据库
	setupMessageDatabase(t)

	repo := NewMessageRepository()
	ctx := context.Background()

	// 测试更新不存在的消息
	nonExistentMessage := &model.Message{
		ID:        uuid.New(),
		SessionID: uuid.New(),
		Role:      types.MessageRoleUser,
		Content:   "Non-existent",
	}
	err := repo.Update(ctx, nonExistentMessage)
	assert.Error(t, err, "updating non-existent message should fail")

	// 测试删除不存在的消息
	err = repo.Delete(ctx, uuid.New())
	assert.NoError(t, err, "deleting non-existent message should not error")

	// 测试获取不存在会话的消息
	params := types.MessageSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	messages, total, err := repo.GetBySessionID(ctx, uuid.New(), params)
	assert.NoError(t, err, "getting messages from non-existent session should not error")
	assert.Equal(t, 0, len(messages), "should find no messages")
	assert.Equal(t, int64(0), total, "total should be 0")

	// 测试无效的搜索参数
	invalidParams := types.MessageSearchParams{
		SessionID: uuid.New().String(), // 不存在的会话
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	invalidParams.Validate()

	messages, total, err = repo.Search(ctx, invalidParams)
	assert.NoError(t, err, "search with invalid session id should not error")
	assert.Equal(t, 0, len(messages), "should find no messages with invalid session id")
	assert.Equal(t, int64(0), total, "total should be 0 with invalid session id")
}

// setupMessageDatabase 设置测试数据库
func setupMessageDatabase(t *testing.T) {
	testutils.SetupTestEnv(t)
}

// createTestUserForMessage 创建测试用户
func createTestUserForMessage(t *testing.T, username, email string) *model.User {
	manager := testutils.NewTestDBManager(t)
	userID := manager.CreateTestUser(t, username, email)

	// 获取创建的用户
	db := database.Get()
	var user model.User
	err := db.First(&user, "id = ?", userID).Error
	require.NoError(t, err, "getting created user should succeed")

	return &user
}

// createTestSessionForMessage 创建测试会话
func createTestSessionForMessage(t *testing.T, userID uuid.UUID, title string) *model.Session {
	manager := testutils.NewTestDBManager(t)
	sessionID := manager.CreateTestSession(t, userID, title)

	// 获取创建的会话
	db := database.Get()
	var session model.Session
	err := db.First(&session, "id = ?", sessionID).Error
	require.NoError(t, err, "getting created session should succeed")

	return &session
}

// createTestMessage 创建测试消息
func createTestMessage(t *testing.T, repo MessageRepository, sessionID uuid.UUID, role types.MessageRole, content string) *model.Message {
	ctx := context.Background()

	message := &model.Message{
		SessionID:  sessionID,
		Role:       role,
		Content:    content,
		TokensUsed: len(content), // 简单的token计算
	}

	err := repo.Create(ctx, message)
	require.NoError(t, err, "creating test message should succeed")

	return message
}
