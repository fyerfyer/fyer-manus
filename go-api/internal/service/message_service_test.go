package service

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
)

func TestNewMessageService(t *testing.T) {
	// 初始化数据库
	setupMessageServiceDatabase(t)
	defer database.Close()

	service := NewMessageService()
	assert.NotNil(t, service, "message service should not be nil")
	assert.NotNil(t, service.messageRepo, "message repository should not be nil")
	assert.NotNil(t, service.sessionRepo, "session repository should not be nil")
}

func TestMessageService_CreateMessage(t *testing.T) {
	// 初始化数据库
	setupMessageServiceDatabase(t)
	defer database.Close()

	service := NewMessageService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessageService(t, "testuser", "test@example.com")
	session := createTestSessionForMessageService(t, user.ID, "Test Session")

	// 测试创建用户消息
	req := model.MessageCreateRequest{
		Role:    types.MessageRoleUser,
		Content: "Hello, how are you?",
		Metadata: map[string]interface{}{
			"source": "test",
		},
	}

	response, err := service.CreateMessage(ctx, user.ID, session.ID, req)
	assert.NoError(t, err, "creating user message should succeed")
	assert.NotNil(t, response, "response should not be nil")
	assert.Equal(t, req.Role, response.Role, "role should match")
	assert.Equal(t, req.Content, response.Content, "content should match")
	assert.Equal(t, session.ID, response.SessionID, "session id should match")
	assert.Equal(t, types.MessageTypeText, response.ContentType, "should use default content type")

	// 测试创建带父消息的回复
	replyReq := model.MessageCreateRequest{
		Role:     types.MessageRoleAssistant,
		Content:  "I'm doing well, thank you!",
		ParentID: &response.ID,
	}

	replyResponse, err := service.CreateMessage(ctx, user.ID, session.ID, replyReq)
	assert.NoError(t, err, "creating reply message should succeed")
	assert.NotNil(t, replyResponse, "reply response should not be nil")
	assert.Equal(t, response.ID, *replyResponse.ParentID, "parent id should match")

	// 测试权限检查
	otherUser := createTestUserForMessageService(t, "otheruser", "other@example.com")
	_, err = service.CreateMessage(ctx, otherUser.ID, session.ID, req)
	assert.Error(t, err, "creating message by other user should fail")
	assert.Contains(t, err.Error(), "access denied", "error should mention access denied")

	// 测试不存在的会话
	_, err = service.CreateMessage(ctx, user.ID, uuid.New(), req)
	assert.Error(t, err, "creating message in non-existent session should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")

	// 测试无效的父消息ID
	invalidParentReq := model.MessageCreateRequest{
		Role:     types.MessageRoleAssistant,
		Content:  "Invalid parent",
		ParentID: &uuid.Nil,
	}

	_, err = service.CreateMessage(ctx, user.ID, session.ID, invalidParentReq)
	assert.Error(t, err, "creating message with invalid parent should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention parent not found")

	// 测试跨会话父消息
	otherSession := createTestSessionForMessageService(t, user.ID, "Other Session")
	crossSessionReq := model.MessageCreateRequest{
		Role:     types.MessageRoleAssistant,
		Content:  "Cross session",
		ParentID: &response.ID,
	}

	_, err = service.CreateMessage(ctx, user.ID, otherSession.ID, crossSessionReq)
	assert.Error(t, err, "creating message with parent from other session should fail")
	assert.Contains(t, err.Error(), "not in same session", "error should mention session mismatch")
}

func TestMessageService_GetMessage(t *testing.T) {
	// 初始化数据库
	setupMessageServiceDatabase(t)
	defer database.Close()

	service := NewMessageService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessageService(t, "testuser", "test@example.com")
	session := createTestSessionForMessageService(t, user.ID, "Test Session")
	message := createTestMessageForService(t, service, user.ID, session.ID, types.MessageRoleUser, "Test message")

	// 测试获取消息
	response, err := service.GetMessage(ctx, user.ID, message.ID)
	assert.NoError(t, err, "getting message should succeed")
	assert.NotNil(t, response, "response should not be nil")
	assert.Equal(t, message.ID, response.ID, "message id should match")
	assert.Equal(t, message.Content, response.Content, "content should match")

	// 测试权限检查
	otherUser := createTestUserForMessageService(t, "otheruser", "other@example.com")
	_, err = service.GetMessage(ctx, otherUser.ID, message.ID)
	assert.Error(t, err, "getting message by other user should fail")
	assert.Contains(t, err.Error(), "access denied", "error should mention access denied")

	// 测试不存在的消息
	_, err = service.GetMessage(ctx, user.ID, uuid.New())
	assert.Error(t, err, "getting non-existent message should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestMessageService_UpdateMessage(t *testing.T) {
	// 初始化数据库
	setupMessageServiceDatabase(t)
	defer database.Close()

	service := NewMessageService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessageService(t, "testuser", "test@example.com")
	session := createTestSessionForMessageService(t, user.ID, "Test Session")
	userMessage := createTestMessageForService(t, service, user.ID, session.ID, types.MessageRoleUser, "Original content")

	// 测试更新用户消息
	newContent := "Updated content"
	newMetadata := map[string]interface{}{
		"updated": true,
	}

	response, err := service.UpdateMessage(ctx, user.ID, userMessage.ID, newContent, newMetadata)
	assert.NoError(t, err, "updating user message should succeed")
	assert.NotNil(t, response, "response should not be nil")
	assert.Equal(t, newContent, response.Content, "content should be updated")
	assert.Equal(t, true, response.Metadata["updated"], "metadata should be updated")

	// 测试只更新内容
	newerContent := "Only content updated"
	response, err = service.UpdateMessage(ctx, user.ID, userMessage.ID, newerContent, nil)
	assert.NoError(t, err, "updating only content should succeed")
	assert.Equal(t, newerContent, response.Content, "content should be updated")
	assert.Equal(t, true, response.Metadata["updated"], "metadata should remain")

	// 测试只更新元数据
	onlyMetadata := map[string]interface{}{
		"only_metadata": true,
	}
	response, err = service.UpdateMessage(ctx, user.ID, userMessage.ID, "", onlyMetadata)
	assert.NoError(t, err, "updating only metadata should succeed")
	assert.Equal(t, newerContent, response.Content, "content should remain")
	assert.Equal(t, true, response.Metadata["only_metadata"], "metadata should be updated")

	// 测试更新非用户消息
	assistantMessage := createTestMessageForService(t, service, user.ID, session.ID, types.MessageRoleAssistant, "Assistant message")
	_, err = service.UpdateMessage(ctx, user.ID, assistantMessage.ID, "New content", nil)
	assert.Error(t, err, "updating non-user message should fail")
	assert.Contains(t, err.Error(), "can only update user messages", "error should mention user messages only")

	// 测试权限检查
	otherUser := createTestUserForMessageService(t, "otheruser", "other@example.com")
	_, err = service.UpdateMessage(ctx, otherUser.ID, userMessage.ID, "Unauthorized update", nil)
	assert.Error(t, err, "updating message by other user should fail")
	assert.Contains(t, err.Error(), "access denied", "error should mention access denied")

	// 测试不存在的消息
	_, err = service.UpdateMessage(ctx, user.ID, uuid.New(), "Non-existent", nil)
	assert.Error(t, err, "updating non-existent message should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestMessageService_DeleteMessage(t *testing.T) {
	// 初始化数据库
	setupMessageServiceDatabase(t)
	defer database.Close()

	service := NewMessageService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessageService(t, "testuser", "test@example.com")
	session := createTestSessionForMessageService(t, user.ID, "Test Session")
	message := createTestMessageForService(t, service, user.ID, session.ID, types.MessageRoleUser, "To delete")

	// 测试删除消息
	err := service.DeleteMessage(ctx, user.ID, message.ID)
	assert.NoError(t, err, "deleting message should succeed")

	// 验证消息被删除
	_, err = service.GetMessage(ctx, user.ID, message.ID)
	assert.Error(t, err, "getting deleted message should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")

	// 测试权限检查
	otherUser := createTestUserForMessageService(t, "otheruser", "other@example.com")
	otherMessage := createTestMessageForService(t, service, user.ID, session.ID, types.MessageRoleUser, "Other message")

	err = service.DeleteMessage(ctx, otherUser.ID, otherMessage.ID)
	assert.Error(t, err, "deleting message by other user should fail")
	assert.Contains(t, err.Error(), "access denied", "error should mention access denied")

	// 测试不存在的消息
	err = service.DeleteMessage(ctx, user.ID, uuid.New())
	assert.Error(t, err, "deleting non-existent message should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestMessageService_ListMessages(t *testing.T) {
	// 初始化数据库
	setupMessageServiceDatabase(t)
	defer database.Close()

	service := NewMessageService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessageService(t, "testuser", "test@example.com")
	session := createTestSessionForMessageService(t, user.ID, "Test Session")

	// 创建多条消息
	for i := 0; i < 5; i++ {
		role := types.MessageRoleUser
		if i%2 == 1 {
			role = types.MessageRoleAssistant
		}
		content := "Message " + string(rune('0'+i+1))
		createTestMessageForService(t, service, user.ID, session.ID, role, content)
	}

	// 测试列表所有消息
	params := types.MessageSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	response, err := service.ListMessages(ctx, user.ID, session.ID, params)
	assert.NoError(t, err, "listing messages should succeed")
	assert.NotNil(t, response, "response should not be nil")
	assert.GreaterOrEqual(t, len(response.Data.([]model.MessageListResponse)), 5, "should have at least 5 messages")
	assert.GreaterOrEqual(t, response.Pagination.Total, int64(5), "total should be at least 5")

	// 测试角色过滤
	params.Role = string(types.MessageRoleUser)
	response, err = service.ListMessages(ctx, user.ID, session.ID, params)
	assert.NoError(t, err, "listing user messages should succeed")
	assert.GreaterOrEqual(t, len(response.Data.([]model.MessageListResponse)), 3, "should have at least 3 user messages")

	// 验证过滤结果
	messages := response.Data.([]model.MessageListResponse)
	for _, msg := range messages {
		assert.Equal(t, types.MessageRoleUser, msg.Role, "all messages should be user messages")
	}

	// 测试分页
	params = types.MessageSearchParams{
		PaginationParams: types.PaginationParams{
			PageSize: 3,
		},
	}
	params.Validate()

	firstPage, err := service.ListMessages(ctx, user.ID, session.ID, params)
	assert.NoError(t, err, "getting first page should succeed")
	assert.Len(t, firstPage.Data.([]model.MessageListResponse), 3, "first page should have 3 messages")

	params.PaginationParams.Page = 2
	params.Validate()

	secondPage, err := service.ListMessages(ctx, user.ID, session.ID, params)
	assert.NoError(t, err, "getting second page should succeed")
	assert.GreaterOrEqual(t, len(secondPage.Data.([]model.MessageListResponse)), 2, "second page should have at least 2 messages")

	// 测试权限检查
	otherUser := createTestUserForMessageService(t, "otheruser", "other@example.com")
	_, err = service.ListMessages(ctx, otherUser.ID, session.ID, params)
	assert.Error(t, err, "listing messages by other user should fail")
	assert.Contains(t, err.Error(), "access denied", "error should mention access denied")

	// 测试不存在的会话
	_, err = service.ListMessages(ctx, user.ID, uuid.New(), params)
	assert.Error(t, err, "listing messages from non-existent session should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestMessageService_GetConversationContext(t *testing.T) {
	// 初始化数据库
	setupMessageServiceDatabase(t)
	defer database.Close()

	service := NewMessageService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessageService(t, "testuser", "test@example.com")
	session := createTestSessionForMessageService(t, user.ID, "Test Session")

	// 创建对话历史
	for i := 0; i < 10; i++ {
		role := types.MessageRoleUser
		if i%2 == 1 {
			role = types.MessageRoleAssistant
		}
		content := "Context message " + string(rune('0'+i+1))
		createTestMessageForService(t, service, user.ID, session.ID, role, content)
	}

	// 测试获取对话上下文（限制5条）
	context, err := service.GetConversationContext(ctx, user.ID, session.ID, 5)
	assert.NoError(t, err, "getting conversation context should succeed")
	assert.Len(t, context, 5, "should return 5 messages")

	// 验证消息按时间正序排列
	for i := 0; i < len(context)-1; i++ {
		assert.True(t, context[i].CreatedAt.Before(context[i+1].CreatedAt) ||
			context[i].CreatedAt.Equal(context[i+1].CreatedAt),
			"messages should be ordered by creation time asc")
	}

	// 测试默认限制
	context, err = service.GetConversationContext(ctx, user.ID, session.ID, 0)
	assert.NoError(t, err, "getting context with 0 limit should succeed")
	assert.Len(t, context, 10, "should use default limit")

	// 测试权限检查
	otherUser := createTestUserForMessageService(t, "otheruser", "other@example.com")
	_, err = service.GetConversationContext(ctx, otherUser.ID, session.ID, 5)
	assert.Error(t, err, "getting context by other user should fail")
	assert.Contains(t, err.Error(), "access denied", "error should mention access denied")

	// 测试不存在的会话
	_, err = service.GetConversationContext(ctx, user.ID, uuid.New(), 5)
	assert.Error(t, err, "getting context from non-existent session should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")
}

func TestMessageService_GetMessageChain(t *testing.T) {
	// 初始化数据库
	setupMessageServiceDatabase(t)
	defer database.Close()

	service := NewMessageService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessageService(t, "testuser", "test@example.com")
	session := createTestSessionForMessageService(t, user.ID, "Test Session")

	// 创建消息链
	rootMessage := createTestMessageForService(t, service, user.ID, session.ID, types.MessageRoleUser, "Root message")
	t.Logf("Created root message: %s", rootMessage.ID.String())

	// 创建子消息
	childReq := model.MessageCreateRequest{
		Role:     types.MessageRoleAssistant,
		Content:  "Child message",
		ParentID: &rootMessage.ID,
	}
	childMessage, err := service.CreateMessage(ctx, user.ID, session.ID, childReq)
	require.NoError(t, err, "creating child message should succeed")
	t.Logf("Created child message: %s, parent: %s", childMessage.ID.String(), childMessage.ParentID.String())

	// 创建第三条消息（孙子消息）
	grandChildReq := model.MessageCreateRequest{
		Role:     types.MessageRoleUser,
		Content:  "Grand child message",
		ParentID: &childMessage.ID,
	}
	grandChildMessage, err := service.CreateMessage(ctx, user.ID, session.ID, grandChildReq)
	require.NoError(t, err, "creating grand child message should succeed")
	t.Logf("Created grand child message: %s, parent: %s", grandChildMessage.ID.String(), grandChildMessage.ParentID.String())

	// 测试获取消息链
	t.Logf("Getting message chain for root message: %s", rootMessage.ID.String())
	chain, err := service.GetMessageChain(ctx, user.ID, rootMessage.ID)
	assert.NoError(t, err, "getting message chain should succeed")
	t.Logf("Got chain with %d messages", len(chain))

	for i, msg := range chain {
		t.Logf("Chain message %d: ID=%s, Role=%s, ParentID=%s",
			i, msg.ID.String(), msg.Role, func() string {
				if msg.ParentID != nil {
					return msg.ParentID.String()
				}
				return "nil"
			}())
	}

	assert.GreaterOrEqual(t, len(chain), 3, "chain should have at least 3 messages")

	// 验证根消息在结果中
	rootFound := false
	for _, msg := range chain {
		if msg.ID == rootMessage.ID {
			rootFound = true
			break
		}
	}
	assert.True(t, rootFound, "root message should be in chain")

	// 测试从中间消息获取链
	t.Logf("Getting message chain for child message: %s", childMessage.ID.String())
	chain, err = service.GetMessageChain(ctx, user.ID, childMessage.ID)
	assert.NoError(t, err, "getting chain from child should succeed")
	t.Logf("Got chain from child with %d messages", len(chain))
	assert.GreaterOrEqual(t, len(chain), 3, "chain from child should have at least 3 messages")

	// 测试从孙子消息获取链
	t.Logf("Getting message chain for grand child message: %s", grandChildMessage.ID.String())
	chain, err = service.GetMessageChain(ctx, user.ID, grandChildMessage.ID)
	assert.NoError(t, err, "getting chain from grand child should succeed")
	t.Logf("Got chain from grand child with %d messages", len(chain))
	assert.GreaterOrEqual(t, len(chain), 3, "chain from grand child should have at least 3 messages")
}

func TestMessageService_SearchMessages(t *testing.T) {
	// 初始化数据库
	setupMessageServiceDatabase(t)
	defer database.Close()

	service := NewMessageService()
	ctx := context.Background()

	// 创建测试数据
	user1 := createTestUserForMessageService(t, "user1", "user1@example.com")
	user2 := createTestUserForMessageService(t, "user2", "user2@example.com")

	session1 := createTestSessionForMessageService(t, user1.ID, "Session 1")
	session2 := createTestSessionForMessageService(t, user2.ID, "Session 2")

	// 创建不同类型的消息 - 修正大小写问题
	createTestMessageForService(t, service, user1.ID, session1.ID, types.MessageRoleUser, "Hello world python programming")
	createTestMessageForService(t, service, user1.ID, session1.ID, types.MessageRoleAssistant, "python is great for programming") // 改为小写
	createTestMessageForService(t, service, user2.ID, session2.ID, types.MessageRoleUser, "Java programming tutorial")

	// 测试内容搜索
	params := types.MessageSearchParams{
		Query: "python",
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	response, err := service.SearchMessages(ctx, params)
	assert.NoError(t, err, "searching messages should succeed")
	assert.GreaterOrEqual(t, len(response.Data.([]model.MessageListResponse)), 2, "should find at least 2 messages with 'python'")

	// 验证搜索结果 - 使用大小写不敏感的检查或调整期望
	messages := response.Data.([]model.MessageListResponse)
	for _, msg := range messages {
		// 使用strings.Contains并转换为小写进行比较，或者调整测试数据
		assert.Contains(t, strings.ToLower(msg.Content), "python", "message content should contain search term (case insensitive)")
	}

	// 测试会话过滤
	params = types.MessageSearchParams{
		SessionID: session1.ID.String(),
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	response, err = service.SearchMessages(ctx, params)
	assert.NoError(t, err, "searching by session should succeed")
	assert.GreaterOrEqual(t, len(response.Data.([]model.MessageListResponse)), 2, "should find at least 2 messages in session1")

	// 测试角色过滤
	params = types.MessageSearchParams{
		Role: string(types.MessageRoleUser),
		PaginationParams: types.PaginationParams{
			PageSize: 10,
		},
	}
	params.Validate()

	response, err = service.SearchMessages(ctx, params)
	assert.NoError(t, err, "searching by role should succeed")
	assert.GreaterOrEqual(t, len(response.Data.([]model.MessageListResponse)), 2, "should find at least 2 user messages")

	// 验证角色过滤结果
	messages = response.Data.([]model.MessageListResponse)
	for _, msg := range messages {
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

	response, err = service.SearchMessages(ctx, params)
	assert.NoError(t, err, "combined search should succeed")
	assert.GreaterOrEqual(t, len(response.Data.([]model.MessageListResponse)), 1, "should find at least 1 message matching all criteria")
}

func TestMessageService_CreateAssistantMessage(t *testing.T) {
	// 初始化数据库
	setupMessageServiceDatabase(t)
	defer database.Close()

	service := NewMessageService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessageService(t, "testuser", "test@example.com")
	session := createTestSessionForMessageService(t, user.ID, "Test Session")
	userMessage := createTestMessageForService(t, service, user.ID, session.ID, types.MessageRoleUser, "User question")

	// 测试创建助手消息
	content := "Assistant response"
	modelName := "gpt-3.5-turbo"
	tokensUsed := 50
	cost := 0.001

	response, err := service.CreateAssistantMessage(ctx, session.ID, content, modelName, &userMessage.ID, tokensUsed, cost)
	assert.NoError(t, err, "creating assistant message should succeed")
	assert.NotNil(t, response, "response should not be nil")
	assert.Equal(t, types.MessageRoleAssistant, response.Role, "role should be assistant")
	assert.Equal(t, content, response.Content, "content should match")
	assert.Equal(t, modelName, response.ModelName, "model name should match")
	assert.Equal(t, tokensUsed, response.TokensUsed, "tokens used should match")
	assert.Equal(t, cost, response.Cost, "cost should match")
	assert.Equal(t, userMessage.ID, *response.ParentID, "parent id should match")

	// 测试不存在的会话
	_, err = service.CreateAssistantMessage(ctx, uuid.New(), content, modelName, nil, tokensUsed, cost)
	assert.Error(t, err, "creating assistant message in non-existent session should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")

	// 测试归档会话
	db := database.Get()
	err = db.Model(&model.Session{}).Where("id = ?", session.ID).Update("status", types.SessionStatusArchived).Error
	require.NoError(t, err, "archiving session should succeed")

	_, err = service.CreateAssistantMessage(ctx, session.ID, content, modelName, nil, tokensUsed, cost)
	assert.Error(t, err, "creating assistant message in archived session should fail")
	assert.Contains(t, err.Error(), "not active", "error should mention not active")
}

func TestMessageService_CreateToolMessage(t *testing.T) {
	// 初始化数据库
	setupMessageServiceDatabase(t)
	defer database.Close()

	service := NewMessageService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessageService(t, "testuser", "test@example.com")
	session := createTestSessionForMessageService(t, user.ID, "Test Session")
	assistantMessage := createTestMessageForService(t, service, user.ID, session.ID, types.MessageRoleAssistant, "I'll help you with that calculation")

	// 测试创建工具消息
	content := "42"
	toolCallID := "call_123"

	response, err := service.CreateToolMessage(ctx, session.ID, content, toolCallID, &assistantMessage.ID)
	assert.NoError(t, err, "creating tool message should succeed")
	assert.NotNil(t, response, "response should not be nil")
	assert.Equal(t, types.MessageRoleTool, response.Role, "role should be tool")
	assert.Equal(t, content, response.Content, "content should match")
	assert.Equal(t, toolCallID, response.ToolCallID, "tool call id should match")
	assert.Equal(t, assistantMessage.ID, *response.ParentID, "parent id should match")

	// 测试不存在的会话
	_, err = service.CreateToolMessage(ctx, uuid.New(), content, toolCallID, nil)
	assert.Error(t, err, "creating tool message in non-existent session should fail")
	assert.Contains(t, err.Error(), "not found", "error should mention not found")

	// 测试归档会话
	db := database.Get()
	err = db.Model(&model.Session{}).Where("id = ?", session.ID).Update("status", types.SessionStatusArchived).Error
	require.NoError(t, err, "archiving session should succeed")

	_, err = service.CreateToolMessage(ctx, session.ID, content, toolCallID, nil)
	assert.Error(t, err, "creating tool message in archived session should fail")
	assert.Contains(t, err.Error(), "not active", "error should mention not active")
}

func TestMessageService_MessageContentTypes(t *testing.T) {
	// 初始化数据库
	setupMessageServiceDatabase(t)
	defer database.Close()

	service := NewMessageService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessageService(t, "testuser", "test@example.com")
	session := createTestSessionForMessageService(t, user.ID, "Test Session")

	// 测试不同内容类型
	contentTypes := []types.MessageType{
		types.MessageTypeText,
		types.MessageTypeImage,
		types.MessageTypeFile,
		types.MessageTypeCode,
	}

	for _, contentType := range contentTypes {
		req := model.MessageCreateRequest{
			Role:        types.MessageRoleUser,
			Content:     "Content for " + string(contentType),
			ContentType: contentType,
		}

		response, err := service.CreateMessage(ctx, user.ID, session.ID, req)
		assert.NoError(t, err, "creating message with content type %s should succeed", contentType)
		assert.Equal(t, contentType, response.ContentType, "content type should match")
	}
}

func TestMessageService_MessageLimits(t *testing.T) {
	// 初始化数据库
	setupMessageServiceDatabase(t)
	defer database.Close()

	service := NewMessageService()
	ctx := context.Background()

	// 创建测试数据
	user := createTestUserForMessageService(t, "testuser", "test@example.com")
	session := createTestSessionForMessageService(t, user.ID, "Test Session")

	// 测试基本消息创建（由于MaxMessagesPerSession=1000，实际测试中不会触发限制）
	req := model.MessageCreateRequest{
		Role:    types.MessageRoleUser,
		Content: "Test message within limits",
	}

	response, err := service.CreateMessage(ctx, user.ID, session.ID, req)
	assert.NoError(t, err, "creating message within limits should succeed")
	assert.NotNil(t, response, "response should not be nil")
}

// setupMessageServiceDatabase 设置测试数据库
func setupMessageServiceDatabase(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	err = database.Init(&cfg.Database)
	require.NoError(t, err, "failed to init database")

	// 自动迁移表结构
	db := database.Get()
	err = db.AutoMigrate(&model.User{}, &model.Role{}, &model.Session{}, &model.Message{})
	require.NoError(t, err, "failed to migrate tables")

	// 清理测试数据
	db.Exec("TRUNCATE TABLE messages CASCADE")
	db.Exec("TRUNCATE TABLE sessions CASCADE")
	db.Exec("TRUNCATE TABLE user_roles CASCADE")
	db.Exec("TRUNCATE TABLE users CASCADE")
	db.Exec("TRUNCATE TABLE roles CASCADE")
}

// createTestUserForMessageService 创建测试用户
func createTestUserForMessageService(t *testing.T, username, email string) *model.User {
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

// createTestSessionForMessageService 创建测试会话
func createTestSessionForMessageService(t *testing.T, userID uuid.UUID, title string) *model.Session {
	db := database.Get()

	session := &model.Session{
		UserID:       userID,
		Title:        title,
		Status:       types.SessionStatusActive,
		ModelName:    "gpt-3.5-turbo",
		SystemPrompt: "You are a helpful assistant",
		Metadata:     make(map[string]interface{}),
	}

	err := db.Create(session).Error
	require.NoError(t, err, "creating test session should succeed")

	return session
}

// createTestMessageForService 创建测试消息
func createTestMessageForService(t *testing.T, service *MessageService, userID, sessionID uuid.UUID, role types.MessageRole, content string) *model.MessageResponse {
	ctx := context.Background()

	req := model.MessageCreateRequest{
		Role:    role,
		Content: content,
		Metadata: map[string]interface{}{
			"test": true,
		},
	}

	response, err := service.CreateMessage(ctx, userID, sessionID, req)
	require.NoError(t, err, "creating test message should succeed")

	return response
}
