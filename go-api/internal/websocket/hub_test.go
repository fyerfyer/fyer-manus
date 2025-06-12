package websocket

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/google/uuid"
)

func TestNewHub(t *testing.T) {
	hub := NewHub()

	assert.NotNil(t, hub, "hub should not be nil")
	assert.NotNil(t, hub.clients, "clients map should be initialized")
	assert.NotNil(t, hub.userClients, "user clients map should be initialized")
	assert.NotNil(t, hub.sessionClients, "session clients map should be initialized")
	assert.NotNil(t, hub.broadcast, "broadcast channel should be initialized")
	assert.NotNil(t, hub.message, "message channel should be initialized")
	assert.NotNil(t, hub.register, "register channel should be initialized")
	assert.NotNil(t, hub.unregister, "unregister channel should be initialized")
	assert.NotNil(t, hub.done, "done channel should be initialized")
}

func TestHub_RegisterClient(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()
	userID := uuid.New()
	client := createMockClient(t, hub, userID, "testuser")

	// 注册客户端
	hub.registerClient(client)

	// 验证客户端被注册
	assert.True(t, hub.clients[client], "client should be registered")
	assert.Contains(t, hub.userClients[userID], client, "client should be in user clients map")
	assert.Equal(t, 1, hub.stats.TotalClients, "total clients should be 1")
	assert.Equal(t, 1, hub.stats.TotalUsers, "total users should be 1")
}

func TestHub_UnregisterClient(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()
	userID := uuid.New()
	client := createMockClient(t, hub, userID, "testuser")

	// 先注册客户端
	hub.registerClient(client)
	assert.Equal(t, 1, hub.stats.TotalClients, "should have 1 client after registration")

	// 注销客户端
	hub.unregisterClient(client)

	// 验证客户端被注销
	assert.False(t, hub.clients[client], "client should not be in clients map")
	assert.NotContains(t, hub.userClients[userID], client, "client should not be in user clients map")
	assert.Equal(t, 0, hub.stats.TotalClients, "total clients should be 0")
	assert.Equal(t, 0, hub.stats.TotalUsers, "total users should be 0")
}

func TestHub_RegisterMultipleClientsForSameUser(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()
	userID := uuid.New()

	// 为同一用户注册多个客户端
	client1 := createMockClient(t, hub, userID, "testuser")
	client2 := createMockClient(t, hub, userID, "testuser")

	hub.registerClient(client1)
	hub.registerClient(client2)

	// 验证统计信息
	assert.Equal(t, 2, hub.stats.TotalClients, "should have 2 clients")
	assert.Equal(t, 1, hub.stats.TotalUsers, "should have 1 user")

	// 验证用户客户端映射
	userClients := hub.userClients[userID]
	assert.Len(t, userClients, 2, "user should have 2 clients")
	assert.Contains(t, userClients, client1, "should contain client1")
	assert.Contains(t, userClients, client2, "should contain client2")
}

func TestHub_BroadcastToAll(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()

	// 创建多个客户端
	user1ID := uuid.New()
	user2ID := uuid.New()
	client1 := createMockClient(t, hub, user1ID, "user1")
	client2 := createMockClient(t, hub, user2ID, "user2")
	sender := createMockClient(t, hub, uuid.New(), "sender")

	hub.registerClient(client1)
	hub.registerClient(client2)
	hub.registerClient(sender)

	// 准备广播消息
	testData := []byte(`{"type":"message","data":{"content":"broadcast test"}}`)
	msg := &BroadcastMessage{
		Type:   BroadcastToAll,
		Data:   testData,
		Sender: sender,
	}

	// 执行广播
	hub.broadcastToAll(msg)

	// 验证消息被发送到所有客户端（除了发送者）
	select {
	case data := <-client1.send:
		assert.Equal(t, testData, data, "client1 should receive broadcast message")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("client1 should receive broadcast message")
	}

	select {
	case data := <-client2.send:
		assert.Equal(t, testData, data, "client2 should receive broadcast message")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("client2 should receive broadcast message")
	}

	// 发送者不应该收到消息
	select {
	case <-sender.send:
		t.Fatal("sender should not receive their own broadcast message")
	case <-time.After(50 * time.Millisecond):
		// 正确行为：发送者不收到消息
	}
}

func TestHub_BroadcastToUser(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()

	// 创建客户端
	targetUserID := uuid.New()
	otherUserID := uuid.New()
	targetClient1 := createMockClient(t, hub, targetUserID, "target")
	targetClient2 := createMockClient(t, hub, targetUserID, "target")
	otherClient := createMockClient(t, hub, otherUserID, "other")
	sender := createMockClient(t, hub, targetUserID, "sender")

	hub.registerClient(targetClient1)
	hub.registerClient(targetClient2)
	hub.registerClient(otherClient)
	hub.registerClient(sender)

	// 准备用户广播消息
	testData := []byte(`{"type":"message","data":{"content":"user broadcast test"}}`)
	msg := &BroadcastMessage{
		Type:   BroadcastToUser,
		UserID: targetUserID,
		Data:   testData,
		Sender: sender,
	}

	// 执行广播
	hub.broadcastToUser(msg)

	// 验证目标用户的客户端收到消息（除了发送者）
	select {
	case data := <-targetClient1.send:
		assert.Equal(t, testData, data, "targetClient1 should receive message")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("targetClient1 should receive message")
	}

	select {
	case data := <-targetClient2.send:
		assert.Equal(t, testData, data, "targetClient2 should receive message")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("targetClient2 should receive message")
	}

	// 其他用户不应该收到消息
	select {
	case <-otherClient.send:
		t.Fatal("other user client should not receive message")
	case <-time.After(50 * time.Millisecond):
		// 正确行为：其他用户不收到消息
	}

	// 发送者不应该收到消息
	select {
	case <-sender.send:
		t.Fatal("sender should not receive their own message")
	case <-time.After(50 * time.Millisecond):
		// 正确行为：发送者不收到消息
	}
}

func TestHub_BroadcastToSession(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()
	sessionID := uuid.New()

	// 创建客户端
	client1 := createMockClient(t, hub, uuid.New(), "user1")
	client2 := createMockClient(t, hub, uuid.New(), "user2")
	outsideClient := createMockClient(t, hub, uuid.New(), "outside")
	sender := createMockClient(t, hub, uuid.New(), "sender")

	hub.registerClient(client1)
	hub.registerClient(client2)
	hub.registerClient(outsideClient)
	hub.registerClient(sender)

	// 将客户端加入会话
	hub.JoinSession(client1, sessionID)
	hub.JoinSession(client2, sessionID)
	hub.JoinSession(sender, sessionID)

	// 准备会话广播消息
	testData := []byte(`{"type":"message","data":{"content":"session broadcast test"}}`)
	msg := &BroadcastMessage{
		Type:      BroadcastToSession,
		SessionID: sessionID,
		Data:      testData,
		Sender:    sender,
	}

	// 执行广播
	hub.broadcastToSession(msg)

	// 验证会话中的客户端收到消息（除了发送者）
	select {
	case data := <-client1.send:
		assert.Equal(t, testData, data, "client1 in session should receive message")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("client1 in session should receive message")
	}

	select {
	case data := <-client2.send:
		assert.Equal(t, testData, data, "client2 in session should receive message")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("client2 in session should receive message")
	}

	// 会话外的客户端不应该收到消息
	select {
	case <-outsideClient.send:
		t.Fatal("client outside session should not receive message")
	case <-time.After(50 * time.Millisecond):
		// 正确行为：会话外客户端不收到消息
	}

	// 发送者不应该收到消息
	select {
	case <-sender.send:
		t.Fatal("sender should not receive their own message")
	case <-time.After(50 * time.Millisecond):
		// 正确行为：发送者不收到消息
	}
}

func TestHub_JoinSession(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()
	sessionID := uuid.New()
	client := createMockClient(t, hub, uuid.New(), "testuser")

	hub.registerClient(client)

	// 加入会话
	hub.JoinSession(client, sessionID)

	// 验证客户端被添加到会话
	assert.Contains(t, hub.sessionClients[sessionID], client, "client should be in session")
	assert.Equal(t, 1, hub.stats.TotalSessions, "should have 1 session")

	// 验证客户端元数据
	currentSession := client.Metadata["current_session"]
	assert.Equal(t, sessionID, currentSession, "client metadata should contain current session")
}

func TestHub_LeaveSession(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()
	sessionID := uuid.New()
	client := createMockClient(t, hub, uuid.New(), "testuser")

	hub.registerClient(client)
	hub.JoinSession(client, sessionID)

	// 验证客户端在会话中
	assert.Contains(t, hub.sessionClients[sessionID], client, "client should be in session")

	// 离开会话
	hub.LeaveSession(client, sessionID)

	// 验证客户端被移除
	assert.NotContains(t, hub.sessionClients[sessionID], client, "client should not be in session")
	assert.Equal(t, 0, hub.stats.TotalSessions, "should have 0 sessions")

	// 验证客户端元数据被清除
	currentSession := client.Metadata["current_session"]
	assert.Nil(t, currentSession, "client metadata should not contain current session")
}

func TestHub_GetClientsByUser(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()
	userID := uuid.New()

	// 为用户创建多个客户端
	client1 := createMockClient(t, hub, userID, "testuser")
	client2 := createMockClient(t, hub, userID, "testuser")
	otherClient := createMockClient(t, hub, uuid.New(), "other")

	hub.registerClient(client1)
	hub.registerClient(client2)
	hub.registerClient(otherClient)

	// 获取用户客户端
	userClients := hub.GetClientsByUser(userID)

	assert.Len(t, userClients, 2, "should return 2 clients for user")
	assert.Contains(t, userClients, client1, "should contain client1")
	assert.Contains(t, userClients, client2, "should contain client2")
	assert.NotContains(t, userClients, otherClient, "should not contain other client")
}

func TestHub_GetClientsByUserWithInactiveClient(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()
	userID := uuid.New()

	// 创建客户端
	activeClient := createMockClient(t, hub, userID, "testuser")
	inactiveClient := createMockClient(t, hub, userID, "testuser")

	hub.registerClient(activeClient)
	hub.registerClient(inactiveClient)

	// 将一个客户端设为不活跃
	inactiveClient.Close()

	// 获取用户活跃客户端
	userClients := hub.GetClientsByUser(userID)

	assert.Len(t, userClients, 1, "should return only active clients")
	assert.Contains(t, userClients, activeClient, "should contain active client")
	assert.NotContains(t, userClients, inactiveClient, "should not contain inactive client")
}

func TestHub_HandleBroadcast(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()
	client := createMockClient(t, hub, uuid.New(), "testuser")
	hub.registerClient(client)

	// 测试不同类型的广播
	tests := []struct {
		name string
		msg  *BroadcastMessage
	}{
		{
			name: "broadcast to all",
			msg: &BroadcastMessage{
				Type:   BroadcastToAll,
				Data:   []byte(`{"type":"test"}`),
				Sender: client,
			},
		},
		{
			name: "broadcast to user",
			msg: &BroadcastMessage{
				Type:   BroadcastToUser,
				UserID: client.UserID,
				Data:   []byte(`{"type":"test"}`),
				Sender: client,
			},
		},
		{
			name: "broadcast to session",
			msg: &BroadcastMessage{
				Type:      BroadcastToSession,
				SessionID: uuid.New(),
				Data:      []byte(`{"type":"test"}`),
				Sender:    client,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalCount := hub.stats.MessagesTotal
			originalTime := hub.stats.LastMessageAt

			// 等待一毫秒确保时间不同
			time.Sleep(time.Millisecond)

			hub.handleBroadcast(tt.msg)

			// 验证统计信息被更新
			assert.Equal(t, originalCount+1, hub.stats.MessagesTotal, "message count should increase")
			assert.True(t, hub.stats.LastMessageAt.After(originalTime), "last message time should be updated")
		})
	}
}

func TestHub_SendToUser(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()
	userID := uuid.New()
	client := createMockClient(t, hub, userID, "testuser")
	hub.registerClient(client)

	// 发送消息给用户
	event := types.WSEvent{
		Type:    types.WSMessageTypeMessage,
		EventID: uuid.New().String(),
		Data:    map[string]interface{}{"content": "test message"},
	}

	hub.SendToUser(userID, event)

	// 验证消息被发送到广播通道
	select {
	case msg := <-hub.broadcast:
		assert.Equal(t, BroadcastToUser, msg.Type, "should be user broadcast")
		assert.Equal(t, userID, msg.UserID, "user ID should match")

		// 验证数据是正确的JSON
		var receivedEvent types.WSEvent
		err := json.Unmarshal(msg.Data, &receivedEvent)
		assert.NoError(t, err, "should unmarshal event data")
		assert.Equal(t, event.Type, receivedEvent.Type, "event type should match")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("should send message to broadcast channel")
	}
}

func TestHub_SendToSession(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()
	sessionID := uuid.New()

	// 发送消息给会话
	event := types.WSEvent{
		Type:    types.WSMessageTypeMessage,
		EventID: uuid.New().String(),
		Data:    map[string]interface{}{"content": "session message"},
	}

	hub.SendToSession(sessionID, event)

	// 验证消息被发送到广播通道
	select {
	case msg := <-hub.broadcast:
		assert.Equal(t, BroadcastToSession, msg.Type, "should be session broadcast")
		assert.Equal(t, sessionID, msg.SessionID, "session ID should match")

		// 验证数据是正确的JSON
		var receivedEvent types.WSEvent
		err := json.Unmarshal(msg.Data, &receivedEvent)
		assert.NoError(t, err, "should unmarshal event data")
		assert.Equal(t, event.Type, receivedEvent.Type, "event type should match")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("should send message to broadcast channel")
	}
}

func TestHub_GetStats(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()

	// 初始统计
	stats := hub.GetStats()
	assert.Equal(t, 0, stats.TotalClients, "initial clients should be 0")
	assert.Equal(t, 0, stats.TotalUsers, "initial users should be 0")
	assert.Equal(t, 0, stats.TotalSessions, "initial sessions should be 0")

	// 添加客户端
	user1ID := uuid.New()
	user2ID := uuid.New()
	client1 := createMockClient(t, hub, user1ID, "user1")
	client2 := createMockClient(t, hub, user2ID, "user2")

	hub.registerClient(client1)
	hub.registerClient(client2)

	// 添加会话
	sessionID := uuid.New()
	hub.JoinSession(client1, sessionID)

	// 更新后的统计
	stats = hub.GetStats()
	assert.Equal(t, 2, stats.TotalClients, "should have 2 clients")
	assert.Equal(t, 2, stats.TotalUsers, "should have 2 users")
	assert.Equal(t, 1, stats.TotalSessions, "should have 1 session")
}

func TestHub_Run(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// 启动Hub
	go hub.Run(ctx)

	// 等待Hub启动
	time.Sleep(10 * time.Millisecond)

	// 测试注册客户端
	client := createMockClient(t, hub, uuid.New(), "testuser")
	hub.register <- client

	// 等待处理
	time.Sleep(10 * time.Millisecond)

	// 验证客户端被注册
	assert.True(t, hub.clients[client], "client should be registered")

	// 测试注销客户端
	hub.unregister <- client

	// 等待处理
	time.Sleep(10 * time.Millisecond)

	// 验证客户端被注销
	assert.False(t, hub.clients[client], "client should be unregistered")
}

func TestHub_Shutdown(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()

	// 添加一些客户端
	client1 := createMockClient(t, hub, uuid.New(), "user1")
	client2 := createMockClient(t, hub, uuid.New(), "user2")
	hub.registerClient(client1)
	hub.registerClient(client2)

	assert.Equal(t, 2, len(hub.clients), "should have 2 clients before shutdown")

	// 关闭Hub
	hub.shutdown()

	// 验证所有映射被清空
	assert.Equal(t, 0, len(hub.clients), "clients should be empty after shutdown")
	assert.Equal(t, 0, len(hub.userClients), "user clients should be empty after shutdown")
	assert.Equal(t, 0, len(hub.sessionClients), "session clients should be empty after shutdown")
}

func TestHub_Stop(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// 启动Hub
	done := make(chan bool)
	go func() {
		hub.Run(ctx)
		done <- true
	}()

	// 等待Hub启动
	time.Sleep(10 * time.Millisecond)

	// 停止Hub
	hub.Stop()

	// 验证Hub停止
	select {
	case <-done:
		// Hub正确停止
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Hub should stop after calling Stop()")
	}
}

func TestHub_CleanupInactiveClients(t *testing.T) {
	// 初始化测试环境
	setupHubTestEnv(t)

	hub := NewHub()

	// 创建客户端
	activeClient := createMockClient(t, hub, uuid.New(), "active")
	inactiveClient := createMockClient(t, hub, uuid.New(), "inactive")

	hub.registerClient(activeClient)
	hub.registerClient(inactiveClient)

	// 设置不活跃客户端的最后ping时间为很久以前
	inactiveClient.LastPing = time.Now().Add(-10 * time.Minute)

	assert.Equal(t, 2, len(hub.clients), "should have 2 clients before cleanup")

	// 执行清理
	hub.cleanupInactiveClients()

	// 等待清理完成
	time.Sleep(10 * time.Millisecond)

	// 验证不活跃客户端被清理
	assert.Equal(t, 1, len(hub.clients), "should have 1 client after cleanup")
	assert.True(t, hub.clients[activeClient], "active client should remain")
	assert.False(t, hub.clients[inactiveClient], "inactive client should be removed")
}

// createMockClient 创建模拟客户端用于测试
func createMockClient(t *testing.T, hub *Hub, userID uuid.UUID, username string) *Client {
	return &Client{
		ID:          uuid.New(),
		UserID:      userID,
		Username:    username,
		hub:         hub,
		send:        make(chan []byte, 256),
		done:        make(chan struct{}),
		isActive:    true,
		ConnectedAt: time.Now(),
		LastPing:    time.Now(),
		Metadata:    make(map[string]interface{}),
	}
}

// setupHubTestEnv 设置Hub测试环境
func setupHubTestEnv(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")
	_ = cfg // 使用配置但不需要特殊设置
}
