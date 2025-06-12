package websocket

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/google/uuid"
)

func TestNewClient(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	userID := uuid.New()
	username := "testuser"

	client := NewClient(conn, hub, userID, username)

	assert.NotNil(t, client, "client should not be nil")
	assert.Equal(t, userID, client.UserID, "user ID should match")
	assert.Equal(t, username, client.Username, "username should match")
	assert.NotEqual(t, uuid.Nil, client.ID, "client ID should be generated")
	assert.True(t, client.IsActive(), "client should be active")
	assert.NotZero(t, client.ConnectedAt, "connected time should be set")
	assert.NotNil(t, client.Metadata, "metadata should be initialized")
}

func TestClient_SendMessage(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	client := NewClient(conn, hub, uuid.New(), "testuser")

	// 测试发送普通消息
	event := types.WSEvent{
		Type:    types.WSMessageTypeMessage,
		EventID: uuid.New().String(),
		Time:    time.Now(),
		Data: map[string]interface{}{
			"content": "Hello, World!",
		},
	}

	err := client.SendMessage(event)
	assert.NoError(t, err, "should send message without error")
}

func TestClient_SendError(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	client := NewClient(conn, hub, uuid.New(), "testuser")

	// 测试发送错误消息
	client.SendError("test error message", http.StatusBadRequest)

	// 验证消息被添加到发送通道
	select {
	case data := <-client.send:
		var event types.WSEvent
		err := json.Unmarshal(data, &event)
		assert.NoError(t, err, "should unmarshal error event")
		assert.Equal(t, types.WSMessageTypeError, event.Type, "should be error type")

		eventData, ok := event.Data.(map[string]interface{})
		assert.True(t, ok, "event data should be map")
		assert.Equal(t, "test error message", eventData["message"], "error message should match")
		assert.Equal(t, float64(http.StatusBadRequest), eventData["code"], "error code should match")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("should receive error message")
	}
}

func TestClient_HandleMessage(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	client := NewClient(conn, hub, uuid.New(), "testuser")

	tests := []struct {
		name        string
		message     types.WSEvent
		expectError bool
	}{
		{
			name: "valid message",
			message: types.WSEvent{
				Type:    types.WSMessageTypeMessage,
				EventID: uuid.New().String(),
				Data:    map[string]interface{}{"content": "test"},
			},
			expectError: false,
		},
		{
			name: "heartbeat message",
			message: types.WSEvent{
				Type:    types.WSMessageTypeHeartbeat,
				EventID: uuid.New().String(),
				Data:    map[string]interface{}{"status": "ping"},
			},
			expectError: false,
		},
		{
			name: "typing message",
			message: types.WSEvent{
				Type:    types.WSMessageTypeTyping,
				EventID: uuid.New().String(),
				Data:    map[string]interface{}{"typing": true},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messageBytes, err := json.Marshal(tt.message)
			require.NoError(t, err, "should marshal message")

			err = client.handleMessage(messageBytes)
			if tt.expectError {
				assert.Error(t, err, "should return error")
			} else {
				assert.NoError(t, err, "should handle message without error")
			}
		})
	}
}

func TestClient_HandleInvalidMessage(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	client := NewClient(conn, hub, uuid.New(), "testuser")

	// 测试无效JSON
	invalidJSON := []byte(`{"type": "message", "data":}`)
	err := client.handleMessage(invalidJSON)
	assert.Error(t, err, "should return error for invalid JSON")
	assert.Contains(t, err.Error(), "invalid message format", "error should mention invalid format")
}

func TestClient_HandleHeartbeat(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	client := NewClient(conn, hub, uuid.New(), "testuser")

	originalPing := client.LastPing

	// 等待一毫秒确保时间不同
	time.Sleep(time.Millisecond)

	client.handleHeartbeat()

	// 验证LastPing被更新
	assert.True(t, client.LastPing.After(originalPing), "last ping should be updated")

	// 验证心跳响应被发送
	select {
	case data := <-client.send:
		var event types.WSEvent
		err := json.Unmarshal(data, &event)
		assert.NoError(t, err, "should unmarshal heartbeat response")
		assert.Equal(t, types.WSMessageTypeHeartbeat, event.Type, "should be heartbeat type")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("should receive heartbeat response")
	}
}

func TestClient_SetMetadata(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	client := NewClient(conn, hub, uuid.New(), "testuser")

	// 设置元数据
	client.SetMetadata("user_agent", "Mozilla/5.0")
	client.SetMetadata("remote_addr", "192.168.1.1")
	client.SetMetadata("session_id", uuid.New())

	// 验证元数据
	assert.Equal(t, "Mozilla/5.0", client.Metadata["user_agent"], "user agent should be set")
	assert.Equal(t, "192.168.1.1", client.Metadata["remote_addr"], "remote addr should be set")
	assert.NotNil(t, client.Metadata["session_id"], "session ID should be set")
}

func TestClient_GetInfo(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	userID := uuid.New()
	username := "testuser"
	client := NewClient(conn, hub, userID, username)

	// 设置一些元数据
	client.SetMetadata("test_key", "test_value")

	info := client.GetInfo()

	assert.Equal(t, client.ID, info["id"], "ID should match")
	assert.Equal(t, userID, info["user_id"], "user ID should match")
	assert.Equal(t, username, info["username"], "username should match")
	assert.NotNil(t, info["connected_at"], "connected at should be set")
	assert.NotNil(t, info["last_ping"], "last ping should be set")
	assert.Equal(t, true, info["is_active"], "should be active")
	assert.NotNil(t, info["metadata"], "metadata should be included")

	metadata, ok := info["metadata"].(map[string]interface{})
	assert.True(t, ok, "metadata should be map")
	assert.Equal(t, "test_value", metadata["test_key"], "metadata should include custom values")
}

func TestClient_IsActive(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	client := NewClient(conn, hub, uuid.New(), "testuser")

	// 新客户端应该是活跃的
	assert.True(t, client.IsActive(), "new client should be active")

	// 关闭客户端
	client.Close()

	// 关闭后应该不活跃
	assert.False(t, client.IsActive(), "closed client should not be active")
}

func TestClient_Close(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	client := NewClient(conn, hub, uuid.New(), "testuser")

	assert.True(t, client.IsActive(), "client should be active initially")

	// 关闭客户端
	client.Close()

	assert.False(t, client.IsActive(), "client should not be active after close")

	// 再次关闭应该是安全的
	client.Close()
	assert.False(t, client.IsActive(), "multiple close calls should be safe")
}

func TestClient_SendMessageAfterClose(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	client := NewClient(conn, hub, uuid.New(), "testuser")

	// 关闭客户端
	client.Close()

	// 尝试发送消息
	event := types.WSEvent{
		Type: types.WSMessageTypeMessage,
		Data: map[string]interface{}{"content": "test"},
	}

	err := client.SendMessage(event)
	assert.Error(t, err, "should return error when sending to closed client")
	assert.Contains(t, err.Error(), "not active", "error should mention client not active")
}

func TestClient_ConcurrentSendMessage(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	client := NewClient(conn, hub, uuid.New(), "testuser")

	const numGoroutines = 10
	const messagesPerGoroutine = 5

	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines*messagesPerGoroutine)

	// 并发发送消息
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()
			for j := 0; j < messagesPerGoroutine; j++ {
				event := types.WSEvent{
					Type:    types.WSMessageTypeMessage,
					EventID: uuid.New().String(),
					Data: map[string]interface{}{
						"content":      "concurrent test",
						"goroutine_id": goroutineID,
						"message_id":   j,
					},
				}
				if err := client.SendMessage(event); err != nil {
					errors <- err
				}
			}
		}(i)
	}

	// 等待所有goroutine完成
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
	close(errors)

	// 检查是否有错误
	errorCount := 0
	for err := range errors {
		errorCount++
		t.Logf("Concurrent send error: %v", err)
	}

	// 在正常情况下不应该有错误（除非通道满了）
	assert.LessOrEqual(t, errorCount, numGoroutines*messagesPerGoroutine/2, "should have minimal errors in concurrent sending")
}

func TestClient_Start(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	client := NewClient(conn, hub, uuid.New(), "testuser")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// 启动客户端
	client.Start(ctx)

	// 等待一段时间让goroutines启动
	time.Sleep(10 * time.Millisecond)

	assert.True(t, client.IsActive(), "client should remain active after start")
}

func TestClient_MessageTypeHandling(t *testing.T) {
	// 初始化测试环境
	setupWebSocketTestEnv(t)

	hub := NewHub()
	conn := createMockWebSocketConn(t)
	client := NewClient(conn, hub, uuid.New(), "testuser")

	// 启动Hub以处理消息
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go hub.Run(ctx)

	// 等待Hub启动
	time.Sleep(10 * time.Millisecond)

	tests := []struct {
		name        string
		messageType types.WSMessageType
		data        map[string]interface{}
	}{
		{
			name:        "message type",
			messageType: types.WSMessageTypeMessage,
			data:        map[string]interface{}{"content": "test message"},
		},
		{
			name:        "typing type",
			messageType: types.WSMessageTypeTyping,
			data:        map[string]interface{}{"typing": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := types.WSEvent{
				Type:    tt.messageType,
				EventID: uuid.New().String(),
				Data:    tt.data,
			}

			messageBytes, err := json.Marshal(event)
			require.NoError(t, err, "should marshal message")

			err = client.handleMessage(messageBytes)
			assert.NoError(t, err, "should handle %s message type", tt.messageType)
		})
	}
}

// createMockWebSocketConn 创建模拟的WebSocket连接
func createMockWebSocketConn(t *testing.T) *websocket.Conn {
	// 创建一个简单的WebSocket服务器用于测试
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade connection: %v", err)
		}
		defer conn.Close()

		// 保持连接开启以便测试
		for {
			select {
			case <-r.Context().Done():
				return
			default:
				time.Sleep(10 * time.Millisecond)
			}
		}
	}))

	// 创建WebSocket客户端连接
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err, "should connect to test WebSocket server")

	// 注意：在实际测试中，我们需要正确管理这个连接的生命周期
	t.Cleanup(func() {
		conn.Close()
		server.Close()
	})

	return conn
}

// setupWebSocketTestEnv 设置WebSocket测试环境
func setupWebSocketTestEnv(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")
	_ = cfg // 使用配置但不需要特殊设置
}
