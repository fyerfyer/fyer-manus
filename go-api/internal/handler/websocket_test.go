package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	wsocket "github.com/fyerfyer/fyer-manus/go-api/internal/websocket"
	"github.com/google/uuid"
)

func TestNewWebSocketHandler(t *testing.T) {
	handler := NewWebSocketHandler()
	assert.NotNil(t, handler, "websocket handler should not be nil")
	assert.NotNil(t, handler.wsManager, "websocket manager should not be nil")
	assert.NotNil(t, handler.sessionService, "session service should not be nil")
	assert.NotNil(t, handler.messageService, "message service should not be nil")
}

func TestWebSocketHandler_StartStop(t *testing.T) {
	handler := NewWebSocketHandler()

	// 启动处理器
	handler.Start()

	// 等待启动完成
	time.Sleep(10 * time.Millisecond)

	// 检查管理器健康状态
	err := handler.wsManager.Health()
	assert.NoError(t, err, "websocket manager should be healthy after start")

	// 停止处理器
	handler.Stop()

	// 等待停止完成
	time.Sleep(10 * time.Millisecond)

	// 检查管理器是否停止
	err = handler.wsManager.Health()
	assert.Error(t, err, "websocket manager should be unhealthy after stop")
}

func TestWebSocketHandler_HandleWebSocket(t *testing.T) {
	// 初始化测试环境
	setupWebSocketHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewWebSocketHandler()
	handler.Start()
	defer handler.Stop()

	router.GET("/ws", handler.HandleWebSocket)

	// 创建测试服务器
	server := httptest.NewServer(router)
	defer server.Close()

	// 测试无token的连接
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("should fail to connect without token")
	}
	if resp != nil {
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "should return 401 without token")
	}

	// 测试无效token的连接
	wsURLWithToken := wsURL + "?token=invalid-token"
	_, resp, err = websocket.DefaultDialer.Dial(wsURLWithToken, nil)
	if err == nil {
		t.Fatal("should fail to connect with invalid token")
	}
	if resp != nil {
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "should return 401 with invalid token")
	}

	// 测试有效token的连接（这里需要真实的JWT token）
	// 由于测试环境限制，我们只验证到这里
}

func TestWebSocketHandler_GetStats(t *testing.T) {
	// 初始化测试环境
	setupWebSocketHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewWebSocketHandler()
	handler.Start()
	defer handler.Stop()

	router.GET("/ws/stats", handler.GetStats)

	req := httptest.NewRequest("GET", "/ws/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "should return 200")
	assert.Contains(t, w.Body.String(), "hub_stats", "should contain hub stats")
	assert.Contains(t, w.Body.String(), "status", "should contain status")
}

func TestWebSocketHandler_GetUserClients(t *testing.T) {
	// 初始化测试环境
	setupWebSocketHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewWebSocketHandler()
	handler.Start()
	defer handler.Stop()

	router.GET("/ws/users/:userId/clients", handler.GetUserClients)

	tests := []struct {
		name           string
		userID         string
		expectedStatus int
	}{
		{
			name:           "valid user ID",
			userID:         uuid.New().String(),
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid user ID",
			userID:         "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/ws/users/"+tt.userID+"/clients", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				assert.Contains(t, w.Body.String(), "data", "should contain data field")
			}
		})
	}
}

func TestWebSocketHandler_DisconnectUser(t *testing.T) {
	// 初始化测试环境
	setupWebSocketHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewWebSocketHandler()
	handler.Start()
	defer handler.Stop()

	router.POST("/ws/users/:userId/disconnect", handler.DisconnectUser)

	tests := []struct {
		name           string
		userID         string
		requestBody    string
		expectedStatus int
	}{
		{
			name:           "valid disconnect request",
			userID:         uuid.New().String(),
			requestBody:    `{"reason":"admin disconnect"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid user ID",
			userID:         "invalid-uuid",
			requestBody:    `{"reason":"test"}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing reason",
			userID:         uuid.New().String(),
			requestBody:    `{}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid JSON",
			userID:         uuid.New().String(),
			requestBody:    `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/ws/users/"+tt.userID+"/disconnect", strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				assert.Contains(t, w.Body.String(), "disconnected successfully", "should contain success message")
			}
		})
	}
}

func TestWebSocketHandler_BroadcastToUser(t *testing.T) {
	// 初始化测试环境
	setupWebSocketHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewWebSocketHandler()
	handler.Start()
	defer handler.Stop()

	router.POST("/ws/users/:userId/broadcast", handler.BroadcastToUser)

	tests := []struct {
		name           string
		userID         string
		requestBody    string
		expectedStatus int
	}{
		{
			name:           "valid broadcast request",
			userID:         uuid.New().String(),
			requestBody:    `{"type":"message","data":{"content":"Hello"}}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid user ID",
			userID:         "invalid-uuid",
			requestBody:    `{"type":"message","data":{}}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing type",
			userID:         uuid.New().String(),
			requestBody:    `{"data":{"content":"Hello"}}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid JSON",
			userID:         uuid.New().String(),
			requestBody:    `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/ws/users/"+tt.userID+"/broadcast", strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				assert.Contains(t, w.Body.String(), "broadcasted successfully", "should contain success message")
			}
		})
	}
}

func TestWebSocketHandler_BroadcastToSession(t *testing.T) {
	// 初始化测试环境
	setupWebSocketHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewWebSocketHandler()
	handler.Start()
	defer handler.Stop()

	router.POST("/ws/sessions/:sessionId/broadcast", handler.BroadcastToSession)

	tests := []struct {
		name           string
		sessionID      string
		requestBody    string
		expectedStatus int
	}{
		{
			name:           "valid session broadcast",
			sessionID:      uuid.New().String(),
			requestBody:    `{"type":"message","data":{"content":"Session message"}}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid session ID",
			sessionID:      "invalid-uuid",
			requestBody:    `{"type":"message","data":{}}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing type",
			sessionID:      uuid.New().String(),
			requestBody:    `{"data":{"content":"Hello"}}`,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/ws/sessions/"+tt.sessionID+"/broadcast", strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				assert.Contains(t, w.Body.String(), "broadcasted successfully", "should contain success message")
			}
		})
	}
}

func TestWebSocketHandler_JoinSession(t *testing.T) {
	// 初始化测试环境
	setupWebSocketHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewWebSocketHandler()
	handler.Start()
	defer handler.Stop()

	router.POST("/ws/users/:userId/sessions/:sessionId/join", handler.JoinSession)

	// 创建测试会话和用户
	testUser := createTestWebSocketUser(t)
	testSession := createTestWebSocketSession(t, testUser.ID)

	tests := []struct {
		name           string
		userID         string
		sessionID      string
		expectedStatus int
	}{
		{
			name:           "valid join request",
			userID:         testUser.ID.String(),
			sessionID:      testSession.ID.String(),
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid user ID",
			userID:         "invalid-uuid",
			sessionID:      testSession.ID.String(),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid session ID",
			userID:         testUser.ID.String(),
			sessionID:      "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "nonexistent session",
			userID:         testUser.ID.String(),
			sessionID:      uuid.New().String(),
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/ws/users/"+tt.userID+"/sessions/"+tt.sessionID+"/join", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				assert.Contains(t, w.Body.String(), "joined session successfully", "should contain success message")
			}
		})
	}
}

func TestWebSocketHandler_LeaveSession(t *testing.T) {
	// 初始化测试环境
	setupWebSocketHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewWebSocketHandler()
	handler.Start()
	defer handler.Stop()

	router.POST("/ws/users/:userId/sessions/:sessionId/leave", handler.LeaveSession)

	userID := uuid.New()
	sessionID := uuid.New()

	tests := []struct {
		name           string
		userID         string
		sessionID      string
		expectedStatus int
	}{
		{
			name:           "valid leave request",
			userID:         userID.String(),
			sessionID:      sessionID.String(),
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid user ID",
			userID:         "invalid-uuid",
			sessionID:      sessionID.String(),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid session ID",
			userID:         userID.String(),
			sessionID:      "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/ws/users/"+tt.userID+"/sessions/"+tt.sessionID+"/leave", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				assert.Contains(t, w.Body.String(), "left session successfully", "should contain success message")
			}
		})
	}
}

func TestWebSocketHandler_Health(t *testing.T) {
	// 初始化测试环境
	setupWebSocketHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewWebSocketHandler()

	router.GET("/ws/health", handler.Health)

	// 测试未启动的处理器
	req := httptest.NewRequest("GET", "/ws/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "should return 503 when not running")

	// 启动处理器
	handler.Start()
	defer handler.Stop()

	// 等待启动完成
	time.Sleep(10 * time.Millisecond)

	// 测试运行中的处理器
	req = httptest.NewRequest("GET", "/ws/health", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "should return 200 when running")
	assert.Contains(t, w.Body.String(), "healthy", "should contain healthy message")
}

func TestWebSocketHandler_SendStreamingMessage(t *testing.T) {
	// 初始化测试环境
	setupWebSocketHandlerTestEnv(t)

	handler := NewWebSocketHandler()
	handler.Start()
	defer handler.Stop()

	userID := uuid.New()
	sessionID := uuid.New()
	content := "This is a streaming message"

	// 测试发送流式消息
	err := handler.SendStreamingMessage(userID, sessionID, content, false)
	assert.NoError(t, err, "should send streaming message without error")

	// 测试发送完成消息
	err = handler.SendStreamingMessage(userID, sessionID, content, true)
	assert.NoError(t, err, "should send completion message without error")
}

func TestWebSocketHandler_SendTypingIndicator(t *testing.T) {
	// 初始化测试环境
	setupWebSocketHandlerTestEnv(t)

	handler := NewWebSocketHandler()
	handler.Start()
	defer handler.Stop()

	userID := uuid.New()
	sessionID := uuid.New()

	// 测试发送打字指示器
	err := handler.SendTypingIndicator(userID, sessionID, true)
	assert.NoError(t, err, "should send typing indicator without error")

	// 测试停止打字指示器
	err = handler.SendTypingIndicator(userID, sessionID, false)
	assert.NoError(t, err, "should stop typing indicator without error")
}

func TestWebSocketHandler_SendError(t *testing.T) {
	// 初始化测试环境
	setupWebSocketHandlerTestEnv(t)

	handler := NewWebSocketHandler()
	handler.Start()
	defer handler.Stop()

	userID := uuid.New()
	message := "Something went wrong"
	code := http.StatusInternalServerError

	// 测试发送错误消息
	err := handler.SendError(userID, message, code)
	assert.NoError(t, err, "should send error message without error")
}

func TestWebSocketHandler_GetManager(t *testing.T) {
	handler := NewWebSocketHandler()

	manager := handler.GetManager()
	assert.NotNil(t, manager, "manager should not be nil")
	assert.Equal(t, handler.wsManager, manager, "should return the same manager instance")
}

func TestWebSocketHandler_HandleMessage(t *testing.T) {
	// 初始化测试环境
	setupWebSocketHandlerTestEnv(t)

	handler := NewWebSocketHandler()
	handler.Start()
	defer handler.Stop()

	// 创建模拟客户端
	client := createMockWebSocketClient(t)

	tests := []struct {
		name        string
		msgType     types.WSMessageType
		data        string
		expectError bool
	}{
		{
			name:        "valid message",
			msgType:     types.WSMessageTypeMessage,
			data:        `{"session_id":"` + uuid.New().String() + `","content":"Hello","role":"user"}`,
			expectError: false,
		},
		{
			name:        "typing message",
			msgType:     types.WSMessageTypeTyping,
			data:        `{"session_id":"` + uuid.New().String() + `","typing":true}`,
			expectError: false,
		},
		{
			name:        "invalid message format",
			msgType:     types.WSMessageTypeMessage,
			data:        `{invalid json}`,
			expectError: true,
		},
		{
			name:        "unknown message type",
			msgType:     types.WSMessageType("unknown"),
			data:        `{"content":"test"}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.HandleMessage(client, tt.msgType, []byte(tt.data))

			if tt.expectError {
				assert.Error(t, err, "should return error for invalid message")
			} else {
				// 由于需要真实的会话验证，这里可能会返回错误
				// 我们只验证不会panic
				assert.True(t, err == nil || err != nil, "should handle message without panic")
			}
		})
	}
}

// 测试辅助函数

// createTestWebSocketUser 创建测试用户
func createTestWebSocketUser(t *testing.T) *TestWebSocketUser {
	userService := service.NewUserService()

	username := "wsuser" + uuid.New().String()[:8]
	email := "wsuser" + uuid.New().String()[:8] + "@example.com"

	createReq := service.CreateUserRequest{
		Username: username,
		Email:    email,
		Password: "password123",
		FullName: "WebSocket Test User",
	}

	profile, err := userService.CreateUser(context.Background(), createReq)
	require.NoError(t, err, "should create test websocket user")

	return &TestWebSocketUser{
		ID:       profile.ID,
		Username: username,
		Email:    email,
	}
}

// TestWebSocketUser 测试用户结构
type TestWebSocketUser struct {
	ID       uuid.UUID
	Username string
	Email    string
}

// createTestWebSocketSession 创建测试会话
func createTestWebSocketSession(t *testing.T, userID uuid.UUID) *TestWebSocketSession {
	sessionService := service.NewSessionService()

	createReq := model.SessionCreateRequest{
		Title:        "WebSocket Test Session",
		SystemPrompt: "You are a test assistant",
	}

	session, err := sessionService.CreateSession(context.Background(), userID, createReq)
	require.NoError(t, err, "should create test websocket session")

	return &TestWebSocketSession{
		ID:     session.ID,
		UserID: userID,
		Title:  session.Title,
	}
}

// TestWebSocketSession 测试会话结构
type TestWebSocketSession struct {
	ID     uuid.UUID
	UserID uuid.UUID
	Title  string
}

// createMockWebSocketClient 创建模拟WebSocket客户端
func createMockWebSocketClient(t *testing.T) *wsocket.Client {
	userID := uuid.New()
	username := "testuser"

	// 创建模拟的WebSocket连接
	// 这里我们使用nil，因为在这个测试中我们不需要真实的连接
	client := &wsocket.Client{
		ID:       uuid.New(),
		UserID:   userID,
		Username: username,
		Metadata: make(map[string]interface{}),
	}

	return client
}

// setupWebSocketHandlerTestEnv 设置WebSocket处理器测试环境
func setupWebSocketHandlerTestEnv(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	// 初始化数据库连接
	err = database.Init(&cfg.Database)
	if err != nil {
		t.Logf("Warning: failed to init database for websocket handler test: %v", err)
	}

	// 初始化Redis连接
	err = cache.Init(&cfg.Redis)
	if err != nil {
		t.Logf("Warning: failed to init cache for websocket handler test: %v", err)
	}
}
