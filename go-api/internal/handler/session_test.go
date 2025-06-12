package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/auth"
	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/middleware"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/google/uuid"
)

func TestNewSessionHandler(t *testing.T) {
	handler := NewSessionHandler()
	assert.NotNil(t, handler, "session handler should not be nil")
	assert.NotNil(t, handler.sessionService, "session service should not be nil")
	assert.NotNil(t, handler.messageService, "message service should not be nil")
}

func TestSessionHandler_CreateSession(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaims()
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.POST("/sessions", handler.CreateSession)

	tests := []struct {
		name           string
		requestBody    model.SessionCreateRequest
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "valid session creation",
			requestBody: model.SessionCreateRequest{
				Title:        "Test Session",
				SystemPrompt: "You are a helpful assistant",
				Metadata: map[string]interface{}{
					"model":       "gpt-3.5-turbo",
					"temperature": 0.7,
				},
			},
			expectedStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")
				assert.Equal(t, float64(http.StatusCreated), response["code"], "response code should match")
				assert.Contains(t, response["message"], "successfully", "should contain success message")
				assert.Contains(t, response, "data", "should contain data field")
			},
		},
		{
			name: "empty title",
			requestBody: model.SessionCreateRequest{
				Title:        "",
				SystemPrompt: "You are a helpful assistant",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "request format", "should mention invalid format")
			},
		},
		{
			name: "title too long",
			requestBody: model.SessionCreateRequest{
				Title: createLongString(300),
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "request format", "should mention invalid format")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.requestBody)
			require.NoError(t, err, "should marshal request body")

			req := httptest.NewRequest("POST", "/sessions", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

func TestSessionHandler_GetSession(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaims()
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.GET("/sessions/:id", handler.GetSession)

	// 创建测试会话
	testSession := createTestSession(t)

	tests := []struct {
		name           string
		sessionID      string
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:           "valid session ID",
			sessionID:      testSession.ID.String(),
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "should have data field")
				assert.Equal(t, testSession.Title, data["title"], "title should match")
			},
		},
		{
			name:           "invalid session ID format",
			sessionID:      "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid session ID", "should mention invalid ID format")
			},
		},
		{
			name:           "nonexistent session ID",
			sessionID:      uuid.New().String(),
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "not found", "should mention session not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/sessions/"+tt.sessionID, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

func TestSessionHandler_UpdateSession(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaims()
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.PUT("/sessions/:id", handler.UpdateSession)

	// 创建测试会话
	testSession := createTestSession(t)

	tests := []struct {
		name           string
		sessionID      string
		requestBody    model.SessionUpdateRequest
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:      "valid session update",
			sessionID: testSession.ID.String(),
			requestBody: model.SessionUpdateRequest{
				Title:        "Updated Session Title",
				SystemPrompt: "You are an updated assistant",
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")
				assert.Contains(t, response["message"], "successfully", "should contain success message")
			},
		},
		{
			name:      "invalid session ID",
			sessionID: "invalid-uuid",
			requestBody: model.SessionUpdateRequest{
				Title: "Updated Title",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid session ID", "should mention invalid ID")
			},
		},
		{
			name:      "nonexistent session",
			sessionID: uuid.New().String(),
			requestBody: model.SessionUpdateRequest{
				Title: "Updated Title",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "not found", "should mention session not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.requestBody)
			require.NoError(t, err, "should marshal request body")

			req := httptest.NewRequest("PUT", "/sessions/"+tt.sessionID, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

func TestSessionHandler_DeleteSession(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaims()
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.DELETE("/sessions/:id", handler.DeleteSession)

	// 创建测试会话
	testSession := createTestSession(t)

	tests := []struct {
		name           string
		sessionID      string
		expectedStatus int
	}{
		{
			name:           "valid session deletion",
			sessionID:      testSession.ID.String(),
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid session ID",
			sessionID:      "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "nonexistent session",
			sessionID:      uuid.New().String(),
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("DELETE", "/sessions/"+tt.sessionID, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				assert.Contains(t, w.Body.String(), "successfully", "should contain success message")
			}
		})
	}
}

func TestSessionHandler_ArchiveSession(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaims()
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.POST("/sessions/:id/archive", handler.ArchiveSession)

	// 创建测试会话
	testSession := createTestSession(t)

	req := httptest.NewRequest("POST", "/sessions/"+testSession.ID.String()+"/archive", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "status code should be 200")
	assert.Contains(t, w.Body.String(), "archived successfully", "should contain archive success message")
}

func TestSessionHandler_ListSessions(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaims()
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.GET("/sessions", handler.ListSessions)

	tests := []struct {
		name        string
		queryParams string
		expectCode  int
	}{
		{
			name:        "default parameters",
			queryParams: "",
			expectCode:  http.StatusOK,
		},
		{
			name:        "with pagination",
			queryParams: "?page=1&page_size=10",
			expectCode:  http.StatusOK,
		},
		{
			name:        "with status filter",
			queryParams: "?status=active",
			expectCode:  http.StatusOK,
		},
		{
			name:        "with search query",
			queryParams: "?query=test",
			expectCode:  http.StatusOK,
		},
		{
			name:        "invalid parameters",
			queryParams: "?page_size=abc",
			expectCode:  http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/sessions"+tt.queryParams, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectCode, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")
				assert.Contains(t, response, "data", "should contain data field")
				assert.Contains(t, response, "pagination", "should contain pagination field")
			}
		})
	}
}

func TestSessionHandler_CreateMessage(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaims()
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.POST("/sessions/:id/messages", handler.CreateMessage)

	// 创建测试会话
	testSession := createTestSession(t)

	tests := []struct {
		name           string
		sessionID      string
		requestBody    model.MessageCreateRequest
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:      "valid message creation",
			sessionID: testSession.ID.String(),
			requestBody: model.MessageCreateRequest{
				Role:    types.MessageRoleUser,
				Content: "Hello, assistant!",
			},
			expectedStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")
				assert.Equal(t, float64(http.StatusCreated), response["code"], "response code should match")
				assert.Contains(t, response, "data", "should contain data field")
			},
		},
		{
			name:      "empty content",
			sessionID: testSession.ID.String(),
			requestBody: model.MessageCreateRequest{
				Role:    types.MessageRoleUser,
				Content: "",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "request format", "should mention invalid format")
			},
		},
		{
			name:      "invalid session ID",
			sessionID: "invalid-uuid",
			requestBody: model.MessageCreateRequest{
				Role:    types.MessageRoleUser,
				Content: "Hello!",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid session ID", "should mention invalid ID")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.requestBody)
			require.NoError(t, err, "should marshal request body")

			req := httptest.NewRequest("POST", "/sessions/"+tt.sessionID+"/messages", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

func TestSessionHandler_ListMessages(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaims()
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.GET("/sessions/:id/messages", handler.ListMessages)

	// 创建测试会话
	testSession := createTestSession(t)

	tests := []struct {
		name        string
		sessionID   string
		queryParams string
		expectCode  int
	}{
		{
			name:        "valid session messages",
			sessionID:   testSession.ID.String(),
			queryParams: "",
			expectCode:  http.StatusOK,
		},
		{
			name:        "with pagination",
			sessionID:   testSession.ID.String(),
			queryParams: "?page=1&page_size=10",
			expectCode:  http.StatusOK,
		},
		{
			name:        "with role filter",
			sessionID:   testSession.ID.String(),
			queryParams: "?role=user",
			expectCode:  http.StatusOK,
		},
		{
			name:        "invalid session ID",
			sessionID:   "invalid-uuid",
			queryParams: "",
			expectCode:  http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/sessions/"+tt.sessionID+"/messages"+tt.queryParams, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectCode, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")
				assert.Contains(t, response, "data", "should contain data field")
				assert.Contains(t, response, "pagination", "should contain pagination field")
			}
		})
	}
}

func TestSessionHandler_GetMessage(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaims()
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.GET("/messages/:messageId", handler.GetMessage)

	// 创建测试消息
	testMessage := createTestMessage(t)

	tests := []struct {
		name           string
		messageID      string
		expectedStatus int
	}{
		{
			name:           "valid message ID",
			messageID:      testMessage.ID.String(),
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid message ID",
			messageID:      "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "nonexistent message",
			messageID:      uuid.New().String(),
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/messages/"+tt.messageID, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")
				assert.Contains(t, response, "data", "should contain data field")
			}
		})
	}
}

func TestSessionHandler_GetConversationContext(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaims()
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.GET("/sessions/:id/context", handler.GetConversationContext)

	// 创建测试会话
	testSession := createTestSession(t)

	tests := []struct {
		name        string
		sessionID   string
		queryParams string
		expectCode  int
	}{
		{
			name:        "default limit",
			sessionID:   testSession.ID.String(),
			queryParams: "",
			expectCode:  http.StatusOK,
		},
		{
			name:        "custom limit",
			sessionID:   testSession.ID.String(),
			queryParams: "?limit=5",
			expectCode:  http.StatusOK,
		},
		{
			name:        "invalid session ID",
			sessionID:   "invalid-uuid",
			queryParams: "",
			expectCode:  http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/sessions/"+tt.sessionID+"/context"+tt.queryParams, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectCode, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")
				assert.Contains(t, response, "data", "should contain data field")
			}
		})
	}
}

func TestSessionHandler_GetSessionStats(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaims()
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.GET("/sessions/stats", handler.GetSessionStats)

	req := httptest.NewRequest("GET", "/sessions/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "status code should be 200")

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err, "response should be valid JSON")
	assert.Contains(t, response, "data", "should contain data field")
}

func TestSessionHandler_SearchSessions(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	router.GET("/admin/sessions/search", handler.SearchSessions)

	tests := []struct {
		name        string
		queryParams string
		expectCode  int
	}{
		{
			name:        "search all sessions",
			queryParams: "",
			expectCode:  http.StatusOK,
		},
		{
			name:        "search with query",
			queryParams: "?query=test",
			expectCode:  http.StatusOK,
		},
		{
			name:        "search with user filter",
			queryParams: "?user_id=" + uuid.New().String(),
			expectCode:  http.StatusOK,
		},
		{
			name:        "invalid parameters",
			queryParams: "?page_size=abc",
			expectCode:  http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/admin/sessions/search"+tt.queryParams, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectCode, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")
				assert.Contains(t, response, "data", "should contain data field")
				assert.Contains(t, response, "pagination", "should contain pagination field")
			}
		})
	}
}

// 测试辅助函数

// createTestClaims 创建测试用的JWT claims
func createTestClaims() *auth.Claims {
	return &auth.Claims{
		UserID:   uuid.New(),
		Username: "testuser",
		Email:    "test@example.com",
		Roles:    []string{"user"},
		Permissions: []string{
			"chat:create", "chat:read", "chat:update", "chat:delete",
		},
	}
}

// createTestSession 创建测试会话
func createTestSession(t *testing.T) *model.Session {
	claims := createTestClaims()
	sessionService := service.NewSessionService()

	createReq := model.SessionCreateRequest{
		Title:        "Test Session",
		SystemPrompt: "You are a helpful assistant",
		Metadata: map[string]interface{}{
			"model": "gpt-3.5-turbo",
		},
	}

	session, err := sessionService.CreateSession(context.Background(), claims.UserID, createReq)
	require.NoError(t, err, "should create test session")

	return &model.Session{
		ID:           session.ID,
		UserID:       session.UserID,
		Title:        session.Title,
		SystemPrompt: session.SystemPrompt,
		Status:       types.SessionStatusActive,
	}
}

// createTestMessage 创建测试消息
func createTestMessage(t *testing.T) *model.Message {
	testSession := createTestSession(t)
	messageService := service.NewMessageService()

	createReq := model.MessageCreateRequest{
		Role:    types.MessageRoleUser,
		Content: "Hello, assistant!",
	}

	message, err := messageService.CreateMessage(context.Background(), testSession.UserID, testSession.ID, createReq)
	require.NoError(t, err, "should create test message")

	return &model.Message{
		ID:        message.ID,
		SessionID: testSession.ID,
		Role:      types.MessageRoleUser,
		Content:   "Hello, assistant!",
	}
}

// createLongString 创建指定长度的字符串
func createLongString(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = 'a'
	}
	return string(result)
}

// setupSessionHandlerTestEnv 设置会话处理器测试环境
func setupSessionHandlerTestEnv(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	// 初始化数据库连接
	err = database.Init(&cfg.Database)
	require.NoError(t, err, "failed to init database")

	// 初始化Redis连接
	err = cache.Init(&cfg.Redis)
	require.NoError(t, err, "failed to init cache")
}
