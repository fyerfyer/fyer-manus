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
	"github.com/fyerfyer/fyer-manus/go-api/internal/middleware"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/fyerfyer/fyer-manus/go-api/internal/types"
	"github.com/fyerfyer/fyer-manus/go-api/testutils"
	"github.com/google/uuid"
)

func TestNewSessionHandler(t *testing.T) {
	setupSessionHandlerTestEnv(t)
	handler := NewSessionHandler()
	assert.NotNil(t, handler, "session handler should not be nil")
	assert.NotNil(t, handler.sessionService, "session service should not be nil")
	assert.NotNil(t, handler.messageService, "message service should not be nil")
}

func TestSessionHandler_CreateSession(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	// 创建测试用户
	testUser := createTestUserForSessionHandler(t)
	defer cleanupTestUserForSessionHandler(t, testUser.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件，使用当前测试用户
	router.Use(func(c *gin.Context) {
		claims := createTestClaimsForUser(testUser)
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
				ModelName:    "gpt-3.5-turbo",
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

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "data should be a map")
				assert.Equal(t, "Test Session", data["title"], "title should match")
				assert.Equal(t, "gpt-3.5-turbo", data["model_name"], "model name should match")
			},
		},
		{
			name: "empty title should use default",
			requestBody: model.SessionCreateRequest{
				Title:        "",
				ModelName:    "gpt-3.5-turbo",
				SystemPrompt: "You are a helpful assistant",
			},
			expectedStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "data should be a map")
				assert.Equal(t, types.DefaultSessionTitle, data["title"], "should use default title")
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

	// 创建测试用户
	testUser := createTestUserForSessionHandler(t)
	defer cleanupTestUserForSessionHandler(t, testUser.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaimsForUser(testUser)
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.GET("/sessions/:id", handler.GetSession)

	// 创建测试会话
	testSession := createTestSessionForUser(t, testUser.ID)

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
				assert.True(t, ok, "data should be a map")
				assert.Equal(t, testSession.ID.String(), data["id"], "session ID should match")
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

	// 创建测试用户
	testUser := createTestUserForSessionHandler(t)
	defer cleanupTestUserForSessionHandler(t, testUser.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaimsForUser(testUser)
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.PUT("/sessions/:id", handler.UpdateSession)

	// 创建测试会话
	testSession := createTestSessionForUser(t, testUser.ID)

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

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "data should be a map")
				assert.Equal(t, "Updated Session Title", data["title"], "title should be updated")
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
				assert.Contains(t, w.Body.String(), "invalid session ID", "should mention invalid ID format")
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

	// 创建测试用户
	testUser := createTestUserForSessionHandler(t)
	defer cleanupTestUserForSessionHandler(t, testUser.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaimsForUser(testUser)
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.DELETE("/sessions/:id", handler.DeleteSession)

	tests := []struct {
		name           string
		sessionID      string
		expectedStatus int
	}{
		{
			name:           "valid session deletion",
			sessionID:      "",
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
			sessionID := tt.sessionID
			if sessionID == "" {
				// 为删除测试创建一个新的会话
				testSession := createTestSessionForUser(t, testUser.ID)
				sessionID = testSession.ID.String()
			}

			req := httptest.NewRequest("DELETE", "/sessions/"+sessionID, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")
		})
	}
}

func TestSessionHandler_ArchiveSession(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	// 创建测试用户
	testUser := createTestUserForSessionHandler(t)
	defer cleanupTestUserForSessionHandler(t, testUser.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaimsForUser(testUser)
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.POST("/sessions/:id/archive", handler.ArchiveSession)

	// 创建测试会话
	testSession := createTestSessionForUser(t, testUser.ID)

	req := httptest.NewRequest("POST", "/sessions/"+testSession.ID.String()+"/archive", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "status code should be 200")
	assert.Contains(t, w.Body.String(), "archived successfully", "should contain archive success message")
}

func TestSessionHandler_ListSessions(t *testing.T) {
	// 初始化测试环境
	setupSessionHandlerTestEnv(t)

	// 创建测试用户
	testUser := createTestUserForSessionHandler(t)
	defer cleanupTestUserForSessionHandler(t, testUser.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaimsForUser(testUser)
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

	// 创建测试用户
	testUser := createTestUserForSessionHandler(t)
	defer cleanupTestUserForSessionHandler(t, testUser.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaimsForUser(testUser)
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.POST("/sessions/:id/messages", handler.CreateMessage)

	// 创建测试会话
	testSession := createTestSessionForUser(t, testUser.ID)

	tests := []struct {
		name           string
		sessionID      string
		requestBody    model.MessageCreateRequest
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:      "valid message creation with default content type",
			sessionID: testSession.ID.String(),
			requestBody: model.MessageCreateRequest{
				Role:    types.MessageRoleUser,
				Content: "Hello, assistant!",
				// ContentType 省略，让它使用默认值
			},
			expectedStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "data should be a map")
				assert.Equal(t, "Hello, assistant!", data["content"], "content should match")
				assert.Equal(t, "text", data["content_type"], "should use default content type")
			},
		},
		{
			name:      "valid message creation with explicit content type",
			sessionID: testSession.ID.String(),
			requestBody: model.MessageCreateRequest{
				Role:        types.MessageRoleUser,
				Content:     "Here's some code",
				ContentType: types.MessageTypeCode, // 显式设置
			},
			expectedStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "data should be a map")
				assert.Equal(t, "code", data["content_type"], "should use explicit content type")
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
			name:      "invalid content type",
			sessionID: testSession.ID.String(),
			requestBody: model.MessageCreateRequest{
				Role:        types.MessageRoleUser,
				Content:     "Hello!",
				ContentType: types.MessageType("invalid"), // 无效的内容类型
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
				assert.Contains(t, w.Body.String(), "invalid session ID", "should mention invalid ID format")
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

	// 创建测试用户
	testUser := createTestUserForSessionHandler(t)
	defer cleanupTestUserForSessionHandler(t, testUser.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaimsForUser(testUser)
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.GET("/sessions/:id/messages", handler.ListMessages)

	// 创建测试会话
	testSession := createTestSessionForUser(t, testUser.ID)

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

	// 创建测试用户
	testUser := createTestUserForSessionHandler(t)
	defer cleanupTestUserForSessionHandler(t, testUser.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaimsForUser(testUser)
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.GET("/messages/:messageId", handler.GetMessage)

	// 创建测试消息
	testMessage := createTestMessageForUser(t, testUser.ID)

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

	// 创建测试用户
	testUser := createTestUserForSessionHandler(t)
	defer cleanupTestUserForSessionHandler(t, testUser.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaimsForUser(testUser)
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.GET("/sessions/:id/context", handler.GetConversationContext)

	// 创建测试会话
	testSession := createTestSessionForUser(t, testUser.ID)

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

	// 创建测试用户
	testUser := createTestUserForSessionHandler(t)
	defer cleanupTestUserForSessionHandler(t, testUser.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewSessionHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestClaimsForUser(testUser)
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

	// 创建测试用户
	testUser := createTestUserForSessionHandler(t)
	defer cleanupTestUserForSessionHandler(t, testUser.ID)

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
			queryParams: "?user_id=" + testUser.ID.String(),
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

// TestSessionUser 测试用户结构
type TestSessionUser struct {
	ID       uuid.UUID
	Username string
	Email    string
}

// createTestUserForSessionHandler 为会话处理器创建测试用户
func createTestUserForSessionHandler(t *testing.T) *TestSessionUser {
	manager := testutils.NewTestDBManager(t)

	username := testutils.GenerateTestUsername(t)
	email := testutils.GenerateTestEmail(t)

	userID := manager.CreateTestUser(t, username, email)

	return &TestSessionUser{
		ID:       userID,
		Username: username,
		Email:    email,
	}
}

// cleanupTestUserForSessionHandler 清理会话处理器的测试用户
func cleanupTestUserForSessionHandler(t *testing.T, userID uuid.UUID) {
	manager := testutils.NewTestDBManager(t)
	manager.CleanupUser(t, userID)
}

// createTestClaimsForUser 为指定用户创建测试用的JWT claims
func createTestClaimsForUser(userData *TestSessionUser) *auth.Claims {
	return &auth.Claims{
		UserID:   userData.ID,
		Username: userData.Username,
		Email:    userData.Email,
		Roles:    []string{"user"},
		Permissions: []string{
			"chat:create", "chat:read", "chat:update", "chat:delete",
		},
	}
}

// createTestSessionForUser 为指定用户创建测试会话
func createTestSessionForUser(t *testing.T, userID uuid.UUID) *model.Session {
	manager := testutils.NewTestDBManager(t)
	sessionID := manager.CreateTestSession(t, userID, "Test Session")

	return &model.Session{
		ID:           sessionID,
		UserID:       userID,
		Title:        "Test Session",
		SystemPrompt: "You are a helpful assistant",
		Status:       types.SessionStatusActive,
	}
}

// createTestMessageForUser 为指定用户创建测试消息
func createTestMessageForUser(t *testing.T, userID uuid.UUID) *model.Message {
	manager := testutils.NewTestDBManager(t)
	sessionID := manager.CreateTestSession(t, userID, "Test Session")

	messageService := service.NewMessageService()
	createReq := model.MessageCreateRequest{
		Role:    types.MessageRoleUser,
		Content: "Hello, assistant!",
	}

	message, err := messageService.CreateMessage(context.Background(), userID, sessionID, createReq)
	require.NoError(t, err, "should create test message")

	return &model.Message{
		ID:        message.ID,
		SessionID: sessionID,
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
	_ = testutils.SetupTestEnv(t)
}
