package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/fyerfyer/fyer-manus/go-api/internal/auth"
	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/middleware"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/fyerfyer/fyer-manus/go-api/testutils"
	"github.com/google/uuid"
)

func TestNewUserHandler(t *testing.T) {
	setupUserHandlerTestEnv(t)
	handler := NewUserHandler()
	assert.NotNil(t, handler, "user handler should not be nil")
	assert.NotNil(t, handler.userService, "user service should not be nil")
}

func TestUserHandler_GetProfile(t *testing.T) {
	// 初始化测试环境
	setupUserHandlerTestEnv(t)

	// 创建测试用户
	testUser := createTestUserForTest(t)
	defer cleanupTestUser(t, testUser.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewUserHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestUserClaimsForUser(testUser)
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.GET("/profile", handler.GetProfile)

	req := httptest.NewRequest("GET", "/profile", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "should return 200")
	assert.Contains(t, w.Body.String(), "profile retrieved successfully", "should contain success message")
	assert.Contains(t, w.Body.String(), "data", "should contain data field")

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err, "response should be valid JSON")

	data, ok := response["data"].(map[string]interface{})
	assert.True(t, ok, "should have data field")
	assert.Equal(t, testUser.Username, data["username"], "username should match")
}

func TestUserHandler_UpdateProfile(t *testing.T) {
	// 初始化测试环境
	setupUserHandlerTestEnv(t)

	// 创建测试用户
	testUser := createTestUserForTest(t)
	defer cleanupTestUser(t, testUser.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewUserHandler()

	// 添加认证中间件
	router.Use(func(c *gin.Context) {
		claims := createTestUserClaimsForUser(testUser)
		c.Set(middleware.ClaimsContextKey, claims)
		c.Next()
	})

	router.PUT("/profile", handler.UpdateProfile)

	tests := []struct {
		name           string
		requestBody    service.UpdateUserRequest
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "valid profile update",
			requestBody: service.UpdateUserRequest{
				FullName:  "Updated Test User",
				AvatarURL: "https://example.com/avatar.jpg",
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "updated successfully", "should contain success message")

				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "should have data field")
				assert.Equal(t, "Updated Test User", data["full_name"], "full name should be updated")
			},
		},
		{
			name: "empty update",
			requestBody: service.UpdateUserRequest{
				FullName:  "",
				AvatarURL: "",
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "updated successfully", "should contain success message")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.requestBody)
			require.NoError(t, err, "should marshal request body")

			req := httptest.NewRequest("PUT", "/profile", bytes.NewBuffer(body))
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

func TestUserHandler_ChangePassword(t *testing.T) {
	// 初始化测试环境
	setupUserHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewUserHandler()

	tests := []struct {
		name           string
		requestBody    service.ChangePasswordRequest
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "valid password change",
			requestBody: service.ChangePasswordRequest{
				OldPassword: "password123",
				NewPassword: "newpassword123",
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "successfully", "should contain success message")
			},
		},
		{
			name: "wrong old password",
			requestBody: service.ChangePasswordRequest{
				OldPassword: "wrongpassword",
				NewPassword: "newpassword123",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid", "should mention invalid old password")
			},
		},
		{
			name: "password too short",
			requestBody: service.ChangePasswordRequest{
				OldPassword: "password123",
				NewPassword: "123",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "request format", "should mention invalid format")
			},
		},
		{
			name: "missing old password",
			requestBody: service.ChangePasswordRequest{
				OldPassword: "",
				NewPassword: "newpassword123",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "request format", "should mention invalid format")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 为每个测试创建独立的用户
			testUser := createTestUserForTest(t)
			defer cleanupTestUser(t, testUser.ID)

			// 为这个用户设置认证中间件
			router.Use(func(c *gin.Context) {
				claims := createTestUserClaimsForUser(testUser)
				c.Set(middleware.ClaimsContextKey, claims)
				c.Next()
			})

			router.POST("/change-password", handler.ChangePassword)

			body, err := json.Marshal(tt.requestBody)
			require.NoError(t, err, "should marshal request body")

			req := httptest.NewRequest("POST", "/change-password", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}

			// 重置路由器为下一个测试
			router = gin.New()
		})
	}
}

func TestUserHandler_GetUserByID(t *testing.T) {
	// 初始化测试环境
	setupUserHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewUserHandler()

	router.GET("/users/:id", handler.GetUserByID)

	// 创建测试用户
	testUser := createTestUserForTest(t)
	defer cleanupTestUser(t, testUser.ID)

	tests := []struct {
		name           string
		userID         string
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:           "valid user ID",
			userID:         testUser.ID.String(),
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "should have data field")
				assert.Equal(t, testUser.Username, data["username"], "username should match")
			},
		},
		{
			name:           "invalid user ID format",
			userID:         "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid user ID", "should mention invalid ID format")
			},
		},
		{
			name:           "nonexistent user ID",
			userID:         uuid.New().String(),
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "not found", "should mention user not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/users/"+tt.userID, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

func TestUserHandler_ListUsers(t *testing.T) {
	// 初始化测试环境
	setupUserHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewUserHandler()

	router.GET("/users", handler.ListUsers)

	// 创建一些测试用户
	testUsers := make([]*TestUserData, 3)
	for i := 0; i < 3; i++ {
		testUsers[i] = createTestUserForTest(t)
		defer cleanupTestUser(t, testUsers[i].ID)
	}

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
			name:        "with large page size",
			queryParams: "?page_size=200",
			expectCode:  http.StatusOK,
		},
		{
			name:        "with invalid page",
			queryParams: "?page=0",
			expectCode:  http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/users"+tt.queryParams, nil)
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

func TestUserHandler_SearchUsers(t *testing.T) {
	// 初始化测试环境
	setupUserHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewUserHandler()

	router.GET("/users/search", handler.SearchUsers)

	// 创建测试用户
	testUser := createTestUserForTest(t)
	defer cleanupTestUser(t, testUser.ID)

	tests := []struct {
		name        string
		queryParams string
		expectCode  int
	}{
		{
			name:        "valid search query",
			queryParams: "?q=" + testUser.Username,
			expectCode:  http.StatusOK,
		},
		{
			name:        "search with pagination",
			queryParams: "?q=" + testUser.Username + "&page=1&page_size=5",
			expectCode:  http.StatusOK,
		},
		{
			name:        "empty search query",
			queryParams: "",
			expectCode:  http.StatusBadRequest,
		},
		{
			name:        "search query with special characters",
			queryParams: "?q=" + testUser.Email,
			expectCode:  http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/users/search"+tt.queryParams, nil)
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

func TestUserHandler_UpdateUserStatus(t *testing.T) {
	// 初始化测试环境
	setupUserHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewUserHandler()

	router.PUT("/users/:id/status", handler.UpdateUserStatus)

	// 创建测试用户
	testUser := createTestUserForTest(t)
	defer cleanupTestUser(t, testUser.ID)

	tests := []struct {
		name           string
		userID         string
		requestBody    map[string]string
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:   "valid status update",
			userID: testUser.ID.String(),
			requestBody: map[string]string{
				"status": "active",
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "updated successfully", "should contain success message")
			},
		},
		{
			name:   "invalid status value",
			userID: testUser.ID.String(),
			requestBody: map[string]string{
				"status": "invalid_status",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "request format", "should mention invalid format")
			},
		},
		{
			name:           "invalid user ID",
			userID:         "invalid-uuid",
			requestBody:    map[string]string{"status": "active"},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid user ID", "should mention invalid ID format")
			},
		},
		{
			name:           "missing status field",
			userID:         testUser.ID.String(),
			requestBody:    map[string]string{},
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

			req := httptest.NewRequest("PUT", "/users/"+tt.userID+"/status", bytes.NewBuffer(body))
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

func TestUserHandler_DeleteUser(t *testing.T) {
	// 初始化测试环境
	setupUserHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewUserHandler()

	router.DELETE("/users/:id", handler.DeleteUser)

	tests := []struct {
		name           string
		userID         string
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:           "valid user deletion",
			userID:         "",
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "deleted successfully", "should contain success message")
			},
		},
		{
			name:           "invalid user ID",
			userID:         "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid user ID", "should mention invalid ID format")
			},
		},
		{
			name:           "nonexistent user",
			userID:         uuid.New().String(),
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "not found", "should mention user not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var userID string
			if tt.userID == "" {
				// 为删除测试创建临时用户
				tempUser := createTestUserForTest(t)
				userID = tempUser.ID.String()
			} else {
				userID = tt.userID
			}

			req := httptest.NewRequest("DELETE", "/users/"+userID, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

func TestUserHandler_GetUserStats(t *testing.T) {
	// 初始化测试环境
	setupUserHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewUserHandler()

	router.GET("/users/stats", handler.GetUserStats)

	req := httptest.NewRequest("GET", "/users/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "should return 200")
	assert.Contains(t, w.Body.String(), "retrieved successfully", "should contain success message")

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err, "response should be valid JSON")
	assert.Contains(t, response, "data", "should contain data field")
}

func TestUserHandler_NoAuth(t *testing.T) {
	// 测试没有认证中间件时的行为
	setupUserHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewUserHandler()

	// 不添加认证中间件
	router.GET("/profile", handler.GetProfile)
	router.PUT("/profile", handler.UpdateProfile)
	router.POST("/change-password", handler.ChangePassword)

	endpoints := []struct {
		method string
		path   string
		body   interface{}
	}{
		{"GET", "/profile", nil},
		{"PUT", "/profile", service.UpdateUserRequest{FullName: "Test"}},
		{"POST", "/change-password", service.ChangePasswordRequest{OldPassword: "old", NewPassword: "new123"}},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.method+" "+endpoint.path+" without auth", func(t *testing.T) {
			var req *http.Request
			if endpoint.body != nil {
				body, _ := json.Marshal(endpoint.body)
				req = httptest.NewRequest(endpoint.method, endpoint.path, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(endpoint.method, endpoint.path, nil)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code, "should return 401 without auth")
			assert.Contains(t, w.Body.String(), "authentication required", "should mention authentication required")
		})
	}
}

// 测试辅助函数

// TestUserData 测试用户数据结构
type TestUserData struct {
	ID       uuid.UUID
	Username string
	Email    string
}

// createTestUserForTest 为测试创建用户
func createTestUserForTest(t *testing.T) *TestUserData {
	manager := testutils.NewTestDBManager(t)

	username := testutils.GenerateTestUsername(t)
	email := testutils.GenerateTestEmail(t)

	userID := manager.CreateTestUser(t, username, email)

	return &TestUserData{
		ID:       userID,
		Username: username,
		Email:    email,
	}
}

// cleanupTestUser 清理测试用户
func cleanupTestUser(t *testing.T, userID uuid.UUID) {
	manager := testutils.NewTestDBManager(t)
	manager.CleanupUser(t, userID)
}

// createTestUserClaimsForUser 为指定用户创建测试用的JWT claims
func createTestUserClaimsForUser(userData *TestUserData) *auth.Claims {
	logger.Debug("createTestUserClaimsForUser: creating claims for test user",
		zap.String("user_id", userData.ID.String()),
		zap.String("username", userData.Username),
		zap.String("email", userData.Email),
	)

	return &auth.Claims{
		UserID:   userData.ID,
		Username: userData.Username,
		Email:    userData.Email,
		Roles:    []string{"user"},
		Permissions: []string{
			"user:read", "user:update",
		},
	}
}

// setupUserHandlerTestEnv 设置用户处理器测试环境
func setupUserHandlerTestEnv(t *testing.T) {
	_ = testutils.SetupTestEnv(t)
}
