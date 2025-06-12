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

	"github.com/fyerfyer/fyer-manus/go-api/internal/cache"
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/middleware"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/google/uuid"
)

func TestNewAuthHandler(t *testing.T) {
	handler := NewAuthHandler()
	assert.NotNil(t, handler, "auth handler should not be nil")
	assert.NotNil(t, handler.authService, "auth service should not be nil")
}

func TestRegister(t *testing.T) {
	// 初始化测试环境
	setupAuthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewAuthHandler()
	router.POST("/register", handler.Register)

	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "valid registration",
			requestBody: service.RegisterRequest{
				Username: "testuser" + uuid.New().String()[:8],
				Email:    "test" + uuid.New().String()[:8] + "@example.com",
				Password: "password123",
				FullName: "Test User",
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
			name: "invalid email format",
			requestBody: service.RegisterRequest{
				Username: "testuser",
				Email:    "invalid-email",
				Password: "password123",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")
				assert.Equal(t, float64(http.StatusBadRequest), response["code"], "should be bad request")
			},
		},
		{
			name: "password too short",
			requestBody: service.RegisterRequest{
				Username: "testuser",
				Email:    "test@example.com",
				Password: "123",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "request format", "should mention invalid format")
			},
		},
		{
			name: "missing required fields",
			requestBody: map[string]interface{}{
				"username": "testuser",
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

			req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
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

func TestLogin(t *testing.T) {
	// 初始化测试环境
	setupAuthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewAuthHandler()
	router.POST("/login", handler.Login)

	// 先创建一个测试用户
	testUser := createTestUser(t)

	tests := []struct {
		name           string
		requestBody    service.LoginRequest
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "valid login with username",
			requestBody: service.LoginRequest{
				Username: testUser.Username,
				Password: "password123",
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "should have data field")
				assert.Contains(t, data, "access_token", "should contain access token")
				assert.Contains(t, data, "refresh_token", "should contain refresh token")
				assert.Equal(t, "Bearer", data["token_type"], "token type should be Bearer")
			},
		},
		{
			name: "valid login with email",
			requestBody: service.LoginRequest{
				Username: testUser.Email,
				Password: "password123",
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "access_token", "should contain access token")
			},
		},
		{
			name: "invalid password",
			requestBody: service.LoginRequest{
				Username: testUser.Username,
				Password: "wrongpassword",
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid", "should mention invalid credentials")
			},
		},
		{
			name: "nonexistent user",
			requestBody: service.LoginRequest{
				Username: "nonexistentuser",
				Password: "password123",
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid", "should mention invalid credentials")
			},
		},
		{
			name: "missing password",
			requestBody: service.LoginRequest{
				Username: testUser.Username,
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

			req := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
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

func TestRefreshToken(t *testing.T) {
	// 初始化测试环境
	setupAuthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewAuthHandler()
	router.POST("/refresh", handler.RefreshToken)

	// 创建测试用户并获取tokens
	testUser := createTestUser(t)
	tokens := loginTestUser(t, testUser)

	tests := []struct {
		name           string
		refreshToken   string
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:           "valid refresh token",
			refreshToken:   tokens.RefreshToken,
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "should have data field")
				assert.Contains(t, data, "access_token", "should contain new access token")
				assert.Contains(t, data, "refresh_token", "should contain new refresh token")
			},
		},
		{
			name:           "invalid refresh token",
			refreshToken:   "invalid.token.here",
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid", "should mention invalid token")
			},
		},
		{
			name:           "empty refresh token",
			refreshToken:   "",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "request format", "should mention invalid format")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestBody := service.RefreshTokenRequest{
				RefreshToken: tt.refreshToken,
			}
			body, err := json.Marshal(requestBody)
			require.NoError(t, err, "should marshal request body")

			req := httptest.NewRequest("POST", "/refresh", bytes.NewBuffer(body))
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

func TestLogout(t *testing.T) {
	// 初始化测试环境
	setupAuthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewAuthHandler()
	router.POST("/logout", handler.Logout)

	// 创建测试用户并获取tokens
	testUser := createTestUser(t)
	tokens := loginTestUser(t, testUser)

	tests := []struct {
		name           string
		accessToken    string
		refreshToken   string
		expectedStatus int
	}{
		{
			name:           "logout with both tokens",
			accessToken:    tokens.AccessToken,
			refreshToken:   tokens.RefreshToken,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "logout with only access token",
			accessToken:    tokens.AccessToken,
			refreshToken:   "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "logout without tokens",
			accessToken:    "",
			refreshToken:   "",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestBody := map[string]string{
				"refresh_token": tt.refreshToken,
			}
			body, err := json.Marshal(requestBody)
			require.NoError(t, err, "should marshal request body")

			req := httptest.NewRequest("POST", "/logout", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			if tt.accessToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.accessToken)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				assert.Contains(t, w.Body.String(), "successfully", "should contain success message")
			}
		})
	}
}

func TestGetProfile(t *testing.T) {
	// 初始化测试环境
	setupAuthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.Auth()) // 添加认证中间件
	handler := NewAuthHandler()
	router.GET("/profile", handler.GetProfile)

	// 创建测试用户并获取token
	testUser := createTestUser(t)
	tokens := loginTestUser(t, testUser)

	tests := []struct {
		name           string
		token          string
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:           "valid token",
			token:          tokens.AccessToken,
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "should have data field")
				assert.Equal(t, testUser.Username, data["username"], "username should match")
				assert.Equal(t, testUser.Email, data["email"], "email should match")
			},
		},
		{
			name:           "missing token",
			token:          "",
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "authentication", "should mention authentication required")
			},
		},
		{
			name:           "invalid token",
			token:          "invalid.token.here",
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid", "should mention invalid token")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/profile", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

func TestChangePassword(t *testing.T) {
	// 初始化测试环境
	setupAuthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.Auth())
	handler := NewAuthHandler()
	router.POST("/change-password", handler.ChangePassword)

	// 创建测试用户并获取token
	testUser := createTestUser(t)
	tokens := loginTestUser(t, testUser)

	tests := []struct {
		name           string
		token          string
		requestBody    map[string]string
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:  "valid password change",
			token: tokens.AccessToken,
			requestBody: map[string]string{
				"old_password": "password123",
				"new_password": "newpassword123",
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "successfully", "should contain success message")
			},
		},
		{
			name:  "wrong old password",
			token: tokens.AccessToken,
			requestBody: map[string]string{
				"old_password": "wrongpassword",
				"new_password": "newpassword123",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid", "should mention invalid old password")
			},
		},
		{
			name:  "new password too short",
			token: tokens.AccessToken,
			requestBody: map[string]string{
				"old_password": "password123",
				"new_password": "123",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "request format", "should mention invalid format")
			},
		},
		{
			name:           "missing token",
			token:          "",
			requestBody:    map[string]string{"old_password": "old", "new_password": "new123"},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "authentication", "should mention authentication required")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.requestBody)
			require.NoError(t, err, "should marshal request body")

			req := httptest.NewRequest("POST", "/change-password", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	// 初始化测试环境
	setupAuthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewAuthHandler()
	router.POST("/validate", handler.ValidateToken)

	// 创建测试用户并获取token
	testUser := createTestUser(t)
	tokens := loginTestUser(t, testUser)

	tests := []struct {
		name           string
		token          string
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:           "valid token",
			token:          tokens.AccessToken,
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")
				assert.Contains(t, response["message"], "valid", "should mention token is valid")

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "should have data field")
				assert.Equal(t, testUser.ID.String(), data["user_id"], "user ID should match")
			},
		},
		{
			name:           "invalid token",
			token:          "invalid.token.here",
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid", "should mention invalid token")
			},
		},
		{
			name:           "missing authorization header",
			token:          "",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "authorization header", "should mention missing header")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/validate", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

func TestGetUserByID(t *testing.T) {
	// 初始化测试环境
	setupAuthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewAuthHandler()
	router.GET("/users/:id", handler.GetUserByID)

	// 创建测试用户
	testUser := createTestUser(t)

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

func TestTestAuth(t *testing.T) {
	// 初始化测试环境
	setupAuthHandlerTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.Auth())
	handler := NewAuthHandler()
	router.GET("/test-auth", handler.TestAuth)

	// 创建测试用户并获取token
	testUser := createTestUser(t)
	tokens := loginTestUser(t, testUser)

	tests := []struct {
		name           string
		token          string
		expectedStatus int
	}{
		{
			name:           "authenticated request",
			token:          tokens.AccessToken,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "unauthenticated request",
			token:          "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test-auth", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")

			if w.Code == http.StatusOK {
				assert.Contains(t, w.Body.String(), "authentication successful", "should contain success message")
			} else {
				assert.Contains(t, w.Body.String(), "not authenticated", "should mention not authenticated")
			}
		})
	}
}

// 测试辅助函数

// UserTokens 存储用户的token信息
type UserTokens struct {
	AccessToken  string
	RefreshToken string
}

// createTestUser 创建测试用户
func createTestUser(t *testing.T) *TestUser {
	userService := service.NewUserService()

	username := "testuser" + uuid.New().String()[:8]
	email := "test" + uuid.New().String()[:8] + "@example.com"

	createReq := service.CreateUserRequest{
		Username: username,
		Email:    email,
		Password: "password123",
		FullName: "Test User",
	}

	profile, err := userService.CreateUser(context.Background(), createReq)
	require.NoError(t, err, "should create test user")

	return &TestUser{
		ID:       profile.ID,
		Username: username,
		Email:    email,
	}
}

// TestUser 测试用户结构
type TestUser struct {
	ID       uuid.UUID
	Username string
	Email    string
}

// loginTestUser 登录测试用户并返回tokens
func loginTestUser(t *testing.T, user *TestUser) *UserTokens {
	authService := service.NewAuthService()

	loginReq := service.LoginRequest{
		Username: user.Username,
		Password: "password123",
	}

	response, err := authService.Login(loginReq)
	require.NoError(t, err, "should login test user")

	return &UserTokens{
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
	}
}

// setupAuthHandlerTestEnv 设置认证处理器测试环境
func setupAuthHandlerTestEnv(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	// 初始化数据库连接
	err = database.Init(&cfg.Database)
	require.NoError(t, err, "failed to init database")

	// 初始化Redis连接
	err = cache.Init(&cfg.Redis)
	require.NoError(t, err, "failed to init cache")
}
