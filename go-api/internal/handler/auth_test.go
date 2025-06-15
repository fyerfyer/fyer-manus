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

	"github.com/fyerfyer/fyer-manus/go-api/internal/middleware"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/fyerfyer/fyer-manus/go-api/testutils"
	"github.com/google/uuid"
)

func TestNewAuthHandler(t *testing.T) {
	setupAuthHandlerTestEnv(t)
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

	tests := []struct {
		name           string
		setupUser      func(*testing.T) *TestAuthUser
		requestBody    service.LoginRequest
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "valid login with username",
			setupUser: func(t *testing.T) *TestAuthUser {
				return createTestAuthUser(t)
			},
			requestBody: service.LoginRequest{
				// Username will be set in test execution
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
			setupUser: func(t *testing.T) *TestAuthUser {
				return createTestAuthUser(t)
			},
			requestBody: service.LoginRequest{
				// Username will be set to email in test execution
				Password: "password123",
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "access_token", "should contain access token")
			},
		},
		{
			name: "invalid password",
			setupUser: func(t *testing.T) *TestAuthUser {
				return createTestAuthUser(t)
			},
			requestBody: service.LoginRequest{
				// Username will be set in test execution
				Password: "wrongpassword",
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid", "should mention invalid credentials")
			},
		},
		{
			name: "nonexistent user",
			setupUser: func(t *testing.T) *TestAuthUser {
				// Return a dummy user that won't be created
				return &TestAuthUser{
					ID:       uuid.New(),
					Username: "nonexistentuser",
					Email:    "nonexistent@example.com",
				}
			},
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
			setupUser: func(t *testing.T) *TestAuthUser {
				return createTestAuthUser(t)
			},
			requestBody: service.LoginRequest{
				// Username will be set in test execution
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "request format", "should mention invalid format")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testUser *TestAuthUser
			if tt.setupUser != nil {
				testUser = tt.setupUser(t)
				if tt.name != "nonexistent user" {
					defer cleanupTestAuthUser(t, testUser.ID)

					// Set username in request for existing user tests
					if tt.requestBody.Username == "" {
						if tt.name == "valid login with email" {
							tt.requestBody.Username = testUser.Email
						} else {
							tt.requestBody.Username = testUser.Username
						}
					}
				}
			}

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

	tests := []struct {
		name           string
		setupTokens    func(*testing.T) (*TestAuthUser, *UserAuthTokens)
		refreshToken   string
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "valid refresh token",
			setupTokens: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				testUser := createTestAuthUser(t)
				tokens := loginTestAuthUser(t, testUser)
				return testUser, tokens
			},
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
			name: "invalid refresh token",
			setupTokens: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				return nil, nil // No setup needed for invalid token test
			},
			refreshToken:   "invalid.token.here",
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid", "should mention invalid token")
			},
		},
		{
			name: "empty refresh token",
			setupTokens: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				return nil, nil // No setup needed for empty token test
			},
			refreshToken:   "",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "request format", "should mention invalid format")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testUser *TestAuthUser
			var tokens *UserAuthTokens

			if tt.setupTokens != nil {
				testUser, tokens = tt.setupTokens(t)
				if testUser != nil {
					defer cleanupTestAuthUser(t, testUser.ID)
				}
			}

			refreshToken := tt.refreshToken
			if tokens != nil && refreshToken == "" {
				refreshToken = tokens.RefreshToken
			}

			requestBody := service.RefreshTokenRequest{
				RefreshToken: refreshToken,
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

	tests := []struct {
		name           string
		setupTokens    func(*testing.T) (*TestAuthUser, *UserAuthTokens)
		useTokens      bool
		expectedStatus int
	}{
		{
			name: "logout with both tokens",
			setupTokens: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				testUser := createTestAuthUser(t)
				tokens := loginTestAuthUser(t, testUser)
				return testUser, tokens
			},
			useTokens:      true,
			expectedStatus: http.StatusOK,
		},
		{
			name: "logout with only access token",
			setupTokens: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				testUser := createTestAuthUser(t)
				tokens := loginTestAuthUser(t, testUser)
				return testUser, tokens
			},
			useTokens:      true,
			expectedStatus: http.StatusOK,
		},
		{
			name: "logout without tokens",
			setupTokens: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				return nil, nil
			},
			useTokens:      false,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testUser *TestAuthUser
			var tokens *UserAuthTokens

			if tt.setupTokens != nil {
				testUser, tokens = tt.setupTokens(t)
				if testUser != nil {
					defer cleanupTestAuthUser(t, testUser.ID)
				}
			}

			var requestBody map[string]string
			req := httptest.NewRequest("POST", "/logout", nil)

			if tt.useTokens && tokens != nil {
				// Set Authorization header
				req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

				// Set refresh token in body for "both tokens" test
				if tt.name == "logout with both tokens" {
					requestBody = map[string]string{
						"refresh_token": tokens.RefreshToken,
					}
					body, _ := json.Marshal(requestBody)
					req = httptest.NewRequest("POST", "/logout", bytes.NewBuffer(body))
					req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
					req.Header.Set("Content-Type", "application/json")
				}
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")
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

	tests := []struct {
		name           string
		setupUser      func(*testing.T) (*TestAuthUser, *UserAuthTokens)
		token          string
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder, *TestAuthUser)
	}{
		{
			name: "valid token",
			setupUser: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				testUser := createTestAuthUser(t)
				tokens := loginTestAuthUser(t, testUser)
				return testUser, tokens
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder, testUser *TestAuthUser) {
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
			name: "missing token",
			setupUser: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				return nil, nil
			},
			token:          "",
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder, testUser *TestAuthUser) {
				assert.Contains(t, w.Body.String(), "authentication required", "should mention authentication required")
			},
		},
		{
			name: "invalid token",
			setupUser: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				return nil, nil
			},
			token:          "invalid.token.here",
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder, testUser *TestAuthUser) {
				assert.Contains(t, w.Body.String(), "invalid", "should mention invalid token")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testUser *TestAuthUser
			var tokens *UserAuthTokens

			if tt.setupUser != nil {
				testUser, tokens = tt.setupUser(t)
				if testUser != nil {
					defer cleanupTestAuthUser(t, testUser.ID)
				}
			}

			req := httptest.NewRequest("GET", "/profile", nil)

			// Set token from setup or use provided token
			if tokens != nil && tokens.AccessToken != "" {
				req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			} else if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")

			if tt.checkResponse != nil {
				tt.checkResponse(t, w, testUser)
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

	tests := []struct {
		name           string
		setupUser      func(*testing.T) (*TestAuthUser, *UserAuthTokens)
		token          string
		requestBody    map[string]string
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "valid password change",
			setupUser: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				testUser := createTestAuthUser(t)
				tokens := loginTestAuthUser(t, testUser)
				return testUser, tokens
			},
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
			name: "wrong old password",
			setupUser: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				testUser := createTestAuthUser(t)
				tokens := loginTestAuthUser(t, testUser)
				return testUser, tokens
			},
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
			name: "new password too short",
			setupUser: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				testUser := createTestAuthUser(t)
				tokens := loginTestAuthUser(t, testUser)
				return testUser, tokens
			},
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
			name: "missing token",
			setupUser: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				return nil, nil
			},
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
			var testUser *TestAuthUser
			var tokens *UserAuthTokens

			if tt.setupUser != nil {
				testUser, tokens = tt.setupUser(t)
				if testUser != nil {
					defer cleanupTestAuthUser(t, testUser.ID)
				}
			}

			body, err := json.Marshal(tt.requestBody)
			require.NoError(t, err, "should marshal request body")

			req := httptest.NewRequest("POST", "/change-password", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			// Set token from setup or use provided token
			if tokens != nil && tokens.AccessToken != "" {
				req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			} else if tt.token != "" {
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

	tests := []struct {
		name           string
		setupUser      func(*testing.T) (*TestAuthUser, *UserAuthTokens)
		token          string
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "valid token",
			setupUser: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				testUser := createTestAuthUser(t)
				tokens := loginTestAuthUser(t, testUser)
				return testUser, tokens
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")
				assert.Contains(t, response["message"], "valid", "should mention token is valid")

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "should have data field")
				assert.Contains(t, data, "user_id", "should contain user_id")
				assert.Contains(t, data, "username", "should contain username")
			},
		},
		{
			name: "invalid token",
			setupUser: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				return nil, nil
			},
			token:          "invalid.token.here",
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid", "should mention invalid token")
			},
		},
		{
			name: "missing authorization header",
			setupUser: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				return nil, nil
			},
			token:          "",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "authorization header required", "should mention missing header")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testUser *TestAuthUser
			var tokens *UserAuthTokens

			if tt.setupUser != nil {
				testUser, tokens = tt.setupUser(t)
				if testUser != nil {
					defer cleanupTestAuthUser(t, testUser.ID)
				}
			}

			req := httptest.NewRequest("POST", "/validate", nil)

			// Set token from setup or use provided token
			if tokens != nil && tokens.AccessToken != "" {
				req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			} else if tt.token != "" {
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

	tests := []struct {
		name           string
		setupUser      func(*testing.T) *TestAuthUser
		userID         string
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "valid user ID",
			setupUser: func(t *testing.T) *TestAuthUser {
				return createTestAuthUser(t)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "response should be valid JSON")

				data, ok := response["data"].(map[string]interface{})
				assert.True(t, ok, "should have data field")
				assert.Contains(t, data, "username", "should contain username")
				assert.Contains(t, data, "email", "should contain email")
			},
		},
		{
			name: "invalid user ID format",
			setupUser: func(t *testing.T) *TestAuthUser {
				return nil
			},
			userID:         "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid user ID", "should mention invalid ID format")
			},
		},
		{
			name: "nonexistent user ID",
			setupUser: func(t *testing.T) *TestAuthUser {
				return nil
			},
			userID:         uuid.New().String(),
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "not found", "should mention user not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testUser *TestAuthUser

			if tt.setupUser != nil {
				testUser = tt.setupUser(t)
				if testUser != nil {
					defer cleanupTestAuthUser(t, testUser.ID)
				}
			}

			userID := tt.userID
			if userID == "" && testUser != nil {
				userID = testUser.ID.String()
			}

			req := httptest.NewRequest("GET", "/users/"+userID, nil)
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

	tests := []struct {
		name           string
		setupUser      func(*testing.T) (*TestAuthUser, *UserAuthTokens)
		token          string
		expectedStatus int
	}{
		{
			name: "authenticated request",
			setupUser: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				testUser := createTestAuthUser(t)
				tokens := loginTestAuthUser(t, testUser)
				return testUser, tokens
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "unauthenticated request",
			setupUser: func(t *testing.T) (*TestAuthUser, *UserAuthTokens) {
				return nil, nil
			},
			token:          "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testUser *TestAuthUser
			var tokens *UserAuthTokens

			if tt.setupUser != nil {
				testUser, tokens = tt.setupUser(t)
				if testUser != nil {
					defer cleanupTestAuthUser(t, testUser.ID)
				}
			}

			req := httptest.NewRequest("GET", "/test-auth", nil)

			// Set token from setup or use provided token
			if tokens != nil && tokens.AccessToken != "" {
				req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			} else if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match expected")
		})
	}
}

// 测试辅助函数

// UserAuthTokens 存储用户的token信息
type UserAuthTokens struct {
	AccessToken  string
	RefreshToken string
}

// TestAuthUser 测试用户结构
type TestAuthUser struct {
	ID       uuid.UUID
	Username string
	Email    string
}

// setupAuthHandlerTestEnv 设置认证处理器测试环境
func setupAuthHandlerTestEnv(t *testing.T) {
	_ = testutils.SetupTestEnv(t)
}

// createTestAuthUser 为认证测试创建用户
func createTestAuthUser(t *testing.T) *TestAuthUser {
	manager := testutils.NewTestDBManager(t)

	username := testutils.GenerateTestUsername(t)
	email := testutils.GenerateTestEmail(t)

	userID := manager.CreateTestUser(t, username, email)

	return &TestAuthUser{
		ID:       userID,
		Username: username,
		Email:    email,
	}
}

// cleanupTestAuthUser 清理认证测试用户
func cleanupTestAuthUser(t *testing.T, userID uuid.UUID) {
	manager := testutils.NewTestDBManager(t)
	manager.CleanupUser(t, userID)
}

// loginTestAuthUser 登录测试用户并返回tokens
func loginTestAuthUser(t *testing.T, user *TestAuthUser) *UserAuthTokens {
	authService := service.NewAuthService()

	loginReq := service.LoginRequest{
		Username: user.Username,
		Password: "password123",
	}

	response, err := authService.Login(loginReq)
	require.NoError(t, err, "should login test auth user")

	return &UserAuthTokens{
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
	}
}
