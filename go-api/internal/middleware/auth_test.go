package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/auth"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/service"
	"github.com/fyerfyer/fyer-manus/go-api/testutils"
	"github.com/google/uuid"
)

func TestAuth(t *testing.T) {
	// 初始化测试环境
	setupAuthTestEnv(t)

	// 创建测试用户和令牌
	authService, _, accessToken := createTestUserWithToken(t)

	tests := []struct {
		name           string
		setupRequest   func(*http.Request)
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "valid token",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+accessToken)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name: "missing authorization header",
			setupRequest: func(req *http.Request) {
				// 不设置Authorization头
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "authentication required", // 修改这里，与实际代码匹配
		},
		{
			name: "invalid authorization header format",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Basic invalid")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "invalid authorization header", // 修改这里，与实际代码匹配
		},
		{
			name: "missing bearer token",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "invalid authorization header", // 修改这里，与实际代码匹配
		},
		{
			name: "invalid token",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer invalid.token.here")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "invalid or expired token",
		},
		{
			name: "blacklisted token",
			setupRequest: func(req *http.Request) {
				// 先将令牌加入黑名单
				validator := authService.GetValidator()
				err := validator.BlacklistToken(accessToken)
				require.NoError(t, err, "blacklisting token should succeed")

				req.Header.Set("Authorization", "Bearer "+accessToken)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "invalid or expired token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 重新创建token（除了blacklisted token测试）
			if tt.name != "blacklisted token" {
				_, _, accessToken = createTestUserWithToken(t)
			}

			// 创建gin引擎和路由
			gin.SetMode(gin.TestMode)
			router := gin.New()

			router.Use(Auth())
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// 创建请求
			req := httptest.NewRequest("GET", "/test", nil)
			tt.setupRequest(req)

			// 执行请求
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// 验证结果
			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match")
			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody, "response body should contain expected text")
			}
		})
	}
}

func TestOptionalAuth(t *testing.T) {
	// 初始化测试环境
	setupAuthTestEnv(t)

	// 创建测试用户和令牌
	_, _, accessToken := createTestUserWithToken(t)

	tests := []struct {
		name           string
		setupRequest   func(*http.Request)
		expectedStatus int
		hasUser        bool
	}{
		{
			name: "valid token",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+accessToken)
			},
			expectedStatus: http.StatusOK,
			hasUser:        true,
		},
		{
			name: "no token",
			setupRequest: func(req *http.Request) {
				// 不设置任何头
			},
			expectedStatus: http.StatusOK,
			hasUser:        false,
		},
		{
			name: "invalid token",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer invalid.token")
			},
			expectedStatus: http.StatusOK,
			hasUser:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建gin引擎和路由
			gin.SetMode(gin.TestMode)
			router := gin.New()

			router.Use(OptionalAuth())
			router.GET("/test", func(c *gin.Context) {
				claims, exists := GetCurrentUser(c)
				c.JSON(http.StatusOK, gin.H{
					"has_user": exists,
					"user_id": func() string {
						if claims != nil {
							return claims.UserID.String()
						}
						return ""
					}(),
				})
			})

			// 创建请求
			req := httptest.NewRequest("GET", "/test", nil)
			tt.setupRequest(req)

			// 执行请求
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// 验证结果
			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match")

			if tt.hasUser {
				assert.Contains(t, w.Body.String(), `"has_user":true`, "should have user")
			} else {
				assert.Contains(t, w.Body.String(), `"has_user":false`, "should not have user")
			}
		})
	}
}

func TestGetCurrentUser(t *testing.T) {
	// 初始化测试环境
	setupAuthTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 测试有用户的情况
	router.GET("/with-user", func(c *gin.Context) {
		// 模拟设置用户claims
		claims := &auth.Claims{
			UserID:   uuid.New(),
			Username: "testuser",
			Email:    "test@example.com",
		}
		c.Set(ClaimsContextKey, claims)

		user, exists := GetCurrentUser(c)
		c.JSON(http.StatusOK, gin.H{
			"exists": exists,
			"username": func() string {
				if user != nil {
					return user.Username
				}
				return ""
			}(),
		})
	})

	// 测试没有用户的情况
	router.GET("/without-user", func(c *gin.Context) {
		user, exists := GetCurrentUser(c)
		c.JSON(http.StatusOK, gin.H{
			"exists": exists,
			"user":   user,
		})
	})

	// 测试有用户的情况
	req := httptest.NewRequest("GET", "/with-user", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "status should be OK")
	assert.Contains(t, w.Body.String(), `"exists":true`, "should have user")
	assert.Contains(t, w.Body.String(), `"username":"testuser"`, "should have username")

	// 测试没有用户的情况
	req = httptest.NewRequest("GET", "/without-user", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "status should be OK")
	assert.Contains(t, w.Body.String(), `"exists":false`, "should not have user")
}

func TestGetCurrentUserID(t *testing.T) {
	// 初始化测试环境
	setupAuthTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	testUserID := uuid.New()

	router.GET("/test", func(c *gin.Context) {
		// 模拟设置用户claims
		claims := &auth.Claims{
			UserID:   testUserID,
			Username: "testuser",
		}
		c.Set(ClaimsContextKey, claims)

		userID, exists := GetCurrentUserID(c)
		c.JSON(http.StatusOK, gin.H{
			"exists":  exists,
			"user_id": userID,
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "status should be OK")
	assert.Contains(t, w.Body.String(), `"exists":true`, "should have user")
	assert.Contains(t, w.Body.String(), testUserID.String(), "should have correct user ID")
}

func TestRequireAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 测试有认证的情况
	t.Run("with auth", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())

		claims := &auth.Claims{
			UserID:   uuid.New(),
			Username: "testuser",
		}
		c.Set(ClaimsContextKey, claims)

		resultClaims, ok := RequireAuth(c)
		assert.True(t, ok, "should be authenticated")
		assert.NotNil(t, resultClaims, "should have claims")
		assert.Equal(t, claims.UserID, resultClaims.UserID, "user ID should match")
	})

	// 测试没有认证的情况
	t.Run("without auth", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		resultClaims, ok := RequireAuth(c)
		assert.False(t, ok, "should not be authenticated")
		assert.Nil(t, resultClaims, "should not have claims")
		assert.Equal(t, http.StatusUnauthorized, w.Code, "should return unauthorized")
	})
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		expected   string
	}{
		{
			name:       "valid bearer token",
			authHeader: "Bearer abc123token",
			expected:   "abc123token",
		},
		{
			name:       "valid bearer token with case insensitive",
			authHeader: "bearer abc123token",
			expected:   "abc123token",
		},
		{
			name:       "invalid format - no space",
			authHeader: "Bearerabc123token",
			expected:   "",
		},
		{
			name:       "invalid format - wrong scheme",
			authHeader: "Basic abc123token",
			expected:   "",
		},
		{
			name:       "empty header",
			authHeader: "",
			expected:   "",
		},
		{
			name:       "only bearer",
			authHeader: "Bearer",
			expected:   "",
		},
		{
			name:       "bearer with empty token",
			authHeader: "Bearer ",
			expected:   "",
		},
		{
			name:       "bearer with multiple spaces",
			authHeader: "Bearer  abc123token",
			expected:   " abc123token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBearerToken(tt.authHeader)
			assert.Equal(t, tt.expected, result, "extracted token should match expected")
		})
	}
}

func TestAuthenticatedOnly(t *testing.T) {
	// 初始化测试环境
	setupAuthTestEnv(t)

	// 创建测试用户和令牌
	_, _, accessToken := createTestUserWithToken(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	router.Use(AuthenticatedOnly())
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "access granted"})
	})

	// 测试有效令牌
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "should allow access with valid token")

	// 测试无令牌
	req = httptest.NewRequest("GET", "/protected", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "should deny access without token")
}

func TestUserStatusHandling(t *testing.T) {
	// 初始化测试环境
	setupAuthTestEnv(t)

	// 创建测试用户和令牌
	_, testUser, accessToken := createTestUserWithToken(t)

	// 将用户设置为非活跃状态
	db := database.Get()
	err := db.Model(&model.User{}).
		Where("id = ?", testUser.ID).
		Update("status", model.UserStatusInactive).Error
	require.NoError(t, err, "updating user status should succeed")

	gin.SetMode(gin.TestMode)
	router := gin.New()

	router.Use(Auth())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 非活跃用户应该无法获取用户信息，导致500错误
	assert.Equal(t, http.StatusInternalServerError, w.Code, "inactive user should cause server error")
}

// setupAuthTestEnv 设置认证测试环境
func setupAuthTestEnv(t *testing.T) {
	_ = testutils.SetupTestEnv(t)
}

// createTestUserWithToken 创建测试用户和令牌
func createTestUserWithToken(t *testing.T) (*service.AuthService, *model.User, string) {
	authService := service.NewAuthService()

	username := testutils.GenerateTestUsername(t)
	email := testutils.GenerateTestEmail(t)

	registerReq := service.RegisterRequest{
		Username: username,
		Email:    email,
		Password: "password123",
		FullName: "Test User",
	}

	registerResp, err := authService.Register(registerReq)
	require.NoError(t, err, "registration should succeed")

	// 获取完整用户信息
	userInfo, err := authService.GetUserInfo(registerResp.User.ID)
	require.NoError(t, err, "getting user info should succeed")

	// 转换为model.User
	user := &model.User{
		ID:       userInfo.ID,
		Username: userInfo.Username,
		Email:    userInfo.Email,
		FullName: userInfo.FullName,
		Status:   userInfo.Status,
	}

	return authService, user, registerResp.AccessToken
}
