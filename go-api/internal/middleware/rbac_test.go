package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fyerfyer/fyer-manus/go-api/internal/auth"
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/google/uuid"
)

func TestRequirePermission(t *testing.T) {
	// 初始化测试环境
	setupRBACTestEnv(t)

	tests := []struct {
		name            string
		permission      string
		userPermissions []string
		expectedStatus  int
	}{
		{
			name:            "user has required permission",
			permission:      model.PermissionChatCreate,
			userPermissions: []string{model.PermissionChatCreate, model.PermissionChatRead},
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "user has admin permission",
			permission:      model.PermissionChatCreate,
			userPermissions: []string{model.PermissionSystemAdmin},
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "user lacks required permission",
			permission:      model.PermissionChatCreate,
			userPermissions: []string{model.PermissionChatRead},
			expectedStatus:  http.StatusForbidden,
		},
		{
			name:            "user has no permissions",
			permission:      model.PermissionChatCreate,
			userPermissions: []string{},
			expectedStatus:  http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建测试用户和令牌
			claims := createTestClaims(tt.userPermissions, []string{model.RoleUser})

			gin.SetMode(gin.TestMode)
			router := gin.New()

			router.Use(func(c *gin.Context) {
				c.Set(ClaimsContextKey, claims)
				c.Next()
			})
			router.Use(RequirePermission(tt.permission))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match")
		})
	}
}

func TestRequirePermissionWithoutAuth(t *testing.T) {
	// 初始化测试环境
	setupRBACTestEnv(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	router.Use(RequirePermission(model.PermissionChatCreate))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "should return unauthorized without auth")
	assert.Contains(t, w.Body.String(), "authentication required", "should mention authentication required")
}

func TestRequireRole(t *testing.T) {
	// 初始化测试环境
	setupRBACTestEnv(t)

	tests := []struct {
		name           string
		requiredRole   string
		userRoles      []string
		expectedStatus int
	}{
		{
			name:           "user has required role",
			requiredRole:   model.RoleAdmin,
			userRoles:      []string{model.RoleAdmin, model.RoleUser},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "user lacks required role",
			requiredRole:   model.RoleAdmin,
			userRoles:      []string{model.RoleUser},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "user has no roles",
			requiredRole:   model.RoleUser,
			userRoles:      []string{},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建测试claims
			claims := createTestClaims([]string{model.PermissionChatRead}, tt.userRoles)

			gin.SetMode(gin.TestMode)
			router := gin.New()

			router.Use(func(c *gin.Context) {
				c.Set(ClaimsContextKey, claims)
				c.Next()
			})
			router.Use(RequireRole(tt.requiredRole))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match")
		})
	}
}

func TestRequireAnyPermission(t *testing.T) {
	// 初始化测试环境
	setupRBACTestEnv(t)

	tests := []struct {
		name                string
		requiredPermissions []string
		userPermissions     []string
		expectedStatus      int
	}{
		{
			name:                "user has one of required permissions",
			requiredPermissions: []string{model.PermissionChatCreate, model.PermissionChatUpdate},
			userPermissions:     []string{model.PermissionChatCreate},
			expectedStatus:      http.StatusOK,
		},
		{
			name:                "user has all required permissions",
			requiredPermissions: []string{model.PermissionChatCreate, model.PermissionChatUpdate},
			userPermissions:     []string{model.PermissionChatCreate, model.PermissionChatUpdate},
			expectedStatus:      http.StatusOK,
		},
		{
			name:                "user has admin permission",
			requiredPermissions: []string{model.PermissionChatCreate, model.PermissionChatUpdate},
			userPermissions:     []string{model.PermissionSystemAdmin},
			expectedStatus:      http.StatusOK,
		},
		{
			name:                "user lacks all required permissions",
			requiredPermissions: []string{model.PermissionChatCreate, model.PermissionChatUpdate},
			userPermissions:     []string{model.PermissionChatRead},
			expectedStatus:      http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建测试claims
			claims := createTestClaims(tt.userPermissions, []string{model.RoleUser})

			gin.SetMode(gin.TestMode)
			router := gin.New()

			router.Use(func(c *gin.Context) {
				c.Set(ClaimsContextKey, claims)
				c.Next()
			})
			router.Use(RequireAnyPermission(tt.requiredPermissions))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match")
		})
	}
}

func TestRequireAllPermissions(t *testing.T) {
	// 初始化测试环境
	setupRBACTestEnv(t)

	tests := []struct {
		name                string
		requiredPermissions []string
		userPermissions     []string
		expectedStatus      int
	}{
		{
			name:                "user has all required permissions",
			requiredPermissions: []string{model.PermissionChatCreate, model.PermissionChatRead},
			userPermissions:     []string{model.PermissionChatCreate, model.PermissionChatRead, model.PermissionChatUpdate},
			expectedStatus:      http.StatusOK,
		},
		{
			name:                "user has admin permission",
			requiredPermissions: []string{model.PermissionChatCreate, model.PermissionChatRead},
			userPermissions:     []string{model.PermissionSystemAdmin},
			expectedStatus:      http.StatusOK,
		},
		{
			name:                "user lacks one required permission",
			requiredPermissions: []string{model.PermissionChatCreate, model.PermissionChatRead},
			userPermissions:     []string{model.PermissionChatCreate},
			expectedStatus:      http.StatusForbidden,
		},
		{
			name:                "user lacks all required permissions",
			requiredPermissions: []string{model.PermissionChatCreate, model.PermissionChatRead},
			userPermissions:     []string{model.PermissionPluginExecute},
			expectedStatus:      http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建测试claims
			claims := createTestClaims(tt.userPermissions, []string{model.RoleUser})

			gin.SetMode(gin.TestMode)
			router := gin.New()

			router.Use(func(c *gin.Context) {
				c.Set(ClaimsContextKey, claims)
				c.Next()
			})
			router.Use(RequireAllPermissions(tt.requiredPermissions))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match")
		})
	}
}

func TestRequireAdmin(t *testing.T) {
	// 初始化测试环境
	setupRBACTestEnv(t)

	tests := []struct {
		name           string
		userRoles      []string
		expectedStatus int
	}{
		{
			name:           "user is admin",
			userRoles:      []string{model.RoleAdmin},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "user is not admin",
			userRoles:      []string{model.RoleUser},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建测试claims
			claims := createTestClaims([]string{model.PermissionChatRead}, tt.userRoles)

			gin.SetMode(gin.TestMode)
			router := gin.New()

			router.Use(func(c *gin.Context) {
				c.Set(ClaimsContextKey, claims)
				c.Next()
			})
			router.Use(RequireAdmin())
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match")
		})
	}
}

func TestRequireOwnerOrAdmin(t *testing.T) {
	// 初始化测试环境
	setupRBACTestEnv(t)

	userID := uuid.New()
	otherUserID := uuid.New()

	// 创建资源所有者检查函数
	getOwnerID := func(c *gin.Context) (string, error) {
		resourceID := c.Param("id")
		if resourceID == "owned" {
			return userID.String(), nil
		}
		return otherUserID.String(), nil
	}

	tests := []struct {
		name           string
		userRoles      []string
		userID         uuid.UUID
		resourceParam  string
		expectedStatus int
	}{
		{
			name:           "user is admin",
			userRoles:      []string{model.RoleAdmin},
			userID:         otherUserID,
			resourceParam:  "owned",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "user is owner",
			userRoles:      []string{model.RoleUser},
			userID:         userID,
			resourceParam:  "owned",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "user is neither admin nor owner",
			userRoles:      []string{model.RoleUser},
			userID:         otherUserID,
			resourceParam:  "owned",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建测试claims
			permissions := []string{model.PermissionChatRead}
			if contains(tt.userRoles, model.RoleAdmin) {
				permissions = append(permissions, model.PermissionSystemAdmin)
			}
			claims := createTestClaimsWithUserID(tt.userID, permissions, tt.userRoles)

			gin.SetMode(gin.TestMode)
			router := gin.New()

			router.Use(func(c *gin.Context) {
				c.Set(ClaimsContextKey, claims)
				c.Next()
			})
			router.Use(RequireOwnerOrAdmin(getOwnerID))
			router.GET("/test/:id", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := httptest.NewRequest("GET", "/test/"+tt.resourceParam, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match")
		})
	}
}

func TestCheckPermissionDynamic(t *testing.T) {
	// 初始化测试环境
	setupRBACTestEnv(t)

	// 动态权限获取函数
	getPermission := func(c *gin.Context) string {
		action := c.Query("action")
		switch action {
		case "read":
			return model.PermissionChatRead
		case "create":
			return model.PermissionChatCreate
		default:
			return ""
		}
	}

	tests := []struct {
		name            string
		action          string
		userPermissions []string
		expectedStatus  int
	}{
		{
			name:            "user has required permission",
			action:          "read",
			userPermissions: []string{model.PermissionChatRead},
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "user lacks required permission",
			action:          "create",
			userPermissions: []string{model.PermissionChatRead},
			expectedStatus:  http.StatusForbidden,
		},
		{
			name:            "no permission required",
			action:          "unknown",
			userPermissions: []string{},
			expectedStatus:  http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建测试claims
			claims := createTestClaims(tt.userPermissions, []string{model.RoleUser})

			gin.SetMode(gin.TestMode)
			router := gin.New()

			router.Use(func(c *gin.Context) {
				c.Set(ClaimsContextKey, claims)
				c.Next()
			})
			router.Use(CheckPermissionDynamic(getPermission))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := httptest.NewRequest("GET", "/test?action="+tt.action, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match")
		})
	}
}

func TestPredefinedMiddlewares(t *testing.T) {
	// 初始化测试环境
	setupRBACTestEnv(t)

	tests := []struct {
		name            string
		middleware      gin.HandlerFunc
		userPermissions []string
		expectedStatus  int
	}{
		{
			name:            "CanCreateChat with permission",
			middleware:      CanCreateChat,
			userPermissions: []string{model.PermissionChatCreate},
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "CanCreateChat without permission",
			middleware:      CanCreateChat,
			userPermissions: []string{model.PermissionChatRead},
			expectedStatus:  http.StatusForbidden,
		},
		{
			name:            "SystemAdmin with permission",
			middleware:      SystemAdmin,
			userPermissions: []string{model.PermissionSystemAdmin},
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "SystemAdmin without permission",
			middleware:      SystemAdmin,
			userPermissions: []string{model.PermissionChatRead},
			expectedStatus:  http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建测试claims
			claims := createTestClaims(tt.userPermissions, []string{model.RoleUser})

			gin.SetMode(gin.TestMode)
			router := gin.New()

			router.Use(func(c *gin.Context) {
				c.Set(ClaimsContextKey, claims)
				c.Next()
			})
			router.Use(tt.middleware)
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "status code should match")
		})
	}
}

func TestParsePermissionFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		method   string
		expected string
	}{
		{
			name:     "chat read",
			path:     "/api/v1/chat/sessions",
			method:   "GET",
			expected: model.PermissionChatRead,
		},
		{
			name:     "chat create",
			path:     "/api/v1/chat/sessions",
			method:   "POST",
			expected: model.PermissionChatCreate,
		},
		{
			name:     "chat update",
			path:     "/api/v1/chat/sessions/123",
			method:   "PUT",
			expected: model.PermissionChatUpdate,
		},
		{
			name:     "chat delete",
			path:     "/api/v1/chat/sessions/123",
			method:   "DELETE",
			expected: model.PermissionChatDelete,
		},
		{
			name:     "plugin execute",
			path:     "/api/v1/plugin/execute",
			method:   "POST",
			expected: model.PermissionPluginExecute,
		},
		{
			name:     "admin access",
			path:     "/api/v1/admin/users",
			method:   "GET",
			expected: model.PermissionSystemAdmin,
		},
		{
			name:     "unknown path",
			path:     "/api/v1/unknown",
			method:   "GET",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(tt.method, tt.path, nil)

			result := ParsePermissionFromPath(c)
			assert.Equal(t, tt.expected, result, "parsed permission should match expected")
		})
	}
}

func TestContainsPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		substr   string
		expected bool
	}{
		{
			name:     "exact match",
			path:     "/chat",
			substr:   "/chat",
			expected: true,
		},
		{
			name:     "path starts with substr and has slash",
			path:     "/chat/sessions",
			substr:   "/chat",
			expected: true,
		},
		{
			name:     "path starts with substr but no slash",
			path:     "/chatroom",
			substr:   "/chat",
			expected: false,
		},
		{
			name:     "path does not contain substr",
			path:     "/api/v1/users",
			substr:   "/chat",
			expected: false,
		},
		{
			name:     "empty substr",
			path:     "/chat",
			substr:   "",
			expected: true,
		},
		{
			name:     "substr longer than path",
			path:     "/a",
			substr:   "/api",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsPath(tt.path, tt.substr)
			assert.Equal(t, tt.expected, result, "contains result should match expected")
		})
	}
}

// setupRBACTestEnv 设置RBAC测试环境
func setupRBACTestEnv(t *testing.T) {
	cfg, err := config.LoadForTest()
	require.NoError(t, err, "failed to load test config")

	err = database.Init(&cfg.Database)
	require.NoError(t, err, "failed to init database")

	// 自动迁移表结构
	db := database.Get()
	err = db.AutoMigrate(&model.User{}, &model.Role{})
	require.NoError(t, err, "failed to migrate tables")

	// 清理测试数据
	db.Exec("TRUNCATE TABLE user_roles CASCADE")
	db.Exec("TRUNCATE TABLE users CASCADE")
	db.Exec("TRUNCATE TABLE roles CASCADE")
}

// createTestClaims 创建测试claims
func createTestClaims(permissions []string, roles []string) *auth.Claims {
	return &auth.Claims{
		UserID:      uuid.New(),
		Username:    "testuser",
		Email:       "test@example.com",
		Permissions: permissions,
		Roles:       roles,
		TokenType:   auth.TokenTypeAccess,
	}
}

// createTestClaimsWithUserID 创建带指定用户ID的测试claims
func createTestClaimsWithUserID(userID uuid.UUID, permissions []string, roles []string) *auth.Claims {
	return &auth.Claims{
		UserID:      userID,
		Username:    "testuser",
		Email:       "test@example.com",
		Permissions: permissions,
		Roles:       roles,
		TokenType:   auth.TokenTypeAccess,
	}
}

// contains 检查字符串切片是否包含指定字符串
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
