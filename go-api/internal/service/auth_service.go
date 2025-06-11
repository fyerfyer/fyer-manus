package service

import (
	"errors"
	"time"

	"github.com/fyerfyer/fyer-manus/go-api/internal/auth"
	"github.com/fyerfyer/fyer-manus/go-api/internal/config"
	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// AuthService 认证服务
type AuthService struct {
	db         *gorm.DB
	jwtManager *auth.JWTManager
	validator  *auth.TokenValidator
	config     *config.JWTConfig
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RegisterRequest 注册请求
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	FullName string `json:"full_name"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	TokenType    string            `json:"token_type"`
	ExpiresIn    int64             `json:"expires_in"`
	User         model.UserProfile `json:"user"`
}

// RefreshTokenRequest 刷新令牌请求
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// NewAuthService 创建认证服务
func NewAuthService() *AuthService {
	cfg := config.Get()

	jwtManager := auth.NewJWTManager(
		cfg.JWT.Secret,
		time.Duration(cfg.JWT.ExpireHours)*time.Hour,
		time.Duration(cfg.JWT.RefreshHours)*time.Hour,
		cfg.JWT.Issuer,
	)

	validator := auth.NewTokenValidator(jwtManager)

	return &AuthService{
		db:         database.Get(),
		jwtManager: jwtManager,
		validator:  validator,
		config:     &cfg.JWT,
	}
}

// Register 用户注册
func (s *AuthService) Register(req RegisterRequest) (*LoginResponse, error) {
	// 检查用户名是否已存在
	var existingUser model.User
	err := s.db.Where("username = ? OR email = ?", req.Username, req.Email).First(&existingUser).Error
	if err == nil {
		return nil, errors.New("username or email already exists")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		logger.Error("failed to check existing user", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	// 创建新用户
	user := model.User{
		Username: req.Username,
		Email:    req.Email,
		FullName: req.FullName,
		Status:   model.UserStatusActive,
	}

	// 设置密码
	if err := user.SetPassword(req.Password); err != nil {
		logger.Error("failed to hash password", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	// 保存用户
	if err := s.db.Create(&user).Error; err != nil {
		logger.Error("failed to create user", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	// 分配默认角色
	if err := s.assignDefaultRole(&user); err != nil {
		logger.Error("failed to assign default role", zap.Error(err))
		// 不返回错误，用户已创建成功
	}

	// 重新加载用户信息（包含角色）
	if err := s.db.Preload("Roles").First(&user, user.ID).Error; err != nil {
		logger.Error("failed to reload user", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	// 生成令牌
	return s.generateTokenResponse(&user)
}

// Login 用户登录
func (s *AuthService) Login(req LoginRequest) (*LoginResponse, error) {
	var user model.User

	// 查找用户
	err := s.db.Preload("Roles").Where("username = ? OR email = ?", req.Username, req.Username).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid username or password")
		}
		logger.Error("failed to find user", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	// 检查用户状态
	if !user.IsActive() {
		return nil, errors.New("user account is not active")
	}

	// 验证密码
	if !user.CheckPassword(req.Password) {
		return nil, errors.New("invalid username or password")
	}

	// 更新最后登录时间
	user.UpdateLastLogin()
	if err := s.db.Save(&user).Error; err != nil {
		logger.Error("failed to update last login", zap.Error(err))
		// 不返回错误，登录仍然成功
	}

	// 生成令牌
	return s.generateTokenResponse(&user)
}

// RefreshToken 刷新访问令牌
func (s *AuthService) RefreshToken(req RefreshTokenRequest) (*LoginResponse, error) {
	// 验证刷新令牌
	claims, err := s.validator.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// 查找用户
	var user model.User
	err = s.db.Preload("Roles").First(&user, "id = ?", claims.UserID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		logger.Error("failed to find user", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	// 检查用户状态
	if !user.IsActive() {
		return nil, errors.New("user account is not active")
	}

	// 生成新的令牌对
	return s.generateTokenResponse(&user)
}

// Logout 用户登出
func (s *AuthService) Logout(accessToken, refreshToken string) error {
	// 将访问令牌加入黑名单
	if accessToken != "" {
		if err := s.validator.BlacklistToken(accessToken); err != nil {
			logger.Error("failed to blacklist access token", zap.Error(err))
		}
	}

	// 将刷新令牌加入黑名单
	if refreshToken != "" {
		if err := s.validator.BlacklistToken(refreshToken); err != nil {
			logger.Error("failed to blacklist refresh token", zap.Error(err))
		}
	}

	return nil
}

// ValidateToken 验证令牌
func (s *AuthService) ValidateToken(tokenString string) (*auth.Claims, error) {
	return s.validator.ValidateAccessToken(tokenString)
}

// ChangePassword 修改密码
func (s *AuthService) ChangePassword(userID uuid.UUID, oldPassword, newPassword string) error {
	var user model.User
	err := s.db.First(&user, "id = ?", userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("user not found")
		}
		logger.Error("failed to find user", zap.Error(err))
		return errors.New("internal server error")
	}

	// 验证旧密码
	if !user.CheckPassword(oldPassword) {
		return errors.New("invalid old password")
	}

	// 设置新密码
	if err := user.SetPassword(newPassword); err != nil {
		logger.Error("failed to hash new password", zap.Error(err))
		return errors.New("internal server error")
	}

	// 保存更改
	if err := s.db.Save(&user).Error; err != nil {
		logger.Error("failed to update password", zap.Error(err))
		return errors.New("internal server error")
	}

	logger.Info("password changed successfully", zap.String("user_id", userID.String()))
	return nil
}

// GetUserInfo 获取用户信息
func (s *AuthService) GetUserInfo(userID uuid.UUID) (*model.UserProfile, error) {
	var user model.User
	err := s.db.Preload("Roles").First(&user, "id = ?", userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		logger.Error("failed to find user", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	profile := user.ToProfile()
	return &profile, nil
}

// generateTokenResponse 生成令牌响应
func (s *AuthService) generateTokenResponse(user *model.User) (*LoginResponse, error) {
	// 提取角色和权限
	roles := make([]string, len(user.Roles))
	var permissions []string
	permissionSet := make(map[string]bool)

	for i, role := range user.Roles {
		roles[i] = role.Name
		for _, permission := range role.Permissions {
			if !permissionSet[permission] {
				permissions = append(permissions, permission)
				permissionSet[permission] = true
			}
		}
	}

	// 生成令牌
	accessToken, refreshToken, err := s.jwtManager.GenerateTokens(
		user.ID,
		user.Username,
		user.Email,
		roles,
		permissions,
	)
	if err != nil {
		logger.Error("failed to generate tokens", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	// 计算过期时间
	expiresIn := int64(time.Duration(s.config.ExpireHours) * time.Hour / time.Second)

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		User:         user.ToProfile(),
	}, nil
}

// assignDefaultRole 分配默认角色
func (s *AuthService) assignDefaultRole(user *model.User) error {
	var defaultRole model.Role
	err := s.db.Where("name = ?", model.RoleUser).First(&defaultRole).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 如果默认角色不存在，创建它
			defaultRole = model.Role{
				Name:        model.RoleUser,
				Description: "Default user role",
				Permissions: []string{
					model.PermissionChatCreate,
					model.PermissionChatRead,
					model.PermissionChatUpdate,
					model.PermissionChatDelete,
					model.PermissionPluginExecute,
				},
			}
			if err := s.db.Create(&defaultRole).Error; err != nil {
				return err
			}
		} else {
			return err
		}
	}

	// 关联用户和角色
	return s.db.Model(user).Association("Roles").Append(&defaultRole)
}

// GetJWTManager 获取JWT管理器
func (s *AuthService) GetJWTManager() *auth.JWTManager {
	return s.jwtManager
}

// GetValidator 获取令牌验证器
func (s *AuthService) GetValidator() *auth.TokenValidator {
	return s.validator
}
