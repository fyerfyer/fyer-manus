package service

import (
	"context"
	"errors"

	"github.com/fyerfyer/fyer-manus/go-api/internal/logger"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/fyerfyer/fyer-manus/go-api/internal/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// UserService 用户业务服务
type UserService struct {
	userRepo repository.UserRepository
}

// NewUserService 创建用户服务
func NewUserService() *UserService {
	return &UserService{
		userRepo: repository.NewUserRepository(),
	}
}

// CreateUserRequest 创建用户请求
type CreateUserRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	FullName string `json:"full_name" binding:"max=100"`
}

// UpdateUserRequest 更新用户请求
type UpdateUserRequest struct {
	FullName  string `json:"full_name" binding:"max=100"`
	AvatarURL string `json:"avatar_url" binding:"max=500"`
}

// ChangePasswordRequest 修改密码请求
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

// CreateUser 创建用户
func (s *UserService) CreateUser(ctx context.Context, req CreateUserRequest) (*model.UserProfile, error) {
	// 检查用户名是否存在
	exists, err := s.userRepo.ExistsByUsername(ctx, req.Username)
	if err != nil {
		logger.Error("failed to check username existence", zap.Error(err))
		return nil, errors.New("internal server error")
	}
	if exists {
		return nil, errors.New("username already exists")
	}

	// 检查邮箱是否存在
	exists, err = s.userRepo.ExistsByEmail(ctx, req.Email)
	if err != nil {
		logger.Error("failed to check email existence", zap.Error(err))
		return nil, errors.New("internal server error")
	}
	if exists {
		return nil, errors.New("email already exists")
	}

	// 创建用户
	user := &model.User{
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

	if err := s.userRepo.Create(ctx, user); err != nil {
		logger.Error("failed to create user", zap.Error(err))
		return nil, errors.New("failed to create user")
	}

	logger.Info("user created successfully",
		zap.String("user_id", user.ID.String()),
		zap.String("username", user.Username),
	)

	profile := user.ToProfile()
	return &profile, nil
}

// GetUserByID 根据ID获取用户
func (s *UserService) GetUserByID(ctx context.Context, userID uuid.UUID) (*model.UserProfile, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		logger.Error("failed to get user by ID", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	profile := user.ToProfile()
	return &profile, nil
}

// GetUserByUsername 根据用户名获取用户
func (s *UserService) GetUserByUsername(ctx context.Context, username string) (*model.UserProfile, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		logger.Error("failed to get user by username", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	profile := user.ToProfile()
	return &profile, nil
}

// GetUserByEmail 根据邮箱获取用户
func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*model.UserProfile, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		logger.Error("failed to get user by email", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	profile := user.ToProfile()
	return &profile, nil
}

// UpdateUser 更新用户信息
func (s *UserService) UpdateUser(ctx context.Context, userID uuid.UUID, req UpdateUserRequest) (*model.UserProfile, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		logger.Error("failed to get user", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	// 更新字段
	if req.FullName != "" {
		user.FullName = req.FullName
	}
	if req.AvatarURL != "" {
		user.AvatarURL = req.AvatarURL
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		logger.Error("failed to update user", zap.Error(err))
		return nil, errors.New("failed to update user")
	}

	logger.Info("user updated successfully",
		zap.String("user_id", userID.String()),
	)

	profile := user.ToProfile()
	return &profile, nil
}

// ChangePassword 修改密码
func (s *UserService) ChangePassword(ctx context.Context, userID uuid.UUID, req ChangePasswordRequest) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("user not found")
		}
		logger.Error("failed to get user", zap.Error(err))
		return errors.New("internal server error")
	}

	// 验证旧密码
	if !user.CheckPassword(req.OldPassword) {
		return errors.New("invalid old password")
	}

	// 设置新密码
	if err := user.SetPassword(req.NewPassword); err != nil {
		logger.Error("failed to hash new password", zap.Error(err))
		return errors.New("internal server error")
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		logger.Error("failed to update password", zap.Error(err))
		return errors.New("failed to change password")
	}

	logger.Info("password changed successfully",
		zap.String("user_id", userID.String()),
	)

	return nil
}

// UpdateUserStatus 更新用户状态
func (s *UserService) UpdateUserStatus(ctx context.Context, userID uuid.UUID, status model.UserStatus) error {
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("user not found")
		}
		logger.Error("failed to get user", zap.Error(err))
		return errors.New("internal server error")
	}

	if err := s.userRepo.UpdateStatus(ctx, userID, status); err != nil {
		logger.Error("failed to update user status", zap.Error(err))
		return errors.New("failed to update user status")
	}

	logger.Info("user status updated successfully",
		zap.String("user_id", userID.String()),
		zap.String("status", string(status)),
	)

	return nil
}

// DeleteUser 删除用户
func (s *UserService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("user not found")
		}
		logger.Error("failed to get user", zap.Error(err))
		return errors.New("internal server error")
	}

	if err := s.userRepo.Delete(ctx, userID); err != nil {
		logger.Error("failed to delete user", zap.Error(err))
		return errors.New("failed to delete user")
	}

	logger.Info("user deleted successfully",
		zap.String("user_id", userID.String()),
		zap.String("username", user.Username),
	)

	return nil
}

// ListUsers 获取用户列表
func (s *UserService) ListUsers(ctx context.Context, page, pageSize int) ([]*model.UserProfile, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	offset := (page - 1) * pageSize

	users, total, err := s.userRepo.List(ctx, offset, pageSize)
	if err != nil {
		logger.Error("failed to list users", zap.Error(err))
		return nil, 0, errors.New("failed to get users")
	}

	// 转换为用户配置文件
	profiles := make([]*model.UserProfile, len(users))
	for i, user := range users {
		profile := user.ToProfile()
		profiles[i] = &profile
	}

	return profiles, total, nil
}

// SearchUsers 搜索用户
func (s *UserService) SearchUsers(ctx context.Context, query string, page, pageSize int) ([]*model.UserProfile, int64, error) {
	if query == "" {
		return s.ListUsers(ctx, page, pageSize)
	}

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	offset := (page - 1) * pageSize

	users, total, err := s.userRepo.Search(ctx, query, offset, pageSize)
	if err != nil {
		logger.Error("failed to search users", zap.Error(err))
		return nil, 0, errors.New("failed to search users")
	}

	// 转换为用户配置文件
	profiles := make([]*model.UserProfile, len(users))
	for i, user := range users {
		profile := user.ToProfile()
		profiles[i] = &profile
	}

	return profiles, total, nil
}

// AssignRole 分配角色
func (s *UserService) AssignRole(ctx context.Context, userID, roleID uuid.UUID) error {
	// 检查用户是否存在
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("user not found")
		}
		logger.Error("failed to get user", zap.Error(err))
		return errors.New("internal server error")
	}

	if err := s.userRepo.AssignRole(ctx, userID, roleID); err != nil {
		logger.Error("failed to assign role", zap.Error(err))
		return errors.New("failed to assign role")
	}

	logger.Info("role assigned successfully",
		zap.String("user_id", userID.String()),
		zap.String("role_id", roleID.String()),
	)

	return nil
}

// RemoveRole 移除角色
func (s *UserService) RemoveRole(ctx context.Context, userID, roleID uuid.UUID) error {
	// 检查用户是否存在
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("user not found")
		}
		logger.Error("failed to get user", zap.Error(err))
		return errors.New("internal server error")
	}

	if err := s.userRepo.RemoveRole(ctx, userID, roleID); err != nil {
		logger.Error("failed to remove role", zap.Error(err))
		return errors.New("failed to remove role")
	}

	logger.Info("role removed successfully",
		zap.String("user_id", userID.String()),
		zap.String("role_id", roleID.String()),
	)

	return nil
}

// GetUserRoles 获取用户角色
func (s *UserService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*model.Role, error) {
	roles, err := s.userRepo.GetUserRoles(ctx, userID)
	if err != nil {
		logger.Error("failed to get user roles", zap.Error(err))
		return nil, errors.New("failed to get user roles")
	}

	return roles, nil
}

// ValidateUser 验证用户登录
func (s *UserService) ValidateUser(ctx context.Context, username, password string) (*model.User, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 为了安全，不暴露用户不存在的信息
			return nil, errors.New("invalid credentials")
		}
		logger.Error("failed to get user for validation", zap.Error(err))
		return nil, errors.New("internal server error")
	}

	if !user.IsActive() {
		return nil, errors.New("user account is not active")
	}

	if !user.CheckPassword(password) {
		return nil, errors.New("invalid credentials")
	}

	// 更新最后登录时间
	user.UpdateLastLogin()
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
		logger.Error("failed to update last login", zap.Error(err))
		// 不返回错误，因为登录验证成功
	}

	return user, nil
}

// GetUserStats 获取用户统计信息
func (s *UserService) GetUserStats(ctx context.Context) (map[string]interface{}, error) {
	// 这里可以扩展更多统计信息
	return map[string]interface{}{
		"status": "basic stats available",
	}, nil
}
