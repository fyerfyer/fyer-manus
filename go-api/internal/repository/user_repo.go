package repository

import (
	"context"
	"errors"
	"strings"

	"github.com/fyerfyer/fyer-manus/go-api/internal/database"
	"github.com/fyerfyer/fyer-manus/go-api/internal/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserRepository 用户仓储接口
type UserRepository interface {
	Create(ctx context.Context, user *model.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	GetByUsername(ctx context.Context, username string) (*model.User, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	Update(ctx context.Context, user *model.User) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status model.UserStatus) error
	ExistsByUsername(ctx context.Context, username string) (bool, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	List(ctx context.Context, offset, limit int) ([]*model.User, int64, error)
	Search(ctx context.Context, query string, offset, limit int) ([]*model.User, int64, error)
	AssignRole(ctx context.Context, userID, roleID uuid.UUID) error
	RemoveRole(ctx context.Context, userID, roleID uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*model.Role, error)
}

// userRepository 用户仓储实现
type userRepository struct {
	db *gorm.DB
}

// NewUserRepository 创建用户仓储
func NewUserRepository() UserRepository {
	return &userRepository{
		db: database.Get(),
	}
}

// validateUser 验证用户数据
func (r *userRepository) validateUser(user *model.User) error {
	if strings.TrimSpace(user.Username) == "" {
		return errors.New("username cannot be empty")
	}

	if strings.TrimSpace(user.Email) == "" {
		return errors.New("email cannot be empty")
	}

	if strings.TrimSpace(user.PasswordHash) == "" {
		return errors.New("password cannot be empty")
	}

	// 简单的邮箱格式验证
	if !strings.Contains(user.Email, "@") || !strings.Contains(user.Email, ".") {
		return errors.New("invalid email format")
	}

	return nil
}

// Create 创建用户
func (r *userRepository) Create(ctx context.Context, user *model.User) error {
	// 验证用户数据
	if err := r.validateUser(user); err != nil {
		return err
	}

	return r.db.WithContext(ctx).Create(user).Error
}

// GetByID 根据ID获取用户
func (r *userRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	var user model.User
	err := r.db.WithContext(ctx).
		Preload("Roles").
		First(&user, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByUsername 根据用户名获取用户
func (r *userRepository) GetByUsername(ctx context.Context, username string) (*model.User, error) {
	var user model.User
	err := r.db.WithContext(ctx).
		Preload("Roles").
		First(&user, "username = ?", username).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByEmail 根据邮箱获取用户
func (r *userRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User
	err := r.db.WithContext(ctx).
		Preload("Roles").
		First(&user, "email = ?", email).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Update 更新用户
func (r *userRepository) Update(ctx context.Context, user *model.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

// Delete 删除用户
func (r *userRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&model.User{}, "id = ?", id).Error
}

// UpdateLastLogin 更新最后登录时间
func (r *userRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&model.User{}).
		Where("id = ?", id).
		Update("last_login_at", gorm.Expr("NOW()")).Error
}

// UpdatePassword 更新用户密码
func (r *userRepository) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	return r.db.WithContext(ctx).Model(&model.User{}).
		Where("id = ?", id).
		Update("password_hash", passwordHash).Error
}

// UpdateStatus 更新用户状态
func (r *userRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status model.UserStatus) error {
	return r.db.WithContext(ctx).Model(&model.User{}).
		Where("id = ?", id).
		Update("status", status).Error
}

// ExistsByUsername 检查用户名是否存在
func (r *userRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.User{}).
		Where("username = ?", username).
		Count(&count).Error
	return count > 0, err
}

// ExistsByEmail 检查邮箱是否存在
func (r *userRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.User{}).
		Where("email = ?", email).
		Count(&count).Error
	return count > 0, err
}

// List 获取用户列表
func (r *userRepository) List(ctx context.Context, offset, limit int) ([]*model.User, int64, error) {
	var users []*model.User
	var total int64

	// 计算总数
	if err := r.db.WithContext(ctx).Model(&model.User{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	err := r.db.WithContext(ctx).
		Order("created_at DESC").
		Offset(offset).
		Limit(limit).
		Find(&users).Error

	return users, total, err
}

// Search 搜索用户
func (r *userRepository) Search(ctx context.Context, query string, offset, limit int) ([]*model.User, int64, error) {
	var users []*model.User
	var total int64

	searchQuery := r.db.WithContext(ctx).Model(&model.User{}).
		Where("username ILIKE ? OR email ILIKE ? OR full_name ILIKE ?",
			"%"+query+"%", "%"+query+"%", "%"+query+"%")

	// 计算总数
	if err := searchQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	err := searchQuery.Order("created_at DESC").
		Offset(offset).
		Limit(limit).
		Find(&users).Error

	return users, total, err
}

// AssignRole 分配角色
func (r *userRepository) AssignRole(ctx context.Context, userID, roleID uuid.UUID) error {
	return r.db.WithContext(ctx).Exec(
		"INSERT INTO user_roles (user_id, role_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
		userID, roleID).Error
}

// RemoveRole 移除角色
func (r *userRepository) RemoveRole(ctx context.Context, userID, roleID uuid.UUID) error {
	return r.db.WithContext(ctx).Exec(
		"DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
		userID, roleID).Error
}

// GetUserRoles 获取用户角色列表
func (r *userRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*model.Role, error) {
	var roles []*model.Role
	err := r.db.WithContext(ctx).
		Table("roles").
		Joins("JOIN user_roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Find(&roles).Error
	return roles, err
}
