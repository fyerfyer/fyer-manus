package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTManager JWT管理器
type JWTManager struct {
	secretKey     string
	accessExpire  time.Duration
	refreshExpire time.Duration
	issuer        string
}

// NewJWTManager 创建JWT管理器
func NewJWTManager(secretKey string, accessExpire, refreshExpire time.Duration, issuer string) *JWTManager {
	return &JWTManager{
		secretKey:     secretKey,
		accessExpire:  accessExpire,
		refreshExpire: refreshExpire,
		issuer:        issuer,
	}
}

// GenerateTokens 生成访问令牌和刷新令牌
func (j *JWTManager) GenerateTokens(userID uuid.UUID, username, email string, roles []string, permissions []string) (string, string, error) {
	// 生成访问令牌
	accessToken, err := j.generateToken(userID, username, email, roles, permissions, TokenTypeAccess, j.accessExpire)
	if err != nil {
		return "", "", err
	}

	// 生成刷新令牌
	refreshToken, err := j.generateToken(userID, username, email, roles, permissions, TokenTypeRefresh, j.refreshExpire)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// generateToken 生成令牌
func (j *JWTManager) generateToken(userID uuid.UUID, username, email string, roles []string, permissions []string, tokenType string, expire time.Duration) (string, error) {
	now := time.Now()
	claims := &Claims{
		UserID:      userID,
		Username:    username,
		Email:       email,
		Roles:       roles,
		Permissions: permissions,
		TokenType:   tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expire)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(j.secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ParseToken 解析令牌
func (j *JWTManager) ParseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return []byte(j.secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}

	return claims, nil
}

// VerifyToken 验证令牌有效性
func (j *JWTManager) VerifyToken(tokenString string) (*Claims, error) {
	claims, err := j.ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	// 检查令牌是否过期
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("token expired")
	}

	// 检查令牌是否还未生效
	if claims.NotBefore != nil && claims.NotBefore.After(time.Now()) {
		return nil, errors.New("token not yet valid")
	}

	return claims, nil
}

// RefreshToken 刷新访问令牌
func (j *JWTManager) RefreshToken(refreshTokenString string) (string, error) {
	claims, err := j.VerifyToken(refreshTokenString)
	if err != nil {
		return "", err
	}

	// 验证是否为刷新令牌
	if !claims.IsRefreshToken() {
		return "", errors.New("invalid refresh token")
	}

	// 生成新的访问令牌
	accessToken, err := j.generateToken(
		claims.UserID,
		claims.Username,
		claims.Email,
		claims.Roles,
		claims.Permissions,
		TokenTypeAccess,
		j.accessExpire,
	)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

// ExtractTokenFromHeader 从Authorization头中提取令牌
func ExtractTokenFromHeader(authHeader string) string {
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}
	return ""
}
