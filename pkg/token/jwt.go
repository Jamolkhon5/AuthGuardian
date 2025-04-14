package token

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Jamolkhon5/authguardian/internal/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type JWTManager struct {
	accessSecret  string
	refreshSecret string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	signingMethod string
}

func NewJWTManager(
	accessSecret string,
	refreshSecret string,
	accessExpiryHours int,
	refreshExpiryDays int,
	signingMethod string,
) *JWTManager {
	return &JWTManager{
		accessSecret:  accessSecret,
		refreshSecret: refreshSecret,
		accessExpiry:  time.Duration(accessExpiryHours) * time.Hour,
		refreshExpiry: time.Duration(refreshExpiryDays) * 24 * time.Hour,
		signingMethod: signingMethod,
	}
}

func (m *JWTManager) GenerateAccessToken(claims models.AccessTokenClaims) (string, time.Time, error) {
	expiresAt := time.Now().Add(m.accessExpiry)

	token := jwt.NewWithClaims(jwt.GetSigningMethod(m.signingMethod), jwt.MapClaims{
		"user_id":  claims.UserID,
		"ip":       claims.IP,
		"token_id": claims.TokenID,
		"exp":      expiresAt.Unix(),
		"iat":      time.Now().Unix(),
	})

	signedToken, err := token.SignedString([]byte(m.accessSecret))
	if err != nil {
		return "", time.Time{}, err
	}

	return signedToken, expiresAt, nil
}

func (m *JWTManager) GenerateRefreshToken() (string, string, error) {
	tokenUUID := uuid.New().String()
	tokenHash := sha256.Sum256([]byte(tokenUUID + m.refreshSecret))
	hashString := hex.EncodeToString(tokenHash[:])
	tokenString := base64.StdEncoding.EncodeToString([]byte(tokenUUID))

	return tokenString, hashString, nil
}

func (m *JWTManager) VerifyAccessToken(tokenString string) (*models.AccessTokenClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != m.signingMethod {
			return nil, fmt.Errorf("неожиданный алгоритм подписи: %v", token.Header["alg"])
		}
		return []byte(m.accessSecret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("невалидный токен")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return nil, fmt.Errorf("ошибка в данных токена: отсутствует user_id")
	}

	ip, ok := claims["ip"].(string)
	if !ok {
		return nil, fmt.Errorf("ошибка в данных токена: отсутствует ip")
	}

	tokenID, ok := claims["token_id"].(string)
	if !ok {
		return nil, fmt.Errorf("ошибка в данных токена: отсутствует token_id")
	}

	return &models.AccessTokenClaims{
		UserID:  userID,
		IP:      ip,
		TokenID: tokenID,
	}, nil
}

// декодируем токен из base64
func (m *JWTManager) GetRefreshTokenHash(tokenString string) (string, error) {
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenString)
	if err != nil {
		return "", fmt.Errorf("невозможно декодировать refresh token: %w", err)
	}
	tokenHash := sha256.Sum256([]byte(string(tokenBytes) + m.refreshSecret))
	return hex.EncodeToString(tokenHash[:]), nil
}

func (m *JWTManager) GetRefreshTokenExpiry() time.Time {
	return time.Now().Add(m.refreshExpiry)
}
