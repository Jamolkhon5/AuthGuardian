package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Jamolkhon5/authguardian/internal/models"
	"github.com/Jamolkhon5/authguardian/pkg/utils"
	"github.com/dgrijalva/jwt-go"
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

func (m *JWTManager) GenerateRefreshToken(tokenID string) (string, string, error) {
	tokenString := base64.StdEncoding.EncodeToString([]byte(tokenID))

	h := hmac.New(sha256.New, []byte(m.refreshSecret))
	h.Write([]byte(tokenID))
	hmacResult := h.Sum(nil)

	hmacBase64 := base64.StdEncoding.EncodeToString(hmacResult)

	bcryptHash, err := utils.HashPassword(hmacBase64)
	if err != nil {
		return "", "", fmt.Errorf("невозможно создать bcrypt хеш: %w", err)
	}

	return tokenString, bcryptHash, nil
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

func (m *JWTManager) GetRefreshTokenExpiry() time.Time {
	return time.Now().Add(m.refreshExpiry)
}

func (m *JWTManager) VerifyRefreshToken(refreshToken, storedHash string) (bool, error) {
	tokenBytes, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		return false, fmt.Errorf("невозможно декодировать refresh token: %w", err)
	}

	tokenUUID := string(tokenBytes)

	h := hmac.New(sha256.New, []byte(m.refreshSecret))
	h.Write([]byte(tokenUUID))
	hmacResult := h.Sum(nil)

	hmacBase64 := base64.StdEncoding.EncodeToString(hmacResult)

	return utils.CheckPasswordHash(hmacBase64, storedHash), nil
}

func (m *JWTManager) GetRefreshTokenUUID(tokenString string) (string, error) {
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenString)
	if err != nil {
		return "", fmt.Errorf("невозможно декодировать refresh token: %w", err)
	}
	return string(tokenBytes), nil
}
