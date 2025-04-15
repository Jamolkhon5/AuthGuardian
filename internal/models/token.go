package models

import (
	"time"
)

// RefreshToken представляет собой модель данных для хранение в базе
type RefreshToken struct {
	ID        string    `pg:"id,pk,type:uuid"`
	UserID    string    `pg:"user_id,notnull"`
	TokenHash string    `pg:"token_hash,notnull"`
	UserIP    string    `pg:"user_ip,notnull"`
	UserAgent string    `pg:"user_agent"`
	ExpiresAt time.Time `pg:"expires_at,notnull"`
	CreatedAt time.Time `pg:"created_at,notnull,default:now()"`
	Revoked   bool      `pg:"revoked,notnull,default:false"`
}

// AccessTokenClaims содержит даные для JWT токена
type AccessTokenClaims struct {
	UserID  string `json:"user_id"`
	IP      string `json:"ip"`
	TokenID string `json:"token_id"`
}

// TokenPair содержит пару токенов для ответа клиенту
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// UserData представляет данные пользователя
type UserData struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}
