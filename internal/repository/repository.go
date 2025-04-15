package repository

import (
	"context"
	"time"

	"github.com/Jamolkhon5/authguardian/internal/models"
)

// TokenRepository определеят интерфейс для работы с токнами в базе данных
type TokenRepository interface {
	StoreRefreshToken(ctx context.Context, token *models.RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenID string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error
	CleanupExpiredTokens(ctx context.Context, before time.Time) error
	GetUserByID(ctx context.Context, userID string) (*models.UserData, error)
	GetRefreshTokenByUserID(ctx context.Context, userID string) ([]*models.RefreshToken, error)
	GetRefreshTokenByUUID(ctx context.Context, tokenUUID string) (*models.RefreshToken, error)
}
