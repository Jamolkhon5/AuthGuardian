package repository

import (
	"context"
	"errors"
	"time"

	"github.com/Jamolkhon5/authguardian/internal/models"
	"github.com/go-pg/pg/v10"
)

type PgTokenRepository struct {
	db *pg.DB
}

// экземпляр PgTokenRepository
func NewPgTokenRepository(db *pg.DB) *PgTokenRepository {
	return &PgTokenRepository{
		db: db,
	}
}

func (r *PgTokenRepository) StoreRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	_, err := r.db.ModelContext(ctx, token).Insert()
	if err != nil {
		return err
	}
	return nil
}

func (r *PgTokenRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	token := &models.RefreshToken{}
	err := r.db.ModelContext(ctx, token).
		Where("token_hash = ?", tokenHash).
		Where("revoked = ?", false).
		Where("expires_at > ?", time.Now()).
		Limit(1).
		Select()

	if err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return token, nil
}

func (r *PgTokenRepository) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	_, err := r.db.ModelContext(ctx, (*models.RefreshToken)(nil)).
		Set("revoked = ?", true).
		Where("id = ?", tokenID).
		Update()

	return err
}

func (r *PgTokenRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	_, err := r.db.ModelContext(ctx, (*models.RefreshToken)(nil)).
		Set("revoked = ?", true).
		Where("user_id = ?", userID).
		Where("revoked = ?", false).
		Update()

	return err
}

func (r *PgTokenRepository) CleanupExpiredTokens(ctx context.Context, before time.Time) error {
	_, err := r.db.ModelContext(ctx, (*models.RefreshToken)(nil)).
		Where("expires_at < ?", before).
		Delete()

	return err
}

// GetUserByID получает данные пользователя по id
// TODO запрос к таблице пользователей
func (r *PgTokenRepository) GetUserByID(ctx context.Context, userID string) (*models.UserData, error) {
	return &models.UserData{
		ID:    userID,
		Email: "user@example.com",
	}, nil
}
