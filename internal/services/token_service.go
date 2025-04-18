package services

import (
	"context"
	"log"
	"time"

	"github.com/Jamolkhon5/authguardian/internal/models"
	"github.com/Jamolkhon5/authguardian/internal/repository"
	"github.com/Jamolkhon5/authguardian/pkg/errs"
	"github.com/Jamolkhon5/authguardian/pkg/token"
	"github.com/google/uuid"
)

type TokenService struct {
	tokenRepo    repository.TokenRepository
	jwtManager   *token.JWTManager
	emailService *EmailService
}

func NewTokenService(tokenRepo repository.TokenRepository, jwtManager *token.JWTManager, emailService *EmailService) *TokenService {
	return &TokenService{
		tokenRepo:    tokenRepo,
		jwtManager:   jwtManager,
		emailService: emailService,
	}
}

// пара Access/Refresh токенов
func (s *TokenService) GenerateTokenPair(ctx context.Context, userID, userIP, userAgent string) (*models.TokenPair, error) {
	user, err := s.tokenRepo.GetUserByID(ctx, userID)
	if err != nil {
		log.Printf("ошибка при получении пользователя: %v", err)
		return nil, err
	}
	if user == nil {
		return nil, errs.ErrUserNotFound
	}

	tokenID := uuid.New().String()
	refreshTokenStr, refreshTokenHash, err := s.jwtManager.GenerateRefreshToken(tokenID)
	if err != nil {
		log.Printf("ошибка при генерации рефреш токен: %v", err)
		return nil, err
	}

	refreshToken := &models.RefreshToken{
		ID:        tokenID,
		UserID:    userID,
		TokenHash: refreshTokenHash,
		UserIP:    userIP,
		UserAgent: userAgent,
		ExpiresAt: s.jwtManager.GetRefreshTokenExpiry(),
		CreatedAt: time.Now(),
		Revoked:   false,
	}

	if err := s.tokenRepo.StoreRefreshToken(ctx, refreshToken); err != nil {
		log.Printf("ошибка при сохранении токена в БД: %v", err)
		return nil, err
	}

	accessToken, expiresAt, err := s.jwtManager.GenerateAccessToken(models.AccessTokenClaims{
		UserID:  userID,
		IP:      userIP,
		TokenID: refreshToken.ID,
	})
	if err != nil {
		log.Printf("ошибка при генерации аксес токен: %v", err)
		return nil, err
	}

	return &models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenStr,
		ExpiresIn:    expiresAt.Unix() - time.Now().Unix(),
	}, nil
}

func (s *TokenService) RefreshTokens(ctx context.Context, refreshTokenStr, userIP, userAgent string) (*models.TokenPair, error) {
	tokenUUID, err := s.jwtManager.GetRefreshTokenUUID(refreshTokenStr)
	if err != nil {
		return nil, errs.ErrRefreshTokenInvalid
	}

	storedToken, err := s.tokenRepo.GetRefreshToken(ctx, tokenUUID)
	if err != nil {
		return nil, err
	}

	if storedToken == nil {
		return nil, errs.ErrRefreshTokenInvalid
	}

	valid, err := s.jwtManager.VerifyRefreshToken(refreshTokenStr, storedToken.TokenHash)
	if err != nil || !valid {
		return nil, errs.ErrRefreshTokenInvalid
	}

	if storedToken.UserIP != userIP {
		user, err := s.tokenRepo.GetUserByID(ctx, storedToken.UserID)
		if err == nil && user != nil {
			go s.emailService.SendIPChangeAlert(user.Email, storedToken.UserIP, userIP)
		}
		_ = s.tokenRepo.RevokeRefreshToken(ctx, storedToken.ID)

		return nil, errs.ErrIPAddressChanged
	}

	if err := s.tokenRepo.RevokeRefreshToken(ctx, storedToken.ID); err != nil {
		return nil, err
	}

	return s.GenerateTokenPair(ctx, storedToken.UserID, userIP, userAgent)
}

func (s *TokenService) RevokeToken(ctx context.Context, refreshTokenStr string) error {
	tokenUUID, err := s.jwtManager.GetRefreshTokenUUID(refreshTokenStr)
	if err != nil {
		return errs.ErrRefreshTokenInvalid
	}

	storedToken, err := s.tokenRepo.GetRefreshToken(ctx, tokenUUID)
	if err != nil {
		return err
	}

	if storedToken == nil {
		return errs.ErrRefreshTokenInvalid
	}

	valid, err := s.jwtManager.VerifyRefreshToken(refreshTokenStr, storedToken.TokenHash)
	if err != nil || !valid {
		return errs.ErrRefreshTokenInvalid
	}

	return s.tokenRepo.RevokeRefreshToken(ctx, storedToken.ID)
}

func (s *TokenService) RevokeAllUserTokens(ctx context.Context, userID string) error {
	return s.tokenRepo.RevokeAllUserTokens(ctx, userID)
}

func (s *TokenService) VerifyAccessToken(accessToken string) (*models.AccessTokenClaims, error) {
	return s.jwtManager.VerifyAccessToken(accessToken)
}

func (s *TokenService) CleanupExpiredTokens(ctx context.Context) error {
	return s.tokenRepo.CleanupExpiredTokens(ctx, time.Now())
}
