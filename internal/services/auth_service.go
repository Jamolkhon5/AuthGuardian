package services

import (
	"context"

	"github.com/Jamolkhon5/authguardian/internal/models"
	"github.com/Jamolkhon5/authguardian/pkg/errs"
)

type AuthService struct {
	tokenService *TokenService
}

func NewAuthService(tokenService *TokenService) *AuthService {
	return &AuthService{
		tokenService: tokenService,
	}
}

func (s *AuthService) GetTokens(ctx context.Context, userID, userIP, userAgent string) (*models.TokenPair, error) {
	if userID == "" {
		return nil, errs.ErrInvalidRequest
	}

	return s.tokenService.GenerateTokenPair(ctx, userID, userIP, userAgent)
}

func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken, userIP, userAgent string) (*models.TokenPair, error) {
	if refreshToken == "" {
		return nil, errs.ErrInvalidRequest
	}

	return s.tokenService.RefreshTokens(ctx, refreshToken, userIP, userAgent)
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return errs.ErrInvalidRequest
	}

	return s.tokenService.RevokeToken(ctx, refreshToken)
}
