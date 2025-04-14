package middleware

import (
	"net/http"
	"strings"

	"github.com/Jamolkhon5/authguardian/internal/services"
	"github.com/Jamolkhon5/authguardian/pkg/errs"
	"github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
	tokenService *services.TokenService
}

func NewAuthMiddleware(tokenService *services.TokenService) *AuthMiddleware {
	return &AuthMiddleware{
		tokenService: tokenService,
	}
}

func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization header is required"})
			return
		}
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			return
		}
		tokenString := parts[1]
		claims, err := m.tokenService.VerifyAccessToken(tokenString)
		if err != nil {
			apiErr := errs.ConvertToAPIError(err)
			c.AbortWithStatusJSON(apiErr.StatusCode, gin.H{"error": apiErr.Error()})
			return
		}
		if claims.IP != c.ClientIP() {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "IP address mismatch"})
			return
		}
		c.Set("user_id", claims.UserID)
		c.Set("token_id", claims.TokenID)

		c.Next()
	}
}
