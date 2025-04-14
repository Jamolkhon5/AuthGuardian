package handlers

import (
	"net/http"

	"github.com/Jamolkhon5/authguardian/internal/services"
	"github.com/Jamolkhon5/authguardian/pkg/errs"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

func (h *AuthHandler) GetTokens(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}
	userIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	tokenPair, err := h.authService.GetTokens(c.Request.Context(), userID, userIP, userAgent)
	if err != nil {
		apiErr := errs.ConvertToAPIError(err)
		c.JSON(apiErr.StatusCode, gin.H{"error": apiErr.Error()})
		return
	}

	c.JSON(http.StatusOK, tokenPair)
}

func (h *AuthHandler) RefreshTokens(c *gin.Context) {
	var request struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "refresh_token is required"})
		return
	}
	userIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	tokenPair, err := h.authService.RefreshTokens(c.Request.Context(), request.RefreshToken, userIP, userAgent)
	if err != nil {
		apiErr := errs.ConvertToAPIError(err)
		c.JSON(apiErr.StatusCode, gin.H{"error": apiErr.Error()})
		return
	}

	c.JSON(http.StatusOK, tokenPair)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var request struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "refresh_token is required"})
		return
	}
	err := h.authService.Logout(c.Request.Context(), request.RefreshToken)
	if err != nil {
		apiErr := errs.ConvertToAPIError(err)
		c.JSON(apiErr.StatusCode, gin.H{"error": apiErr.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// RegisterRoutes регистрирует маршруты для авторизации
func (h *AuthHandler) RegisterRoutes(router *gin.Engine) {
	auth := router.Group("/api/v1/auth")
	{
		auth.GET("/token", h.GetTokens)
		auth.POST("/refresh", h.RefreshTokens)
		auth.POST("/logout", h.Logout)
	}
}
