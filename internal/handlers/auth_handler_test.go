package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Jamolkhon5/authguardian/internal/models"
	"github.com/Jamolkhon5/authguardian/pkg/errs"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) RefreshTokens(ctx context.Context, refreshToken, userIP, userAgent string) (*models.TokenPair, error) {
	args := m.Called(ctx, refreshToken, userIP, userAgent)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TokenPair), args.Error(1)
}

func (m *MockAuthService) Logout(ctx context.Context, refreshToken string) error {
	args := m.Called(ctx, refreshToken)
	return args.Error(0)
}

func (m *MockAuthService) GetTokens(ctx context.Context, userID, userIP, userAgent string) (*models.TokenPair, error) {
	args := m.Called(ctx, userID, userIP, userAgent)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TokenPair), args.Error(1)
}

// тестовый хендлер с моком вместо реального сервиса
type TestAuthHandler struct {
	authService *MockAuthService
}

func (h *TestAuthHandler) GetTokens(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}
	userIP := "127.0.0.1"
	userAgent := c.GetHeader("User-Agent")
	tokenPair, err := h.authService.GetTokens(c.Request.Context(), userID, userIP, userAgent)
	if err != nil {
		apiErr := errs.ConvertToAPIError(err)
		c.JSON(apiErr.StatusCode, gin.H{"error": apiErr.Error()})
		return
	}

	c.JSON(http.StatusOK, tokenPair)
}

func (h *TestAuthHandler) RefreshTokens(c *gin.Context) {
	var request struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "refresh_token is required"})
		return
	}
	userIP := "127.0.0.1"
	userAgent := c.GetHeader("User-Agent")
	tokenPair, err := h.authService.RefreshTokens(c.Request.Context(), request.RefreshToken, userIP, userAgent)
	if err != nil {
		apiErr := errs.ConvertToAPIError(err)
		c.JSON(apiErr.StatusCode, gin.H{"error": apiErr.Error()})
		return
	}

	c.JSON(http.StatusOK, tokenPair)
}

func (h *TestAuthHandler) Logout(c *gin.Context) {
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

// тест на получение token
func TestGetTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockAuthService)
	authHandler := &TestAuthHandler{
		authService: mockService,
	}

	router := gin.New()
	router.GET("/api/v1/auth/token", authHandler.GetTokens)

	userID := "test-user-id"
	userIP := "127.0.0.1"
	userAgent := "test-agent"

	expectedTokens := &models.TokenPair{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		ExpiresIn:    3600,
	}

	mockService.On("GetTokens", mock.Anything, userID, userIP, userAgent).Return(expectedTokens, nil)

	req, _ := http.NewRequest("GET", "/api/v1/auth/token?user_id="+userID, nil)
	req.Header.Set("User-Agent", userAgent)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.TokenPair
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, expectedTokens.AccessToken, response.AccessToken)
	assert.Equal(t, expectedTokens.RefreshToken, response.RefreshToken)
	assert.Equal(t, expectedTokens.ExpiresIn, response.ExpiresIn)

	mockService.AssertExpectations(t)
}

// тест когда нету user_id
func TestGetTokens_MissingUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockAuthService)
	authHandler := &TestAuthHandler{
		authService: mockService,
	}

	router := gin.New()
	router.GET("/api/v1/auth/token", authHandler.GetTokens)

	req, _ := http.NewRequest("GET", "/api/v1/auth/token", nil)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "user_id is required")
}

// тест на ошыбку сервиса
func TestGetTokens_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockAuthService)
	authHandler := &TestAuthHandler{
		authService: mockService,
	}

	router := gin.New()
	router.GET("/api/v1/auth/token", authHandler.GetTokens)

	userID := "invalid-user-id"
	userIP := "127.0.0.1"
	userAgent := "test-agent"

	mockService.On("GetTokens", mock.Anything, userID, userIP, userAgent).Return(nil, errs.ErrUserNotFound)

	req, _ := http.NewRequest("GET", "/api/v1/auth/token?user_id="+userID, nil)
	req.Header.Set("User-Agent", userAgent)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "пользователь не найден")
}

// тест на обновление токена
func TestRefreshTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockAuthService)
	authHandler := &TestAuthHandler{
		authService: mockService,
	}

	router := gin.New()
	router.POST("/api/v1/auth/refresh", authHandler.RefreshTokens)

	refreshToken := "test-refresh-token"
	userIP := "127.0.0.1"
	userAgent := "test-agent"

	expectedTokens := &models.TokenPair{
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
		ExpiresIn:    3600,
	}

	reqBody := map[string]string{
		"refresh_token": refreshToken,
	}

	reqJSON, _ := json.Marshal(reqBody)

	mockService.On("RefreshTokens", mock.Anything, refreshToken, userIP, userAgent).Return(expectedTokens, nil)

	req, _ := http.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewBuffer(reqJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.TokenPair
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.Equal(t, expectedTokens.AccessToken, response.AccessToken)
	assert.Equal(t, expectedTokens.RefreshToken, response.RefreshToken)
	assert.Equal(t, expectedTokens.ExpiresIn, response.ExpiresIn)

	mockService.AssertExpectations(t)
}

// тест когда нету токена для обновлния
func TestRefreshTokens_MissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockAuthService)
	authHandler := &TestAuthHandler{
		authService: mockService,
	}

	router := gin.New()
	router.POST("/api/v1/auth/refresh", authHandler.RefreshTokens)

	reqBody := map[string]string{}
	reqJSON, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewBuffer(reqJSON))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "refresh_token is required")
}

// тест при изменение ip адреса
func TestRefreshTokens_IPChanged(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockAuthService)
	authHandler := &TestAuthHandler{
		authService: mockService,
	}

	router := gin.New()
	router.POST("/api/v1/auth/refresh", authHandler.RefreshTokens)

	refreshToken := "test-refresh-token"
	userIP := "127.0.0.1"
	userAgent := "test-agent"

	reqBody := map[string]string{
		"refresh_token": refreshToken,
	}

	reqJSON, _ := json.Marshal(reqBody)

	mockService.On("RefreshTokens", mock.Anything, refreshToken, userIP, userAgent).Return(nil, errs.ErrIPAddressChanged)

	req, _ := http.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewBuffer(reqJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "изменился IP-адрес")
}

// тест на выход из ситсемы
func TestLogout(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockAuthService)
	authHandler := &TestAuthHandler{
		authService: mockService,
	}

	router := gin.New()
	router.POST("/api/v1/auth/logout", authHandler.Logout)

	refreshToken := "test-refresh-token"

	reqBody := map[string]string{
		"refresh_token": refreshToken,
	}

	reqJSON, _ := json.Marshal(reqBody)

	mockService.On("Logout", mock.Anything, refreshToken).Return(nil)

	req, _ := http.NewRequest("POST", "/api/v1/auth/logout", bytes.NewBuffer(reqJSON))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	mockService.AssertExpectations(t)
}

// тест на ошыбку при выходе
func TestLogout_Error(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockAuthService)
	authHandler := &TestAuthHandler{
		authService: mockService,
	}

	router := gin.New()
	router.POST("/api/v1/auth/logout", authHandler.Logout)

	refreshToken := "test-refresh-token"

	reqBody := map[string]string{
		"refresh_token": refreshToken,
	}

	reqJSON, _ := json.Marshal(reqBody)

	mockService.On("Logout", mock.Anything, refreshToken).Return(errors.New("ошибка отзыва токена"))

	req, _ := http.NewRequest("POST", "/api/v1/auth/logout", bytes.NewBuffer(reqJSON))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "внутренняя ошибка сервера")
}
