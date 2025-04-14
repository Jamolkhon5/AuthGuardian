package errs

import (
	"errors"
	"net/http"
)

var (
	ErrInvalidRequest      = errors.New("неверный запрос")
	ErrUnauthorized        = errors.New("неавторизованный доступ")
	ErrTokenExpired        = errors.New("токен истек")
	ErrTokenInvalid        = errors.New("невалидный токен")
	ErrUserNotFound        = errors.New("пользователь не найден")
	ErrInternalServer      = errors.New("внутренняя ошибка сервера")
	ErrRefreshTokenInvalid = errors.New("невалидный refresh токен")
	ErrIPAddressChanged    = errors.New("изменился IP-адрес")
)

type APIError struct {
	StatusCode int
	Err        error
}

func NewAPIError(statusCode int, err error) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Err:        err,
	}
}

func (e *APIError) Error() string {
	return e.Err.Error()
}

func ConvertToAPIError(err error) *APIError {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return NewAPIError(http.StatusBadRequest, err)
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrTokenExpired), errors.Is(err, ErrTokenInvalid), errors.Is(err, ErrRefreshTokenInvalid):
		return NewAPIError(http.StatusUnauthorized, err)
	case errors.Is(err, ErrUserNotFound):
		return NewAPIError(http.StatusNotFound, err)
	case errors.Is(err, ErrIPAddressChanged):
		return NewAPIError(http.StatusForbidden, err)
	default:
		return NewAPIError(http.StatusInternalServerError, ErrInternalServer)
	}
}
