package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// структура приложения
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Email    EmailConfig
}

// структура сервера
type ServerConfig struct {
	Port         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// структура базы данных
type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// структура jwt токенов
type JWTConfig struct {
	AccessSecret      string
	AccessExpiryHours int
	RefreshSecret     string
	RefreshExpiryDays int
	SigningMethod     string
}

// структура для отправки email
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
	FromEmail    string
}

// LoadConfig загружает конфигурацию из env файл
func LoadConfig(path string) (*Config, error) {
	viper.SetConfigFile(path)

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("ошибка чтения файла конфигурацй: %w", err)
	}
	viper.AutomaticEnv()

	var cfg Config

	cfg.Server.Port = viper.GetString("SERVER_PORT")
	cfg.Server.ReadTimeout = viper.GetDuration("SERVER_READ_TIMEOUT") * time.Second
	cfg.Server.WriteTimeout = viper.GetDuration("SERVER_WRITE_TIMEOUT") * time.Second

	cfg.Database.Host = viper.GetString("DB_HOST")
	cfg.Database.Port = viper.GetString("DB_PORT")
	cfg.Database.User = viper.GetString("DB_USER")
	cfg.Database.Password = viper.GetString("DB_PASSWORD")
	cfg.Database.DBName = viper.GetString("DB_NAME")
	cfg.Database.SSLMode = viper.GetString("DB_SSLMODE")

	cfg.JWT.AccessSecret = viper.GetString("JWT_ACCESS_SECRET")
	cfg.JWT.AccessExpiryHours = viper.GetInt("JWT_ACCESS_EXPIRY_HOURS")
	cfg.JWT.RefreshSecret = viper.GetString("JWT_REFRESH_SECRET")
	cfg.JWT.RefreshExpiryDays = viper.GetInt("JWT_REFRESH_EXPIRY_DAYS")
	cfg.JWT.SigningMethod = viper.GetString("JWT_SIGNING_METHOD")

	cfg.Email.SMTPHost = viper.GetString("SMTP_HOST")
	cfg.Email.SMTPPort = viper.GetString("SMTP_PORT")
	cfg.Email.SMTPUser = viper.GetString("SMTP_USER")
	cfg.Email.SMTPPassword = viper.GetString("SMTP_PASSWORD")
	cfg.Email.FromEmail = viper.GetString("FROM_EMAIL")

	return &cfg, nil
}
