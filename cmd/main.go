package main

import (
	"context"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Jamolkhon5/authguardian/internal/config"
	"github.com/Jamolkhon5/authguardian/internal/handlers"
	"github.com/Jamolkhon5/authguardian/internal/middleware"
	"github.com/Jamolkhon5/authguardian/internal/repository"
	"github.com/Jamolkhon5/authguardian/internal/services"
	"github.com/Jamolkhon5/authguardian/pkg/token"
	"github.com/gin-gonic/gin"
	"github.com/go-pg/pg/v10"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("дотенв конфиг не найден, использум значения по умолчаню")
	}

	cfg, err := config.LoadConfig(".env")
	if err != nil {
		log.Fatalf("ошибка загрскзи конфиг %v", err)
	}

	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.DBName,
		cfg.Database.SSLMode,
	)

	m, err := migrate.New("file://migrations", dbURL)
	if err != nil {
		log.Printf("ошибак создания миграцй: %v", err)
	} else {
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			log.Printf("проблеми миграций базы: %v", err)
		} else {
			log.Println("миграции выполнелись успещно или уже применены")
		}
	}

	db := pg.Connect(&pg.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.Database.Host, cfg.Database.Port),
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
		Database: cfg.Database.DBName,
	})
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.Ping(ctx); err != nil {
		log.Fatalf("подключения к бд ошибка %v", err)
	}
	log.Println("коннект с бд успешн")

	tokenRepo := repository.NewPgTokenRepository(db)

	jwtManager := token.NewJWTManager(
		cfg.JWT.AccessSecret,
		cfg.JWT.RefreshSecret,
		cfg.JWT.AccessExpiryHours,
		cfg.JWT.RefreshExpiryDays,
		cfg.JWT.SigningMethod,
	)

	emailService := services.NewEmailService(
		cfg.Email.SMTPHost,
		cfg.Email.SMTPPort,
		cfg.Email.SMTPUser,
		cfg.Email.SMTPPassword,
		cfg.Email.FromEmail,
	)
	tokenService := services.NewTokenService(tokenRepo, jwtManager, emailService)
	authService := services.NewAuthService(tokenService)

	authHandler := handlers.NewAuthHandler(authService)
	authMiddleware := middleware.NewAuthMiddleware(tokenService)
	router := gin.Default()
	authHandler.RegisterRoutes(router)
	protected := router.Group("/api/v1/protected")
	protected.Use(authMiddleware.RequireAuth())
	{
		protected.GET("/profile", func(c *gin.Context) {
			userID, _ := c.Get("user_id")
			c.JSON(http.StatusOK, gin.H{
				"message": "это защишеный роут, вхоть ток с токеном",
				"user_id": userID,
			})
		})
	}

	server := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ошибка старта сервера %v", err)
		}
	}()

	log.Printf("сервер поднелся на порту :%s", cfg.Server.Port)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("выключаюс...")

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("ошика закрытия сервера: %v", err)
	}

	log.Println("сервер закрылся нармално")
}
