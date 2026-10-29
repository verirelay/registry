package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/verirelay/registry/internal/buildrecord"
	"github.com/verirelay/registry/internal/httpapi"
	"github.com/verirelay/registry/internal/store"
)

type config struct {
	HTTPAddr        string
	DatabaseURL     string
	APIPasswordHash string
	PublicKey       ed25519.PublicKey
	MaxConns        int32
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("service stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	config, err := loadConfig()
	if err != nil {
		return err
	}

	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelStartup()
	database, err := store.Open(startupCtx, config.DatabaseURL, config.MaxConns, config.PublicKey)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.EnsureSchema(startupCtx); err != nil {
		return fmt.Errorf("ensure database schema: %w", err)
	}

	api, err := httpapi.New(database, config.PublicKey, config.APIPasswordHash, logger)
	if err != nil {
		return fmt.Errorf("create API: %w", err)
	}
	server := &http.Server{
		Addr:              config.HTTPAddr,
		Handler:           api,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("Registry API listening", "address", config.HTTPAddr, "key_id", buildrecord.KeyID(config.PublicKey))
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelShutdown()
		return server.Shutdown(shutdownCtx)
	}
}

func loadConfig() (config, error) {
	result := config{
		HTTPAddr:        envOrDefault("HTTP_ADDR", ":8080"),
		APIPasswordHash: os.Getenv("API_PWD_HASH"),
		MaxConns:        32,
	}
	databaseURL, err := databaseURLFromEnvironment()
	if err != nil {
		return result, err
	}
	result.DatabaseURL = databaseURL
	if result.APIPasswordHash == "" {
		return result, errors.New("API_PWD_HASH is required")
	}
	publicKey, err := buildrecord.DecodePublicKey(strings.TrimSpace(os.Getenv("RELEASE_PUBLIC_KEY")))
	if err != nil {
		return result, errors.New("RELEASE_PUBLIC_KEY must be the unpadded base64url of a 32-byte Ed25519 public key")
	}
	result.PublicKey = publicKey

	if value := os.Getenv("DB_MAX_CONNS"); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 32)
		if err != nil || parsed < 2 || parsed > 1000 {
			return result, errors.New("DB_MAX_CONNS must be between 2 and 1000")
		}
		result.MaxConns = int32(parsed)
	}
	return result, nil
}

func databaseURLFromEnvironment() (string, error) {
	host := strings.TrimSpace(os.Getenv("DB_HOST"))
	name := strings.TrimSpace(os.Getenv("DB_NAME"))
	port := strings.TrimSpace(os.Getenv("DB_PORT"))
	password := os.Getenv("DB_PWD")
	user := strings.TrimSpace(os.Getenv("DB_USER"))
	for variable, value := range map[string]string{
		"DB_HOST": host,
		"DB_NAME": name,
		"DB_PORT": port,
		"DB_PWD":  password,
		"DB_USER": user,
	} {
		if value == "" {
			return "", fmt.Errorf("%s is required", variable)
		}
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return "", errors.New("DB_PORT must be between 1 and 65535")
	}
	sslMode := envOrDefault("DB_SSLMODE", "verify-full")
	if !slices.Contains([]string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}, sslMode) {
		return "", errors.New("DB_SSLMODE is invalid")
	}
	query := url.Values{}
	query.Set("sslmode", sslMode)
	databaseURL := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, password),
		Host:     net.JoinHostPort(strings.Trim(host, "[]"), port),
		Path:     "/" + name,
		RawQuery: query.Encode(),
	}
	return databaseURL.String(), nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
