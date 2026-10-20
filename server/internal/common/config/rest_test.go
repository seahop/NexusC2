// internal/common/config/rest_test.go
package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateRandomSecret(t *testing.T) {
	t.Parallel()

	t.Run("produces non-empty output", func(t *testing.T) {
		t.Parallel()
		secret := generateRandomSecret()
		if secret == "" {
			t.Fatal("generateRandomSecret returned empty string")
		}
	})

	t.Run("produces valid base64 URL encoding", func(t *testing.T) {
		t.Parallel()
		secret := generateRandomSecret()
		decoded, err := base64.URLEncoding.DecodeString(secret)
		if err != nil {
			t.Fatalf("generateRandomSecret produced invalid base64: %v", err)
		}
		// Should be 32 bytes of random data
		if len(decoded) != 32 {
			t.Errorf("expected 32 decoded bytes, got %d", len(decoded))
		}
	})

	t.Run("produces different values each call (crypto/rand)", func(t *testing.T) {
		t.Parallel()
		secrets := make(map[string]bool)
		for i := 0; i < 100; i++ {
			s := generateRandomSecret()
			if secrets[s] {
				t.Fatalf("generateRandomSecret produced duplicate on iteration %d", i)
			}
			secrets[s] = true
		}
	})

	t.Run("has sufficient entropy (32 bytes = 256 bits)", func(t *testing.T) {
		t.Parallel()
		secret := generateRandomSecret()
		decoded, err := base64.URLEncoding.DecodeString(secret)
		if err != nil {
			t.Fatalf("decode error: %v", err)
		}
		// Check it's not all zeros (extremely unlikely with crypto/rand, but guards against bugs)
		allZero := true
		for _, b := range decoded {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Fatal("generateRandomSecret produced all-zero bytes (broken RNG)")
		}
	})
}

func TestLoadDatabaseConfig(t *testing.T) {
	t.Run("SSLMode defaults to disable", func(t *testing.T) {
		// Clear env vars that might interfere
		origPassword := os.Getenv("POSTGRES_PASSWORD")
		origDBPass := os.Getenv("DB_PASSWORD")
		origDBHost := os.Getenv("DB_HOST")
		defer func() {
			os.Setenv("POSTGRES_PASSWORD", origPassword)
			os.Setenv("DB_PASSWORD", origDBPass)
			os.Setenv("DB_HOST", origDBHost)
		}()

		os.Setenv("POSTGRES_PASSWORD", "testpass")
		os.Setenv("DB_HOST", "testhost")

		cfg, err := LoadDatabaseConfig()
		if err != nil {
			t.Fatalf("LoadDatabaseConfig returned error: %v", err)
		}

		if cfg.SSLMode != "disable" {
			t.Errorf("expected SSLMode 'disable', got '%s'", cfg.SSLMode)
		}
	})

	t.Run("default host is database when DB_HOST unset", func(t *testing.T) {
		origDBHost := os.Getenv("DB_HOST")
		defer os.Setenv("DB_HOST", origDBHost)

		os.Unsetenv("DB_HOST")

		cfg, err := LoadDatabaseConfig()
		if err != nil {
			t.Fatalf("LoadDatabaseConfig returned error: %v", err)
		}

		if cfg.Host != "database" {
			t.Errorf("expected default Host 'database', got '%s'", cfg.Host)
		}
	})

	t.Run("DB_HOST env var is respected", func(t *testing.T) {
		origDBHost := os.Getenv("DB_HOST")
		defer os.Setenv("DB_HOST", origDBHost)

		os.Setenv("DB_HOST", "custom-host")

		cfg, err := LoadDatabaseConfig()
		if err != nil {
			t.Fatalf("LoadDatabaseConfig returned error: %v", err)
		}

		if cfg.Host != "custom-host" {
			t.Errorf("expected Host 'custom-host', got '%s'", cfg.Host)
		}
	})

	t.Run("default port is 5432", func(t *testing.T) {
		cfg, err := LoadDatabaseConfig()
		if err != nil {
			t.Fatalf("LoadDatabaseConfig returned error: %v", err)
		}

		if cfg.Port != 5432 {
			t.Errorf("expected Port 5432, got %d", cfg.Port)
		}
	})

	t.Run("default user is operator", func(t *testing.T) {
		cfg, err := LoadDatabaseConfig()
		if err != nil {
			t.Fatalf("LoadDatabaseConfig returned error: %v", err)
		}

		if cfg.User != "operator" {
			t.Errorf("expected User 'operator', got '%s'", cfg.User)
		}
	})

	t.Run("default dbname is ops", func(t *testing.T) {
		cfg, err := LoadDatabaseConfig()
		if err != nil {
			t.Fatalf("LoadDatabaseConfig returned error: %v", err)
		}

		if cfg.DBName != "ops" {
			t.Errorf("expected DBName 'ops', got '%s'", cfg.DBName)
		}
	})

	t.Run("DB_PASSWORD takes precedence over POSTGRES_PASSWORD", func(t *testing.T) {
		origPG := os.Getenv("POSTGRES_PASSWORD")
		origDB := os.Getenv("DB_PASSWORD")
		defer func() {
			os.Setenv("POSTGRES_PASSWORD", origPG)
			os.Setenv("DB_PASSWORD", origDB)
		}()

		os.Setenv("POSTGRES_PASSWORD", "pg-pass")
		os.Setenv("DB_PASSWORD", "db-pass")

		cfg, err := LoadDatabaseConfig()
		if err != nil {
			t.Fatalf("LoadDatabaseConfig returned error: %v", err)
		}

		if cfg.Password != "db-pass" {
			t.Errorf("expected Password 'db-pass' (from DB_PASSWORD), got '%s'", cfg.Password)
		}
	})

	t.Run("falls back to POSTGRES_PASSWORD when DB_PASSWORD unset", func(t *testing.T) {
		origPG := os.Getenv("POSTGRES_PASSWORD")
		origDB := os.Getenv("DB_PASSWORD")
		defer func() {
			os.Setenv("POSTGRES_PASSWORD", origPG)
			os.Setenv("DB_PASSWORD", origDB)
		}()

		os.Unsetenv("DB_PASSWORD")
		os.Setenv("POSTGRES_PASSWORD", "fallback-pass")

		cfg, err := LoadDatabaseConfig()
		if err != nil {
			t.Fatalf("LoadDatabaseConfig returned error: %v", err)
		}

		if cfg.Password != "fallback-pass" {
			t.Errorf("expected Password 'fallback-pass' (from POSTGRES_PASSWORD), got '%s'", cfg.Password)
		}
	})
}

func TestLoadRESTConfig(t *testing.T) {
	t.Run("CORS defaults to restrictive localhost origins", func(t *testing.T) {
		// Create a minimal config file
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.toml")
		err := os.WriteFile(configFile, []byte(`
[rest_api]
port = "9999"
`), 0600)
		if err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		// Save and set env vars
		origConfigFile := os.Getenv("CONFIG_FILE")
		origPGPass := os.Getenv("POSTGRES_PASSWORD")
		origJWT := os.Getenv("JWT_SECRET")
		defer func() {
			os.Setenv("CONFIG_FILE", origConfigFile)
			os.Setenv("POSTGRES_PASSWORD", origPGPass)
			os.Setenv("JWT_SECRET", origJWT)
		}()

		os.Setenv("CONFIG_FILE", configFile)
		os.Setenv("POSTGRES_PASSWORD", "testpass")
		os.Setenv("JWT_SECRET", "test-jwt-secret")

		cfg, err := LoadRESTConfig()
		if err != nil {
			t.Fatalf("LoadRESTConfig returned error: %v", err)
		}

		expectedOrigins := []string{"https://localhost:3131", "https://127.0.0.1:3131"}
		if len(cfg.CORS.AllowedOrigins) != len(expectedOrigins) {
			t.Fatalf("expected %d CORS origins, got %d: %v",
				len(expectedOrigins), len(cfg.CORS.AllowedOrigins), cfg.CORS.AllowedOrigins)
		}
		for i, expected := range expectedOrigins {
			if cfg.CORS.AllowedOrigins[i] != expected {
				t.Errorf("CORS origin[%d]: expected %q, got %q", i, expected, cfg.CORS.AllowedOrigins[i])
			}
		}

		// Verify CORS does NOT default to wildcard
		for _, origin := range cfg.CORS.AllowedOrigins {
			if origin == "*" {
				t.Error("CORS default should not include wildcard '*'")
			}
		}
	})

	t.Run("JWT secret from environment is used", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.toml")
		err := os.WriteFile(configFile, []byte("[rest_api]\n"), 0600)
		if err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		origConfigFile := os.Getenv("CONFIG_FILE")
		origPGPass := os.Getenv("POSTGRES_PASSWORD")
		origJWT := os.Getenv("JWT_SECRET")
		defer func() {
			os.Setenv("CONFIG_FILE", origConfigFile)
			os.Setenv("POSTGRES_PASSWORD", origPGPass)
			os.Setenv("JWT_SECRET", origJWT)
		}()

		os.Setenv("CONFIG_FILE", configFile)
		os.Setenv("POSTGRES_PASSWORD", "testpass")
		os.Setenv("JWT_SECRET", "my-specific-jwt-secret")

		cfg, err := LoadRESTConfig()
		if err != nil {
			t.Fatalf("LoadRESTConfig returned error: %v", err)
		}

		if cfg.JWT.SecretKey != "my-specific-jwt-secret" {
			t.Errorf("expected JWT secret from env, got %q", cfg.JWT.SecretKey)
		}
	})

	t.Run("generates random JWT secret when env not set", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.toml")
		err := os.WriteFile(configFile, []byte("[rest_api]\n"), 0600)
		if err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		origConfigFile := os.Getenv("CONFIG_FILE")
		origPGPass := os.Getenv("POSTGRES_PASSWORD")
		origJWT := os.Getenv("JWT_SECRET")
		defer func() {
			os.Setenv("CONFIG_FILE", origConfigFile)
			os.Setenv("POSTGRES_PASSWORD", origPGPass)
			os.Setenv("JWT_SECRET", origJWT)
		}()

		os.Setenv("CONFIG_FILE", configFile)
		os.Setenv("POSTGRES_PASSWORD", "testpass")
		os.Unsetenv("JWT_SECRET")

		cfg, err := LoadRESTConfig()
		if err != nil {
			t.Fatalf("LoadRESTConfig returned error: %v", err)
		}

		if cfg.JWT.SecretKey == "" {
			t.Fatal("JWT secret should be auto-generated when env not set")
		}

		// Verify it's valid base64 (from generateRandomSecret)
		_, decErr := base64.URLEncoding.DecodeString(cfg.JWT.SecretKey)
		if decErr != nil {
			t.Errorf("auto-generated JWT secret is not valid base64: %v", decErr)
		}
	})

	t.Run("default rate limit is 100 requests per minute", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.toml")
		err := os.WriteFile(configFile, []byte("[rest_api]\n"), 0600)
		if err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		origConfigFile := os.Getenv("CONFIG_FILE")
		origPGPass := os.Getenv("POSTGRES_PASSWORD")
		origJWT := os.Getenv("JWT_SECRET")
		defer func() {
			os.Setenv("CONFIG_FILE", origConfigFile)
			os.Setenv("POSTGRES_PASSWORD", origPGPass)
			os.Setenv("JWT_SECRET", origJWT)
		}()

		os.Setenv("CONFIG_FILE", configFile)
		os.Setenv("POSTGRES_PASSWORD", "testpass")
		os.Setenv("JWT_SECRET", "secret")

		cfg, err := LoadRESTConfig()
		if err != nil {
			t.Fatalf("LoadRESTConfig returned error: %v", err)
		}

		if cfg.RateLimit.RequestsPerMinute != 100 {
			t.Errorf("expected default rate limit 100, got %d", cfg.RateLimit.RequestsPerMinute)
		}
	})

	t.Run("default access expiry is 1 hour", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.toml")
		err := os.WriteFile(configFile, []byte("[rest_api]\n"), 0600)
		if err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		origConfigFile := os.Getenv("CONFIG_FILE")
		origPGPass := os.Getenv("POSTGRES_PASSWORD")
		origJWT := os.Getenv("JWT_SECRET")
		defer func() {
			os.Setenv("CONFIG_FILE", origConfigFile)
			os.Setenv("POSTGRES_PASSWORD", origPGPass)
			os.Setenv("JWT_SECRET", origJWT)
		}()

		os.Setenv("CONFIG_FILE", configFile)
		os.Setenv("POSTGRES_PASSWORD", "testpass")
		os.Setenv("JWT_SECRET", "secret")

		cfg, err := LoadRESTConfig()
		if err != nil {
			t.Fatalf("LoadRESTConfig returned error: %v", err)
		}

		if cfg.JWT.AccessExpiry != 1*time.Hour {
			t.Errorf("expected default access expiry 1h, got %v", cfg.JWT.AccessExpiry)
		}
	})

	t.Run("default listen port is 8443", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.toml")
		err := os.WriteFile(configFile, []byte("[rest_api]\n"), 0600)
		if err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		origConfigFile := os.Getenv("CONFIG_FILE")
		origPGPass := os.Getenv("POSTGRES_PASSWORD")
		origJWT := os.Getenv("JWT_SECRET")
		defer func() {
			os.Setenv("CONFIG_FILE", origConfigFile)
			os.Setenv("POSTGRES_PASSWORD", origPGPass)
			os.Setenv("JWT_SECRET", origJWT)
		}()

		os.Setenv("CONFIG_FILE", configFile)
		os.Setenv("POSTGRES_PASSWORD", "testpass")
		os.Setenv("JWT_SECRET", "secret")

		cfg, err := LoadRESTConfig()
		if err != nil {
			t.Fatalf("LoadRESTConfig returned error: %v", err)
		}

		if cfg.ListenAddr != ":8443" {
			t.Errorf("expected default listen addr ':8443', got '%s'", cfg.ListenAddr)
		}
	})
}
