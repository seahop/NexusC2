// internal/common/config/rest.go
package config

import (
	"log"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

type RESTConfig struct {
	ListenAddr  string
	APIPassword string // Shared API password for authentication
	TLS         struct {
		CertFile string
		KeyFile  string
	}
	JWT struct {
		SecretKey     string
		AccessExpiry  time.Duration
		RefreshExpiry time.Duration
	}
	RateLimit struct {
		RequestsPerMinute int
	}
	CORS struct {
		AllowedOrigins []string
	}
	Database *DatabaseConfig
}

type restTomlConfig struct {
	RestAPI struct {
		Port     string `toml:"port"`
		CertFile string `toml:"cert_file"`
		KeyFile  string `toml:"key_file"`

		JWT struct {
			AccessExpiry  string `toml:"access_expiry"`
			RefreshExpiry string `toml:"refresh_expiry"`
		} `toml:"jwt"`

		RateLimit struct {
			RequestsPerMinute int `toml:"requests_per_minute"`
		} `toml:"rate_limit"`

		CORS struct {
			AllowedOrigins []string `toml:"allowed_origins"`
		} `toml:"cors"`
	} `toml:"rest_api"`
}

func LoadRESTConfig() (*RESTConfig, error) {
	configPath := os.Getenv("CONFIG_FILE")
	if configPath == "" {
		configPath = "/app/config.toml"
	}

	var conf restTomlConfig
	if _, err := toml.DecodeFile(configPath, &conf); err != nil {
		return nil, err
	}

	dbConfig, err := LoadDatabaseConfig()
	if err != nil {
		return nil, err
	}

	// Parse durations with defaults
	accessExpiry := 1 * time.Hour
	if conf.RestAPI.JWT.AccessExpiry != "" {
		if parsed, err := time.ParseDuration(conf.RestAPI.JWT.AccessExpiry); err == nil {
			accessExpiry = parsed
		}
	}

	refreshExpiry := 24 * time.Hour
	if conf.RestAPI.JWT.RefreshExpiry != "" {
		if parsed, err := time.ParseDuration(conf.RestAPI.JWT.RefreshExpiry); err == nil {
			refreshExpiry = parsed
		}
	}

	// Get JWT secret from environment
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		// Generate a random secret if not provided (not recommended for production)
		jwtSecret = generateRandomSecret(32)
	}

	// Get shared API password from environment
	apiPassword := os.Getenv("API_PASSWORD")
	if apiPassword == "" {
		log.Println("Warning: API_PASSWORD not set. Password-based authentication will be unavailable.")
	}

	// Defaults
	if conf.RestAPI.RateLimit.RequestsPerMinute == 0 {
		conf.RestAPI.RateLimit.RequestsPerMinute = 100
	}
	if len(conf.RestAPI.CORS.AllowedOrigins) == 0 {
		conf.RestAPI.CORS.AllowedOrigins = []string{"*"}
	}
	if conf.RestAPI.Port == "" {
		conf.RestAPI.Port = "8443"
	}
	if conf.RestAPI.CertFile == "" {
		conf.RestAPI.CertFile = "/app/certs/api_server.crt"
	}
	if conf.RestAPI.KeyFile == "" {
		conf.RestAPI.KeyFile = "/app/certs/api_server.key"
	}

	return &RESTConfig{
		ListenAddr:  ":" + conf.RestAPI.Port,
		APIPassword: apiPassword,
		TLS: struct {
			CertFile string
			KeyFile  string
		}{
			CertFile: conf.RestAPI.CertFile,
			KeyFile:  conf.RestAPI.KeyFile,
		},
		JWT: struct {
			SecretKey     string
			AccessExpiry  time.Duration
			RefreshExpiry time.Duration
		}{
			SecretKey:     jwtSecret,
			AccessExpiry:  accessExpiry,
			RefreshExpiry: refreshExpiry,
		},
		RateLimit: struct {
			RequestsPerMinute int
		}{
			RequestsPerMinute: conf.RestAPI.RateLimit.RequestsPerMinute,
		},
		CORS: struct {
			AllowedOrigins []string
		}{
			AllowedOrigins: conf.RestAPI.CORS.AllowedOrigins,
		},
		Database: dbConfig,
	}, nil
}

func generateRandomSecret(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[int(time.Now().UnixNano())%len(charset)]
		time.Sleep(time.Nanosecond) // Add some variation
	}
	return string(b)
}
