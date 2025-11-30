// internal/common/config/database.go
package config

import (
	"context"
	"database/sql"
	"log"
	"os"
	"time"
)

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type AuthConfig struct {
	ListenAddr string
	Database   *DatabaseConfig
}

func LoadDatabaseConfig() (*DatabaseConfig, error) {
	// Try POSTGRES_PASSWORD first (used in Docker), fall back to DB_PASSWORD
	dbPassword := os.Getenv("POSTGRES_PASSWORD")
	if dbPassword == "" {
		dbPassword = os.Getenv("DB_PASSWORD")
	}
	if dbPassword == "" {
		log.Printf("Warning: Neither POSTGRES_PASSWORD nor DB_PASSWORD environment variable is set")
	}

	// Get database host from environment, default to "database" for Docker
	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "database" // Docker service name
	}

	// Log configuration for debugging
	config := &DatabaseConfig{
		Host:     dbHost,
		Port:     5432,
		User:     "operator",
		Password: dbPassword,
		DBName:   "ops",
		SSLMode:  "disable",
	}

	log.Printf("Database Config: Host=%s, Port=%d, User=%s, DBName=%s, SSLMode=%s",
		config.Host, config.Port, config.User, config.DBName, config.SSLMode)

	return config, nil
}

func LoadAuthConfig() (*AuthConfig, error) {
	log.Printf("Loading auth config...")

	dbConfig, err := LoadDatabaseConfig()
	if err != nil {
		log.Printf("Failed to load database config: %v", err)
		return nil, err
	}

	config := &AuthConfig{
		ListenAddr: ":8080",
		Database:   dbConfig,
	}

	log.Printf("Auth config loaded: ListenAddr=%s", config.ListenAddr)
	return config, nil
}

func ConfigureDB(db *sql.DB) error {
	log.Println("Configuring database connection pool...")

	// Set reasonable pool sizes based on expected load
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(3 * time.Minute)

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Printf("Failed to verify database connection: %v", err)
		return err
	}

	log.Println("Database connection pool configured successfully")
	return nil
}
