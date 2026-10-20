// internal/database/postgres/connection.go
package postgres

import (
	"c2/internal/common/config"
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
)

// NewConnection creates a new database connection with the given pool settings.
// If pool is nil, default pool settings are used.
func NewConnection(cfg *config.DatabaseConfig, pool *PoolConfig) (*sql.DB, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host,
		cfg.Port,
		cfg.User,
		cfg.Password,
		cfg.DBName,
		cfg.SSLMode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Apply pool settings from the provided config, or use defaults
	if pool != nil {
		db.SetMaxOpenConns(pool.MaxOpenConns)
		db.SetMaxIdleConns(pool.MaxIdleConns)
		db.SetConnMaxLifetime(pool.ConnMaxLifetime)
		db.SetConnMaxIdleTime(pool.ConnMaxIdleTime)
	} else {
		defaults := DefaultOptimizedPoolConfig()
		db.SetMaxOpenConns(defaults.MaxOpenConns)
		db.SetMaxIdleConns(defaults.MaxIdleConns)
		db.SetConnMaxLifetime(defaults.ConnMaxLifetime)
		db.SetConnMaxIdleTime(defaults.ConnMaxIdleTime)
	}

	// Test the connection with context timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err = db.PingContext(ctx); err != nil {
		db.Close() // Clean up if ping fails
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Log successful configuration
	stats := db.Stats()
	log.Printf("Database connected and configured successfully (Max Open: %d)",
		stats.MaxOpenConnections)

	return db, nil
}
