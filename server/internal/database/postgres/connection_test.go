// internal/database/postgres/connection_test.go
package postgres

import (
	"testing"

	"c2/internal/common/config"
)

func TestNewConnection(t *testing.T) {
	cfg, err := config.LoadDatabaseConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	db, err := NewConnection(cfg)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Test connection with direct Ping
	err = db.Ping()
	if err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}
}
