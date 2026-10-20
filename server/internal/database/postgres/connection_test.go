// internal/database/postgres/connection_test.go
package postgres

import (
	"os"
	"testing"

	"c2/internal/common/config"
)

func TestNewConnection(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test (set INTEGRATION_TEST=1 to run)")
	}

	cfg, err := config.LoadDatabaseConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	db, err := NewConnection(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}
}
