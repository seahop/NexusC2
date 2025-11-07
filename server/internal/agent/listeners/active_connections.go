// internal/agent/listeners/active_connections.go
package listeners

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"
)

type ActiveConnection struct {
	ClientID string
	Protocol string
	Secret1  string
	Secret2  string
}

type ActiveConnectionManager struct {
	connections map[string]*ActiveConnection
	mutex       sync.RWMutex
	db          *sql.DB
}

func newActiveConnectionManager(db *sql.DB) *ActiveConnectionManager {
	acm := &ActiveConnectionManager{
		connections: make(map[string]*ActiveConnection),
		db:          db,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := acm.loadConnectionsFromDB(ctx); err != nil {
		log.Printf("Warning: Failed to load connections from database: %v", err)
	}
	return acm
}

func (acm *ActiveConnectionManager) loadConnectionsFromDB(ctx context.Context) error {
	query := `
        SELECT clientID, protocol, secret1, secret2 
        FROM connections 
        WHERE deleted_at IS NULL
        AND lastSEEN > $1
    `
	// Only load connections seen in the last hour
	cutoff := time.Now().Add(-1 * time.Hour)

	rows, err := acm.db.QueryContext(ctx, query, cutoff)
	if err != nil {
		return fmt.Errorf("failed to query connections table: %v", err)
	}
	defer rows.Close()

	var count int
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	// Clear existing connections before loading
	acm.connections = make(map[string]*ActiveConnection)

	for rows.Next() {
		var conn ActiveConnection
		if err := rows.Scan(
			&conn.ClientID,
			&conn.Protocol,
			&conn.Secret1,
			&conn.Secret2,
		); err != nil {
			log.Printf("Error scanning connection row: %v", err)
			continue
		}

		acm.connections[conn.ClientID] = &conn
		count++
	}

	if err = rows.Err(); err != nil {
		return fmt.Errorf("error iterating connection rows: %v", err)
	}

	log.Printf("Loaded %d active connections from database", count)
	if count > 0 {
		log.Printf("Current Active Connections:")
		for clientID, conn := range acm.connections {
			log.Printf("ClientID: %s, Protocol: %s, Secret lengths: %d/%d",
				clientID, conn.Protocol, len(conn.Secret1), len(conn.Secret2))
		}
	}

	return nil
}

func (acm *ActiveConnectionManager) AddConnection(conn *ActiveConnection) error {
	if conn == nil {
		return fmt.Errorf("connection cannot be nil")
	}
	if conn.ClientID == "" {
		return fmt.Errorf("client ID cannot be empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start transaction
	tx, err := acm.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Check if connection exists in database
	var exists bool
	err = tx.QueryRowContext(ctx, `
        SELECT EXISTS(
            SELECT 1 FROM connections 
            WHERE clientID = $1 
            AND deleted_at IS NULL
        )`, conn.ClientID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check connection existence: %v", err)
	}

	if exists {
		return fmt.Errorf("connection already exists for client ID: %s", conn.ClientID)
	}

	// Update memory first
	acm.mutex.Lock()
	if _, exists := acm.connections[conn.ClientID]; exists {
		acm.mutex.Unlock()
		return fmt.Errorf("connection already exists in memory for client ID: %s", conn.ClientID)
	}
	acm.connections[conn.ClientID] = conn
	acm.mutex.Unlock()

	if err := tx.Commit(); err != nil {
		// If commit fails, remove from memory
		acm.mutex.Lock()
		delete(acm.connections, conn.ClientID)
		acm.mutex.Unlock()
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	log.Printf("Successfully added connection for client: %s", conn.ClientID)
	return nil
}

func (acm *ActiveConnectionManager) RemoveConnection(clientID string) error {
	if clientID == "" {
		return fmt.Errorf("client ID cannot be empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := acm.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Soft delete in database
	result, err := tx.ExecContext(ctx, `
        UPDATE connections 
        SET deleted_at = CURRENT_TIMESTAMP 
        WHERE clientID = $1 
        AND deleted_at IS NULL`,
		clientID)
	if err != nil {
		return fmt.Errorf("failed to mark connection as deleted: %v", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %v", err)
	}

	// Remove from memory
	acm.mutex.Lock()
	delete(acm.connections, clientID)
	acm.mutex.Unlock()

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	log.Printf("Successfully removed connection for client %s, affected %d rows", clientID, rows)
	return nil
}

func (acm *ActiveConnectionManager) GetConnection(clientID string) (*ActiveConnection, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client ID cannot be empty")
	}

	acm.mutex.RLock()
	conn, exists := acm.connections[clientID]
	acm.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no active connection found for client ID: %s", clientID)
	}

	// Update last seen timestamp in database
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := acm.db.ExecContext(ctx, `
        UPDATE connections 
        SET lastSEEN = CURRENT_TIMESTAMP 
        WHERE clientID = $1 
        AND deleted_at IS NULL`,
		clientID)
	if err != nil {
		log.Printf("Warning: Failed to update lastSEEN timestamp: %v", err)
		// Continue anyway as this is not critical
	}

	return conn, nil
}
