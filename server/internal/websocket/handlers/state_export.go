// internal/websocket/handlers/state_export.go
package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// exportState exports the current state from the database
func (h *WSHandler) exportState(ctx context.Context) (*StateExport, error) {
	// Create context with timeout for the entire operation
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Start read-only transaction
	tx, err := h.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, &DBOperationError{
			Operation: "begin transaction",
			Err:       err,
		}
	}
	defer tx.Rollback() // Will be no-op if transaction is committed

	export := &StateExport{}

	// 1. Query all connections
	rows, err := tx.QueryContext(ctx, `
		SELECT 
			newclientID, clientID, protocol, secret1, secret2,
			extIP, intIP, username, hostname, note,
			process, pid, arch, lastSEEN, os,
			proto, deleted_at, alias
		FROM connections
		ORDER BY lastSEEN DESC
	`)
	if err != nil {
		return nil, &DBOperationError{
			Operation: "query connections",
			Err:       err,
		}
	}
	defer rows.Close()

	for rows.Next() {
		var conn Connection
		var alias sql.NullString // Add this
		if err := rows.Scan(
			&conn.NewclientID, &conn.ClientID, &conn.Protocol, &conn.Secret1, &conn.Secret2,
			&conn.ExtIP, &conn.IntIP, &conn.Username, &conn.Hostname, &conn.Note,
			&conn.Process, &conn.PID, &conn.Arch, &conn.LastSeen, &conn.OS,
			&conn.Proto, &conn.DeletedAt, &alias); err != nil { // scan into alias
			return nil, &DBOperationError{
				Operation: "scan connection",
				Err:       err,
			}
		}

		// Set the alias if it exists
		if alias.Valid {
			conn.Alias = &alias.String
		}

		export.Connections = append(export.Connections, conn)
		logMessage(LOG_VERBOSE, "Exported connection: ClientID=%s, Hostname=%s, Alias=%v",
			conn.ClientID, conn.Hostname, conn.Alias)
	}

	// 2. Query all listeners
	rows, err = tx.QueryContext(ctx, `
        SELECT 
            id, name, protocol, port, ip
        FROM listeners 
        ORDER BY name ASC
    `)
	if err != nil {
		return nil, &DBOperationError{
			Operation: "query listeners",
			Err:       err,
		}
	}
	defer rows.Close()

	for rows.Next() {
		var listener Listener
		if err := rows.Scan(&listener.ID, &listener.Name, &listener.Protocol, &listener.Port, &listener.IP); err != nil {
			return nil, &DBOperationError{
				Operation: "scan listener",
				Err:       err,
			}
		}
		export.Listeners = append(export.Listeners, listener)
		logMessage(LOG_VERBOSE, "Exported listener: Name=%s, Protocol=%s, Port=%s",
			listener.Name, listener.Protocol, listener.Port)
	}

	// 3. Query recent commands
	rows, err = tx.QueryContext(ctx, `
        SELECT 
            id, username, guid, command, timestamp
        FROM commands 
        ORDER BY timestamp DESC
        LIMIT 1000
    `)
	if err != nil {
		return nil, &DBOperationError{
			Operation: "query commands",
			Err:       err,
		}
	}
	defer rows.Close()

	for rows.Next() {
		var cmd Command
		if err := rows.Scan(&cmd.ID, &cmd.Username, &cmd.GUID, &cmd.Command, &cmd.Timestamp); err != nil {
			return nil, &DBOperationError{
				Operation: "scan command",
				Err:       err,
			}
		}
		export.Commands = append(export.Commands, cmd)
		logMessage(LOG_VERBOSE, "Exported command: ID=%d, Command=%s", cmd.ID, cmd.Command)
	}

	// 4. Query command outputs
	if len(export.Commands) > 0 {
		cmdIDs := make([]string, len(export.Commands))
		for i, cmd := range export.Commands {
			cmdIDs[i] = fmt.Sprintf("%d", cmd.ID)
		}

		rows, err = tx.QueryContext(ctx, fmt.Sprintf(`
            SELECT id, command_id, output, timestamp 
            FROM command_outputs 
            WHERE command_id IN (%s)
            ORDER BY timestamp ASC`,
			strings.Join(cmdIDs, ",")))

		if err != nil {
			return nil, &DBOperationError{
				Operation: "query command outputs",
				Err:       err,
			}
		}
		defer rows.Close()

		for rows.Next() {
			var output CommandOutput
			if err := rows.Scan(&output.ID, &output.CommandID, &output.Output, &output.Timestamp); err != nil {
				return nil, &DBOperationError{
					Operation: "scan command output",
					Err:       err,
				}
			}
			export.CommandOutputs = append(export.CommandOutputs, output)
		}
	}

	// Log summary of exported data
	logMessage(LOG_NORMAL, "Export state summary:")
	logMessage(LOG_NORMAL, "- Connections: %d", len(export.Connections))
	logMessage(LOG_NORMAL, "- Listeners: %d", len(export.Listeners))
	logMessage(LOG_NORMAL, "- Commands: %d", len(export.Commands))
	logMessage(LOG_NORMAL, "- Command Outputs: %d", len(export.CommandOutputs))

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return nil, &DBOperationError{
			Operation: "commit transaction",
			Err:       err,
		}
	}

	return export, nil
}
