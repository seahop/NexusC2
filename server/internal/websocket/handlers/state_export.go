// internal/websocket/handlers/state_export.go
package handlers

import (
	"c2/internal/common/config"
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
			proto, deleted_at, alias, parent_clientID, link_type
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
		var alias sql.NullString
		var parentClientID sql.NullString
		var linkType sql.NullString
		if err := rows.Scan(
			&conn.NewclientID, &conn.ClientID, &conn.Protocol, &conn.Secret1, &conn.Secret2,
			&conn.ExtIP, &conn.IntIP, &conn.Username, &conn.Hostname, &conn.Note,
			&conn.Process, &conn.PID, &conn.Arch, &conn.LastSeen, &conn.OS,
			&conn.Proto, &conn.DeletedAt, &alias, &parentClientID, &linkType); err != nil {
			return nil, &DBOperationError{
				Operation: "scan connection",
				Err:       err,
			}
		}

		// Set the alias if it exists
		if alias.Valid {
			conn.Alias = &alias.String
		}
		// Set parent client ID if it exists (for linked agents)
		if parentClientID.Valid {
			conn.ParentClientID = &parentClientID.String
		}
		// Set link type if it exists
		if linkType.Valid {
			conn.LinkType = &linkType.String
		}

		export.Connections = append(export.Connections, conn)
		logMessage(LOG_VERBOSE, "Exported connection: ClientID=%s, Hostname=%s, Alias=%v, ParentClientID=%v, LinkType=%v",
			conn.ClientID, conn.Hostname, conn.Alias, conn.ParentClientID, conn.LinkType)
	}

	// 2. Query all listeners
	rows, err = tx.QueryContext(ctx, `
        SELECT
            id, name, protocol, port, ip, COALESCE(pipe_name, ''),
            COALESCE(get_profile, 'default-get'),
            COALESCE(post_profile, 'default-post'),
            COALESCE(server_response_profile, 'default-response'),
            COALESCE(smb_profile, '')
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
		if err := rows.Scan(&listener.ID, &listener.Name, &listener.Protocol, &listener.Port, &listener.IP, &listener.PipeName,
			&listener.GetProfile, &listener.PostProfile, &listener.ServerResponseProfile, &listener.SMBProfile); err != nil {
			return nil, &DBOperationError{
				Operation: "scan listener",
				Err:       err,
			}
		}
		export.Listeners = append(export.Listeners, listener)
		logMessage(LOG_VERBOSE, "Exported listener: Name=%s, Protocol=%s, Port=%s, PipeName=%s, Profiles: GET=%s POST=%s Response=%s SMB=%s",
			listener.Name, listener.Protocol, listener.Port, listener.PipeName,
			listener.GetProfile, listener.PostProfile, listener.ServerResponseProfile, listener.SMBProfile)
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

	// 4. Query command outputs using parameterized query
	if len(export.Commands) > 0 {
		cmdIDs := make([]interface{}, len(export.Commands))
		for i, cmd := range export.Commands {
			cmdIDs[i] = cmd.ID
		}

		// Build parameterized query with $1, $2, $3, etc.
		placeholders := make([]string, len(cmdIDs))
		for i := range placeholders {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
		}

		query := fmt.Sprintf(`
            SELECT id, command_id, output, timestamp
            FROM command_outputs
            WHERE command_id IN (%s)
            ORDER BY timestamp ASC`,
			strings.Join(placeholders, ","))

		rows, err = tx.QueryContext(ctx, query, cmdIDs...)

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

	// 5. Query all agent tags
	rows, err = tx.QueryContext(ctx, `
		SELECT agent_guid, tag_name, tag_color
		FROM agent_tags
		ORDER BY agent_guid, tag_name ASC
	`)
	if err != nil {
		return nil, &DBOperationError{
			Operation: "query agent tags",
			Err:       err,
		}
	}
	defer rows.Close()

	export.AgentTags = make(map[string][]Tag)
	for rows.Next() {
		var agentGUID string
		var tag Tag
		if err := rows.Scan(&agentGUID, &tag.Name, &tag.Color); err != nil {
			return nil, &DBOperationError{
				Operation: "scan agent tag",
				Err:       err,
			}
		}
		export.AgentTags[agentGUID] = append(export.AgentTags[agentGUID], tag)
		logMessage(LOG_VERBOSE, "Exported tag: Agent=%s, Tag=%s", agentGUID, tag.Name)
	}

	// 6. Populate available profiles from agent configuration
	if h.agentConfig != nil {
		profiles := &AvailableProfiles{
			Get:            make([]string, 0),
			Post:           make([]string, 0),
			ServerResponse: make([]string, 0),
			SMB:            make([]string, 0),
		}

		// Extract GET profile names
		for _, p := range h.agentConfig.HTTPProfiles.Get {
			profiles.Get = append(profiles.Get, p.Name)
		}

		// Extract POST profile names
		for _, p := range h.agentConfig.HTTPProfiles.Post {
			profiles.Post = append(profiles.Post, p.Name)
		}

		// Extract Server Response profile names
		for _, p := range h.agentConfig.HTTPProfiles.ServerResponse {
			profiles.ServerResponse = append(profiles.ServerResponse, p.Name)
		}

		// Extract SMB profile names from SMB config
		if smbConfig, err := config.GetSMBLinkConfig(); err == nil && smbConfig != nil {
			profiles.SMB = smbConfig.GetSMBProfileNames()
		}

		export.AvailableProfiles = profiles
		logMessage(LOG_VERBOSE, "Exported available profiles: GET=%d, POST=%d, ServerResponse=%d, SMB=%d",
			len(profiles.Get), len(profiles.Post), len(profiles.ServerResponse), len(profiles.SMB))
	}

	// Log summary of exported data
	logMessage(LOG_NORMAL, "Export state summary:")
	logMessage(LOG_NORMAL, "- Connections: %d", len(export.Connections))
	logMessage(LOG_NORMAL, "- Listeners: %d", len(export.Listeners))
	logMessage(LOG_NORMAL, "- Commands: %d", len(export.Commands))
	logMessage(LOG_NORMAL, "- Command Outputs: %d", len(export.CommandOutputs))
	logMessage(LOG_NORMAL, "- Agent Tags: %d agents with tags", len(export.AgentTags))
	if export.AvailableProfiles != nil {
		logMessage(LOG_NORMAL, "- Available Profiles: GET=%d, POST=%d, Response=%d, SMB=%d",
			len(export.AvailableProfiles.Get), len(export.AvailableProfiles.Post), len(export.AvailableProfiles.ServerResponse), len(export.AvailableProfiles.SMB))
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return nil, &DBOperationError{
			Operation: "commit transaction",
			Err:       err,
		}
	}

	return export, nil
}
