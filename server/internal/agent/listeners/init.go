// internal/agent/listeners/init.go
package listeners

import (
	"fmt"
	"log"
)

// InitData represents the initialization data for a new agent
type InitData struct {
	ID         string
	ClientID   string
	Type       string
	Secret     string
	OS         string
	Arch       string
	RSAKey     string
	Protocol   string
	SMBProfile string // SMB profile name for transform configuration
	SMBXorKey  string // Per-build unique XOR key for SMB transforms
	HTTPXorKey string // Per-build unique XOR key for HTTP transforms
}

// StoreInitData stores the initialization data in memory
func (m *Manager) StoreInitData(data *InitData) error {
	if data == nil {
		return fmt.Errorf("init data cannot be nil")
	}
	if data.ClientID == "" {
		return fmt.Errorf("client ID cannot be empty")
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.initData[data.ClientID] = data
	log.Printf("Stored init data for client %s", data.ClientID)

	// Debug output showing all stored init data
	log.Printf("Current InitData Map State (%d entries):", len(m.initData))
	for clientID, initData := range m.initData {
		log.Printf("----------------------------------------------")
		log.Printf("ClientID: %s", clientID)
		log.Printf("  ID: %s", initData.ID)
		log.Printf("  Type: %s", initData.Type)
		log.Printf("  Protocol: %s", initData.Protocol)
		log.Printf("  OS: %s", initData.OS)
		log.Printf("  Architecture: %s", initData.Arch)
		log.Printf("  Secret Length: %d chars", len(initData.Secret))
		log.Printf("  RSA Key Length: %d chars", len(initData.RSAKey))
		if initData.SMBProfile != "" {
			log.Printf("  SMB Profile: %s", initData.SMBProfile)
		}
		if initData.SMBXorKey != "" {
			log.Printf("  SMB XOR Key: %s... (%d chars)", initData.SMBXorKey[:min(4, len(initData.SMBXorKey))], len(initData.SMBXorKey))
		}
		if initData.HTTPXorKey != "" {
			log.Printf("  HTTP XOR Key: %s... (%d chars)", initData.HTTPXorKey[:min(4, len(initData.HTTPXorKey))], len(initData.HTTPXorKey))
		}
	}
	log.Printf("----------------------------------------------")

	return nil
}

// GetInitData retrieves initialization data for a given client ID
func (m *Manager) GetInitData(clientID string) (*InitData, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	data, exists := m.initData[clientID]
	if !exists {
		return nil, fmt.Errorf("no init data found for client ID: %s", clientID)
	}
	return data, nil
}

// RemoveInitData removes initialization data for a given client ID
func (m *Manager) RemoveInitData(clientID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.initData, clientID)
	log.Printf("Removed init data for client %s", clientID)
}

func (m *Manager) loadInitDataFromDB() error {
	query := `
        SELECT id, clientID, type, secret, os, arch, RSAkey,
               COALESCE(smb_profile, ''), COALESCE(smb_xor_key, ''), COALESCE(http_xor_key, '')
        FROM inits
        WHERE id IS NOT NULL`

	rows, err := m.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query inits table: %v", err)
	}
	defer rows.Close()

	var count int
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for rows.Next() {
		var data InitData
		err := rows.Scan(
			&data.ID,
			&data.ClientID,
			&data.Type,
			&data.Secret,
			&data.OS,
			&data.Arch,
			&data.RSAKey,
			&data.SMBProfile,
			&data.SMBXorKey,
			&data.HTTPXorKey,
		)
		if err != nil {
			log.Printf("Error scanning init row: %v", err)
			continue
		}

		m.initData[data.ClientID] = &data
		count++
	}

	if err = rows.Err(); err != nil {
		return fmt.Errorf("error iterating init rows: %v", err)
	}

	// Debug output showing loaded data
	log.Printf("Loaded InitData from Database (%d entries):", count)
	for clientID, initData := range m.initData {
		log.Printf("----------------------------------------------")
		log.Printf("ClientID: %s", clientID)
		log.Printf("  ID: %s", initData.ID)
		log.Printf("  Type: %s", initData.Type)
		log.Printf("  OS: %s", initData.OS)
		log.Printf("  Architecture: %s", initData.Arch)
		log.Printf("  Secret Length: %d chars", len(initData.Secret))
		log.Printf("  RSA Key Length: %d chars", len(initData.RSAKey))
		if initData.SMBProfile != "" {
			log.Printf("  SMB Profile: %s", initData.SMBProfile)
		}
		if initData.SMBXorKey != "" {
			log.Printf("  SMB XOR Key: %s... (%d chars)", initData.SMBXorKey[:min(4, len(initData.SMBXorKey))], len(initData.SMBXorKey))
		}
		if initData.HTTPXorKey != "" {
			log.Printf("  HTTP XOR Key: %s... (%d chars)", initData.HTTPXorKey[:min(4, len(initData.HTTPXorKey))], len(initData.HTTPXorKey))
		}
	}
	if count > 0 {
		log.Printf("----------------------------------------------")
	}

	return nil
}
