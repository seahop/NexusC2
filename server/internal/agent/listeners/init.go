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
	TCPProfile string // TCP profile name for transform configuration
	TCPXorKey  string // Per-build unique XOR key for TCP transforms
	TCPPort    string // TCP port for TCP payloads
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
	log.Printf("Stored init data for client %s (total entries: %d)", data.ClientID, len(m.initData))

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
               COALESCE(smb_profile, ''), COALESCE(smb_xor_key, ''), COALESCE(http_xor_key, ''),
               COALESCE(tcp_profile, ''), COALESCE(tcp_xor_key, ''), COALESCE(protocol, '')
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
			&data.TCPProfile,
			&data.TCPXorKey,
			&data.Protocol,
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

	log.Printf("Loaded %d init data entries from database", count)

	return nil
}
