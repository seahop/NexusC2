// internal/common/config/malleable.go
package config

import (
	"fmt"
	"sync"

	"github.com/BurntSushi/toml"
)

// MalleableCommandsConfig holds customizable command values
type MalleableCommandsConfig struct {
	RekeyCommand      string
	RekeyStatusField  string
	RekeyDataField    string
	RekeyIDField      string
	mu                sync.RWMutex
}

type malleableTomlConfig struct {
	PayloadConfig struct {
		MalleableCommands struct {
			Rekey            string `toml:"rekey"`
			RekeyStatusField string `toml:"rekey_status_field"`
			RekeyDataField   string `toml:"rekey_data_field"`
			RekeyIDField     string `toml:"rekey_id_field"`
		} `toml:"malleable_commands"`
	} `toml:"payload_config"`
}

var (
	malleableConfig *MalleableCommandsConfig
	malleableOnce   sync.Once
)

// LoadMalleableConfig loads the malleable commands configuration from config.toml
func LoadMalleableConfig() (*MalleableCommandsConfig, error) {
	var conf malleableTomlConfig
	if _, err := toml.DecodeFile("/app/config.toml", &conf); err != nil {
		return nil, fmt.Errorf("failed to decode config.toml: %w", err)
	}

	// Default to "rekey" if not specified
	rekeyCmd := conf.PayloadConfig.MalleableCommands.Rekey
	if rekeyCmd == "" {
		rekeyCmd = "rekey"
	}

	// Default field names if not specified
	statusField := conf.PayloadConfig.MalleableCommands.RekeyStatusField
	if statusField == "" {
		statusField = "status"
	}

	dataField := conf.PayloadConfig.MalleableCommands.RekeyDataField
	if dataField == "" {
		dataField = "data"
	}

	idField := conf.PayloadConfig.MalleableCommands.RekeyIDField
	if idField == "" {
		idField = "command_db_id"
	}

	return &MalleableCommandsConfig{
		RekeyCommand:     rekeyCmd,
		RekeyStatusField: statusField,
		RekeyDataField:   dataField,
		RekeyIDField:     idField,
	}, nil
}

// GetMalleableConfig returns the singleton instance of MalleableCommandsConfig
// It loads the config on first call and caches it for subsequent calls
func GetMalleableConfig() (*MalleableCommandsConfig, error) {
	var err error
	malleableOnce.Do(func() {
		malleableConfig, err = LoadMalleableConfig()
	})
	return malleableConfig, err
}

// GetRekeyCommand returns the current rekey command value
func (m *MalleableCommandsConfig) GetRekeyCommand() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.RekeyCommand
}
