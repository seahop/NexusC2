// internal/common/config/smb_link.go
package config

import (
	"fmt"
	"sync"

	"github.com/BurntSushi/toml"
)

// SMBLinkConfig holds configuration for SMB-based agent linking
type SMBLinkConfig struct {
	ConnectionTimeout int              `toml:"connection_timeout"`
	MaxMessageSize    int              `toml:"max_message_size"`
	HeartbeatInterval int              `toml:"heartbeat_interval"`
	PipePresets       []PipePreset     `toml:"pipe_presets"`
	Malleable         SMBLinkMalleable `toml:"malleable"`
	mu                sync.RWMutex
}

// PipePreset represents a legitimate-looking pipe name suggestion
type PipePreset struct {
	Name        string `toml:"name"`
	Description string `toml:"description"`
}

// SMBLinkMalleable holds customizable field names for the link protocol
type SMBLinkMalleable struct {
	LinkDataField              string `toml:"link_data_field"`
	LinkCommandsField          string `toml:"link_commands_field"`
	LinkHandshakeField         string `toml:"link_handshake_field"`
	LinkHandshakeResponseField string `toml:"link_handshake_response_field"`
	RoutingIDField             string `toml:"routing_id_field"`
	PayloadField               string `toml:"payload_field"`
}

type smbLinkTomlConfig struct {
	SMBLink SMBLinkConfig `toml:"smb_link"`
}

var (
	smbLinkConfig *SMBLinkConfig
	smbLinkOnce   sync.Once
)

// LoadSMBLinkConfig loads the SMB link configuration from config.toml
func LoadSMBLinkConfig() (*SMBLinkConfig, error) {
	var conf smbLinkTomlConfig
	if _, err := toml.DecodeFile("/app/config.toml", &conf); err != nil {
		return nil, fmt.Errorf("failed to decode config.toml: %w", err)
	}

	config := &conf.SMBLink

	// Set defaults if not specified
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 30
	}
	if config.MaxMessageSize == 0 {
		config.MaxMessageSize = 1048576 // 1MB
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 60
	}

	// Set default malleable field names
	if config.Malleable.LinkDataField == "" {
		config.Malleable.LinkDataField = "ld"
	}
	if config.Malleable.LinkCommandsField == "" {
		config.Malleable.LinkCommandsField = "lc"
	}
	if config.Malleable.LinkHandshakeField == "" {
		config.Malleable.LinkHandshakeField = "lh"
	}
	if config.Malleable.LinkHandshakeResponseField == "" {
		config.Malleable.LinkHandshakeResponseField = "lr"
	}
	if config.Malleable.RoutingIDField == "" {
		config.Malleable.RoutingIDField = "r"
	}
	if config.Malleable.PayloadField == "" {
		config.Malleable.PayloadField = "p"
	}

	return config, nil
}

// GetSMBLinkConfig returns the singleton instance of SMBLinkConfig
func GetSMBLinkConfig() (*SMBLinkConfig, error) {
	var err error
	smbLinkOnce.Do(func() {
		smbLinkConfig, err = LoadSMBLinkConfig()
	})
	return smbLinkConfig, err
}

// GetPipePresets returns the list of pipe name presets
func (c *SMBLinkConfig) GetPipePresets() []PipePreset {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.PipePresets
}

// GetMalleable returns the malleable field configuration
func (c *SMBLinkConfig) GetMalleable() SMBLinkMalleable {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Malleable
}
