// internal/common/config/tcp_link.go
package config

import (
	"fmt"
	"sync"

	"github.com/BurntSushi/toml"
)

// TCPLinkConfig holds configuration for TCP-based agent linking
type TCPLinkConfig struct {
	DefaultPort       int              `toml:"default_port"`
	ConnectionTimeout int              `toml:"connection_timeout"`
	MaxMessageSize    int              `toml:"max_message_size"`
	HeartbeatInterval int              `toml:"heartbeat_interval"`
	Malleable         TCPLinkMalleable `toml:"malleable"`
	Profiles          []TCPProfile     `toml:"profiles"`
	mu                sync.RWMutex
}

// TCPLinkMalleable holds customizable field names for the TCP link protocol
// Uses the same field names as SMB for consistency
type TCPLinkMalleable struct {
	LinkDataField              string `toml:"link_data_field"`
	LinkCommandsField          string `toml:"link_commands_field"`
	LinkHandshakeField         string `toml:"link_handshake_field"`
	LinkHandshakeResponseField string `toml:"link_handshake_response_field"`
	LinkUnlinkField            string `toml:"link_unlink_field"`
	RoutingIDField             string `toml:"routing_id_field"`
	PayloadField               string `toml:"payload_field"`
}

// TCPProfile defines malleable transforms for TCP traffic
type TCPProfile struct {
	Name string     `toml:"name" json:"name"`
	Data *DataBlock `toml:"data,omitempty" json:"data,omitempty"`
}

type tcpLinkTomlConfig struct {
	TCPLink TCPLinkConfig `toml:"tcp_link"`
}

var (
	tcpLinkConfig *TCPLinkConfig
	tcpLinkOnce   sync.Once
)

// LoadTCPLinkConfig loads the TCP link configuration from config.toml
func LoadTCPLinkConfig() (*TCPLinkConfig, error) {
	var conf tcpLinkTomlConfig
	if _, err := toml.DecodeFile("/app/config.toml", &conf); err != nil {
		return nil, fmt.Errorf("failed to decode config.toml: %w", err)
	}

	config := &conf.TCPLink

	// Set defaults if not specified
	if config.DefaultPort == 0 {
		config.DefaultPort = 4444
	}
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 30
	}
	if config.MaxMessageSize == 0 {
		config.MaxMessageSize = 10485760 // 10MB
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 60
	}

	// Set default malleable field names (same as SMB for consistency)
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
	if config.Malleable.LinkUnlinkField == "" {
		config.Malleable.LinkUnlinkField = "lu"
	}
	if config.Malleable.RoutingIDField == "" {
		config.Malleable.RoutingIDField = "r"
	}
	if config.Malleable.PayloadField == "" {
		config.Malleable.PayloadField = "p"
	}

	return config, nil
}

// GetTCPLinkConfig returns the singleton instance of TCPLinkConfig
func GetTCPLinkConfig() (*TCPLinkConfig, error) {
	var err error
	tcpLinkOnce.Do(func() {
		tcpLinkConfig, err = LoadTCPLinkConfig()
	})
	return tcpLinkConfig, err
}

// GetMalleable returns the malleable field configuration
func (c *TCPLinkConfig) GetMalleable() TCPLinkMalleable {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Malleable
}

// GetTCPProfile returns a specific TCP profile by name
func (c *TCPLinkConfig) GetTCPProfile(name string) *TCPProfile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.Profiles {
		if c.Profiles[i].Name == name {
			return &c.Profiles[i]
		}
	}
	return nil
}

// GetTCPProfileNames returns a list of all TCP profile names
func (c *TCPLinkConfig) GetTCPProfileNames() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	names := make([]string, len(c.Profiles))
	for i, p := range c.Profiles {
		names[i] = p.Name
	}
	return names
}

// GetTCPProfiles returns all TCP profiles
func (c *TCPLinkConfig) GetTCPProfiles() []TCPProfile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Profiles
}

// AddTCPProfile adds a new TCP profile, returning error if name already exists
func (c *TCPLinkConfig) AddTCPProfile(profile TCPProfile) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check for duplicate name
	for _, p := range c.Profiles {
		if p.Name == profile.Name {
			return fmt.Errorf("TCP profile '%s' already exists", profile.Name)
		}
	}

	c.Profiles = append(c.Profiles, profile)
	return nil
}

// RemoveTCPProfile removes a TCP profile by name, returning true if found
func (c *TCPLinkConfig) RemoveTCPProfile(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, p := range c.Profiles {
		if p.Name == name {
			c.Profiles = append(c.Profiles[:i], c.Profiles[i+1:]...)
			return true
		}
	}
	return false
}

// ReplaceTCPProfiles replaces all TCP profiles with the provided list
func (c *TCPLinkConfig) ReplaceTCPProfiles(profiles []TCPProfile) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Profiles = profiles
}

// TCPProfileUploadResult contains the results of a TCP profile upload
type TCPProfileUploadResult struct {
	ProfilesAdded []string
	Errors        []string
}

// ValidateAndAddTCPProfiles validates and adds TCP profiles from TOML content
func (c *TCPLinkConfig) ValidateAndAddTCPProfiles(profiles []TCPProfile) *TCPProfileUploadResult {
	result := &TCPProfileUploadResult{
		ProfilesAdded: []string{},
		Errors:        []string{},
	}

	for _, profile := range profiles {
		// Validate required fields
		if profile.Name == "" {
			result.Errors = append(result.Errors, "TCP profile missing required 'name' field")
			continue
		}

		// Validate transforms if Data block exists
		if profile.Data != nil {
			for _, t := range profile.Data.Transforms {
				if !isValidTCPTransformType(t.Type) {
					result.Errors = append(result.Errors,
						fmt.Sprintf("TCP profile '%s': invalid transform type '%s'", profile.Name, t.Type))
					continue
				}
			}
		}

		// Try to add the profile
		if err := c.AddTCPProfile(profile); err != nil {
			result.Errors = append(result.Errors, err.Error())
		} else {
			result.ProfilesAdded = append(result.ProfilesAdded, profile.Name)
		}
	}

	return result
}

// isValidTCPTransformType checks if a transform type is valid for TCP
func isValidTCPTransformType(t string) bool {
	validTypes := map[string]bool{
		"base64":         true,
		"base64url":      true,
		"hex":            true,
		"gzip":           true,
		"netbios":        true,
		"xor":            true,
		"prepend":        true,
		"append":         true,
		"random_prepend": true,
		"random_append":  true,
	}
	return validTypes[t]
}
