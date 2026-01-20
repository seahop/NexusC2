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
	Profiles          []SMBProfile     `toml:"profiles"`
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

// SMBProfile defines malleable transforms for named pipe traffic
type SMBProfile struct {
	Name string     `toml:"name" json:"name"`
	Data *DataBlock `toml:"data,omitempty" json:"data,omitempty"`
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

// GetSMBProfile returns a specific SMB profile by name
func (c *SMBLinkConfig) GetSMBProfile(name string) *SMBProfile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.Profiles {
		if c.Profiles[i].Name == name {
			return &c.Profiles[i]
		}
	}
	return nil
}

// GetSMBProfileNames returns a list of all SMB profile names
func (c *SMBLinkConfig) GetSMBProfileNames() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	names := make([]string, len(c.Profiles))
	for i, p := range c.Profiles {
		names[i] = p.Name
	}
	return names
}

// GetSMBProfiles returns all SMB profiles
func (c *SMBLinkConfig) GetSMBProfiles() []SMBProfile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Profiles
}

// AddSMBProfile adds a new SMB profile, returning error if name already exists
func (c *SMBLinkConfig) AddSMBProfile(profile SMBProfile) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check for duplicate name
	for _, p := range c.Profiles {
		if p.Name == profile.Name {
			return fmt.Errorf("SMB profile '%s' already exists", profile.Name)
		}
	}

	c.Profiles = append(c.Profiles, profile)
	return nil
}

// RemoveSMBProfile removes an SMB profile by name, returning true if found
func (c *SMBLinkConfig) RemoveSMBProfile(name string) bool {
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

// SMBProfileUploadResult contains the results of an SMB profile upload
type SMBProfileUploadResult struct {
	ProfilesAdded []string
	Errors        []string
}

// ValidateAndAddSMBProfiles validates and adds SMB profiles from TOML content
func (c *SMBLinkConfig) ValidateAndAddSMBProfiles(profiles []SMBProfile) *SMBProfileUploadResult {
	result := &SMBProfileUploadResult{
		ProfilesAdded: []string{},
		Errors:        []string{},
	}

	for _, profile := range profiles {
		// Validate required fields
		if profile.Name == "" {
			result.Errors = append(result.Errors, "SMB profile missing required 'name' field")
			continue
		}

		// Validate transforms if Data block exists
		if profile.Data != nil {
			for _, t := range profile.Data.Transforms {
				if !isValidTransformType(t.Type) {
					result.Errors = append(result.Errors,
						fmt.Sprintf("SMB profile '%s': invalid transform type '%s'", profile.Name, t.Type))
					continue
				}
			}
		}

		// Try to add the profile
		if err := c.AddSMBProfile(profile); err != nil {
			result.Errors = append(result.Errors, err.Error())
		} else {
			result.ProfilesAdded = append(result.ProfilesAdded, profile.Name)
		}
	}

	return result
}

// isValidTransformType checks if a transform type is valid
func isValidTransformType(t string) bool {
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
