// internal/common/config/link_malleable.go
package config

import (
	"fmt"
	"sync"

	"github.com/BurntSushi/toml"
)

// LinkMalleable holds customizable field names for the link protocol
// This is shared between SMB and TCP links since they can communicate with each other
type LinkMalleable struct {
	LinkDataField              string `toml:"link_data_field"`
	LinkCommandsField          string `toml:"link_commands_field"`
	LinkHandshakeField         string `toml:"link_handshake_field"`
	LinkHandshakeResponseField string `toml:"link_handshake_response_field"`
	LinkUnlinkField            string `toml:"link_unlink_field"`
	RoutingIDField             string `toml:"routing_id_field"`
	PayloadField               string `toml:"payload_field"`
}

// LinkConfig holds the unified link malleable configuration
type LinkConfig struct {
	Malleable LinkMalleable `toml:"malleable"`
	mu        sync.RWMutex
}

type linkTomlConfig struct {
	Link LinkConfig `toml:"link"`
}

var (
	linkConfig *LinkConfig
	linkOnce   sync.Once
)

// LoadLinkConfig loads the unified link configuration from config.toml
func LoadLinkConfig() (*LinkConfig, error) {
	var conf linkTomlConfig
	if _, err := toml.DecodeFile("/app/config.toml", &conf); err != nil {
		return nil, fmt.Errorf("failed to decode config.toml: %w", err)
	}

	config := &conf.Link

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

// GetLinkConfig returns the singleton instance of LinkConfig
func GetLinkConfig() (*LinkConfig, error) {
	var err error
	linkOnce.Do(func() {
		linkConfig, err = LoadLinkConfig()
	})
	return linkConfig, err
}

// GetMalleable returns the malleable field configuration
func (c *LinkConfig) GetMalleable() LinkMalleable {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Malleable
}

// GetLinkMalleable is a convenience function to get the link malleable config directly
func GetLinkMalleable() (LinkMalleable, error) {
	cfg, err := GetLinkConfig()
	if err != nil {
		// Return defaults on error
		return LinkMalleable{
			LinkDataField:              "ld",
			LinkCommandsField:          "lc",
			LinkHandshakeField:         "lh",
			LinkHandshakeResponseField: "lr",
			LinkUnlinkField:            "lu",
			RoutingIDField:             "r",
			PayloadField:               "p",
		}, err
	}
	return cfg.GetMalleable(), nil
}
