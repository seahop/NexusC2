// internal/common/config/agent_config.go
package config

import (
	"github.com/BurntSushi/toml"
)

type ListenerConfig struct {
	Name                  string
	Protocol              string
	Port                  int
	Secure                bool
	URLPath               string
	AllowedMethods        []string
	Headers               map[string]string
	BindIP                string
	Timeout               int
	EnableLogging         bool
	GetProfile            string // Bound GET profile name
	PostProfile           string // Bound POST profile name
	ServerResponseProfile string // Bound server response profile name
}

// ServerHeadersConfig holds global default headers for all listeners
type ServerHeadersConfig struct {
	Server                  string `toml:"server"`
	StrictTransportSecurity string `toml:"strict_transport_security"`
	XFrameOptions           string `toml:"x_frame_options"`
	XContentTypeOptions     string `toml:"x_content_type_options"`
}

type AgentConfig struct {
	WebServer struct {
		CertFile string `toml:"cert_file"`
		KeyFile  string `toml:"key_file"`
	} `toml:"web_server"`
	ServerHeaders        ServerHeadersConfig `toml:"server_headers"`
	HTTPProfiles         HTTPProfiles        `toml:"http_profiles"`
	Database             *DatabaseConfig
	Listeners            []ListenerConfig
	DefaultTimeout       int  `toml:"default_timeout"`
	DefaultEnableLogging bool `toml:"default_enable_logging"`
}

type WebServerConfig struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

type Handler struct {
	Path         string  `toml:"path"`
	Method       string  `toml:"method"` // NEW: Custom HTTP verb (optional)
	Enabled      bool    `toml:"enabled"`
	AuthRequired bool    `toml:"auth_required"`
	MaxBodySize  string  `toml:"max_body_size,omitempty"`
	Params       []Param `toml:"params"`
}

type Param struct {
	Name     string `toml:"name"`
	Type     string `toml:"type"`
	Format   string `toml:"format"`
	Location string `toml:"location"` // query, header, cookie
}

// Header represents a configurable HTTP header
type Header struct {
	Name  string `toml:"name" json:"name"`
	Value string `toml:"value" json:"value"`
}

// GetProfile defines a named GET request profile
type GetProfile struct {
	Name    string   `toml:"name" json:"name"`
	Path    string   `toml:"path" json:"path"`
	Method  string   `toml:"method" json:"method"`
	Headers []Header `toml:"headers" json:"headers"`
	Params  []Param  `toml:"params" json:"params"`
}

// PostProfile defines a named POST request profile
type PostProfile struct {
	Name        string   `toml:"name" json:"name"`
	Path        string   `toml:"path" json:"path"`
	Method      string   `toml:"method" json:"method"`
	ContentType string   `toml:"content_type" json:"content_type"`
	Headers     []Header `toml:"headers" json:"headers"`
	Params      []Param  `toml:"params" json:"params"`
}

// ServerResponseProfile defines how the server responds to agents
type ServerResponseProfile struct {
	Name           string   `toml:"name" json:"name"`
	ContentType    string   `toml:"content_type" json:"content_type"`
	StatusField    string   `toml:"status_field" json:"status_field"`
	DataField      string   `toml:"data_field" json:"data_field"`
	CommandIDField string   `toml:"command_id_field" json:"command_id_field"`
	RekeyValue     string   `toml:"rekey_value" json:"rekey_value"`
	Headers        []Header `toml:"headers" json:"headers"`
}

// HTTPProfiles holds all named profiles for GET, POST, and server responses
type HTTPProfiles struct {
	Get            []GetProfile            `toml:"get" json:"get_profiles"`
	Post           []PostProfile           `toml:"post" json:"post_profiles"`
	ServerResponse []ServerResponseProfile `toml:"server_response" json:"server_response_profiles"`
}

// LoadAgentConfig loads the configuration from a TOML file
func LoadAgentConfig() (*AgentConfig, error) {
	var config AgentConfig
	if _, err := toml.DecodeFile("/app/config.toml", &config); err != nil {
		return nil, err
	}

	dbConfig, err := LoadDatabaseConfig()
	if err != nil {
		return nil, err
	}
	config.Database = dbConfig

	// Set default values if not provided in the config
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 30
	}
	if !config.DefaultEnableLogging {
		config.DefaultEnableLogging = true
	}

	// Set default server headers if not specified
	if config.ServerHeaders.Server == "" {
		config.ServerHeaders.Server = "nginx/1.18.0"
	}
	if config.ServerHeaders.StrictTransportSecurity == "" {
		config.ServerHeaders.StrictTransportSecurity = "max-age=31536000; includeSubDomains"
	}
	if config.ServerHeaders.XFrameOptions == "" {
		config.ServerHeaders.XFrameOptions = "DENY"
	}
	if config.ServerHeaders.XContentTypeOptions == "" {
		config.ServerHeaders.XContentTypeOptions = "nosniff"
	}

	// Set default methods for profiles if not specified
	for i := range config.HTTPProfiles.Get {
		if config.HTTPProfiles.Get[i].Method == "" {
			config.HTTPProfiles.Get[i].Method = "GET"
		}
	}
	for i := range config.HTTPProfiles.Post {
		if config.HTTPProfiles.Post[i].Method == "" {
			config.HTTPProfiles.Post[i].Method = "POST"
		}
	}

	// Set default values for server response profiles
	for i := range config.HTTPProfiles.ServerResponse {
		if config.HTTPProfiles.ServerResponse[i].ContentType == "" {
			config.HTTPProfiles.ServerResponse[i].ContentType = "application/json"
		}
		if config.HTTPProfiles.ServerResponse[i].StatusField == "" {
			config.HTTPProfiles.ServerResponse[i].StatusField = "status"
		}
		if config.HTTPProfiles.ServerResponse[i].DataField == "" {
			config.HTTPProfiles.ServerResponse[i].DataField = "data"
		}
		if config.HTTPProfiles.ServerResponse[i].CommandIDField == "" {
			config.HTTPProfiles.ServerResponse[i].CommandIDField = "id"
		}
		if config.HTTPProfiles.ServerResponse[i].RekeyValue == "" {
			config.HTTPProfiles.ServerResponse[i].RekeyValue = "rekey"
		}
	}

	return &config, nil
}

// GetHeaders returns default headers to be applied to listeners (loaded from config)
func (cfg *AgentConfig) GetHeaders() map[string]string {
	return map[string]string{
		"Server":                    cfg.ServerHeaders.Server,
		"Strict-Transport-Security": cfg.ServerHeaders.StrictTransportSecurity,
		"X-Frame-Options":           cfg.ServerHeaders.XFrameOptions,
		"X-Content-Type-Options":    cfg.ServerHeaders.XContentTypeOptions,
	}
}

// GetGetProfile returns a GET profile by name, or nil if not found
func (cfg *AgentConfig) GetGetProfile(name string) *GetProfile {
	for i := range cfg.HTTPProfiles.Get {
		if cfg.HTTPProfiles.Get[i].Name == name {
			return &cfg.HTTPProfiles.Get[i]
		}
	}
	return nil
}

// GetPostProfile returns a POST profile by name, or nil if not found
func (cfg *AgentConfig) GetPostProfile(name string) *PostProfile {
	for i := range cfg.HTTPProfiles.Post {
		if cfg.HTTPProfiles.Post[i].Name == name {
			return &cfg.HTTPProfiles.Post[i]
		}
	}
	return nil
}

// GetServerResponseProfile returns a server response profile by name, or nil if not found
func (cfg *AgentConfig) GetServerResponseProfile(name string) *ServerResponseProfile {
	for i := range cfg.HTTPProfiles.ServerResponse {
		if cfg.HTTPProfiles.ServerResponse[i].Name == name {
			return &cfg.HTTPProfiles.ServerResponse[i]
		}
	}
	return nil
}

// GetGetProfileNames returns a list of all GET profile names
func (cfg *AgentConfig) GetGetProfileNames() []string {
	names := make([]string, len(cfg.HTTPProfiles.Get))
	for i, profile := range cfg.HTTPProfiles.Get {
		names[i] = profile.Name
	}
	return names
}

// GetPostProfileNames returns a list of all POST profile names
func (cfg *AgentConfig) GetPostProfileNames() []string {
	names := make([]string, len(cfg.HTTPProfiles.Post))
	for i, profile := range cfg.HTTPProfiles.Post {
		names[i] = profile.Name
	}
	return names
}

// GetServerResponseProfileNames returns a list of all server response profile names
func (cfg *AgentConfig) GetServerResponseProfileNames() []string {
	names := make([]string, len(cfg.HTTPProfiles.ServerResponse))
	for i, profile := range cfg.HTTPProfiles.ServerResponse {
		names[i] = profile.Name
	}
	return names
}
