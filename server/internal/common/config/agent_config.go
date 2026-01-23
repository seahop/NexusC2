// internal/common/config/agent_config.go
package config

import (
	"fmt"

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

// =============================================================================
// MALLEABLE TRANSFORMS - Data encoding and placement configuration
// =============================================================================

// Transform represents a single transformation step in a transform chain
// Transforms are applied in order (first to last) when sending data
// and reversed (last to first) when receiving data
type Transform struct {
	// Type of transform: base64, base64url, hex, gzip, xor, netbios, prepend, append, random_prepend, random_append
	Type string `toml:"type" json:"type"`

	// Value used by certain transforms:
	// - prepend/append: the static string to add
	// - xor: the XOR key (hex string or raw)
	Value string `toml:"value,omitempty" json:"value,omitempty"`

	// Length for random_prepend/random_append: number of random bytes to add
	Length int `toml:"length,omitempty" json:"length,omitempty"`

	// Charset for random_prepend/random_append:
	// - "numeric": 0-9
	// - "alpha": a-zA-Z
	// - "alphanumeric": a-zA-Z0-9 (default)
	// - "hex": 0-9a-f
	Charset string `toml:"charset,omitempty" json:"charset,omitempty"`
}

// DataBlock defines how a piece of data (clientID, body, etc.) is transformed and placed
type DataBlock struct {
	// Output location for the transformed data:
	// - "body": HTTP body
	// - "header:<name>": in a specific header (e.g., "header:X-Request-ID")
	// - "cookie:<name>": in a cookie (e.g., "cookie:session")
	// - "query:<name>": as a query parameter (e.g., "query:id")
	// - "uri_append": appended to the URI path
	Output string `toml:"output" json:"output"`

	// Ordered list of transforms to apply
	Transforms []Transform `toml:"transforms,omitempty" json:"transforms,omitempty"`
}

// GetProfile defines a named GET request profile
type GetProfile struct {
	Name    string   `toml:"name" json:"name"`
	Path    string   `toml:"path" json:"path"`
	Method  string   `toml:"method" json:"method"`
	Headers []Header `toml:"headers" json:"headers"`
	Params  []Param  `toml:"params" json:"params"`

	// ClientID defines how the client ID is transformed and placed in GET requests
	// If not specified, falls back to legacy Params-based clientID placement
	ClientID *DataBlock `toml:"client_id,omitempty" json:"client_id,omitempty"`
}

// PostProfile defines a named POST request profile
type PostProfile struct {
	Name        string   `toml:"name" json:"name"`
	Path        string   `toml:"path" json:"path"`
	Method      string   `toml:"method" json:"method"`
	ContentType string   `toml:"content_type" json:"content_type"`
	Headers     []Header `toml:"headers" json:"headers"`
	Params      []Param  `toml:"params" json:"params"`

	// ClientID defines how the client ID is transformed and placed in POST requests
	// If not specified, falls back to legacy Params-based clientID placement
	ClientID *DataBlock `toml:"client_id,omitempty" json:"client_id,omitempty"`

	// Data defines how the POST body data is transformed
	// If not specified, data is sent as-is in the body
	Data *DataBlock `toml:"data,omitempty" json:"data,omitempty"`
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

	// Data defines how response data is transformed before sending to agent
	// If not specified, data is sent as-is
	Data *DataBlock `toml:"data,omitempty" json:"data,omitempty"`
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

// ProfileUploadResult contains the results of a profile upload operation
type ProfileUploadResult struct {
	GetProfiles            []string `json:"get_profiles"`
	PostProfiles           []string `json:"post_profiles"`
	ServerResponseProfiles []string `json:"server_response_profiles"`
	SMBProfiles            []string `json:"smb_profiles"`
	TCPProfiles            []string `json:"tcp_profiles"`
	Errors                 []string `json:"errors,omitempty"`
}

// ValidateAndAddProfiles parses TOML content and adds valid profiles to the config
// Returns the names of successfully added profiles and any validation errors
func (cfg *AgentConfig) ValidateAndAddProfiles(tomlContent string) (*ProfileUploadResult, error) {
	result := &ProfileUploadResult{
		GetProfiles:            []string{},
		PostProfiles:           []string{},
		ServerResponseProfiles: []string{},
		SMBProfiles:            []string{},
		TCPProfiles:            []string{},
		Errors:                 []string{},
	}

	// Parse the uploaded TOML - includes HTTP, SMB, and TCP profiles
	var uploaded struct {
		HTTPProfiles HTTPProfiles `toml:"http_profiles"`
		SMBLink      struct {
			Profiles []SMBProfile `toml:"profiles"`
		} `toml:"smb_link"`
		TCPLink struct {
			Profiles []TCPProfile `toml:"profiles"`
		} `toml:"tcp_link"`
	}

	if _, err := toml.Decode(tomlContent, &uploaded); err != nil {
		return nil, fmt.Errorf("failed to parse TOML: %v", err)
	}

	// Validate and add GET profiles
	for _, profile := range uploaded.HTTPProfiles.Get {
		if err := cfg.validateGetProfile(&profile); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("GET profile '%s': %v", profile.Name, err))
			continue
		}
		// Set defaults
		if profile.Method == "" {
			profile.Method = "GET"
		}
		cfg.HTTPProfiles.Get = append(cfg.HTTPProfiles.Get, profile)
		result.GetProfiles = append(result.GetProfiles, profile.Name)
	}

	// Validate and add POST profiles
	for _, profile := range uploaded.HTTPProfiles.Post {
		if err := cfg.validatePostProfile(&profile); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("POST profile '%s': %v", profile.Name, err))
			continue
		}
		// Set defaults
		if profile.Method == "" {
			profile.Method = "POST"
		}
		if profile.ContentType == "" {
			profile.ContentType = "application/json"
		}
		cfg.HTTPProfiles.Post = append(cfg.HTTPProfiles.Post, profile)
		result.PostProfiles = append(result.PostProfiles, profile.Name)
	}

	// Validate and add Server Response profiles
	for _, profile := range uploaded.HTTPProfiles.ServerResponse {
		if err := cfg.validateServerResponseProfile(&profile); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Server Response profile '%s': %v", profile.Name, err))
			continue
		}
		// Set defaults
		if profile.ContentType == "" {
			profile.ContentType = "application/json"
		}
		if profile.StatusField == "" {
			profile.StatusField = "status"
		}
		if profile.DataField == "" {
			profile.DataField = "data"
		}
		if profile.CommandIDField == "" {
			profile.CommandIDField = "id"
		}
		if profile.RekeyValue == "" {
			profile.RekeyValue = "rekey"
		}
		cfg.HTTPProfiles.ServerResponse = append(cfg.HTTPProfiles.ServerResponse, profile)
		result.ServerResponseProfiles = append(result.ServerResponseProfiles, profile.Name)
	}

	// Validate and add SMB profiles (uses the global SMB config)
	if len(uploaded.SMBLink.Profiles) > 0 {
		smbConfig, err := GetSMBLinkConfig()
		if err == nil && smbConfig != nil {
			smbResult := smbConfig.ValidateAndAddSMBProfiles(uploaded.SMBLink.Profiles)
			result.SMBProfiles = append(result.SMBProfiles, smbResult.ProfilesAdded...)
			result.Errors = append(result.Errors, smbResult.Errors...)
		} else {
			result.Errors = append(result.Errors, "SMB config not available for profile upload")
		}
	}

	// Validate and add TCP profiles (uses the global TCP config)
	if len(uploaded.TCPLink.Profiles) > 0 {
		tcpConfig, err := GetTCPLinkConfig()
		if err == nil && tcpConfig != nil {
			tcpResult := tcpConfig.ValidateAndAddTCPProfiles(uploaded.TCPLink.Profiles)
			result.TCPProfiles = append(result.TCPProfiles, tcpResult.ProfilesAdded...)
			result.Errors = append(result.Errors, tcpResult.Errors...)
		} else {
			result.Errors = append(result.Errors, "TCP config not available for profile upload")
		}
	}

	return result, nil
}

// validateGetProfile validates a GET profile
func (cfg *AgentConfig) validateGetProfile(profile *GetProfile) error {
	if profile.Name == "" {
		return fmt.Errorf("name is required")
	}
	if profile.Path == "" {
		return fmt.Errorf("path is required")
	}
	// Check for duplicate name
	if cfg.GetGetProfile(profile.Name) != nil {
		return fmt.Errorf("profile with name '%s' already exists", profile.Name)
	}
	// Validate params have required fields
	for i, param := range profile.Params {
		if param.Name == "" {
			return fmt.Errorf("param[%d]: name is required", i)
		}
		if param.Type == "" {
			return fmt.Errorf("param[%d]: type is required", i)
		}
	}
	return nil
}

// validatePostProfile validates a POST profile
func (cfg *AgentConfig) validatePostProfile(profile *PostProfile) error {
	if profile.Name == "" {
		return fmt.Errorf("name is required")
	}
	if profile.Path == "" {
		return fmt.Errorf("path is required")
	}
	// Check for duplicate name
	if cfg.GetPostProfile(profile.Name) != nil {
		return fmt.Errorf("profile with name '%s' already exists", profile.Name)
	}
	// Validate params have required fields
	for i, param := range profile.Params {
		if param.Name == "" {
			return fmt.Errorf("param[%d]: name is required", i)
		}
		if param.Type == "" {
			return fmt.Errorf("param[%d]: type is required", i)
		}
	}
	return nil
}

// validateServerResponseProfile validates a Server Response profile
func (cfg *AgentConfig) validateServerResponseProfile(profile *ServerResponseProfile) error {
	if profile.Name == "" {
		return fmt.Errorf("name is required")
	}
	// Check for duplicate name
	if cfg.GetServerResponseProfile(profile.Name) != nil {
		return fmt.Errorf("profile with name '%s' already exists", profile.Name)
	}
	return nil
}

// RemoveGetProfile removes a GET profile by name
func (cfg *AgentConfig) RemoveGetProfile(name string) bool {
	for i, profile := range cfg.HTTPProfiles.Get {
		if profile.Name == name {
			cfg.HTTPProfiles.Get = append(cfg.HTTPProfiles.Get[:i], cfg.HTTPProfiles.Get[i+1:]...)
			return true
		}
	}
	return false
}

// RemovePostProfile removes a POST profile by name
func (cfg *AgentConfig) RemovePostProfile(name string) bool {
	for i, profile := range cfg.HTTPProfiles.Post {
		if profile.Name == name {
			cfg.HTTPProfiles.Post = append(cfg.HTTPProfiles.Post[:i], cfg.HTTPProfiles.Post[i+1:]...)
			return true
		}
	}
	return false
}

// RemoveServerResponseProfile removes a Server Response profile by name
func (cfg *AgentConfig) RemoveServerResponseProfile(name string) bool {
	for i, profile := range cfg.HTTPProfiles.ServerResponse {
		if profile.Name == name {
			cfg.HTTPProfiles.ServerResponse = append(cfg.HTTPProfiles.ServerResponse[:i], cfg.HTTPProfiles.ServerResponse[i+1:]...)
			return true
		}
	}
	return false
}
