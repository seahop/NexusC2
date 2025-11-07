// internal/common/config/agent_config.go
package config

import (
	"github.com/BurntSushi/toml"
)

type ListenerConfig struct {
	Name           string
	Protocol       string
	Port           int
	Secure         bool
	URLPath        string
	AllowedMethods []string
	Headers        map[string]string
	BindIP         string
	Timeout        int
	EnableLogging  bool
}

type AgentConfig struct {
	WebServer struct {
		CertFile string `toml:"cert_file"`
		KeyFile  string `toml:"key_file"`
	} `toml:"web_server"`
	Routes struct {
		Get  []Handler `toml:"get_handlers"`
		Post []Handler `toml:"post_handlers"`
	} `toml:"http_routes"`
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
	Name   string `toml:"name"`
	Type   string `toml:"type"`
	Format string `toml:"format"`
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

	// Set default HTTP methods if not specified
	for i := range config.Routes.Get {
		if config.Routes.Get[i].Method == "" {
			config.Routes.Get[i].Method = "GET"
		}
	}

	for i := range config.Routes.Post {
		if config.Routes.Post[i].Method == "" {
			config.Routes.Post[i].Method = "POST"
		}
	}

	// Set default values if not provided in the config
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 30
	}
	if !config.DefaultEnableLogging {
		config.DefaultEnableLogging = true
	}

	return &config, nil
}

// GetAllowedMethods returns all configured methods from handlers
func (cfg *AgentConfig) GetAllowedMethods(listenerType string) []string {
	methodMap := make(map[string]bool)

	// Collect all unique methods from GET handlers
	for _, handler := range cfg.Routes.Get {
		if handler.Enabled && handler.Method != "" {
			methodMap[handler.Method] = true
		}
	}

	// Collect all unique methods from POST handlers
	for _, handler := range cfg.Routes.Post {
		if handler.Enabled && handler.Method != "" {
			methodMap[handler.Method] = true
		}
	}

	// Convert map to slice
	methods := make([]string, 0, len(methodMap))
	for method := range methodMap {
		methods = append(methods, method)
	}

	// If no methods found, return defaults based on listener type
	if len(methods) == 0 {
		switch listenerType {
		case "HTTP", "HTTPS":
			return []string{"GET", "POST"}
		case "TCP", "UDP":
			return []string{}
		default:
			return []string{"GET"}
		}
	}

	return methods
}

// GetHeaders returns default headers to be applied to listeners
func (cfg *AgentConfig) GetHeaders() map[string]string {
	return map[string]string{
		"Server":                    "nginx/1.18.0",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
	}
}
