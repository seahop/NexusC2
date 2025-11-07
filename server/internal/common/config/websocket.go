// internal/common/config/websocket.go
package config

import (
	"github.com/BurntSushi/toml"
)

type WSConfig struct {
	ListenAddr string
	TLS        struct {
		CertFile string
		KeyFile  string
	}
	Database *DatabaseConfig
}

type tomlConfig struct {
	Websocket struct {
		Port     string `toml:"port"`
		CertFile string `toml:"cert_file"`
		KeyFile  string `toml:"key_file"`
	} `toml:"websocket"`
}

func LoadWSConfig() (*WSConfig, error) {
	var conf tomlConfig
	if _, err := toml.DecodeFile("/app/config.toml", &conf); err != nil {
		return nil, err
	}

	dbConfig, err := LoadDatabaseConfig()
	if err != nil {
		return nil, err
	}

	return &WSConfig{
		ListenAddr: ":" + conf.Websocket.Port,
		TLS: struct {
			CertFile string
			KeyFile  string
		}{
			CertFile: conf.Websocket.CertFile,
			KeyFile:  conf.Websocket.KeyFile,
		},
		Database: dbConfig,
	}, nil
}
