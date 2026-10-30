package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

type BuilderConfig struct {
	Mode   string             `toml:"mode"`
	Remote BuilderRemoteConfig `toml:"remote"`
}

type BuilderRemoteConfig struct {
	Address    string `toml:"address"`
	CACert     string `toml:"ca_cert"`
	ClientCert string `toml:"client_cert"`
	ClientKey  string `toml:"client_key"`
	Timeout    string `toml:"timeout"`
}

type builderTomlConfig struct {
	Builder BuilderConfig `toml:"builder"`
}

func LoadBuilderConfig() (*BuilderConfig, error) {
	configPath := os.Getenv("CONFIG_FILE")
	if configPath == "" {
		configPath = "/app/config.toml"
	}

	var conf builderTomlConfig
	if _, err := toml.DecodeFile(configPath, &conf); err != nil {
		return nil, err
	}

	if conf.Builder.Mode == "" {
		conf.Builder.Mode = "local"
	}

	return &conf.Builder, nil
}
