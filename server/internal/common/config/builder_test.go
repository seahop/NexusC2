package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBuilderConfig_Local(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgFile, []byte(`
[builder]
mode = "local"
`), 0644)

	t.Setenv("CONFIG_FILE", cfgFile)

	cfg, err := LoadBuilderConfig()
	if err != nil {
		t.Fatalf("LoadBuilderConfig failed: %v", err)
	}
	if cfg.Mode != "local" {
		t.Errorf("expected mode=local, got %q", cfg.Mode)
	}
}

func TestLoadBuilderConfig_Remote(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgFile, []byte(`
[builder]
mode = "remote"

[builder.remote]
address = "https://10.0.0.50:9443"
ca_cert = "/certs/ca.crt"
client_cert = "/certs/client.crt"
client_key = "/certs/client.key"
timeout = "5m"
`), 0644)

	t.Setenv("CONFIG_FILE", cfgFile)

	cfg, err := LoadBuilderConfig()
	if err != nil {
		t.Fatalf("LoadBuilderConfig failed: %v", err)
	}
	if cfg.Mode != "remote" {
		t.Errorf("expected mode=remote, got %q", cfg.Mode)
	}
	if cfg.Remote.Address != "https://10.0.0.50:9443" {
		t.Errorf("unexpected address: %s", cfg.Remote.Address)
	}
	if cfg.Remote.Timeout != "5m" {
		t.Errorf("unexpected timeout: %s", cfg.Remote.Timeout)
	}
}

func TestLoadBuilderConfig_DefaultsToLocal(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgFile, []byte(`
[builder]
`), 0644)

	t.Setenv("CONFIG_FILE", cfgFile)

	cfg, err := LoadBuilderConfig()
	if err != nil {
		t.Fatalf("LoadBuilderConfig failed: %v", err)
	}
	if cfg.Mode != "local" {
		t.Errorf("expected default mode=local, got %q", cfg.Mode)
	}
}

func TestLoadBuilderConfig_MissingSectionDefaultsToLocal(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgFile, []byte(`
[some_other_section]
key = "value"
`), 0644)

	t.Setenv("CONFIG_FILE", cfgFile)

	cfg, err := LoadBuilderConfig()
	if err != nil {
		t.Fatalf("LoadBuilderConfig failed: %v", err)
	}
	if cfg.Mode != "local" {
		t.Errorf("expected default mode=local, got %q", cfg.Mode)
	}
}
