package builder

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"
)

type BuilderConfig struct {
	Mode   string       `toml:"mode"`
	Remote RemoteConfig `toml:"remote"`
}

type RemoteConfig struct {
	Address    string `toml:"address"`
	CACert     string `toml:"ca_cert"`
	ClientCert string `toml:"client_cert"`
	ClientKey  string `toml:"client_key"`
	Timeout    string `toml:"timeout"`
}

func (c *RemoteConfig) ParseTimeout() time.Duration {
	if c.Timeout == "" {
		return 10 * time.Minute
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 10 * time.Minute
	}
	return d
}

func (c *RemoteConfig) TLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	caCertPEM, err := os.ReadFile(c.CACert)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func NewBuilderFromConfig(cfg *BuilderConfig) (Builder, error) {
	switch cfg.Mode {
	case "", "local":
		return NewLocalBuilder()
	case "remote":
		return NewRemoteBuilder(&cfg.Remote)
	default:
		return nil, fmt.Errorf("unknown builder mode: %q (use \"local\" or \"remote\")", cfg.Mode)
	}
}
