package builder

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

type RemoteBuilder struct {
	client    *http.Client
	address   string
	sharedDir string
}

type remoteBuildRequest struct {
	EnvVars    []string `json:"env_vars"`
	BinaryName string   `json:"binary_name"`
}

func NewRemoteBuilder(cfg *RemoteConfig) (*RemoteBuilder, error) {
	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		return nil, fmt.Errorf("remote builder TLS setup failed: %v", err)
	}

	sharedDir := cfg.SharedDir
	if sharedDir == "" {
		sharedDir = "/shared"
	}

	return &RemoteBuilder{
		client: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			Timeout:   cfg.ParseTimeout(),
		},
		address:   cfg.Address,
		sharedDir: sharedDir,
	}, nil
}

func (b *RemoteBuilder) Build(ctx context.Context, req *BuildRequest) (*BuildResult, error) {
	body := remoteBuildRequest{
		EnvVars:    req.EnvVars,
		BinaryName: req.BinaryName,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal build request: %v", err)
	}

	url := fmt.Sprintf("%s/api/v1/build", b.address)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	log.Printf("[RemoteBuilder] Sending build request for %s to %s", req.BinaryName, b.address)

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("remote build request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("remote build failed (HTTP %d): %s", resp.StatusCode, string(errBody))
	}

	outPath := filepath.Join(b.sharedDir, req.BinaryName)
	tmpFile, err := os.CreateTemp(b.sharedDir, req.BinaryName+"-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()

	written, err := io.Copy(tmpFile, resp.Body)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to write binary from remote builder: %v", err)
	}

	if err := os.Rename(tmpPath, outPath); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to move binary to final path: %v", err)
	}

	log.Printf("[RemoteBuilder] Received %d bytes for %s", written, req.BinaryName)

	return &BuildResult{BinaryPath: outPath}, nil
}
