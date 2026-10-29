// internal/rest/wsproxy/execute_handlers.go
// REST API handlers for BOF and inline-assembly execution via WebSocket proxy
package wsproxy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/gin-gonic/gin"
)

type ExecuteBOFRequest struct {
	Data           string   `json:"data" binding:"required"`
	Arguments      []string `json:"arguments,omitempty"`
	ArgumentsPacked string  `json:"arguments_packed,omitempty"`
	BOFName        string   `json:"bof_name,omitempty"`
	Arch           string   `json:"arch,omitempty"`
	Async          bool     `json:"async,omitempty"`
}

type ExecuteAssemblyRequest struct {
	Data        string   `json:"data" binding:"required"`
	Arguments   []string `json:"arguments,omitempty"`
	AppDomain   string   `json:"app_domain,omitempty"`
	EntryPoint  string   `json:"entry_point,omitempty"`
	DisableAMSI bool     `json:"disable_amsi,omitempty"`
	DisableETW  bool     `json:"disable_etw,omitempty"`
	RevertETW   bool     `json:"revert_etw,omitempty"`
	Async       bool     `json:"async,omitempty"`
}

// ExecuteBOF sends a BOF for execution on an agent.
// POST /api/v1/agents/:id/bof
func (p *ProxyHandlers) ExecuteBOF(c *gin.Context) {
	agentID := c.Param("id")

	var req ExecuteBOFRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	// Decode file data to compute size and hash
	fileBytes, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid base64 in data field"})
		return
	}
	fileSize := len(fileBytes)
	fileHash := fmt.Sprintf("%x", sha256.Sum256(fileBytes))

	if req.Arch == "" {
		req.Arch = "x64"
	}
	if req.BOFName == "" {
		req.BOFName = "api-bof"
	}

	// Pack arguments if raw typed args provided
	packedArgs := req.ArgumentsPacked
	if packedArgs == "" && len(req.Arguments) > 0 {
		packed, err := packBOFArguments(req.Arguments)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to pack arguments: " + err.Error()})
			return
		}
		packedArgs = packed
	}

	username, _ := c.Get("username")
	usernameStr, _ := username.(string)
	if usernameStr == "" {
		usernameStr = "api-user"
	}

	commandID := fmt.Sprintf("%d", time.Now().UnixNano())
	timestamp := time.Now().Format(time.RFC3339)

	command := "bof"
	if req.Async {
		command = "bof-async"
	}
	// Build display command string so other operators see what was sent
	displayCommand := command + " " + req.BOFName
	if len(req.Arguments) > 0 {
		displayCommand += " " + strings.Join(req.Arguments, " ")
	}

	wsMsg := map[string]interface{}{
		"type": "agent_command",
		"data": map[string]interface{}{
			"command":      displayCommand,
			"agent_id":     agentID,
			"command_id":   commandID,
			"filename":     req.BOFName,
			"currentChunk": 0,
			"totalChunks":  1,
			"data":         req.Data,
			"arch":         req.Arch,
			"file_size":    fileSize,
			"file_hash":    fileHash,
			"arguments":    packedArgs,
			"bof_name":     req.BOFName,
			"timestamp":    timestamp,
			"username":     usernameStr,
		},
	}

	p.sendAndWaitForAck(c, wsMsg, agentID, commandID, command, usernameStr, timestamp)
}

// ExecuteAssembly sends a .NET assembly for execution on an agent.
// POST /api/v1/agents/:id/assembly
func (p *ProxyHandlers) ExecuteAssembly(c *gin.Context) {
	agentID := c.Param("id")

	var req ExecuteAssemblyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	// Validate base64
	if _, err := base64.StdEncoding.DecodeString(req.Data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid base64 in data field"})
		return
	}

	if req.AppDomain == "" {
		req.AppDomain = "InlineAssembly"
	}
	if req.EntryPoint == "" {
		req.EntryPoint = "Main"
	}

	username, _ := c.Get("username")
	usernameStr, _ := username.(string)
	if usernameStr == "" {
		usernameStr = "api-user"
	}

	commandID := fmt.Sprintf("%d", time.Now().UnixNano())
	timestamp := time.Now().Format(time.RFC3339)

	command := "inline-assembly"
	if req.Async {
		command = "inline-assembly-async"
	}
	// Build display command string so other operators see what was sent
	displayCommand := command
	if len(req.Arguments) > 0 {
		displayCommand += " " + strings.Join(req.Arguments, " ")
	}

	wsMsg := map[string]interface{}{
		"type": "agent_command",
		"data": map[string]interface{}{
			"command":        displayCommand,
			"agent_id":       agentID,
			"command_id":     commandID,
			"currentChunk":   0,
			"totalChunks":    1,
			"assembly_b64":   req.Data,
			"arguments_list": req.Arguments,
			"app_domain":     req.AppDomain,
			"entry_point":    req.EntryPoint,
			"disable_amsi":   req.DisableAMSI,
			"disable_etw":    req.DisableETW,
			"revert_etw":     req.RevertETW,
			"timestamp":      timestamp,
			"username":       usernameStr,
		},
	}

	p.sendAndWaitForAck(c, wsMsg, agentID, commandID, command, usernameStr, timestamp)
}

// sendAndWaitForAck sends a command via WS proxy and waits for acknowledgement.
func (p *ProxyHandlers) sendAndWaitForAck(
	c *gin.Context,
	wsMsg map[string]interface{},
	agentID, commandID, command, username, timestamp string,
) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	msgCh := p.client.Subscribe()
	defer p.client.Unsubscribe(msgCh)

	if err := p.client.Send(ctx, wsMsg); err != nil {
		log.Printf("[WSProxy] Execute command error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send command: " + err.Error()})
		return
	}

	log.Printf("[WSProxy] Sent %s: agent=%s command_id=%s", command, agentID, commandID)

	timeout := time.After(30 * time.Second)
	for {
		select {
		case msg := <-msgCh:
			if msg.Type == "command_ack" {
				var ackData struct {
					AgentID   string `json:"agent_id"`
					CommandID string `json:"command_id"`
					DBID      int    `json:"db_id"`
					Status    string `json:"status"`
				}
				if err := json.Unmarshal(msg.Data, &ackData); err == nil && ackData.CommandID == commandID {
					response := gin.H{
						"message":    "command queued successfully",
						"agent_id":   agentID,
						"command_id": commandID,
						"command":    command,
						"username":   username,
						"timestamp":  timestamp,
						"status":     "queued",
					}
					if ackData.DBID > 0 {
						response["db_id"] = ackData.DBID
					}
					c.JSON(http.StatusOK, response)
					return
				}
				continue
			}

			if msg.Type == "command_validation" {
				var validationData struct {
					Status  string `json:"status"`
					Message string `json:"message"`
				}
				if err := json.Unmarshal(msg.Data, &validationData); err == nil && validationData.Status == "error" {
					c.JSON(http.StatusBadRequest, gin.H{"error": validationData.Message, "agent_id": agentID})
					return
				}
				continue
			}

			if msg.Type == "command_queued" || msg.Type == "command_success" {
				continue
			}

		case <-timeout:
			log.Printf("[WSProxy] Execute timeout: agent=%s cmd=%s", agentID, commandID)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "timeout waiting for command confirmation"})
			return

		case <-ctx.Done():
			c.JSON(http.StatusInternalServerError, gin.H{"error": "request cancelled"})
			return
		}
	}
}

// packBOFArguments converts typed argument strings into packed binary format.
// Argument types: -s:string, -w:wide_string, -i:int32, -I:int64, -h:short, -z:base64, -Z:base64_with_size
func packBOFArguments(args []string) (string, error) {
	var buf []byte

	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") || !strings.Contains(arg, ":") {
			buf = appendPackedString(buf, arg)
			continue
		}

		parts := strings.SplitN(arg, ":", 2)
		argType := parts[0]
		value := parts[1]

		switch argType {
		case "-s":
			buf = appendPackedString(buf, value)
		case "-w":
			buf = appendPackedWideString(buf, value)
		case "-i":
			n, err := strconv.ParseInt(value, 0, 32)
			if err != nil {
				return "", fmt.Errorf("invalid int32 %q: %w", value, err)
			}
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, uint32(int32(n)))
			buf = append(buf, b...)
		case "-I":
			n, err := strconv.ParseInt(value, 0, 64)
			if err != nil {
				return "", fmt.Errorf("invalid int64 %q: %w", value, err)
			}
			b := make([]byte, 8)
			binary.LittleEndian.PutUint64(b, uint64(n))
			buf = append(buf, b...)
		case "-h":
			n, err := strconv.ParseInt(value, 0, 16)
			if err != nil {
				return "", fmt.Errorf("invalid int16 %q: %w", value, err)
			}
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, uint16(int16(n)))
			buf = append(buf, b...)
		case "-z":
			data, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return "", fmt.Errorf("invalid base64 in -z arg: %w", err)
			}
			buf = append(buf, data...)
		case "-Z":
			data, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return "", fmt.Errorf("invalid base64 in -Z arg: %w", err)
			}
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, uint32(len(data)))
			buf = append(buf, b...)
			buf = append(buf, data...)
		default:
			return "", fmt.Errorf("unknown argument type %q", argType)
		}
	}

	return base64.StdEncoding.EncodeToString(buf), nil
}

func appendPackedString(buf []byte, s string) []byte {
	data := append([]byte(s), 0) // null terminator
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(len(data)))
	buf = append(buf, length...)
	buf = append(buf, data...)
	return buf
}

func appendPackedWideString(buf []byte, s string) []byte {
	runes := utf16.Encode([]rune(s))
	// UTF-16LE encoded bytes + null terminator (2 bytes)
	data := make([]byte, 0, len(runes)*2+2)
	for _, r := range runes {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, r)
		data = append(data, b...)
	}
	data = append(data, 0, 0) // null terminator

	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(len(data)))
	buf = append(buf, length...)
	buf = append(buf, data...)
	return buf
}
