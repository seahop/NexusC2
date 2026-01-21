// internal/rest/wsproxy/handlers.go
// HTTP handlers that proxy requests to the WebSocket service
package wsproxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ProxyHandlers provides HTTP handlers that proxy to WebSocket service
type ProxyHandlers struct {
	client *Client
	db     *sql.DB
}

// NewProxyHandlers creates a new proxy handlers instance
func NewProxyHandlers(client *Client, db *sql.DB) *ProxyHandlers {
	return &ProxyHandlers{
		client: client,
		db:     db,
	}
}

// CreateListenerRequest matches the REST API's expected format
type CreateListenerRequest struct {
	Name                  string `json:"name" binding:"required"`
	Protocol              string `json:"protocol" binding:"required"`
	Port                  int    `json:"port"`
	IP                    string `json:"ip"` // REST API uses "ip"
	PipeName              string `json:"pipe_name,omitempty"`
	GetProfile            string `json:"get_profile,omitempty"`
	PostProfile           string `json:"post_profile,omitempty"`
	ServerResponseProfile string `json:"server_response_profile,omitempty"`
	SMBProfile            string `json:"smb_profile,omitempty"`
}

// CreateListener proxies listener creation to WebSocket service
// POST /api/v1/listeners
func (p *ProxyHandlers) CreateListener(c *gin.Context) {
	var req CreateListenerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Set default IP if not provided
	if req.IP == "" {
		req.IP = "0.0.0.0"
	}

	// Build WebSocket message - note: WebSocket service uses "host" not "ip"
	wsMsg := map[string]interface{}{
		"type": "create_listener",
		"data": map[string]interface{}{
			"name":                    req.Name,
			"protocol":                req.Protocol,
			"port":                    req.Port,
			"host":                    req.IP, // Map IP to host for WebSocket service
			"pipe_name":               req.PipeName,
			"get_profile":             req.GetProfile,
			"post_profile":            req.PostProfile,
			"server_response_profile": req.ServerResponseProfile,
			"smb_profile":             req.SMBProfile,
		},
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Subscribe to messages before sending
	msgCh := p.client.Subscribe()

	// Send the create_listener message
	if err := p.client.Send(ctx, wsMsg); err != nil {
		log.Printf("[WSProxy] CreateListener send error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send request: " + err.Error()})
		return
	}

	// Wait for response - ListenerResponse doesn't have a type field,
	// so we need to parse raw messages
	timeout := time.After(30 * time.Second)
	for {
		select {
		case msg := <-msgCh:
			log.Printf("[WSProxy] CreateListener received message type=%q, data=%d bytes", msg.Type, len(msg.Data))

			// First check if this is a listener_update broadcast (has type field)
			if msg.Type == "listener_update" {
				var updateData struct {
					Event    string `json:"event"`
					Listener struct {
						ID                    string `json:"id"`
						Name                  string `json:"name"`
						Protocol              string `json:"protocol"`
						Port                  int    `json:"port"`
						IP                    string `json:"ip"`
						PipeName              string `json:"pipe_name,omitempty"`
						GetProfile            string `json:"get_profile,omitempty"`
						PostProfile           string `json:"post_profile,omitempty"`
						ServerResponseProfile string `json:"server_response_profile,omitempty"`
						SMBProfile            string `json:"smb_profile,omitempty"`
					} `json:"listener"`
				}
				if err := json.Unmarshal(msg.Data, &updateData); err == nil {
					log.Printf("[WSProxy] listener_update event=%s name=%s", updateData.Event, updateData.Listener.Name)
					if updateData.Event == "created" && updateData.Listener.Name == req.Name {
						c.JSON(http.StatusCreated, gin.H{
							"message": "listener created successfully",
							"listener": gin.H{
								"id":                      updateData.Listener.ID,
								"name":                    updateData.Listener.Name,
								"protocol":                updateData.Listener.Protocol,
								"port":                    fmt.Sprintf("%d", updateData.Listener.Port),
								"ip":                      updateData.Listener.IP,
								"pipe_name":               updateData.Listener.PipeName,
								"get_profile":             updateData.Listener.GetProfile,
								"post_profile":            updateData.Listener.PostProfile,
								"server_response_profile": updateData.Listener.ServerResponseProfile,
								"smb_profile":             updateData.Listener.SMBProfile,
							},
						})
						return
					}
				}
				continue
			}

			// For messages without a type field (like ListenerResponse),
			// msg.Data contains the full raw message
			// Try parsing as ListenerResponse: {"status":"...", "message":"...", "data":{...}}
			var listenerResp struct {
				Status  string `json:"status"`
				Message string `json:"message"`
				Data    struct {
					ID                    string `json:"id"`
					Name                  string `json:"name"`
					Protocol              string `json:"protocol"`
					Port                  string `json:"port"`
					IP                    string `json:"ip"`
					PipeName              string `json:"pipe_name,omitempty"`
					GetProfile            string `json:"get_profile,omitempty"`
					PostProfile           string `json:"post_profile,omitempty"`
					ServerResponseProfile string `json:"server_response_profile,omitempty"`
					SMBProfile            string `json:"smb_profile,omitempty"`
				} `json:"data"`
			}

			if err := json.Unmarshal(msg.Data, &listenerResp); err == nil && listenerResp.Status != "" {
				log.Printf("[WSProxy] Parsed ListenerResponse: status=%s message=%s", listenerResp.Status, listenerResp.Message)
				if listenerResp.Status == "error" {
					c.JSON(http.StatusBadRequest, gin.H{"error": listenerResp.Message})
					return
				}
				if listenerResp.Status == "success" {
					c.JSON(http.StatusCreated, gin.H{
						"message": listenerResp.Message,
						"listener": gin.H{
							"id":                      listenerResp.Data.ID,
							"name":                    listenerResp.Data.Name,
							"protocol":                listenerResp.Data.Protocol,
							"port":                    listenerResp.Data.Port,
							"ip":                      listenerResp.Data.IP,
							"pipe_name":               listenerResp.Data.PipeName,
							"get_profile":             listenerResp.Data.GetProfile,
							"post_profile":            listenerResp.Data.PostProfile,
							"server_response_profile": listenerResp.Data.ServerResponseProfile,
							"smb_profile":             listenerResp.Data.SMBProfile,
						},
					})
					return
				}
			} else if err != nil {
				log.Printf("[WSProxy] Failed to parse as ListenerResponse: %v", err)
			}

		case <-timeout:
			log.Printf("[WSProxy] CreateListener timeout waiting for response")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "timeout waiting for response"})
			return

		case <-ctx.Done():
			c.JSON(http.StatusInternalServerError, gin.H{"error": "request cancelled"})
			return
		}
	}
}

// DeleteListener proxies listener deletion to WebSocket service
// DELETE /api/v1/listeners/:name
func (p *ProxyHandlers) DeleteListener(c *gin.Context) {
	name := c.Param("name")

	wsMsg := map[string]interface{}{
		"type": "delete_listener",
		"data": map[string]interface{}{
			"name": name,
		},
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// Send message (delete might not have a direct response)
	if err := p.client.Send(ctx, wsMsg); err != nil {
		log.Printf("[WSProxy] DeleteListener error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete listener: " + err.Error()})
		return
	}

	// Wait briefly for any error response
	time.Sleep(500 * time.Millisecond)

	c.JSON(http.StatusOK, gin.H{"message": "listener deleted successfully"})
}

// PayloadRequest matches the WebSocket service's expected format
type PayloadRequest struct {
	Type    string          `json:"type"`
	Data    json.RawMessage `json:"data"`
}

// CreatePayloadRequest is the request body for payload creation
type CreatePayloadRequest struct {
	Listener     string `json:"listener" binding:"required"`
	OS           string `json:"os" binding:"required"`
	Arch         string `json:"arch" binding:"required"`
	Language     string `json:"language"`
	PayloadType  string `json:"payload_type"`
	PipeName     string `json:"pipe_name,omitempty"`
	SafetyChecks *struct {
		Hostname  string `json:"hostname,omitempty"`
		Username  string `json:"username,omitempty"`
		Domain    string `json:"domain,omitempty"`
		FileCheck *struct {
			Path      string `json:"path"`
			MustExist bool   `json:"must_exist"`
		} `json:"file_check,omitempty"`
		Process      string `json:"process,omitempty"`
		KillDate     string `json:"kill_date,omitempty"`
		WorkingHours *struct {
			Start string `json:"start"`
			End   string `json:"end"`
		} `json:"working_hours,omitempty"`
	} `json:"safety_checks,omitempty"`
}

// CreatePayload proxies payload creation to WebSocket service
// POST /api/v1/payloads/build
func (p *ProxyHandlers) CreatePayload(c *gin.Context) {
	var req CreatePayloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	// Get username from auth context
	username, _ := c.Get("username")
	usernameStr, _ := username.(string)
	if usernameStr == "" {
		usernameStr = "api-user"
	}

	// Set defaults
	if req.Language == "" {
		req.Language = "go"
	}
	if req.PayloadType == "" {
		req.PayloadType = "http"
	}

	// Build the payload data in WebSocket format
	payloadData := map[string]interface{}{
		"listener":     req.Listener,
		"os":           req.OS,
		"arch":         req.Arch,
		"language":     req.Language,
		"payload_type": req.PayloadType,
	}

	if req.PipeName != "" {
		payloadData["pipe_name"] = req.PipeName
	}

	if req.SafetyChecks != nil {
		safetyChecks := make(map[string]interface{})
		if req.SafetyChecks.Hostname != "" {
			safetyChecks["hostname"] = req.SafetyChecks.Hostname
		}
		if req.SafetyChecks.Username != "" {
			safetyChecks["username"] = req.SafetyChecks.Username
		}
		if req.SafetyChecks.Domain != "" {
			safetyChecks["domain"] = req.SafetyChecks.Domain
		}
		if req.SafetyChecks.FileCheck != nil {
			safetyChecks["file_check"] = map[string]interface{}{
				"path":       req.SafetyChecks.FileCheck.Path,
				"must_exist": req.SafetyChecks.FileCheck.MustExist,
			}
		}
		if req.SafetyChecks.Process != "" {
			safetyChecks["process"] = req.SafetyChecks.Process
		}
		if req.SafetyChecks.KillDate != "" {
			safetyChecks["kill_date"] = req.SafetyChecks.KillDate
		}
		if req.SafetyChecks.WorkingHours != nil {
			safetyChecks["working_hours"] = map[string]interface{}{
				"start": req.SafetyChecks.WorkingHours.Start,
				"end":   req.SafetyChecks.WorkingHours.End,
			}
		}
		payloadData["safety_checks"] = safetyChecks
	}

	// Build WebSocket message
	wsMsg := map[string]interface{}{
		"type": "create_payload",
		"data": payloadData,
	}

	// Register binary transfer handler
	// We'll use an empty filename since we don't know it yet
	transfer := p.client.RegisterBinaryTransfer("")
	defer p.client.UnregisterBinaryTransfer("")

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
	defer cancel()

	// Send payload build request
	if err := p.client.Send(ctx, wsMsg); err != nil {
		log.Printf("[WSProxy] CreatePayload send error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send payload request: " + err.Error()})
		return
	}

	log.Printf("[WSProxy] Payload build request sent for %s/%s, waiting for binary transfer", req.OS, req.Arch)

	// Wait for binary transfer to complete
	data, err := p.client.WaitForBinaryTransfer(ctx, transfer, 5*time.Minute)
	if err != nil {
		log.Printf("[WSProxy] CreatePayload binary transfer error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to receive payload: " + err.Error()})
		return
	}

	// Determine filename and content type
	filename := fmt.Sprintf("payload_%s_%s", req.OS, req.Arch)
	contentType := "application/octet-stream"

	switch req.OS {
	case "windows":
		filename += ".exe"
	case "linux", "darwin":
		// No extension
	}

	// Return the binary
	c.Header("Content-Type", contentType)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Header("Content-Length", fmt.Sprintf("%d", len(data)))
	c.Data(http.StatusOK, contentType, data)
}

// SendAgentCommand proxies agent commands to WebSocket service
// POST /api/v1/agents/:id/commands
func (p *ProxyHandlers) SendAgentCommand(c *gin.Context) {
	agentID := c.Param("id")

	var req struct {
		Command string `json:"command" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Get username from auth context
	username, _ := c.Get("username")
	usernameStr, _ := username.(string)
	if usernameStr == "" {
		usernameStr = "api-user"
	}

	// Generate command ID and timestamp
	commandID := fmt.Sprintf("%d", time.Now().UnixNano())
	timestamp := time.Now().Format(time.RFC3339)

	// Build WebSocket message - must match format expected by WebSocket handler
	// Uses agent_id (not guid), command_id, timestamp, and username from JWT
	wsMsg := map[string]interface{}{
		"type": "agent_command",
		"data": map[string]interface{}{
			"agent_id":   agentID,
			"command":    req.Command,
			"command_id": commandID,
			"timestamp":  timestamp,
			"username":   usernameStr, // Include JWT user's username for proper attribution
		},
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Subscribe to messages before sending
	msgCh := p.client.Subscribe()

	// Send command
	if err := p.client.Send(ctx, wsMsg); err != nil {
		log.Printf("[WSProxy] SendAgentCommand error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send command: " + err.Error()})
		return
	}

	log.Printf("[WSProxy] Sent agent_command: agent=%s command_id=%s command=%s", agentID, commandID, req.Command)

	// Wait for command_ack (from agent-handler, includes DB ID) or error responses
	timeout := time.After(30 * time.Second)
	for {
		select {
		case msg := <-msgCh:
			log.Printf("[WSProxy] SendAgentCommand received message type=%q", msg.Type)

			// Check for command_ack from agent-handler (sent AFTER DB insert, includes db_id)
			if msg.Type == "command_ack" {
				var ackData struct {
					AgentID   string `json:"agent_id"`
					CommandID string `json:"command_id"`
					DBID      int    `json:"db_id"`
					Status    string `json:"status"`
					Timestamp string `json:"timestamp"`
				}
				if err := json.Unmarshal(msg.Data, &ackData); err == nil {
					log.Printf("[WSProxy] command_ack: agent_id=%s command_id=%s db_id=%d (expecting agent=%s cmd=%s)",
						ackData.AgentID, ackData.CommandID, ackData.DBID, agentID, commandID)
					// Match on command_id for accuracy (we generated it)
					if ackData.CommandID == commandID {
						response := gin.H{
							"message":    "command queued successfully",
							"agent_id":   agentID,
							"command_id": commandID,
							"command":    req.Command,
							"username":   usernameStr,
							"timestamp":  timestamp,
							"status":     "queued",
						}
						if ackData.DBID > 0 {
							response["db_id"] = ackData.DBID
						}
						c.JSON(http.StatusOK, response)
						return
					}
				}
				continue
			}

			// Check for command_validation error response
			if msg.Type == "command_validation" {
				var validationData struct {
					Status  string `json:"status"`
					Message string `json:"message"`
					AgentID string `json:"agent_id"`
				}
				if err := json.Unmarshal(msg.Data, &validationData); err == nil {
					if validationData.Status == "error" {
						c.JSON(http.StatusBadRequest, gin.H{
							"error":    validationData.Message,
							"agent_id": agentID,
						})
						return
					}
				}
				continue
			}

			// Ignore command_queued and command_success - we wait for command_ack which has the DB ID
			if msg.Type == "command_queued" || msg.Type == "command_success" {
				log.Printf("[WSProxy] Ignoring %s, waiting for command_ack with db_id", msg.Type)
				continue
			}

		case <-timeout:
			log.Printf("[WSProxy] SendAgentCommand timeout waiting for response (agent=%s cmd=%s)", agentID, commandID)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "timeout waiting for command confirmation"})
			return

		case <-ctx.Done():
			c.JSON(http.StatusInternalServerError, gin.H{"error": "request cancelled"})
			return
		}
	}
}

// RemoveAgent proxies agent removal to WebSocket service
// DELETE /api/v1/agents/:id
func (p *ProxyHandlers) RemoveAgent(c *gin.Context) {
	agentID := c.Param("id")

	wsMsg := map[string]interface{}{
		"type": "remove_agent",
		"data": map[string]interface{}{
			"guid": agentID,
		},
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if err := p.client.Send(ctx, wsMsg); err != nil {
		log.Printf("[WSProxy] RemoveAgent error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove agent: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "agent removed successfully"})
}

// RenameAgent proxies agent renaming to WebSocket service
// PATCH /api/v1/agents/:id
func (p *ProxyHandlers) RenameAgent(c *gin.Context) {
	agentID := c.Param("id")

	var req struct {
		Alias string `json:"alias"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	wsMsg := map[string]interface{}{
		"type": "rename_agent",
		"data": map[string]interface{}{
			"guid":  agentID,
			"alias": req.Alias,
		},
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if err := p.client.Send(ctx, wsMsg); err != nil {
		log.Printf("[WSProxy] RenameAgent error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rename agent: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "agent renamed successfully"})
}

// AddTag proxies tag addition to WebSocket service
// POST /api/v1/agents/:id/tags
func (p *ProxyHandlers) AddTag(c *gin.Context) {
	agentID := c.Param("id")

	var req struct {
		Tag string `json:"tag" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	wsMsg := map[string]interface{}{
		"type": "add_tag",
		"data": map[string]interface{}{
			"guid": agentID,
			"tag":  req.Tag,
		},
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if err := p.client.Send(ctx, wsMsg); err != nil {
		log.Printf("[WSProxy] AddTag error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add tag: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "tag added successfully"})
}

// RemoveTag proxies tag removal to WebSocket service
// DELETE /api/v1/agents/:id/tags/:tag
func (p *ProxyHandlers) RemoveTag(c *gin.Context) {
	agentID := c.Param("id")
	tag := c.Param("tag")

	wsMsg := map[string]interface{}{
		"type": "remove_tag",
		"data": map[string]interface{}{
			"guid": agentID,
			"tag":  tag,
		},
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if err := p.client.Send(ctx, wsMsg); err != nil {
		log.Printf("[WSProxy] RemoveTag error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove tag: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "tag removed successfully"})
}

// RefreshState proxies state refresh to WebSocket service
// POST /api/v1/refresh
func (p *ProxyHandlers) RefreshState(c *gin.Context) {
	wsMsg := map[string]interface{}{
		"type": "refresh_state",
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Send and wait for state response
	resp, err := p.client.SendAndWait(ctx, wsMsg, "state", 30*time.Second)
	if err != nil {
		log.Printf("[WSProxy] RefreshState error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh state: " + err.Error()})
		return
	}

	// Parse and return state
	var state interface{}
	if err := json.Unmarshal(resp.Data, &state); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse state"})
		return
	}

	c.JSON(http.StatusOK, state)
}

// UploadProfiles proxies profile uploads to WebSocket service
// POST /api/v1/profiles/upload
func (p *ProxyHandlers) UploadProfiles(c *gin.Context) {
	var tomlContent string

	// Check if it's a file upload or raw content
	contentType := c.GetHeader("Content-Type")

	if contentType == "application/toml" || contentType == "text/plain" {
		// Raw TOML content in body
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			return
		}
		tomlContent = string(body)
	} else {
		// Try multipart form file upload
		file, err := c.FormFile("profile")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "No profile file provided. Send TOML content with Content-Type: application/toml or upload a file with form field 'profile'",
			})
			return
		}

		// Open and read the file
		f, err := file.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open uploaded file"})
			return
		}
		defer f.Close()

		content, err := io.ReadAll(f)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read uploaded file"})
			return
		}
		tomlContent = string(content)
	}

	// Build WebSocket message
	wsMsg := map[string]interface{}{
		"type": "upload_profiles",
		"data": map[string]interface{}{
			"content": tomlContent,
		},
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Subscribe to messages before sending
	msgCh := p.client.Subscribe()

	// Send the upload_profiles message
	if err := p.client.Send(ctx, wsMsg); err != nil {
		log.Printf("[WSProxy] UploadProfiles send error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send request: " + err.Error()})
		return
	}

	// Wait for response
	timeout := time.After(30 * time.Second)
	for {
		select {
		case msg := <-msgCh:
			log.Printf("[WSProxy] UploadProfiles received message type=%q", msg.Type)

			// Check for profile_upload_response
			if msg.Type == "profile_upload_response" {
				var respData struct {
					Success                bool     `json:"success"`
					Message                string   `json:"message"`
					GetProfiles            []string `json:"get_profiles,omitempty"`
					PostProfiles           []string `json:"post_profiles,omitempty"`
					ServerResponseProfiles []string `json:"server_response_profiles,omitempty"`
					SMBProfiles            []string `json:"smb_profiles,omitempty"`
					Errors                 []string `json:"errors,omitempty"`
				}
				if err := json.Unmarshal(msg.Data, &respData); err == nil {
					log.Printf("[WSProxy] Received raw message: %s", string(msg.Data))
					if !respData.Success && len(respData.Errors) > 0 {
						c.JSON(http.StatusBadRequest, gin.H{
							"status":  "error",
							"message": respData.Message,
							"errors":  respData.Errors,
						})
						return
					}

					status := "success"
					if len(respData.Errors) > 0 {
						status = "partial"
					}

					c.JSON(http.StatusOK, gin.H{
						"status":                 status,
						"message":                respData.Message,
						"get_profiles_added":     respData.GetProfiles,
						"post_profiles_added":    respData.PostProfiles,
						"server_response_added":  respData.ServerResponseProfiles,
						"smb_profiles_added":     respData.SMBProfiles,
						"errors":                 respData.Errors,
					})
					return
				}
			}

		case <-timeout:
			log.Printf("[WSProxy] UploadProfiles timeout waiting for response")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "timeout waiting for response"})
			return

		case <-ctx.Done():
			c.JSON(http.StatusInternalServerError, gin.H{"error": "request cancelled"})
			return
		}
	}
}
