// internal/rest/handlers/listeners.go
package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"c2/internal/common/config"
	"c2/internal/rest/sse"
	"c2/internal/websocket/agent"
	"c2/internal/websocket/listeners"
	pb "c2/proto"

	"github.com/gin-gonic/gin"
)

type ListenerHandler struct {
	db              *sql.DB
	listenerManager *listeners.Manager
	agentClient     *agent.Client
	sseHub          *sse.Hub
	agentConfig     *config.AgentConfig
}

func NewListenerHandler(db *sql.DB, listenerManager *listeners.Manager, agentClient *agent.Client, sseHub *sse.Hub, agentConfig *config.AgentConfig) *ListenerHandler {
	return &ListenerHandler{
		db:              db,
		listenerManager: listenerManager,
		agentClient:     agentClient,
		sseHub:          sseHub,
		agentConfig:     agentConfig,
	}
}

// SetAgentClient updates the gRPC client (for reconnection handling)
func (h *ListenerHandler) SetAgentClient(client *agent.Client) {
	h.agentClient = client
}

type Listener struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	Protocol              string `json:"protocol"`
	Port                  string `json:"port"`
	IP                    string `json:"ip"`
	PipeName              string `json:"pipe_name,omitempty"`
	GetProfile            string `json:"get_profile"`
	PostProfile           string `json:"post_profile"`
	ServerResponseProfile string `json:"server_response_profile"`
	SMBProfile            string `json:"smb_profile,omitempty"`
}

type CreateListenerRequest struct {
	Name                  string `json:"name" binding:"required"`
	Protocol              string `json:"protocol" binding:"required"`
	Port                  int    `json:"port"`
	IP                    string `json:"ip"`
	PipeName              string `json:"pipe_name,omitempty"`
	GetProfile            string `json:"get_profile,omitempty"`
	PostProfile           string `json:"post_profile,omitempty"`
	ServerResponseProfile string `json:"server_response,omitempty"`
	SMBProfile            string `json:"smb_profile,omitempty"`
}

// ListListeners returns all configured listeners
// GET /api/v1/listeners
func (h *ListenerHandler) ListListeners(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	rows, err := h.db.QueryContext(ctx, `
		SELECT id, name, protocol, port, ip, COALESCE(pipe_name, ''),
		       COALESCE(get_profile, 'default-get'),
		       COALESCE(post_profile, 'default-post'),
		       COALESCE(server_response_profile, 'default-response'),
		       COALESCE(smb_profile, '')
		FROM listeners
		ORDER BY name
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query listeners"})
		return
	}
	defer rows.Close()

	listeners := make([]Listener, 0)
	for rows.Next() {
		var l Listener
		if err := rows.Scan(&l.ID, &l.Name, &l.Protocol, &l.Port, &l.IP, &l.PipeName,
			&l.GetProfile, &l.PostProfile, &l.ServerResponseProfile, &l.SMBProfile); err == nil {
			listeners = append(listeners, l)
		}
	}

	c.JSON(http.StatusOK, gin.H{"listeners": listeners})
}

// GetListener returns a single listener by name
// GET /api/v1/listeners/:name
func (h *ListenerHandler) GetListener(c *gin.Context) {
	name := c.Param("name")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var l Listener
	err := h.db.QueryRowContext(ctx, `
		SELECT id, name, protocol, port, ip, COALESCE(pipe_name, ''),
		       COALESCE(get_profile, 'default-get'),
		       COALESCE(post_profile, 'default-post'),
		       COALESCE(server_response_profile, 'default-response'),
		       COALESCE(smb_profile, '')
		FROM listeners WHERE name = $1
	`, name).Scan(&l.ID, &l.Name, &l.Protocol, &l.Port, &l.IP, &l.PipeName,
		&l.GetProfile, &l.PostProfile, &l.ServerResponseProfile, &l.SMBProfile)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "listener not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get listener"})
		return
	}

	c.JSON(http.StatusOK, l)
}

// CreateListener creates a new listener
// POST /api/v1/listeners
func (h *ListenerHandler) CreateListener(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	var req CreateListenerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Normalize protocol
	protocol := strings.ToUpper(req.Protocol)

	// Validate protocol
	validProtocols := map[string]bool{"HTTP": true, "HTTPS": true, "SMB": true, "RPC": true}
	if !validProtocols[protocol] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid protocol, must be HTTP, HTTPS, SMB, or RPC"})
		return
	}

	// SMB doesn't need port/IP
	isSMB := protocol == "SMB" || protocol == "RPC"

	if !isSMB {
		if req.Port < 1 || req.Port > 65535 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid port, must be 1-65535"})
			return
		}
		if req.IP == "" {
			req.IP = "0.0.0.0"
		}
	} else {
		if req.PipeName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "pipe_name required for SMB listeners"})
			return
		}
		req.Port = 0
		req.IP = ""
	}

	// Set default profile names if not provided
	if req.GetProfile == "" {
		req.GetProfile = "default-get"
	}
	if req.PostProfile == "" {
		req.PostProfile = "default-post"
	}
	if req.ServerResponseProfile == "" {
		req.ServerResponseProfile = "default-response"
	}

	// Validate that the specified profiles exist in config
	if err := h.validateListenerProfiles(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create via listener manager with profiles
	listener, err := h.listenerManager.CreateWithProfiles(req.Name, protocol, req.Port, req.IP, req.PipeName,
		req.GetProfile, req.PostProfile, req.ServerResponseProfile, req.SMBProfile)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// For non-SMB listeners, start via gRPC
	if !isSMB && h.agentClient != nil {
		listenerType := parseListenerType(protocol)
		secure := protocol == "HTTPS"

		resp, err := h.agentClient.StartListener(ctx, req.Name, int32(req.Port), listenerType, secure,
			req.GetProfile, req.PostProfile, req.ServerResponseProfile)
		if err != nil {
			// Rollback the database entry
			h.listenerManager.DeleteByName(req.Name)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start listener: " + err.Error()})
			return
		}

		if !resp.Success {
			h.listenerManager.DeleteByName(req.Name)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start listener: " + resp.Message})
			return
		}
	}

	createdListener := Listener{
		ID:                    listener.ID.String(),
		Name:                  listener.Name,
		Protocol:              listener.Protocol,
		Port:                  strconv.Itoa(listener.Port),
		IP:                    listener.IP,
		PipeName:              listener.PipeName,
		GetProfile:            listener.GetProfile,
		PostProfile:           listener.PostProfile,
		ServerResponseProfile: listener.ServerResponseProfile,
	}

	// Broadcast listener creation via SSE
	if h.sseHub != nil {
		h.sseHub.Broadcast("listener_update", map[string]interface{}{
			"event":    "created",
			"listener": createdListener,
		})
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":  "listener created successfully",
		"listener": createdListener,
	})
}

// DeleteListener removes a listener
// DELETE /api/v1/listeners/:name
func (h *ListenerHandler) DeleteListener(c *gin.Context) {
	name := c.Param("name")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// Get listener info first
	listener, exists := h.listenerManager.GetListener(name)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "listener not found"})
		return
	}

	protocol := strings.ToUpper(listener.Protocol)
	isSMB := protocol == "SMB" || protocol == "RPC"

	// Stop via gRPC if not SMB
	if !isSMB && h.agentClient != nil {
		if err := h.agentClient.StopListener(ctx, name); err != nil {
			// Log but continue with deletion
			// The listener might already be stopped
		}
	}

	// Delete from database
	if err := h.listenerManager.DeleteByName(name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete listener"})
		return
	}

	// Broadcast listener deletion via SSE
	if h.sseHub != nil {
		h.sseHub.Broadcast("listener_update", map[string]interface{}{
			"event": "deleted",
			"name":  name,
		})
	}

	c.JSON(http.StatusOK, gin.H{"message": "listener deleted successfully"})
}

func parseListenerType(protocol string) pb.ListenerType {
	switch strings.ToUpper(protocol) {
	case "HTTP":
		return pb.ListenerType_HTTP
	case "HTTPS":
		return pb.ListenerType_HTTPS
	case "TCP":
		return pb.ListenerType_TCP
	case "UDP":
		return pb.ListenerType_UDP
	default:
		return pb.ListenerType_UNKNOWN
	}
}

// validateListenerProfiles checks that all profile names exist in config
// Returns nil if all profiles are valid or if agentConfig is not available
func (h *ListenerHandler) validateListenerProfiles(req *CreateListenerRequest) error {
	// Skip validation if config not available
	if h.agentConfig == nil {
		return nil
	}

	// Validate GET profile if specified and not default
	if req.GetProfile != "" && req.GetProfile != "default-get" {
		if h.agentConfig.GetGetProfile(req.GetProfile) == nil {
			return fmt.Errorf("GET profile '%s' not found in config", req.GetProfile)
		}
	}

	// Validate POST profile if specified and not default
	if req.PostProfile != "" && req.PostProfile != "default-post" {
		if h.agentConfig.GetPostProfile(req.PostProfile) == nil {
			return fmt.Errorf("POST profile '%s' not found in config", req.PostProfile)
		}
	}

	// Validate ServerResponse profile if specified and not default
	if req.ServerResponseProfile != "" && req.ServerResponseProfile != "default-response" {
		if h.agentConfig.GetServerResponseProfile(req.ServerResponseProfile) == nil {
			return fmt.Errorf("ServerResponse profile '%s' not found in config", req.ServerResponseProfile)
		}
	}

	return nil
}
