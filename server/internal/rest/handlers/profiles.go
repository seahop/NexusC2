// internal/rest/handlers/profiles.go
package handlers

import (
	"c2/internal/common/config"
	"c2/internal/websocket/agent"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

type ProfileHandler struct {
	config      *config.AgentConfig
	agentClient *agent.Client
}

func NewProfileHandler(cfg *config.AgentConfig) *ProfileHandler {
	return &ProfileHandler{config: cfg}
}

// SetAgentClient sets the gRPC client for syncing profiles to agent-handler
func (h *ProfileHandler) SetAgentClient(client *agent.Client) {
	h.agentClient = client
}

// ListAllProfiles returns all available profiles (GET, POST, server response, and SMB)
// GET /api/v1/profiles
func (h *ProfileHandler) ListAllProfiles(c *gin.Context) {
	response := gin.H{
		"get_profiles":             h.config.HTTPProfiles.Get,
		"post_profiles":            h.config.HTTPProfiles.Post,
		"server_response_profiles": h.config.HTTPProfiles.ServerResponse,
	}

	// Include SMB profiles if available
	if smbConfig, err := config.GetSMBLinkConfig(); err == nil && smbConfig != nil {
		response["smb_profiles"] = smbConfig.GetSMBProfiles()
	}

	// Include TCP profiles if available
	if tcpConfig, err := config.GetTCPLinkConfig(); err == nil && tcpConfig != nil {
		response["tcp_profiles"] = tcpConfig.GetTCPProfiles()
	}

	c.JSON(http.StatusOK, response)
}

// ListGetProfiles returns all GET profiles
// GET /api/v1/profiles/get
func (h *ProfileHandler) ListGetProfiles(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"profiles": h.config.HTTPProfiles.Get})
}

// GetGetProfile returns a specific GET profile by name
// GET /api/v1/profiles/get/:name
func (h *ProfileHandler) GetGetProfile(c *gin.Context) {
	name := c.Param("name")
	profile := h.config.GetGetProfile(name)
	if profile == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "GET profile not found"})
		return
	}
	c.JSON(http.StatusOK, profile)
}

// ListPostProfiles returns all POST profiles
// GET /api/v1/profiles/post
func (h *ProfileHandler) ListPostProfiles(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"profiles": h.config.HTTPProfiles.Post})
}

// GetPostProfile returns a specific POST profile by name
// GET /api/v1/profiles/post/:name
func (h *ProfileHandler) GetPostProfile(c *gin.Context) {
	name := c.Param("name")
	profile := h.config.GetPostProfile(name)
	if profile == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "POST profile not found"})
		return
	}
	c.JSON(http.StatusOK, profile)
}

// ListServerResponseProfiles returns all server response profiles
// GET /api/v1/profiles/server-response
func (h *ProfileHandler) ListServerResponseProfiles(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"profiles": h.config.HTTPProfiles.ServerResponse})
}

// GetServerResponseProfile returns a specific server response profile by name
// GET /api/v1/profiles/server-response/:name
func (h *ProfileHandler) GetServerResponseProfile(c *gin.Context) {
	name := c.Param("name")
	profile := h.config.GetServerResponseProfile(name)
	if profile == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "server response profile not found"})
		return
	}
	c.JSON(http.StatusOK, profile)
}

// GetProfileNames returns just the names of all profiles (useful for dropdowns)
// GET /api/v1/profiles/names
func (h *ProfileHandler) GetProfileNames(c *gin.Context) {
	response := gin.H{
		"get_profiles":             h.config.GetGetProfileNames(),
		"post_profiles":            h.config.GetPostProfileNames(),
		"server_response_profiles": h.config.GetServerResponseProfileNames(),
	}

	// Include SMB profile names if available
	if smbConfig, err := config.GetSMBLinkConfig(); err == nil && smbConfig != nil {
		response["smb_profiles"] = smbConfig.GetSMBProfileNames()
	}

	// Include TCP profile names if available
	if tcpConfig, err := config.GetTCPLinkConfig(); err == nil && tcpConfig != nil {
		response["tcp_profiles"] = tcpConfig.GetTCPProfileNames()
	}

	c.JSON(http.StatusOK, response)
}

// UploadProfiles accepts a TOML file or raw TOML content and adds profiles to the config
// POST /api/v1/profiles/upload
func (h *ProfileHandler) UploadProfiles(c *gin.Context) {
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

	// Validate and add profiles
	result, err := h.config.ValidateAndAddProfiles(tomlContent)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Determine response status - include SMB and TCP profiles in count
	totalAdded := len(result.GetProfiles) + len(result.PostProfiles) + len(result.ServerResponseProfiles) + len(result.SMBProfiles) + len(result.TCPProfiles)
	if totalAdded == 0 && len(result.Errors) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "No profiles were added",
			"errors":  result.Errors,
		})
		return
	}

	status := "success"
	if len(result.Errors) > 0 {
		status = "partial"
	}

	// Sync HTTP profiles to agent-handler if client available
	httpAdded := len(result.GetProfiles) + len(result.PostProfiles) + len(result.ServerResponseProfiles)
	if h.agentClient != nil && httpAdded > 0 {
		profileData := map[string]interface{}{
			"get_profiles":             h.config.HTTPProfiles.Get,
			"post_profiles":            h.config.HTTPProfiles.Post,
			"server_response_profiles": h.config.HTTPProfiles.ServerResponse,
		}
		if err := h.agentClient.SyncProfiles(profileData); err != nil {
			log.Printf("[REST] Warning: Failed to sync profiles to agent-handler: %v", err)
			// Don't fail the request - profiles are saved, just not synced yet
		} else {
			log.Printf("[REST] Successfully synced profiles to agent-handler (%d GET, %d POST, %d Response)",
				len(h.config.HTTPProfiles.Get),
				len(h.config.HTTPProfiles.Post),
				len(h.config.HTTPProfiles.ServerResponse))
		}
	}

	// Log SMB profile additions and current state
	if len(result.SMBProfiles) > 0 {
		log.Printf("[REST] Added %d SMB profiles: %v", len(result.SMBProfiles), result.SMBProfiles)
	}
	// Debug: log current SMB profile count
	if smbConfig, err := config.GetSMBLinkConfig(); err == nil && smbConfig != nil {
		log.Printf("[REST] Current SMB profiles in config: %v", smbConfig.GetSMBProfileNames())
	}

	// Log TCP profile additions and current state
	if len(result.TCPProfiles) > 0 {
		log.Printf("[REST] Added %d TCP profiles: %v", len(result.TCPProfiles), result.TCPProfiles)
	}
	// Debug: log current TCP profile count
	if tcpConfig, err := config.GetTCPLinkConfig(); err == nil && tcpConfig != nil {
		log.Printf("[REST] Current TCP profiles in config: %v", tcpConfig.GetTCPProfileNames())
	}

	message := fmt.Sprintf("Successfully added %d profile(s)", totalAdded)
	if totalAdded == 0 {
		message = "No new profiles added (may already exist)"
	}

	c.JSON(http.StatusOK, gin.H{
		"status":                   status,
		"message":                  message,
		"get_profiles_added":       result.GetProfiles,
		"post_profiles_added":      result.PostProfiles,
		"server_response_added":    result.ServerResponseProfiles,
		"smb_profiles_added":       result.SMBProfiles,
		"tcp_profiles_added":       result.TCPProfiles,
		"errors":                   result.Errors,
	})
}

// GetTemplate returns the profile template file
// GET /api/v1/profiles/template
func (h *ProfileHandler) GetTemplate(c *gin.Context) {
	templatePath := "/app/templates/listener_template.toml"

	content, err := os.ReadFile(templatePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Template file not found"})
		return
	}

	c.Header("Content-Type", "application/toml")
	c.Header("Content-Disposition", "attachment; filename=listener_template.toml")
	c.String(http.StatusOK, string(content))
}

// DeleteGetProfile removes a GET profile by name
// DELETE /api/v1/profiles/get/:name
func (h *ProfileHandler) DeleteGetProfile(c *gin.Context) {
	name := c.Param("name")
	if h.config.RemoveGetProfile(name) {
		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "GET profile deleted"})
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error": "GET profile not found"})
	}
}

// DeletePostProfile removes a POST profile by name
// DELETE /api/v1/profiles/post/:name
func (h *ProfileHandler) DeletePostProfile(c *gin.Context) {
	name := c.Param("name")
	if h.config.RemovePostProfile(name) {
		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "POST profile deleted"})
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error": "POST profile not found"})
	}
}

// DeleteServerResponseProfile removes a server response profile by name
// DELETE /api/v1/profiles/server-response/:name
func (h *ProfileHandler) DeleteServerResponseProfile(c *gin.Context) {
	name := c.Param("name")
	if h.config.RemoveServerResponseProfile(name) {
		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Server response profile deleted"})
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server response profile not found"})
	}
}

// SyncProfiles receives profile updates from other services (internal endpoint)
// POST /internal/profiles/sync
func (h *ProfileHandler) SyncProfiles(c *gin.Context) {
	var profileData struct {
		GetProfiles            []config.GetProfile            `json:"get_profiles"`
		PostProfiles           []config.PostProfile           `json:"post_profiles"`
		ServerResponseProfiles []config.ServerResponseProfile `json:"server_response_profiles"`
		SMBProfiles            []config.SMBProfile            `json:"smb_profiles"`
		TCPProfiles            []config.TCPProfile            `json:"tcp_profiles"`
	}

	if err := c.ShouldBindJSON(&profileData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid profile data: " + err.Error()})
		return
	}

	// Update the HTTP profiles in config
	h.config.HTTPProfiles.Get = profileData.GetProfiles
	h.config.HTTPProfiles.Post = profileData.PostProfiles
	h.config.HTTPProfiles.ServerResponse = profileData.ServerResponseProfiles

	// Update SMB profiles in SMBLinkConfig singleton
	smbCount := 0
	if len(profileData.SMBProfiles) > 0 {
		if smbConfig, err := config.GetSMBLinkConfig(); err == nil && smbConfig != nil {
			// Replace all SMB profiles with the synced ones
			smbConfig.ReplaceSMBProfiles(profileData.SMBProfiles)
			smbCount = len(profileData.SMBProfiles)
			log.Printf("[REST] Synced %d SMB profiles from WebSocket service", smbCount)
		}
	}

	// Update TCP profiles in TCPLinkConfig singleton
	tcpCount := 0
	if len(profileData.TCPProfiles) > 0 {
		if tcpConfig, err := config.GetTCPLinkConfig(); err == nil && tcpConfig != nil {
			// Replace all TCP profiles with the synced ones
			tcpConfig.ReplaceTCPProfiles(profileData.TCPProfiles)
			tcpCount = len(profileData.TCPProfiles)
			log.Printf("[REST] Synced %d TCP profiles from WebSocket service", tcpCount)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Profiles synced successfully",
		"count": gin.H{
			"get":             len(profileData.GetProfiles),
			"post":            len(profileData.PostProfiles),
			"server_response": len(profileData.ServerResponseProfiles),
			"smb":             smbCount,
			"tcp":             tcpCount,
		},
	})
}
