// internal/websocket/handlers/profiles.go
package handlers

import (
	"bytes"
	"c2/internal/common/config"
	"c2/internal/websocket/hub"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ProfileUploadMessage represents a profile upload request from the client
type ProfileUploadMessage struct {
	Type string `json:"type"`
	Data struct {
		Content string `json:"content"` // TOML content
	} `json:"data"`
}

// ProfileUploadResponse represents the response sent back to the client
type ProfileUploadResponse struct {
	Type string `json:"type"`
	Data struct {
		Success                bool     `json:"success"`
		Message                string   `json:"message"`
		GetProfiles            []string `json:"get_profiles,omitempty"`
		PostProfiles           []string `json:"post_profiles,omitempty"`
		ServerResponseProfiles []string `json:"server_response_profiles,omitempty"`
		SMBProfiles            []string `json:"smb_profiles,omitempty"`
		Errors                 []string `json:"errors,omitempty"`
	} `json:"data"`
}

// handleUploadProfiles processes profile upload requests from WebSocket clients
func (h *WSHandler) handleUploadProfiles(client *hub.Client, message []byte) error {
	var uploadMsg ProfileUploadMessage
	if err := json.Unmarshal(message, &uploadMsg); err != nil {
		return h.sendProfileError(client, fmt.Sprintf("Failed to parse message: %v", err))
	}

	if uploadMsg.Data.Content == "" {
		return h.sendProfileError(client, "No profile content provided")
	}

	// Check if we have the agent config
	if h.agentConfig == nil {
		return h.sendProfileError(client, "Server configuration not available")
	}

	// Validate and add profiles
	result, err := h.agentConfig.ValidateAndAddProfiles(uploadMsg.Data.Content)
	if err != nil {
		return h.sendProfileError(client, fmt.Sprintf("Failed to parse TOML: %v", err))
	}

	// Count successful additions
	totalAdded := len(result.GetProfiles) + len(result.PostProfiles) + len(result.ServerResponseProfiles) + len(result.SMBProfiles)

	// Build response
	response := ProfileUploadResponse{
		Type: "profile_upload_response",
	}
	response.Data.Success = totalAdded > 0 || len(result.Errors) == 0
	response.Data.GetProfiles = result.GetProfiles
	response.Data.PostProfiles = result.PostProfiles
	response.Data.ServerResponseProfiles = result.ServerResponseProfiles
	response.Data.SMBProfiles = result.SMBProfiles
	response.Data.Errors = result.Errors

	if totalAdded > 0 {
		response.Data.Message = fmt.Sprintf("Successfully added %d profile(s)", totalAdded)
		logMessage(LOG_MINIMAL, "Profile upload: added %d GET, %d POST, %d Response, %d SMB profiles",
			len(result.GetProfiles), len(result.PostProfiles), len(result.ServerResponseProfiles), len(result.SMBProfiles))
	} else if len(result.Errors) > 0 {
		response.Data.Message = "No profiles were added due to validation errors"
	} else {
		response.Data.Message = "No profiles found in the uploaded content"
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %v", err)
	}

	client.Send <- responseJSON

	// If profiles were added, broadcast an update to all clients and sync to other services
	if totalAdded > 0 {
		h.broadcastProfileUpdate()
		h.syncProfilesToAgentHandler()
		h.syncProfilesToRestAPI()
	}

	return nil
}

// sendProfileError sends an error response for profile uploads
func (h *WSHandler) sendProfileError(client *hub.Client, message string) error {
	response := ProfileUploadResponse{
		Type: "profile_upload_response",
	}
	response.Data.Success = false
	response.Data.Message = message

	responseJSON, _ := json.Marshal(response)
	client.Send <- responseJSON

	logMessage(LOG_NORMAL, "Profile upload error: %s", message)
	return nil
}

// broadcastProfileUpdate notifies all clients that profiles have been updated
func (h *WSHandler) broadcastProfileUpdate() {
	if h.agentConfig == nil {
		return
	}

	update := struct {
		Type string `json:"type"`
		Data struct {
			GetProfiles            []string `json:"get_profiles"`
			PostProfiles           []string `json:"post_profiles"`
			ServerResponseProfiles []string `json:"server_response_profiles"`
			SMBProfiles            []string `json:"smb_profiles"`
		} `json:"data"`
	}{
		Type: "profiles_updated",
	}

	update.Data.GetProfiles = h.agentConfig.GetGetProfileNames()
	update.Data.PostProfiles = h.agentConfig.GetPostProfileNames()
	update.Data.ServerResponseProfiles = h.agentConfig.GetServerResponseProfileNames()

	// Get SMB profile names from SMB config
	if smbConfig, err := config.GetSMBLinkConfig(); err == nil && smbConfig != nil {
		update.Data.SMBProfiles = smbConfig.GetSMBProfileNames()
	}

	if updateJSON, err := json.Marshal(update); err == nil {
		h.hub.BroadcastToAll(context.Background(), updateJSON)
		logMessage(LOG_MINIMAL, "Broadcast profile update to all clients")
	}
}

// syncProfilesToAgentHandler sends profile updates to the agent-handler service via gRPC
// This ensures the agent-handler can route requests using newly uploaded profile paths
func (h *WSHandler) syncProfilesToAgentHandler() {
	if h.agentConfig == nil {
		return
	}

	// Get the agent client (with circuit breaker/reconnection support)
	agentClient, err := h.GetAgentClient()
	if err != nil {
		logMessage(LOG_NORMAL, "Cannot sync profiles to agent-handler: %v", err)
		return
	}

	// Serialize all profiles to send to agent-handler
	profileData := map[string]interface{}{
		"get_profiles":             h.agentConfig.HTTPProfiles.Get,
		"post_profiles":            h.agentConfig.HTTPProfiles.Post,
		"server_response_profiles": h.agentConfig.HTTPProfiles.ServerResponse,
	}

	if err := agentClient.SyncProfiles(profileData); err != nil {
		logMessage(LOG_NORMAL, "Failed to sync profiles to agent-handler: %v", err)
		return
	}

	logMessage(LOG_MINIMAL, "Successfully synced profiles to agent-handler (%d GET, %d POST, %d Response)",
		len(h.agentConfig.HTTPProfiles.Get),
		len(h.agentConfig.HTTPProfiles.Post),
		len(h.agentConfig.HTTPProfiles.ServerResponse))
}

// syncProfilesToRestAPI sends profile updates to the REST API service via HTTP
// This ensures the REST API can return accurate profile information
func (h *WSHandler) syncProfilesToRestAPI() {
	if h.agentConfig == nil {
		return
	}

	// Serialize all profiles
	profileData := map[string]interface{}{
		"get_profiles":             h.agentConfig.HTTPProfiles.Get,
		"post_profiles":            h.agentConfig.HTTPProfiles.Post,
		"server_response_profiles": h.agentConfig.HTTPProfiles.ServerResponse,
	}

	jsonData, err := json.Marshal(profileData)
	if err != nil {
		logMessage(LOG_NORMAL, "Failed to marshal profiles for REST API sync: %v", err)
		return
	}

	// Create HTTP client with TLS skip verify (internal service communication)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// REST API internal endpoint
	url := "https://rest-api:8443/internal/profiles/sync"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		logMessage(LOG_NORMAL, "Failed to create REST API sync request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logMessage(LOG_NORMAL, "Failed to sync profiles to REST API: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		logMessage(LOG_MINIMAL, "Successfully synced profiles to REST API (%d GET, %d POST, %d Response)",
			len(h.agentConfig.HTTPProfiles.Get),
			len(h.agentConfig.HTTPProfiles.Post),
			len(h.agentConfig.HTTPProfiles.ServerResponse))
	} else {
		logMessage(LOG_NORMAL, "REST API profile sync returned status: %d", resp.StatusCode)
	}
}

// handleGetProfiles returns the current list of available profiles
func (h *WSHandler) handleGetProfiles(client *hub.Client, message []byte) error {
	if h.agentConfig == nil {
		return h.sendProfileError(client, "Server configuration not available")
	}

	response := struct {
		Type string `json:"type"`
		Data struct {
			GetProfiles            []string `json:"get_profiles"`
			PostProfiles           []string `json:"post_profiles"`
			ServerResponseProfiles []string `json:"server_response_profiles"`
			SMBProfiles            []string `json:"smb_profiles"`
		} `json:"data"`
	}{
		Type: "profiles_list",
	}

	response.Data.GetProfiles = h.agentConfig.GetGetProfileNames()
	response.Data.PostProfiles = h.agentConfig.GetPostProfileNames()
	response.Data.ServerResponseProfiles = h.agentConfig.GetServerResponseProfileNames()

	// Get SMB profile names from SMB config
	if smbConfig, err := config.GetSMBLinkConfig(); err == nil && smbConfig != nil {
		response.Data.SMBProfiles = smbConfig.GetSMBProfileNames()
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal profiles list: %v", err)
	}

	client.Send <- responseJSON
	return nil
}
