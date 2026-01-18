// internal/rest/handlers/profiles.go
package handlers

import (
	"c2/internal/common/config"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ProfileHandler struct {
	config *config.AgentConfig
}

func NewProfileHandler(cfg *config.AgentConfig) *ProfileHandler {
	return &ProfileHandler{config: cfg}
}

// ListAllProfiles returns all available profiles (GET, POST, and server response)
// GET /api/v1/profiles
func (h *ProfileHandler) ListAllProfiles(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"get_profiles":             h.config.HTTPProfiles.Get,
		"post_profiles":            h.config.HTTPProfiles.Post,
		"server_response_profiles": h.config.HTTPProfiles.ServerResponse,
	})
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
	c.JSON(http.StatusOK, gin.H{
		"get_profiles":             h.config.GetGetProfileNames(),
		"post_profiles":            h.config.GetPostProfileNames(),
		"server_response_profiles": h.config.GetServerResponseProfileNames(),
	})
}
