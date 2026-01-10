// internal/rest/handlers/auth.go
package handlers

import (
	"net/http"

	"c2/internal/rest/auth"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	jwtManager  *auth.JWTManager
	apiPassword string // Shared API password for simplified auth
}

func NewAuthHandler(jwtManager *auth.JWTManager, apiPassword string) *AuthHandler {
	return &AuthHandler{
		jwtManager:  jwtManager,
		apiPassword: apiPassword,
	}
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type CertLoginRequest struct {
	Username string `json:"username" binding:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// Login authenticates a user and returns a token pair
// POST /api/v1/auth/login
//
// This endpoint supports two authentication modes:
// 1. Shared API password: If the password matches the API_PASSWORD env var,
//    the user is authenticated (auto-provisioned if needed).
// 2. User-specific password: Falls back to checking user's stored password.
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	var tokenPair *auth.TokenPair
	var err error

	// First, try shared API password if configured
	if h.apiPassword != "" && req.Password == h.apiPassword {
		// Use cert-style auth (auto-provisions user if needed)
		tokenPair, err = h.jwtManager.AuthenticateByUsername(req.Username)
	} else {
		// Fall back to user-specific password
		tokenPair, err = h.jwtManager.Authenticate(req.Username, req.Password)
	}

	if err != nil {
		switch err {
		case auth.ErrInvalidCredentials:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		case auth.ErrUserInactive:
			c.JSON(http.StatusForbidden, gin.H{"error": "user account is inactive"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication failed"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"expires_in":    tokenPair.ExpiresIn,
		"token_type":    tokenPair.TokenType,
		"username":      req.Username,
	})
}

// Refresh generates a new token pair using a refresh token
// POST /api/v1/auth/refresh
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	result, err := h.jwtManager.RefreshTokens(req.RefreshToken)
	if err != nil {
		switch err {
		case auth.ErrInvalidToken:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		case auth.ErrTokenExpired:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token expired"})
		case auth.ErrUserInactive:
			c.JSON(http.StatusForbidden, gin.H{"error": "user account is inactive"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "token refresh failed"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  result.TokenPair.AccessToken,
		"refresh_token": result.TokenPair.RefreshToken,
		"expires_in":    result.TokenPair.ExpiresIn,
		"token_type":    result.TokenPair.TokenType,
		"username":      result.Username,
	})
}

// Logout invalidates a refresh token
// POST /api/v1/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := h.jwtManager.InvalidateRefreshToken(req.RefreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "logout failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

// Me returns the current user's info
// GET /api/v1/auth/me
func (h *AuthHandler) Me(c *gin.Context) {
	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")

	c.JSON(http.StatusOK, gin.H{
		"user_id":  userID,
		"username": username,
	})
}

// CertLogin authenticates using TLS connection (no password required)
// If user can establish TLS connection, they are authorized
// POST /api/v1/auth/cert-login
func (h *AuthHandler) CertLogin(c *gin.Context) {
	var req CertLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}

	// Auto-provision user and generate token
	tokenPair, err := h.jwtManager.AuthenticateByUsername(req.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"expires_in":    tokenPair.ExpiresIn,
		"token_type":    tokenPair.TokenType,
		"username":      req.Username,
	})
}
