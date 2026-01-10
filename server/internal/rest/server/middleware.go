// internal/rest/server/middleware.go
package server

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"c2/internal/rest/auth"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware validates JWT tokens
func AuthMiddleware(jwtManager *auth.JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]
		claims, err := jwtManager.ValidateAccessToken(tokenString)
		if err != nil {
			switch err {
			case auth.ErrTokenExpired:
				c.JSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
			case auth.ErrInvalidToken:
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			default:
				c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
			}
			c.Abort()
			return
		}

		// Set user info in context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Next()
	}
}

// CORSMiddleware handles Cross-Origin Resource Sharing
func CORSMiddleware(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Check if origin is allowed
		allowed := false
		for _, o := range allowedOrigins {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	tokens         map[string]int
	lastRefill     map[string]time.Time
	maxTokens      int
	refillRate     int // tokens per minute
	mu             sync.Mutex
	cleanupTicker  *time.Ticker
}

func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	rl := &RateLimiter{
		tokens:     make(map[string]int),
		lastRefill: make(map[string]time.Time),
		maxTokens:  requestsPerMinute,
		refillRate: requestsPerMinute,
	}

	// Cleanup old entries periodically
	rl.cleanupTicker = time.NewTicker(5 * time.Minute)
	go func() {
		for range rl.cleanupTicker.C {
			rl.cleanup()
		}
	}()

	return rl
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for key, lastRefill := range rl.lastRefill {
		if lastRefill.Before(cutoff) {
			delete(rl.tokens, key)
			delete(rl.lastRefill, key)
		}
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Initialize if new key
	if _, exists := rl.tokens[key]; !exists {
		rl.tokens[key] = rl.maxTokens
		rl.lastRefill[key] = now
	}

	// Refill tokens based on time elapsed
	elapsed := now.Sub(rl.lastRefill[key])
	tokensToAdd := int(elapsed.Minutes()) * rl.refillRate
	if tokensToAdd > 0 {
		rl.tokens[key] = min(rl.tokens[key]+tokensToAdd, rl.maxTokens)
		rl.lastRefill[key] = now
	}

	// Check if request is allowed
	if rl.tokens[key] > 0 {
		rl.tokens[key]--
		return true
	}

	return false
}

func (rl *RateLimiter) Stop() {
	if rl.cleanupTicker != nil {
		rl.cleanupTicker.Stop()
	}
}

// RateLimitMiddleware applies rate limiting per IP
func RateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use IP as rate limit key
		key := c.ClientIP()

		if !limiter.Allow(key) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
				"retry_after": 60,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// LoggingMiddleware logs requests
func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method

		log.Printf("[API] %s | %3d | %13v | %15s | %s %s",
			time.Now().Format("2006/01/02 - 15:04:05"),
			status,
			latency,
			clientIP,
			method,
			path,
		)
	}
}

// RecoveryMiddleware recovers from panics
func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("[PANIC] %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "internal server error",
				})
				c.Abort()
			}
		}()
		c.Next()
	}
}
