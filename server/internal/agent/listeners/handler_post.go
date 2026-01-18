// internal/agent/listeners/handler_post.go
package listeners

import (
	"c2/internal/common/config"
	"database/sql"
	"log"
	"net/http"
)

// handlePostRequest processes POST requests from agents
func (m *Manager) handlePostRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] Received request to path: %s", r.Method, r.URL.Path)
	log.Printf("[%s] Looking for handler in %d configured POST routes", r.Method, len(m.routes.Routes.Post))

	// Check if async handler is available
	var asyncHandler *AsyncHandler
	var hasAsync bool

	if m.asyncEnabled {
		asyncHandler, hasAsync = m.handler.(*AsyncHandler)
		if hasAsync {
			log.Printf("[%s] Async processing is enabled", r.Method)
		} else {
			log.Printf("[%s] Async enabled but handler not found", r.Method)
		}
	}

	// Find the matching POST handler based on path AND method
	var matchingHandler *config.Handler
	for i, postHandler := range m.routes.Routes.Post {
		log.Printf("[%s] Checking against configured path: %s, method: %s (enabled: %v)",
			r.Method, postHandler.Path, postHandler.Method, postHandler.Enabled)

		if postHandler.Path == r.URL.Path && postHandler.Method == r.Method && postHandler.Enabled {
			matchingHandler = &m.routes.Routes.Post[i]
			break
		}
	}

	if matchingHandler == nil {
		log.Printf("[%s] No matching route found for %s with method %s", r.Method, r.URL.Path, r.Method)
		http.NotFound(w, r)
		return
	}

	log.Printf("[%s] Found matching route for %s", r.Method, r.URL.Path)

	clientID, err := m.extractClientID(r, *matchingHandler)
	if err != nil {
		log.Printf("[%s] Failed to extract client ID: %v", r.Method, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	log.Printf("[%s] Successfully extracted client ID: %s", r.Method, clientID)

	// First check reactivation
	if initData, err := m.GetInitData(clientID); err == nil {
		// Check if agent exists but was deleted
		var deletedAt sql.NullTime
		err := m.db.QueryRow(`
			SELECT deleted_at 
			FROM connections 
			WHERE newclientid = $1`, clientID).Scan(&deletedAt)

		if err == nil && deletedAt.Valid {
			// Clear deleted_at flag
			if _, err := m.db.Exec(`
				UPDATE connections 
				SET deleted_at = NULL, 
					lastSEEN = CURRENT_TIMESTAMP
				WHERE newclientid = $1`, clientID); err != nil {
				log.Printf("Failed to reactivate agent: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// Notify websocket service about reactivation
			notification := m.createReactivationNotification(clientID, initData, r.RemoteAddr)
			if err := m.notifyWebsocketService(notification); err != nil {
				log.Printf("Warning: Failed to notify about agent reactivation: %v", err)
			}
		}
	}

	// Check if this is an init request
	initData, err := m.validateClientID(clientID)
	if err == nil {
		log.Printf("[%s] Found init data for client %s, handling initial handshake", r.Method, clientID)
		if err := m.handleInitialHandshake(w, r, initData); err != nil {
			log.Printf("[%s] Initial handshake failed for client %s: %v", r.Method, clientID, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		log.Printf("[%s] Successfully handled initial handshake for client %s", r.Method, clientID)
		return
	}
	log.Printf("[%s] No init data found for %s, checking active connections", r.Method, clientID)

	// Check for active session
	activeConn, err := m.activeConnections.GetConnection(clientID)
	if err != nil {
		log.Printf("[%s] No active connection found for client %s: %v", r.Method, clientID, err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	log.Printf("[%s] Found active connection for client %s", r.Method, clientID)

	// Use async handler if available, otherwise fall back to sync
	if hasAsync && asyncHandler != nil {
		log.Printf("[%s] Using async handler for client %s", r.Method, clientID)
		asyncHandler.handleActiveConnectionAsync(w, r, activeConn)
	} else {
		log.Printf("[%s] Using sync handler for client %s", r.Method, clientID)
		m.handleActiveConnection(w, r, activeConn, m.db)
	}
}

// handlePostRequestWithProfile handles POST requests for profile-bound listeners
// Used by shared port routing when a profile is explicitly bound
func (m *Manager) handlePostRequestWithProfile(w http.ResponseWriter, r *http.Request, postProfile *config.PostProfile) {
	log.Printf("[%s] Processing request using profile: %s", r.Method, postProfile.Name)

	// Extract clientID using profile's params
	handler := config.Handler{
		Path:    postProfile.Path,
		Method:  postProfile.Method,
		Enabled: true,
		Params:  postProfile.Params,
	}

	clientID, err := m.extractClientID(r, handler)
	if err != nil {
		log.Printf("[%s] Failed to extract client ID: %v", r.Method, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	log.Printf("[%s] Extracted client ID: %s", r.Method, clientID)

	// Check async handler availability
	var asyncHandler *AsyncHandler
	var hasAsync bool
	if m.asyncEnabled {
		asyncHandler, hasAsync = m.handler.(*AsyncHandler)
	}

	// === Begin: Same logic as handlePostRequest after clientID extraction ===

	// First check reactivation
	if initData, err := m.GetInitData(clientID); err == nil {
		var deletedAt sql.NullTime
		err := m.db.QueryRow(`
			SELECT deleted_at
			FROM connections
			WHERE newclientid = $1`, clientID).Scan(&deletedAt)

		if err == nil && deletedAt.Valid {
			if _, err := m.db.Exec(`
				UPDATE connections
				SET deleted_at = NULL,
					lastSEEN = CURRENT_TIMESTAMP
				WHERE newclientid = $1`, clientID); err != nil {
				log.Printf("Failed to reactivate agent: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			notification := m.createReactivationNotification(clientID, initData, r.RemoteAddr)
			if err := m.notifyWebsocketService(notification); err != nil {
				log.Printf("Warning: Failed to notify about agent reactivation: %v", err)
			}
		}
	}

	// Check if this is an init request
	initData, err := m.validateClientID(clientID)
	if err == nil {
		log.Printf("[%s] Found init data for client %s, handling initial handshake", r.Method, clientID)
		if err := m.handleInitialHandshake(w, r, initData); err != nil {
			log.Printf("[%s] Initial handshake failed: %v", r.Method, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}

	// Check for active session
	activeConn, err := m.activeConnections.GetConnection(clientID)
	if err != nil {
		log.Printf("[%s] No active connection found: %v", r.Method, err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Use async or sync handler
	if hasAsync && asyncHandler != nil {
		asyncHandler.handleActiveConnectionAsync(w, r, activeConn)
	} else {
		m.handleActiveConnection(w, r, activeConn, m.db)
	}
}
