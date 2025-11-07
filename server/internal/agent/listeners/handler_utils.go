// internal/agent/listeners/handler_utils.go
package listeners

import (
	"c2/internal/common/config"
	pb "c2/proto"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// extractClientID gets the client ID from the request URL parameters
func (m *Manager) extractClientID(r *http.Request, handler config.Handler) (string, error) {
	// Find the client ID parameter configuration
	var clientIDParam config.Param
	for _, param := range handler.Params {
		if param.Type == "clientID_param" {
			clientIDParam = param
			break
		}
	}

	// Get the client ID from the URL parameters
	clientID := r.URL.Query().Get(clientIDParam.Name)
	if clientID == "" {
		return "", fmt.Errorf("missing client ID parameter")
	}

	return clientID, nil
}

// validateClientID checks if the client ID exists and returns the InitData if valid
func (m *Manager) validateClientID(clientID string) (*InitData, error) {
	initData, err := m.GetInitData(clientID)
	if err != nil {
		return nil, err
	}
	return initData, nil
}

// getRemoteIP extracts the real IP address from the request
func getRemoteIP(r *http.Request) string {
	// Check X-Forwarded-For header
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Return first IP in the list
		return strings.Split(forwarded, ",")[0]
	}

	// Get direct IP
	remoteIP := r.RemoteAddr
	// Strip port if present
	if strings.Contains(remoteIP, ":") {
		remoteIP = strings.Split(remoteIP, ":")[0]
	}
	return remoteIP
}

// createReactivationNotification creates a notification for agent reactivation
func (m *Manager) createReactivationNotification(clientID string, initData *InitData, remoteAddr string) *pb.ConnectionNotification {
	return &pb.ConnectionNotification{
		NewClientId: clientID,
		ClientId:    initData.ClientID,
		Protocol:    initData.Protocol,
		ExtIp:       remoteAddr,
		LastSeen:    time.Now().Unix(),
	}
}
