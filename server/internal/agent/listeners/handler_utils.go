// internal/agent/listeners/handler_utils.go
package listeners

import (
	"c2/internal/common/config"
	"c2/internal/common/transforms"
	pb "c2/proto"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
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

// getHTTPXorKeyForAgent retrieves the per-build unique HTTP XOR key for an agent
func (m *Manager) getHTTPXorKeyForAgent(clientID string) string {
	// Try to get from InitData cache first
	if initData, err := m.GetInitData(clientID); err == nil && initData.HTTPXorKey != "" {
		log.Printf("[HTTPTransform] Using per-agent HTTP XOR key for %s (from init cache)", clientID)
		return initData.HTTPXorKey
	}

	// Fall back to database lookup via connections table
	var xorKey sql.NullString
	err := m.db.QueryRow(`
        SELECT i.http_xor_key FROM inits i
        INNER JOIN connections c ON c.clientID = i.clientID::text
        WHERE c.newclientID = $1 OR c.clientID = $1`,
		clientID).Scan(&xorKey)

	if err == nil && xorKey.Valid && xorKey.String != "" {
		log.Printf("[HTTPTransform] Using per-agent HTTP XOR key for %s (from database)", clientID)
		return xorKey.String
	}

	// No per-agent key found - will use profile's static key
	return ""
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

// =============================================================================
// DATABLOCK-AWARE EXTRACTION FUNCTIONS (Malleable Transforms Support)
// =============================================================================

// extractFromLocation extracts raw data from an HTTP request based on output location
// Supports: body, header:<name>, cookie:<name>, query:<name>, uri_append
func extractFromLocation(r *http.Request, output string, basePath string) ([]byte, error) {
	locType, name := transforms.ParseOutput(output)
	log.Printf("[extractFromLocation] Extracting from output=%q (type=%s, name=%s)", output, locType, name)

	switch locType {
	case "body":
		// Read entire body
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read body: %v", err)
		}
		return data, nil

	case "header":
		value := r.Header.Get(name)
		if value == "" {
			log.Printf("[extractFromLocation] Available headers: %v", r.Header)
			return nil, fmt.Errorf("header %s not found or empty", name)
		}
		return []byte(value), nil

	case "cookie":
		// Log all available cookies for debugging
		cookies := r.Cookies()
		cookieNames := make([]string, len(cookies))
		for i, c := range cookies {
			cookieNames[i] = c.Name
		}
		log.Printf("[extractFromLocation] Looking for cookie %q, available cookies: %v", name, cookieNames)

		cookie, err := r.Cookie(name)
		if err != nil {
			return nil, fmt.Errorf("cookie %s not found: %v", name, err)
		}
		log.Printf("[extractFromLocation] Found cookie %s with value: %q", name, cookie.Value)
		return []byte(cookie.Value), nil

	case "query":
		value := r.URL.Query().Get(name)
		if value == "" {
			return nil, fmt.Errorf("query param %s not found or empty", name)
		}
		return []byte(value), nil

	case "uri_append":
		// Extract suffix after the base path
		if !strings.HasPrefix(r.URL.Path, basePath) {
			return nil, fmt.Errorf("path %s does not start with base %s", r.URL.Path, basePath)
		}
		suffix := strings.TrimPrefix(r.URL.Path, basePath)
		suffix = strings.TrimPrefix(suffix, "/") // Remove leading slash if present
		return []byte(suffix), nil

	default:
		return nil, fmt.Errorf("unknown output location type: %s", locType)
	}
}

// convertConfigTransforms converts config.Transform slice to transforms.Transform slice
func convertConfigTransforms(cfgTransforms []config.Transform) []transforms.Transform {
	result := make([]transforms.Transform, len(cfgTransforms))
	for i, t := range cfgTransforms {
		result[i] = transforms.Transform{
			Type:    transforms.TransformType(t.Type),
			Value:   t.Value,
			Length:  t.Length,
			Charset: transforms.Charset(t.Charset),
		}
	}
	return result
}

// extractClientIDFromDataBlock extracts clientID using DataBlock configuration
// Falls back to legacy extraction if dataBlock is nil
// xorKeyOverride: if provided, replaces XOR transform values for per-agent unique keys
func (m *Manager) extractClientIDFromDataBlock(r *http.Request, dataBlock *config.DataBlock, legacyHandler config.Handler, basePath string, xorKeyOverride string) (string, error) {
	// Fall back to legacy extraction if no DataBlock configured
	if dataBlock == nil {
		return m.extractClientID(r, legacyHandler)
	}

	// Extract raw data from configured location
	rawData, err := extractFromLocation(r, dataBlock.Output, basePath)
	if err != nil {
		return "", fmt.Errorf("failed to extract from location %s: %v", dataBlock.Output, err)
	}

	// If no transforms, return data as-is
	if len(dataBlock.Transforms) == 0 {
		return string(rawData), nil
	}

	// Convert config transforms to transform package types
	xforms := convertConfigTransforms(dataBlock.Transforms)

	// Override XOR values with per-agent unique key if provided
	if xorKeyOverride != "" {
		xforms = overrideXorValue(xforms, xorKeyOverride)
	}

	// Reverse transforms to get original clientID (pass 0 to use transform's Length)
	clientIDBytes, err := transforms.Reverse(rawData, xforms, 0, 0)
	if err != nil {
		return "", fmt.Errorf("transform reversal failed: %v", err)
	}

	clientID := string(clientIDBytes)
	if clientID == "" {
		return "", fmt.Errorf("extracted clientID is empty after transform reversal")
	}

	return clientID, nil
}

// extractDataFromDataBlock extracts and reverses transforms on request data
// Returns raw data if dataBlock is nil (legacy mode)
// xorKeyOverride: if provided, replaces XOR transform values for per-agent unique keys
func (m *Manager) extractDataFromDataBlock(r *http.Request, dataBlock *config.DataBlock, basePath string, xorKeyOverride string) ([]byte, error) {
	// Legacy mode: read body directly
	if dataBlock == nil {
		return io.ReadAll(r.Body)
	}

	// Extract raw data from configured location
	rawData, err := extractFromLocation(r, dataBlock.Output, basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract from location %s: %v", dataBlock.Output, err)
	}

	// If no transforms, return data as-is
	if len(dataBlock.Transforms) == 0 {
		return rawData, nil
	}

	// Get padding lengths from headers
	prependLen, _ := strconv.Atoi(r.Header.Get("X-Pad-Pre"))
	appendLen, _ := strconv.Atoi(r.Header.Get("X-Pad-App"))

	// Convert and reverse transforms
	xforms := convertConfigTransforms(dataBlock.Transforms)

	// Override XOR values with per-agent unique key if provided
	if xorKeyOverride != "" {
		xforms = overrideXorValue(xforms, xorKeyOverride)
	}

	return transforms.Reverse(rawData, xforms, prependLen, appendLen)
}
