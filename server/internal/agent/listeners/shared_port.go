// internal/agent/listeners/shared_port.go
package listeners

import (
	"c2/internal/common/config"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"sync"
)

// SharedPortServer manages a single http.Server that can host multiple listeners
// sharing the same port, differentiated by their URL paths from malleable profiles.
type SharedPortServer struct {
	Port      int
	Protocol  string // HTTP or HTTPS
	Server    *http.Server
	TLSConfig *tls.Config

	// pathRoutes maps "METHOD:path" to listener name for routing
	// e.g., "GET:/api/v1/status" -> "listener-1"
	pathRoutes map[string]string

	// listenerHandlers maps listener name to its handler configuration
	listenerHandlers map[string]*ListenerHandler

	// listenerConfigs stores the original config for each listener (used for fallback routing)
	listenerConfigs map[string]config.ListenerConfig

	mu sync.RWMutex
}

// ListenerHandler holds the routing configuration for a single listener on a shared port
type ListenerHandler struct {
	ListenerName          string
	GetProfile            *config.GetProfile
	PostProfile           *config.PostProfile
	ServerResponseProfile *config.ServerResponseProfile
	Headers               map[string]string
	AllowedMethods        []string
}

// PathRoute represents a registered path on a shared port (for debugging/inspection)
type PathRoute struct {
	Path         string
	Method       string
	ListenerName string
	ProfileType  string // "get" or "post"
}

// NewSharedPortServer creates a new shared port server
func NewSharedPortServer(port int, protocol string) *SharedPortServer {
	return &SharedPortServer{
		Port:             port,
		Protocol:         protocol,
		pathRoutes:       make(map[string]string),
		listenerHandlers: make(map[string]*ListenerHandler),
		listenerConfigs:  make(map[string]config.ListenerConfig),
	}
}

// RegisterListener adds a listener's routes to this shared port
// Returns error if any path conflicts with existing listeners
func (sps *SharedPortServer) RegisterListener(name string, handler *ListenerHandler, cfg config.ListenerConfig) error {
	sps.mu.Lock()
	defer sps.mu.Unlock()

	// Check for path conflicts before registering
	if handler.GetProfile != nil {
		key := handler.GetProfile.Method + ":" + handler.GetProfile.Path
		if existing, exists := sps.pathRoutes[key]; exists {
			return fmt.Errorf("path conflict: %s %s already registered by listener '%s'",
				handler.GetProfile.Method, handler.GetProfile.Path, existing)
		}
	}

	if handler.PostProfile != nil {
		key := handler.PostProfile.Method + ":" + handler.PostProfile.Path
		if existing, exists := sps.pathRoutes[key]; exists {
			return fmt.Errorf("path conflict: %s %s already registered by listener '%s'",
				handler.PostProfile.Method, handler.PostProfile.Path, existing)
		}
	}

	// Register GET profile path
	if handler.GetProfile != nil {
		key := handler.GetProfile.Method + ":" + handler.GetProfile.Path
		sps.pathRoutes[key] = name
		log.Printf("[SharedPort:%d] Registered route: %s -> listener '%s' (GET profile)",
			sps.Port, key, name)
	}

	// Register POST profile path
	if handler.PostProfile != nil {
		key := handler.PostProfile.Method + ":" + handler.PostProfile.Path
		sps.pathRoutes[key] = name
		log.Printf("[SharedPort:%d] Registered route: %s -> listener '%s' (POST profile)",
			sps.Port, key, name)
	}

	sps.listenerHandlers[name] = handler
	sps.listenerConfigs[name] = cfg

	log.Printf("[SharedPort:%d] Listener '%s' registered successfully (total listeners: %d)",
		sps.Port, name, len(sps.listenerHandlers))

	return nil
}

// UnregisterListener removes a listener's routes from this shared port
func (sps *SharedPortServer) UnregisterListener(name string) {
	sps.mu.Lock()
	defer sps.mu.Unlock()

	handler, exists := sps.listenerHandlers[name]
	if !exists {
		log.Printf("[SharedPort:%d] Listener '%s' not found for unregister", sps.Port, name)
		return
	}

	// Remove path routes
	if handler.GetProfile != nil {
		key := handler.GetProfile.Method + ":" + handler.GetProfile.Path
		delete(sps.pathRoutes, key)
		log.Printf("[SharedPort:%d] Unregistered route: %s", sps.Port, key)
	}

	if handler.PostProfile != nil {
		key := handler.PostProfile.Method + ":" + handler.PostProfile.Path
		delete(sps.pathRoutes, key)
		log.Printf("[SharedPort:%d] Unregistered route: %s", sps.Port, key)
	}

	delete(sps.listenerHandlers, name)
	delete(sps.listenerConfigs, name)

	log.Printf("[SharedPort:%d] Listener '%s' unregistered (remaining listeners: %d)",
		sps.Port, name, len(sps.listenerHandlers))
}

// IsEmpty returns true if no listeners are registered
func (sps *SharedPortServer) IsEmpty() bool {
	sps.mu.RLock()
	defer sps.mu.RUnlock()
	return len(sps.listenerHandlers) == 0
}

// GetListenerCount returns the number of registered listeners
func (sps *SharedPortServer) GetListenerCount() int {
	sps.mu.RLock()
	defer sps.mu.RUnlock()
	return len(sps.listenerHandlers)
}

// GetListenerNames returns all listener names on this shared port
func (sps *SharedPortServer) GetListenerNames() []string {
	sps.mu.RLock()
	defer sps.mu.RUnlock()

	names := make([]string, 0, len(sps.listenerHandlers))
	for name := range sps.listenerHandlers {
		names = append(names, name)
	}
	return names
}

// GetRoutes returns all registered routes for debugging/inspection
func (sps *SharedPortServer) GetRoutes() []PathRoute {
	sps.mu.RLock()
	defer sps.mu.RUnlock()

	routes := make([]PathRoute, 0)
	for key, listenerName := range sps.pathRoutes {
		// Parse key back into method:path
		var method, path string
		for i, c := range key {
			if c == ':' {
				method = key[:i]
				path = key[i+1:]
				break
			}
		}

		// Determine profile type
		profileType := "unknown"
		if handler, exists := sps.listenerHandlers[listenerName]; exists {
			if handler.GetProfile != nil && handler.GetProfile.Path == path {
				profileType = "get"
			} else if handler.PostProfile != nil && handler.PostProfile.Path == path {
				profileType = "post"
			}
		}

		routes = append(routes, PathRoute{
			Path:         path,
			Method:       method,
			ListenerName: listenerName,
			ProfileType:  profileType,
		})
	}
	return routes
}

// LookupListener finds the listener name for a given method and path
func (sps *SharedPortServer) LookupListener(method, path string) (string, *ListenerHandler, bool) {
	sps.mu.RLock()
	defer sps.mu.RUnlock()

	key := method + ":" + path
	listenerName, found := sps.pathRoutes[key]
	if !found {
		return "", nil, false
	}

	handler, handlerExists := sps.listenerHandlers[listenerName]
	if !handlerExists {
		return "", nil, false
	}

	return listenerName, handler, true
}

// GetListenerConfig returns the config for a specific listener
func (sps *SharedPortServer) GetListenerConfig(name string) (config.ListenerConfig, bool) {
	sps.mu.RLock()
	defer sps.mu.RUnlock()

	cfg, exists := sps.listenerConfigs[name]
	return cfg, exists
}

// HasPathConflict checks if a new listener's paths would conflict with existing ones
func (sps *SharedPortServer) HasPathConflict(handler *ListenerHandler) (bool, string) {
	sps.mu.RLock()
	defer sps.mu.RUnlock()

	if handler.GetProfile != nil {
		key := handler.GetProfile.Method + ":" + handler.GetProfile.Path
		if existing, exists := sps.pathRoutes[key]; exists {
			return true, fmt.Sprintf("%s %s conflicts with listener '%s'",
				handler.GetProfile.Method, handler.GetProfile.Path, existing)
		}
	}

	if handler.PostProfile != nil {
		key := handler.PostProfile.Method + ":" + handler.PostProfile.Path
		if existing, exists := sps.pathRoutes[key]; exists {
			return true, fmt.Sprintf("%s %s conflicts with listener '%s'",
				handler.PostProfile.Method, handler.PostProfile.Path, existing)
		}
	}

	return false, ""
}
