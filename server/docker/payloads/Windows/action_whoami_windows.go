// server/docker/payloads/Windows/action_whoami_windows.go
//go:build windows
// +build windows

package main

import (
	"syscall"
	"unsafe"
)

// GetThreadToken gets the current thread's impersonation token
func GetThreadToken() syscall.Handle {
	var token syscall.Token

	// First try with OpenAsSelf = TRUE
	err := OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &token)
	if err != nil {
		// If that fails, try with OpenAsSelf = FALSE
		err = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, false, &token)
		if err != nil {
			return 0
		}
	}
	return syscall.Handle(token)
}

// GetProcessToken gets the current process token
func GetProcessToken() syscall.Handle {
	var token syscall.Token
	err := OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)
	if err != nil {
		return 0
	}
	return syscall.Handle(token)
}

// GetTokenUser extracts user information from a token
func GetTokenUser(token syscall.Handle) (string, string) {
	// Get required buffer size
	var needed uint32
	procGetTokenInformation.Call(
		uintptr(token),
		1, // TokenUser
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)

	if needed == 0 {
		return "", ""
	}

	// Allocate buffer and get token information
	buffer := make([]byte, needed)
	ret, _, _ := procGetTokenInformation.Call(
		uintptr(token),
		1, // TokenUser
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)

	if ret == 0 {
		return "", ""
	}

	// Extract SID from buffer
	tokenUser := (*TokenUser)(unsafe.Pointer(&buffer[0]))

	// Convert SID to username
	var nameSize, domainSize uint32 = 256, 256
	nameBuffer := make([]uint16, nameSize)
	domainBuffer := make([]uint16, domainSize)
	var use uint32

	ret, _, _ = procLookupAccountSidW.Call(
		0,
		uintptr(unsafe.Pointer(tokenUser.User.Sid)),
		uintptr(unsafe.Pointer(&nameBuffer[0])),
		uintptr(unsafe.Pointer(&nameSize)),
		uintptr(unsafe.Pointer(&domainBuffer[0])),
		uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&use)),
	)

	if ret == 0 {
		return "", ""
	}

	return syscall.UTF16ToString(nameBuffer), syscall.UTF16ToString(domainBuffer)
}

// GetImpersonatedUser gets the impersonated user from the token store
func GetImpersonatedUser(ctx *CommandContext) (string, string, bool) {
	if ctx == nil || ctx.TokenStore == nil {
		return "", "", false
	}

	store, ok := ctx.TokenStore.(*UnifiedTokenStore)
	if !ok {
		return "", "", false
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	if !store.IsImpersonating || store.ActiveToken == "" {
		return "", "", false
	}

	// Get the metadata instead of querying the token
	if metadata, exists := store.Metadata[store.ActiveToken]; exists {
		return metadata.User, metadata.Domain, true
	}

	return "", "", false
}
