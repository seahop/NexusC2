// server/docker/payloads/Windows/action_bof.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"runtime"
	"strings"
)

// BOFCommand handles BOF execution
type BOFCommand struct{}

func (c *BOFCommand) Name() string {
	return "bof"
}

func (c *BOFCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// For Windows only - BOF is Windows-specific
	if runtime.GOOS != "windows" {
		return CommandResult{
			Output:   "Error: BOF execution is only supported on Windows",
			Error:    fmt.Errorf("unsupported platform: %s", runtime.GOOS),
			ExitCode: 1,
		}
	}
	// This will be handled by the command queue's processBOF method
	// The actual execution happens there with the full Command data
	return CommandResult{
		Output:   "BOF execution initiated",
		ExitCode: 0,
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
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("BOF execution not supported on %s", runtime.GOOS)
	}

	// The actual Windows implementation would go here
	// This would use the coff loader from the provided code
	// On Windows, this calls executeBOFPlatform from action_bof_windows.go
	return executeBOFPlatform(bofBytes, args)
}
