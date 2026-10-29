// server/docker/payloads/Linux/action_download.go

//go:build linux
// +build linux

package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Buffer pool for download chunks to reduce allocations
var downloadBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 512*1024) // 512KB chunks
		return &buf
	},
}

type FM struct{}

// Modified execute function from action_download.go
func (c *FM) execute(ctx *OpCtx, args []string) OpResult {
	// With the improved parsing, we should receive exactly one argument (the full path)
	// But let's still handle the case where it might have been split
	if len(args) == 0 {
		return OpResult{
			Error:       fmt.Errorf(Err(E1)),
			EStr: Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Join all args back together in case they were incorrectly split
	// With the new parsing, this should usually just be args[0]
	targetPath := strings.Join(args, " ")

	// Remove any surrounding quotes if present (should already be done by parser)
	targetPath = strings.Trim(targetPath, "\"'")

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

	// Use NetworkAwareOpenFile to support network shares
	// This handles network authentication properly
	file, err := NetworkAwareOpenFile(targetPath, os.O_RDONLY, 0)

	if err != nil {
		return OpResult{
			Output:      ErrCtx(E10, displayPath),
			Error:       err,
			EStr: Err(E10),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}
	defer file.Close()

	// Get file information
	fileInfo, err := file.Stat()
	if err != nil {
		return OpResult{
			Output:      ErrCtx(E10, displayPath),
			Error:       err,
			EStr: Err(E10),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Check if it's a directory
	if fileInfo.IsDir() {
		return OpResult{
			Output:      ErrCtx(E6, displayPath),
			Error:       fmt.Errorf(Err(E6)),
			EStr: Err(E6),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Minimal context
	contextInfo := ""

	// Read first chunk using buffer pool
	const chunkSize = 512 * 1024 // 512KB chunks
	bufPtr := downloadBufferPool.Get().(*[]byte)
	defer downloadBufferPool.Put(bufPtr)
	chunk := *bufPtr
	n, err := file.Read(chunk)
	if err != nil && err != io.EOF {
		return OpResult{
			Output:      ErrCtx(E10, displayPath),
			Error:       err,
			EStr: Err(E10),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// For tracking purposes, use the base filename
	baseFilename := filepath.Base(targetPath)
	trackedFilename := baseFilename

	// Special case: single small file
	if n < chunkSize && err == io.EOF {
		encodedData := base64.StdEncoding.EncodeToString(chunk[:n])
		return OpResult{
			Output:      contextInfo + SuccCtx(S5, baseFilename),
			EC:    0,
			Done: time.Now().Format(time.RFC3339),
			Cmd: Msg{
				Cmd:      fmt.Sprintf("download %s", baseFilename),
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
	commandQueue.addOrUpdateDownload(trackedFilename, targetPath, int(totalChunks))
	commandQueue.updateDownloadProgress(trackedFilename, 1)

	result := OpResult{
		Output:      contextInfo + SuccCtx(S4, fmt.Sprintf("1/%d", totalChunks)),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
		Cmd: Msg{
			Cmd:      fmt.Sprintf("download %s", baseFilename),
			Filename:     trackedFilename,
			CurrentChunk: 1,
			TotalChunks:  int(totalChunks),
			Data:         encodedData,
		},
	}

	return result
}

// Note: NetworkAwareOpenFile is already defined in netonly_file_support.go for Windows
// and has a stub implementation in network_aware_stub.go for non-Windows systems.
// It handles network authentication automatically when accessing network shares.

// GetNextFileChunk continues downloading a file from a specific chunk
func GetNextFileChunk(filePath string, chunkNumber int, originalCmd Msg) (*OpResult, error) {
	// Use NetworkAwareOpenFile for network authentication support
	file, err := NetworkAwareOpenFile(filePath, os.O_RDONLY, 0)

	if err != nil {
		return nil, fmt.Errorf(Err(E10))
	}
	defer file.Close()

	// Get file information
	_, err = file.Stat()
	if err != nil {
		return nil, fmt.Errorf(Err(E10))
	}

	const chunkSize = 512 * 1024 // 512KB chunks

	// Seek to the correct position
	offset := int64(chunkNumber-1) * chunkSize
	_, err = file.Seek(offset, 0)
	if err != nil {
		return nil, fmt.Errorf(Err(E10))
	}

	// Read the chunk using buffer pool
	bufPtr := downloadBufferPool.Get().(*[]byte)
	defer downloadBufferPool.Put(bufPtr)
	chunk := *bufPtr
	n, err := file.Read(chunk)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf(Err(E10))
	}

	if n == 0 {
		return nil, fmt.Errorf(Err(E24))
	}

	// Encode the chunk
	encodedData := base64.StdEncoding.EncodeToString(chunk[:n])

	// Create the result
	result := &OpResult{
		Output:      SuccCtx(S4, fmt.Sprintf("%d/%d", chunkNumber, originalCmd.TotalChunks)),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
		Cmd: Msg{
			CID:    originalCmd.CID,
			DID:  originalCmd.DID,
			AID:      originalCmd.AID,
			Cmd:      originalCmd.Cmd,
			Filename:     originalCmd.Filename,
			CurrentChunk: chunkNumber,
			TotalChunks:  originalCmd.TotalChunks,
			Data:         encodedData,
			Timestamp:    originalCmd.Timestamp,
		},
	}

	return result, nil
}
