// internal/websocket/handlers/file_operations.go
package handlers

import (
	"c2/internal/websocket/hub"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// handleFileDownload handles file download requests
func (h *WSHandler) handleFileDownload(client *hub.Client, message []byte) error {
	var req struct {
		Type string `json:"type"`
		Data struct {
			Filename string `json:"filename"`
		} `json:"data"`
	}

	if err := json.Unmarshal(message, &req); err != nil {
		return fmt.Errorf("failed to parse file download request: %v", err)
	}

	// Sanitize filename to prevent path traversal
	sanitized := filepath.Base(req.Data.Filename)
	if sanitized == "" || sanitized == "." || sanitized == ".." {
		return fmt.Errorf("invalid filename: %q", req.Data.Filename)
	}

	// Path to downloads directory
	downloadsDir := "/app/downloads"
	filePath := filepath.Join(downloadsDir, sanitized)

	// Verify resolved path is still within the downloads directory
	resolvedPath, err := filepath.Abs(filePath)
	if err != nil || !strings.HasPrefix(resolvedPath, downloadsDir) {
		return fmt.Errorf("invalid file path: path traversal detected")
	}

	// Open file but don't close it yet - move the close into the goroutine
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}

	// Get file info for size
	fileInfo, err := file.Stat()
	if err != nil {
		file.Close() // Close here if we error out
		return fmt.Errorf("failed to get file info: %v", err)
	}

	// Calculate number of chunks needed
	const chunkSize = 1024 * 1024 // 1MB chunks
	totalChunks := (fileInfo.Size() + chunkSize - 1) / chunkSize

	// Read and send file in chunks using goroutine
	go func() {
		defer file.Close() // Move defer into the goroutine

		buffer := make([]byte, chunkSize)
		for chunkNum := int64(0); chunkNum < totalChunks; chunkNum++ {
			n, err := file.Read(buffer)
			if err != nil && err != io.EOF {
				logMessage(LOG_NORMAL, "Error reading file chunk: %v", err)
				return
			}

			if n == 0 {
				break // End of file
			}

			chunk := buffer[:n]
			chunkMsg := struct {
				Type string `json:"type"`
				Data struct {
					Filename    string `json:"filename"`
					ChunkNum    int64  `json:"chunk_num"`
					TotalChunks int64  `json:"total_chunks"`
					Data        string `json:"data"`
				} `json:"data"`
			}{
				Type: "download_chunk",
				Data: struct {
					Filename    string `json:"filename"`
					ChunkNum    int64  `json:"chunk_num"`
					TotalChunks int64  `json:"total_chunks"`
					Data        string `json:"data"`
				}{
					Filename:    sanitized,
					ChunkNum:    chunkNum,
					TotalChunks: totalChunks,
					Data:        base64.StdEncoding.EncodeToString(chunk),
				},
			}

			chunkJSON, err := json.Marshal(chunkMsg)
			if err != nil {
				logMessage(LOG_NORMAL, "Failed to marshal chunk message: %v", err)
				return
			}

			select {
			case client.Send <- chunkJSON:
				logMessage(LOG_VERBOSE, "Sent chunk %d/%d for file %s", chunkNum+1, totalChunks, sanitized)
			default:
				logMessage(LOG_NORMAL, "Warning: Client send buffer full, chunk %d/%d dropped", chunkNum+1, totalChunks)
			}
		}

		logMessage(LOG_MINIMAL, "Finished sending all chunks for file %s", sanitized)
	}()

	return nil
}

// handleDownloadsRequest handles requests for the downloads manifest
func (h *WSHandler) handleDownloadsRequest(client *hub.Client) error {
	// Read manifest from database or filesystem
	downloads, err := h.getDownloadsManifest()
	if err != nil {
		logMessage(LOG_NORMAL, "Error reading downloads manifest: %v", err)
		return err
	}

	// Create response message
	response := struct {
		Type string         `json:"type"`
		Data []DownloadInfo `json:"data"`
	}{
		Type: "downloads_manifest",
		Data: downloads,
	}

	// Marshal and send response
	responseJSON, err := json.Marshal(response)
	if err != nil {
		logMessage(LOG_NORMAL, "Error marshaling downloads response: %v", err)
		return err
	}

	client.Send <- responseJSON
	return nil
}

// getDownloadsManifest retrieves the downloads manifest
func (h *WSHandler) getDownloadsManifest() ([]DownloadInfo, error) {
	// Read the manifest file from /app/downloads/downloads.json
	manifestPath := "/app/downloads/downloads.json"
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			// If file doesn't exist, return empty array
			return []DownloadInfo{}, nil
		}
		return nil, fmt.Errorf("failed to read downloads manifest: %v", err)
	}

	var manifest struct {
		Downloads []DownloadInfo `json:"downloads"`
	}

	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse downloads manifest: %v", err)
	}

	return manifest.Downloads, nil
}
