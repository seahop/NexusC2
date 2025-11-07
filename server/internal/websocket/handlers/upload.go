// internal/websocket/handlers/upload.go
package handlers

import (
	"c2/internal/websocket/hub"
	pb "c2/proto"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type FileUploadMessage struct {
	Type string `json:"type"`
	Data struct {
		UploadID    string `json:"upload_id"`
		AgentID     string `json:"agent_id"`
		FileName    string `json:"file_name"`
		RemotePath  string `json:"remote_path"`
		ChunkNum    int    `json:"chunk_num"`
		TotalChunks int    `json:"total_chunks"`
		ChunkData   string `json:"chunk_data"`
		FileSize    int64  `json:"file_size"`
		Timestamp   string `json:"timestamp"`
	} `json:"data"`
}

type UploadTracker struct {
	UploadID       string
	AgentID        string
	FileName       string
	RemotePath     string
	ChunksDir      string
	TotalChunks    int
	ReceivedChunks map[int]bool
	mu             sync.Mutex
}

func (h *WSHandler) handleFileUpload(client *hub.Client, message []byte) error {
	var uploadMsg FileUploadMessage
	if err := json.Unmarshal(message, &uploadMsg); err != nil {
		return fmt.Errorf("failed to unmarshal upload message: %v", err)
	}

	log.Printf("Received file upload chunk %d/%d for file %s",
		uploadMsg.Data.ChunkNum, uploadMsg.Data.TotalChunks, uploadMsg.Data.FileName)

	// Get or create upload tracker
	tracker, err := h.getOrCreateUploadTracker(uploadMsg.Data)
	if err != nil {
		return err
	}

	// Process the chunk
	if err := h.processUploadChunk(tracker, uploadMsg.Data); err != nil {
		return err
	}

	// Check if upload is complete
	if h.isUploadComplete(tracker) {
		if err := h.finalizeUpload(tracker); err != nil {
			return err
		}
	}

	// Send response
	response := Response{
		Type:    "upload_response",
		Status:  "success",
		Message: fmt.Sprintf("Chunk %d received successfully", uploadMsg.Data.ChunkNum),
		Data: map[string]interface{}{
			"upload_id": uploadMsg.Data.UploadID,
			"chunk_num": uploadMsg.Data.ChunkNum,
			"complete":  h.isUploadComplete(tracker),
		},
	}
	responseJSON, _ := json.Marshal(response)
	client.Send <- responseJSON

	return nil
}

func (h *WSHandler) getOrCreateUploadTracker(data struct {
	UploadID    string `json:"upload_id"`
	AgentID     string `json:"agent_id"`
	FileName    string `json:"file_name"`
	RemotePath  string `json:"remote_path"`
	ChunkNum    int    `json:"chunk_num"`
	TotalChunks int    `json:"total_chunks"`
	ChunkData   string `json:"chunk_data"`
	FileSize    int64  `json:"file_size"`
	Timestamp   string `json:"timestamp"`
}) (*UploadTracker, error) {
	// Try to get existing tracker
	if trackerIface, ok := h.activeUploads.Load(data.UploadID); ok {
		log.Printf("DEBUG: Retrieved existing tracker for upload %s", data.UploadID)
		return trackerIface.(*UploadTracker), nil
	}

	// Create temp directory path
	chunksDir := filepath.Join("/app/temp", data.UploadID)
	log.Printf("DEBUG: Creating chunks directory: %s", chunksDir)

	// Create temp directory
	if err := os.MkdirAll(chunksDir, 0755); err != nil {
		log.Printf("ERROR: Failed to create chunks directory %s: %v", chunksDir, err)
		return nil, fmt.Errorf("failed to create chunks directory: %v", err)
	}

	// Create new tracker
	tracker := &UploadTracker{
		UploadID:       data.UploadID,
		AgentID:        data.AgentID, // Store the AgentID
		FileName:       data.FileName,
		RemotePath:     data.RemotePath,
		ChunksDir:      chunksDir,
		TotalChunks:    data.TotalChunks,
		ReceivedChunks: make(map[int]bool),
	}

	h.activeUploads.Store(data.UploadID, tracker)
	log.Printf("DEBUG: Created new tracker for upload %s", data.UploadID)
	return tracker, nil
}

func (h *WSHandler) processUploadChunk(tracker *UploadTracker, data struct {
	UploadID    string `json:"upload_id"`
	AgentID     string `json:"agent_id"`
	FileName    string `json:"file_name"`
	RemotePath  string `json:"remote_path"`
	ChunkNum    int    `json:"chunk_num"`
	TotalChunks int    `json:"total_chunks"`
	ChunkData   string `json:"chunk_data"`
	FileSize    int64  `json:"file_size"`
	Timestamp   string `json:"timestamp"`
}) error {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	// Decode base64 chunk data
	chunkData, err := base64.StdEncoding.DecodeString(data.ChunkData)
	if err != nil {
		return fmt.Errorf("failed to decode chunk data: %v", err)
	}

	// Write chunk to temp file
	chunkPath := filepath.Join(tracker.ChunksDir, fmt.Sprintf("chunk_%d", data.ChunkNum))
	if err := os.WriteFile(chunkPath, chunkData, 0644); err != nil {
		return fmt.Errorf("failed to write chunk file: %v", err)
	}

	tracker.ReceivedChunks[data.ChunkNum] = true
	return nil
}

func (h *WSHandler) isUploadComplete(tracker *UploadTracker) bool {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	return len(tracker.ReceivedChunks) == tracker.TotalChunks
}

func (h *WSHandler) finalizeUpload(tracker *UploadTracker) error {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	// Generate timestamped filename
	ext := filepath.Ext(tracker.FileName)
	baseFilename := strings.TrimSuffix(tracker.FileName, ext)
	timestamp := time.Now().Format("20060102_150405")
	newFilename := fmt.Sprintf("%s_%s%s", baseFilename, timestamp, ext)

	// Create the final file
	uploadPath := filepath.Join("/app/uploads", newFilename)
	finalFile, err := os.Create(uploadPath)
	if err != nil {
		return fmt.Errorf("failed to create final file: %v", err)
	}
	defer finalFile.Close()

	// Combine chunks in order
	for i := 0; i < tracker.TotalChunks; i++ {
		chunkPath := filepath.Join(tracker.ChunksDir, fmt.Sprintf("chunk_%d", i))
		chunkData, err := os.ReadFile(chunkPath)
		if err != nil {
			return fmt.Errorf("failed to read chunk %d: %v", i, err)
		}

		if _, err := finalFile.Write(chunkData); err != nil {
			return fmt.Errorf("failed to write chunk %d to final file: %v", i, err)
		}
	}

	log.Printf("Successfully assembled file: %s", newFilename)

	// Clean up temp directory
	if err := os.RemoveAll(tracker.ChunksDir); err != nil {
		log.Printf("Warning: failed to clean up chunks directory: %v", err)
	}

	// Remove from active uploads
	h.activeUploads.Delete(tracker.UploadID)

	// Notify agent service about the upload
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if h.agentClient == nil {
		return fmt.Errorf("no connection to agent service")
	}

	uploadReq := &pb.HandleUploadRequest{
		AgentId:          tracker.AgentID,
		OriginalFilename: tracker.FileName,
		CurrentFilename:  newFilename,
		RemotePath:       tracker.RemotePath,
		Timestamp:        timestamp,
	}

	response, err := h.agentClient.HandleUpload(ctx, uploadReq)
	if err != nil {
		log.Printf("Warning: Failed to notify agent service about upload: %v", err)
		// Don't return error here as the upload itself was successful
	} else if !response.Success {
		log.Printf("Warning: Agent service reported issue with upload: %s", response.Message)
	}

	return nil
}
