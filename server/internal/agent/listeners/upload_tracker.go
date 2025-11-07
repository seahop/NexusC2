// internal/agent/listeners/upload_tracker.go
package listeners

import (
	"bytes"
	"c2/internal/common/progress"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

type UploadChunk struct {
	Filename     string
	CurrentChunk int
	TotalChunks  int
	Data         string
	FileSize     int64 // Add this field
}

type UploadTracker struct {
	mutex      sync.RWMutex
	tempDir    string
	uploadDir  string
	inProgress map[string]bool
	progress   *progress.Tracker // Add progress tracker
}

func NewUploadTracker(tempDir, uploadDir string) *UploadTracker {
	// Create directories if they don't exist
	for _, dir := range []string{tempDir, uploadDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("[UploadTracker] Warning: Failed to create directory %s: %v", dir, err)
		}
	}

	return &UploadTracker{
		tempDir:    tempDir,
		uploadDir:  uploadDir,
		inProgress: make(map[string]bool),
		progress:   progress.NewTracker(),
	}
}

func (ut *UploadTracker) handleUploadChunk(chunk UploadChunk) error {
	ut.mutex.Lock()
	defer ut.mutex.Unlock()

	log.Printf("[UploadTracker] Processing chunk %d/%d for file %s",
		chunk.CurrentChunk, chunk.TotalChunks, chunk.Filename)

	// Initialize progress tracking for first chunk
	if chunk.CurrentChunk == 0 {
		ut.progress.StartTracking(chunk.Filename, chunk.FileSize)
	}

	// Create the chunk directory
	chunkDir := filepath.Join(ut.tempDir, chunk.Filename)
	if err := os.MkdirAll(chunkDir, 0755); err != nil {
		return fmt.Errorf("failed to create chunk directory: %v", err)
	}

	// Create stream for chunk processing
	chunkPath := filepath.Join(chunkDir, fmt.Sprintf("chunk_%d", chunk.CurrentChunk))

	// Process chunk data using streaming
	if err := func() error {
		chunkFile, err := os.Create(chunkPath)
		if err != nil {
			return fmt.Errorf("failed to create chunk file: %v", err)
		}
		defer chunkFile.Close()

		// Decode and stream chunk data
		data, err := base64.StdEncoding.DecodeString(chunk.Data)
		if err != nil {
			return fmt.Errorf("failed to decode chunk data: %v", err)
		}

		buffer := make([]byte, 32*1024) // 32KB buffer
		reader := bytes.NewReader(data)
		bytesWritten := int64(0)

		for {
			n, err := reader.Read(buffer)
			if n > 0 {
				if _, writeErr := chunkFile.Write(buffer[:n]); writeErr != nil {
					return fmt.Errorf("failed to write chunk data: %v", writeErr)
				}
				bytesWritten += int64(n)

				// Update progress
				totalProgress := int64(chunk.CurrentChunk)*int64(len(data)) + bytesWritten
				ut.progress.UpdateProgress(chunk.Filename, totalProgress)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to read chunk data: %v", err)
			}
		}
		return nil
	}(); err != nil {
		return err
	}

	// Check if all chunks received
	if chunk.CurrentChunk == chunk.TotalChunks-1 {
		// Use parallel assembly
		destPath := filepath.Join(ut.uploadDir, chunk.Filename)
		progressCh := make(chan int64)
		errCh := make(chan error)

		go func() {
			err := assembleFileParallel(chunkDir, destPath, chunk.TotalChunks, progressCh)
			errCh <- err
		}()

		// Monitor assembly progress
		go func() {
			for progress := range progressCh {
				ut.progress.UpdateProgress(chunk.Filename, progress)
			}
		}()

		// Wait for assembly
		if err := <-errCh; err != nil {
			return fmt.Errorf("failed to assemble file: %v", err)
		}

		// Cleanup
		if err := os.RemoveAll(chunkDir); err != nil {
			log.Printf("[UploadTracker] Warning: Failed to clean up chunk directory: %v", err)
		}

		delete(ut.inProgress, chunk.Filename)
	}

	return nil
}

func (ut *UploadTracker) IsUploadInProgress(filename string) bool {
	ut.mutex.RLock()
	defer ut.mutex.RUnlock()
	return ut.inProgress[filename]
}

func (ut *UploadTracker) SetUploadInProgress(filename string, inProgress bool) {
	ut.mutex.Lock()
	defer ut.mutex.Unlock()
	if inProgress {
		ut.inProgress[filename] = true
	} else {
		delete(ut.inProgress, filename)
	}
}

// SaveMetadata saves upload metadata to a JSON file
func (ut *UploadTracker) SaveMetadata(chunkDir string, metadata map[string]interface{}) error {
	metadataFile := filepath.Join(chunkDir, "metadata.json")
	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %v", err)
	}

	if err := os.WriteFile(metadataFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write metadata file: %v", err)
	}

	return nil
}

// LoadMetadata loads upload metadata from a JSON file
func (ut *UploadTracker) LoadMetadata(chunkDir string) (map[string]interface{}, error) {
	metadataFile := filepath.Join(chunkDir, "metadata.json")
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata file: %v", err)
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %v", err)
	}

	return metadata, nil
}
