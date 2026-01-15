// internal/agent/listeners/handle_downloads.go
package listeners

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// Add these structs to your package
type DownloadChunk struct {
	Filename     string `json:"filename"`
	CurrentChunk int    `json:"currentChunk"`
	TotalChunks  int    `json:"totalChunks"`
	Data         string `json:"data"`
}

type DownloadTracker struct {
	mu              sync.RWMutex
	ongoing         map[string]map[int]bool
	tempPath        string
	destPath        string
	manifestManager *ManifestManager
}

func NewDownloadTracker(tempPath, destPath string) *DownloadTracker {
	// Create directories if they don't exist
	os.MkdirAll(tempPath, 0755)
	os.MkdirAll(destPath, 0755)

	manifestPath := filepath.Join(destPath, "downloads.json")
	manifestManager := NewManifestManager(manifestPath, destPath)

	// Validate manifest on startup
	if err := manifestManager.ValidateManifest(); err != nil {
		log.Printf("[DownloadTracker] Warning: Failed to validate manifest: %v", err)
	}

	return &DownloadTracker{
		ongoing:         make(map[string]map[int]bool),
		tempPath:        tempPath,
		destPath:        destPath,
		manifestManager: manifestManager,
	}
}

func (dt *DownloadTracker) handleDownloadChunk(chunk DownloadChunk) error {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	// Initialize tracking for new downloads and log start
	if _, exists := dt.ongoing[chunk.Filename]; !exists {
		log.Printf("[TRANSFER] Download started: %s (%d chunks)", chunk.Filename, chunk.TotalChunks)
		dt.ongoing[chunk.Filename] = make(map[int]bool)
	}

	// Decode base64 data
	data, err := base64.StdEncoding.DecodeString(chunk.Data)
	if err != nil {
		return fmt.Errorf("failed to decode chunk data: %v", err)
	}

	// Only create the part file if we have data
	if len(data) > 0 {
		chunkPath := filepath.Join(dt.tempPath, fmt.Sprintf("%s.part%d", chunk.Filename, chunk.CurrentChunk))

		if err := os.WriteFile(chunkPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write chunk file: %v", err)
		}

		dt.ongoing[chunk.Filename][chunk.CurrentChunk] = true
	}

	// Check if download is complete
	if len(dt.ongoing[chunk.Filename]) == chunk.TotalChunks {
		if err := dt.assembleFile(chunk.Filename, chunk.TotalChunks); err != nil {
			return fmt.Errorf("failed to assemble file: %v", err)
		}
	}

	return nil
}

func (dt *DownloadTracker) assembleFile(filename string, totalChunks int) error {
	destPath := filepath.Join(dt.destPath, filename)

	outFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	// Assemble chunks in order
	for i := 1; i <= totalChunks; i++ {
		chunkPath := filepath.Join(dt.tempPath, fmt.Sprintf("%s.part%d", filename, i))

		chunkData, err := os.ReadFile(chunkPath)
		if err != nil {
			return fmt.Errorf("failed to read chunk %d: %v", i, err)
		}

		if _, err := outFile.Write(chunkData); err != nil {
			return fmt.Errorf("failed to write chunk %d: %v", i, err)
		}

		os.Remove(chunkPath)
	}

	// Add to manifest
	dt.manifestManager.AddDownload(filename)

	// Clean up tracking and log completion
	delete(dt.ongoing, filename)
	log.Printf("[TRANSFER] Download complete: %s", filename)
	return nil
}

// GetDownloads returns the list of completed downloads
func (dt *DownloadTracker) GetDownloads() ([]DownloadEntry, error) {
	return dt.manifestManager.GetDownloads()
}
