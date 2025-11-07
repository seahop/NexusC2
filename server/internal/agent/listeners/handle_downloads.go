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

	log.Printf("[DownloadTracker] Starting to handle chunk %d/%d for file %s",
		chunk.CurrentChunk, chunk.TotalChunks, chunk.Filename)

	// Initialize tracking for new downloads
	if _, exists := dt.ongoing[chunk.Filename]; !exists {
		log.Printf("[DownloadTracker] Initializing tracking for new download: %s", chunk.Filename)
		dt.ongoing[chunk.Filename] = make(map[int]bool)
	}

	// Decode base64 data
	data, err := base64.StdEncoding.DecodeString(chunk.Data)
	if err != nil {
		log.Printf("[DownloadTracker] Failed to decode chunk data: %v", err)
		return fmt.Errorf("failed to decode chunk data: %v", err)
	}

	// Only create the part file if we have data
	if len(data) > 0 {
		// Create temp file path - use the full original filename for all parts
		chunkPath := filepath.Join(dt.tempPath, fmt.Sprintf("%s.part%d", chunk.Filename, chunk.CurrentChunk))
		log.Printf("[DownloadTracker] Writing chunk to: %s", chunkPath)

		// Write chunk to temp file
		if err := os.WriteFile(chunkPath, data, 0644); err != nil {
			log.Printf("[DownloadTracker] Failed to write chunk file: %v", err)
			return fmt.Errorf("failed to write chunk file: %v", err)
		}

		// Mark chunk as received only if we successfully wrote the data
		dt.ongoing[chunk.Filename][chunk.CurrentChunk] = true
		log.Printf("[DownloadTracker] Marked chunk %d as received for %s", chunk.CurrentChunk, chunk.Filename)
	} else {
		log.Printf("[DownloadTracker] Skipping zero-byte chunk %d for %s", chunk.CurrentChunk, chunk.Filename)
	}

	// Check if download is complete
	currentChunks := len(dt.ongoing[chunk.Filename])
	log.Printf("[DownloadTracker] File %s has %d/%d chunks", chunk.Filename, currentChunks, chunk.TotalChunks)

	if currentChunks == chunk.TotalChunks {
		log.Printf("[DownloadTracker] All chunks received for %s, starting assembly", chunk.Filename)
		if err := dt.assembleFile(chunk.Filename, chunk.TotalChunks); err != nil {
			log.Printf("[DownloadTracker] Failed to assemble file: %v", err)
			return fmt.Errorf("failed to assemble file: %v", err)
		}
		log.Printf("[DownloadTracker] Successfully assembled file %s", chunk.Filename)
	}

	return nil
}

func (dt *DownloadTracker) assembleFile(filename string, totalChunks int) error {
	log.Printf("[DownloadTracker] Starting assembly of %s from %d chunks", filename, totalChunks)

	// Create final file
	destPath := filepath.Join(dt.destPath, filename)
	log.Printf("[DownloadTracker] Creating final file at: %s", destPath)

	outFile, err := os.Create(destPath)
	if err != nil {
		log.Printf("[DownloadTracker] Failed to create output file: %v", err)
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	// Assemble chunks in order
	for i := 1; i <= totalChunks; i++ {
		chunkPath := filepath.Join(dt.tempPath, fmt.Sprintf("%s.part%d", filename, i))
		log.Printf("[DownloadTracker] Processing chunk %d/%d from: %s", i, totalChunks, chunkPath)

		// Read chunk
		chunkData, err := os.ReadFile(chunkPath)
		if err != nil {
			log.Printf("[DownloadTracker] Failed to read chunk %d: %v", i, err)
			return fmt.Errorf("failed to read chunk %d: %v", i, err)
		}

		// Write to final file
		if _, err := outFile.Write(chunkData); err != nil {
			log.Printf("[DownloadTracker] Failed to write chunk %d to final file: %v", i, err)
			return fmt.Errorf("failed to write chunk %d to final file: %v", i, err)
		}

		// Delete temp chunk file
		if err := os.Remove(chunkPath); err != nil {
			log.Printf("[DownloadTracker] Warning: failed to remove temp chunk %d: %v", i, err)
		}
	}

	// Add to manifest
	if err := dt.manifestManager.AddDownload(filename); err != nil {
		log.Printf("[DownloadTracker] Warning: Failed to add download to manifest: %v", err)
	}

	// Clean up tracking
	delete(dt.ongoing, filename)
	log.Printf("[DownloadTracker] Completed assembly of %s", filename)
	return nil
}

// GetDownloads returns the list of completed downloads
func (dt *DownloadTracker) GetDownloads() ([]DownloadEntry, error) {
	return dt.manifestManager.GetDownloads()
}
