// internal/agent/listeners/manifest.go
package listeners

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DownloadManifest represents the overall manifest file
type DownloadManifest struct {
	Downloads []DownloadEntry `json:"downloads"`
}

// DownloadEntry represents a single downloaded file
type DownloadEntry struct {
	ID        int       `json:"id"`
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	Timestamp time.Time `json:"timestamp"`
}

// ManifestManager handles the manifest file operations
type ManifestManager struct {
	mu           sync.RWMutex
	manifestPath string
	downloadsDir string
}

// NewManifestManager creates a new manifest manager
func NewManifestManager(manifestPath, downloadsDir string) *ManifestManager {
	return &ManifestManager{
		manifestPath: manifestPath,
		downloadsDir: downloadsDir,
	}
}

// loadManifest reads the current manifest file
func (mm *ManifestManager) loadManifest() (DownloadManifest, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	var manifest DownloadManifest

	// Check if manifest file exists
	if _, err := os.Stat(mm.manifestPath); os.IsNotExist(err) {
		// Return empty manifest if file doesn't exist
		return manifest, nil
	}

	data, err := os.ReadFile(mm.manifestPath)
	if err != nil {
		return manifest, fmt.Errorf("failed to read manifest file: %v", err)
	}

	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("failed to parse manifest file: %v", err)
	}

	return manifest, nil
}

// saveManifest writes the manifest to disk
func (mm *ManifestManager) saveManifest(manifest DownloadManifest) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %v", err)
	}

	if err := os.WriteFile(mm.manifestPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write manifest file: %v", err)
	}

	return nil
}

// AddDownload adds a new download entry to the manifest
func (mm *ManifestManager) AddDownload(filename string) error {
	// Load current manifest
	manifest, err := mm.loadManifest()
	if err != nil {
		return err
	}

	// Get file info
	filePath := filepath.Join(mm.downloadsDir, filename)
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}

	// Generate next ID
	nextID := 1
	if len(manifest.Downloads) > 0 {
		nextID = manifest.Downloads[len(manifest.Downloads)-1].ID + 1
	}

	// Create new entry
	entry := DownloadEntry{
		ID:        nextID,
		Filename:  filename,
		Size:      fileInfo.Size(),
		Timestamp: time.Now(),
	}

	// Add to manifest
	manifest.Downloads = append(manifest.Downloads, entry)

	// Save updated manifest
	return mm.saveManifest(manifest)
}

// GetDownloads returns all download entries
func (mm *ManifestManager) GetDownloads() ([]DownloadEntry, error) {
	manifest, err := mm.loadManifest()
	if err != nil {
		return nil, err
	}
	return manifest.Downloads, nil
}

// RemoveDownload removes a download entry by ID
func (mm *ManifestManager) RemoveDownload(id int) error {
	manifest, err := mm.loadManifest()
	if err != nil {
		return err
	}

	// Find and remove the entry
	found := false
	newDownloads := make([]DownloadEntry, 0, len(manifest.Downloads))
	for _, entry := range manifest.Downloads {
		if entry.ID != id {
			newDownloads = append(newDownloads, entry)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("download ID %d not found", id)
	}

	manifest.Downloads = newDownloads
	return mm.saveManifest(manifest)
}

// ValidateManifest checks if all files in manifest exist and removes entries for missing files
func (mm *ManifestManager) ValidateManifest() error {
	manifest, err := mm.loadManifest()
	if err != nil {
		return err
	}

	validDownloads := make([]DownloadEntry, 0, len(manifest.Downloads))
	for _, entry := range manifest.Downloads {
		filePath := filepath.Join(mm.downloadsDir, entry.Filename)
		if _, err := os.Stat(filePath); err == nil {
			validDownloads = append(validDownloads, entry)
		}
	}

	manifest.Downloads = validDownloads
	return mm.saveManifest(manifest)
}
