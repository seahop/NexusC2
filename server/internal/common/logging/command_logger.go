// server/internal/common/logging/command_logger.go
package logging

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultMaxFileSize is 100MB
	DefaultMaxFileSize = 100 * 1024 * 1024
	// DefaultMaxOutputLength for truncation
	DefaultMaxOutputLength = 1000
)

// SimpleLogger provides file logging for commands with enhanced context
// This version maintains backward compatibility while adding more fields
type SimpleLogger struct {
	mu           sync.Mutex
	file         *os.File
	logDir       string
	filename     string
	agentCache   map[string]*AgentInfo // Cache agent info for enrichment
	sessionMap   map[string]string     // Map agent to session ID
	maxFileSize  int64                 // Maximum file size before rotation
	fileSequence int                   // Sequence number for same-day rotations
}

// LogEntry represents a single log entry with enhanced fields
// All new fields are optional to maintain backward compatibility
type LogEntry struct {
	Timestamp  time.Time              `json:"timestamp"`
	Type       string                 `json:"type"`
	AgentID    string                 `json:"agent_id,omitempty"`
	Username   string                 `json:"username,omitempty"`
	Command    string                 `json:"command,omitempty"`
	CommandID  interface{}            `json:"command_id,omitempty"` // Can be string or int
	Output     string                 `json:"output,omitempty"`
	OutputSize int                    `json:"output_size,omitempty"`
	Error      string                 `json:"error,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`

	// Enhanced fields (all optional for backward compatibility)
	CommandType string `json:"command_type,omitempty"` // ls, pwd, bof, etc.
	Hostname    string `json:"hostname,omitempty"`
	ExternalIP  string `json:"external_ip,omitempty"`
	InternalIP  string `json:"internal_ip,omitempty"`
	OS          string `json:"os,omitempty"`
	Arch        string `json:"arch,omitempty"`
	Process     string `json:"process,omitempty"`
	PID         string `json:"pid,omitempty"`
	Integrity   string `json:"integrity,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
}

// AgentInfo stores cached agent information
type AgentInfo struct {
	AgentID    string    `json:"agent_id"`
	Hostname   string    `json:"hostname"`
	ExternalIP string    `json:"external_ip"`
	InternalIP string    `json:"internal_ip"`
	Username   string    `json:"username"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	Process    string    `json:"process"`
	PID        string    `json:"pid"`
	Integrity  string    `json:"integrity"`
	LastSeen   time.Time `json:"last_seen"`
}

// NewSimpleLogger creates a new logger instance (backward compatible signature)
func NewSimpleLogger(logDir string) (*SimpleLogger, error) {
	// Create logs directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	logger := &SimpleLogger{
		logDir:       logDir,
		agentCache:   make(map[string]*AgentInfo),
		sessionMap:   make(map[string]string),
		maxFileSize:  DefaultMaxFileSize,
		fileSequence: 0,
	}

	// Initialize log file
	if err := logger.initLogFile(); err != nil {
		return nil, err
	}

	return logger, nil
}

// NewSimpleLoggerWithConfig creates a logger with custom configuration
func NewSimpleLoggerWithConfig(logDir string, maxFileSize int64) (*SimpleLogger, error) {
	logger, err := NewSimpleLogger(logDir)
	if err != nil {
		return nil, err
	}

	if maxFileSize > 0 {
		logger.maxFileSize = maxFileSize
	}

	return logger, nil
}

func (sl *SimpleLogger) initLogFile() error {
	// Find the next available sequence number for today
	baseFilename := fmt.Sprintf("commands_%s", time.Now().Format("2006-01-02"))
	filename := fmt.Sprintf("%s.log", baseFilename)
	fullPath := filepath.Join(sl.logDir, filename) // Changed from 'filepath' to 'fullPath'

	// Check if file exists and its size
	if info, err := os.Stat(fullPath); err == nil {
		// File exists, check if it's too large
		if info.Size() >= sl.maxFileSize {
			// Find the next available sequence number
			sl.fileSequence = sl.findNextSequence(baseFilename)
			filename = fmt.Sprintf("%s_%d.log", baseFilename, sl.fileSequence)
			fullPath = filepath.Join(sl.logDir, filename)
		}
	}

	// Open or create the log file
	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}

	// Close previous file if exists
	if sl.file != nil {
		sl.file.Close()
	}

	sl.file = file
	sl.filename = filename

	log.Printf("[SimpleLogger] Logging to file: %s", filename)

	return nil
}

// findNextSequence finds the next available sequence number for the given base filename
func (sl *SimpleLogger) findNextSequence(baseFilename string) int {
	sequence := 1
	for {
		testFilename := fmt.Sprintf("%s_%d.log", baseFilename, sequence)
		testPath := filepath.Join(sl.logDir, testFilename)
		if _, err := os.Stat(testPath); os.IsNotExist(err) {
			return sequence
		}
		sequence++
	}
}

// checkRotation checks if we need to rotate to a new file (daily or size-based)
func (sl *SimpleLogger) checkRotation() error {
	// First check for daily rotation
	baseFilename := fmt.Sprintf("commands_%s", time.Now().Format("2006-01-02"))

	// Check if date has changed
	if !strings.HasPrefix(sl.filename, baseFilename) {
		// Date has changed - archive previous day's logs before rotating
		previousDate := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
		if err := sl.archivePreviousDay(previousDate); err != nil {
			log.Printf("[SimpleLogger] Failed to archive previous day's logs: %v", err)
			// Continue anyway - don't block logging due to archive failure
		}

		// Reset sequence and create new file
		sl.fileSequence = 0
		return sl.initLogFile()
	}

	// Check for size-based rotation (same as before)
	if sl.file != nil {
		if info, err := sl.file.Stat(); err == nil {
			if info.Size() >= sl.maxFileSize {
				log.Printf("[SimpleLogger] Current log file %s reached size limit (%d bytes), rotating...",
					sl.filename, info.Size())

				// Increment sequence and create new file
				sl.fileSequence++
				newFilename := fmt.Sprintf("%s_%d.log", baseFilename, sl.fileSequence)
				newPath := filepath.Join(sl.logDir, newFilename)

				// Create new file
				newFile, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
				if err != nil {
					return fmt.Errorf("failed to create rotated log file: %v", err)
				}

				// Close old file and switch to new one
				sl.file.Close()
				sl.file = newFile
				sl.filename = newFilename

				log.Printf("[SimpleLogger] Rotated to new log file: %s", newFilename)
			}
		}
	}

	return nil
}

// archivePreviousDay compresses all log files from the previous day
func (sl *SimpleLogger) archivePreviousDay(dateStr string) error {
	archiveDir := filepath.Join(sl.logDir, "archive")

	// Create archive directory if it doesn't exist
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return fmt.Errorf("failed to create archive directory: %v", err)
	}

	// Find all log files for the previous day
	pattern := fmt.Sprintf("commands_%s*.log", dateStr)
	files, err := filepath.Glob(filepath.Join(sl.logDir, pattern))
	if err != nil {
		return fmt.Errorf("failed to find log files: %v", err)
	}

	// Skip if no files found (might be the first day of operation)
	if len(files) == 0 {
		log.Printf("[SimpleLogger] No log files found for %s, skipping archive", dateStr)
		return nil
	}

	// Create tar.gz archive
	archivePath := filepath.Join(archiveDir, fmt.Sprintf("commands_%s.tar.gz", dateStr))

	// Start archiving in a goroutine to not block logging
	go func() {
		if err := sl.createTarGzArchive(archivePath, files); err != nil {
			log.Printf("[SimpleLogger] Failed to create archive: %v", err)
			return
		}

		// Delete original files after successful compression
		for _, file := range files {
			if err := os.Remove(file); err != nil {
				log.Printf("[SimpleLogger] Failed to delete archived file %s: %v", file, err)
			} else {
				log.Printf("[SimpleLogger] Archived and deleted: %s", filepath.Base(file))
			}
		}

		log.Printf("[SimpleLogger] Successfully archived %d files to %s", len(files), archivePath)
	}()

	return nil
}

// createTarGzArchive creates a tar.gz archive from the given files
func (sl *SimpleLogger) createTarGzArchive(archivePath string, files []string) error {
	// Create the archive file
	archiveFile, err := os.Create(archivePath)
	if err != nil {
		return fmt.Errorf("failed to create archive file: %v", err)
	}
	defer archiveFile.Close()

	// Create gzip writer
	gzipWriter := gzip.NewWriter(archiveFile)
	defer gzipWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Add each file to the archive
	for _, filePath := range files {
		if err := sl.addFileToTar(tarWriter, filePath); err != nil {
			return fmt.Errorf("failed to add %s to archive: %v", filePath, err)
		}
	}

	return nil
}

// addFileToTar adds a single file to the tar archive
func (sl *SimpleLogger) addFileToTar(tw *tar.Writer, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file info
	info, err := file.Stat()
	if err != nil {
		return err
	}

	// Create tar header
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}

	// Use just the filename in the archive (not the full path)
	header.Name = filepath.Base(filePath)

	// Write header
	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	// Copy file content
	_, err = io.Copy(tw, file)
	return err
}

// Log writes a generic log entry (backward compatible)
func (sl *SimpleLogger) Log(entry LogEntry) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	// Check if we need to rotate files
	if err := sl.checkRotation(); err != nil {
		log.Printf("[SimpleLogger] Failed to rotate log file: %v", err)
		// Try to continue with current file
	}

	// Set timestamp if not provided
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// Enrich with cached agent info if available
	sl.enrichEntry(&entry)

	// Write as JSON line
	if data, err := json.Marshal(entry); err == nil {
		sl.file.Write(data)
		sl.file.Write([]byte("\n"))
		sl.file.Sync() // Ensure it's written to disk
	}

	// Also log to stdout if in debug mode
	if os.Getenv("DEBUG_LOGGING") == "true" {
		log.Printf("[CommandLog] %s: %s", entry.Type, entry.Command)
	}
}

// LogCommand logs a command being executed (backward compatible signature)
func (sl *SimpleLogger) LogCommand(agentID, username, command string, commandID interface{}) {
	// Extract command type from command
	cmdType := ""
	if command != "" {
		parts := strings.Fields(command)
		if len(parts) > 0 {
			cmdType = parts[0]
		}
	}

	entry := LogEntry{
		Type:        "command",
		AgentID:     agentID,
		Username:    username,
		Command:     truncateString(command, 500),
		CommandID:   commandID,
		CommandType: cmdType,
	}

	sl.Log(entry)
}

// LogOutput logs command output (backward compatible signature)
func (sl *SimpleLogger) LogOutput(agentID string, commandID interface{}, output string) {
	outputSize := len(output)
	truncatedOutput := truncateString(output, 1000)

	entry := LogEntry{
		Type:       "output",
		AgentID:    agentID,
		CommandID:  commandID,
		Output:     truncatedOutput,
		OutputSize: outputSize,
	}

	sl.Log(entry)
}

// LogError logs an error (backward compatible signature)
func (sl *SimpleLogger) LogError(agentID, command string, err error) {
	entry := LogEntry{
		Type:    "error",
		AgentID: agentID,
		Command: truncateString(command, 500),
		Error:   err.Error(),
	}

	sl.Log(entry)
}

// UpdateAgentInfo updates cached agent information (new enhanced method)
func (sl *SimpleLogger) UpdateAgentInfo(info *AgentInfo) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	info.LastSeen = time.Now()
	sl.agentCache[info.AgentID] = info

	// Generate session ID if needed
	if _, exists := sl.sessionMap[info.AgentID]; !exists {
		sl.sessionMap[info.AgentID] = fmt.Sprintf("session_%s_%d",
			truncateString(info.AgentID, 8), time.Now().Unix())
	}

	// Check rotation before writing
	if err := sl.checkRotation(); err != nil {
		log.Printf("[SimpleLogger] Failed to rotate log file: %v", err)
	}

	// Log the agent checkin
	entry := LogEntry{
		Type:       "checkin",
		AgentID:    info.AgentID,
		Hostname:   info.Hostname,
		ExternalIP: info.ExternalIP,
		InternalIP: info.InternalIP,
		Username:   info.Username,
		OS:         info.OS,
		Arch:       info.Arch,
		Process:    info.Process,
		PID:        info.PID,
		Integrity:  info.Integrity,
		SessionID:  sl.sessionMap[info.AgentID],
		Timestamp:  time.Now(),
	}

	// Write directly without going through Log() to avoid double-lock
	if data, err := json.Marshal(entry); err == nil {
		sl.file.Write(data)
		sl.file.Write([]byte("\n"))
		sl.file.Sync()
	}
}

// LogCommandWithDetails logs a command with additional details (new enhanced method)
func (sl *SimpleLogger) LogCommandWithDetails(entry LogEntry) {
	if entry.Type == "" {
		entry.Type = "command"
	}
	sl.Log(entry)
}

// GetAgentInfo returns cached agent information (new enhanced method)
func (sl *SimpleLogger) GetAgentInfo(agentID string) (*AgentInfo, bool) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	info, exists := sl.agentCache[agentID]
	return info, exists
}

// SetMaxFileSize updates the maximum file size for rotation
func (sl *SimpleLogger) SetMaxFileSize(maxSize int64) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.maxFileSize = maxSize
	log.Printf("[SimpleLogger] Max file size set to %d bytes", maxSize)
}

// GetCurrentLogInfo returns information about the current log file
func (sl *SimpleLogger) GetCurrentLogInfo() (filename string, size int64, err error) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if sl.file == nil {
		return "", 0, fmt.Errorf("no log file is open")
	}

	info, err := sl.file.Stat()
	if err != nil {
		return "", 0, err
	}

	return sl.filename, info.Size(), nil
}

// enrichEntry enriches a log entry with cached agent information
func (sl *SimpleLogger) enrichEntry(entry *LogEntry) {
	if entry.AgentID == "" {
		return
	}

	// Get cached agent info (already under lock from Log())
	if info, exists := sl.agentCache[entry.AgentID]; exists {
		// Only add fields if they're empty (don't override)
		if entry.Hostname == "" {
			entry.Hostname = info.Hostname
		}
		if entry.ExternalIP == "" {
			entry.ExternalIP = info.ExternalIP
		}
		if entry.InternalIP == "" {
			entry.InternalIP = info.InternalIP
		}
		if entry.OS == "" {
			entry.OS = info.OS
		}
		if entry.Arch == "" {
			entry.Arch = info.Arch
		}
		if entry.Process == "" {
			entry.Process = info.Process
		}
		if entry.PID == "" {
			entry.PID = info.PID
		}
		if entry.Integrity == "" {
			entry.Integrity = info.Integrity
		}
		if entry.Username == "" && info.Username != "" {
			entry.Username = info.Username
		}
	}

	// Add session ID if available
	if session, exists := sl.sessionMap[entry.AgentID]; exists {
		entry.SessionID = session
	}
}

// Close closes the log file (backward compatible)
func (sl *SimpleLogger) Close() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if sl.file != nil {
		return sl.file.Close()
	}
	return nil
}

// truncateString truncates a string to maxLen
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
