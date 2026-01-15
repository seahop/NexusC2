// Package logging provides file-based logging with rotation for server components
package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger wraps the standard logger with file output
type Logger struct {
	mu          sync.Mutex
	file        *os.File
	filePath    string
	maxSizeMB   int64
	currentSize int64
	serviceName string
}

// Config holds logger configuration
type Config struct {
	LogDir      string // Directory to write logs (default: /app/logs)
	ServiceName string // Name of the service (used in filename)
	MaxSizeMB   int64  // Max log file size before rotation (default: 50MB)
}

// New creates a new file logger
func New(cfg Config) (*Logger, error) {
	if cfg.LogDir == "" {
		cfg.LogDir = "/app/logs"
	}
	if cfg.MaxSizeMB == 0 {
		cfg.MaxSizeMB = 50
	}

	// Ensure log directory exists
	if err := os.MkdirAll(cfg.LogDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	l := &Logger{
		filePath:    filepath.Join(cfg.LogDir, cfg.ServiceName+".log"),
		maxSizeMB:   cfg.MaxSizeMB,
		serviceName: cfg.ServiceName,
	}

	if err := l.openLogFile(); err != nil {
		return nil, err
	}

	// Set up standard logger to write to both stdout and file
	multiWriter := io.MultiWriter(os.Stdout, l)
	log.SetOutput(multiWriter)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	return l, nil
}

// openLogFile opens or creates the log file
func (l *Logger) openLogFile() error {
	f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}

	// Get current file size
	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to stat log file: %v", err)
	}

	l.file = f
	l.currentSize = stat.Size()
	return nil
}

// Write implements io.Writer for the logger
func (l *Logger) Write(p []byte) (n int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check if we need to rotate
	if l.currentSize+int64(len(p)) > l.maxSizeMB*1024*1024 {
		if err := l.rotate(); err != nil {
			// Log rotation failed, but continue writing
			fmt.Fprintf(os.Stderr, "Log rotation failed: %v\n", err)
		}
	}

	n, err = l.file.Write(p)
	l.currentSize += int64(n)
	return n, err
}

// rotate rotates the log file
func (l *Logger) rotate() error {
	// Close current file
	if l.file != nil {
		l.file.Close()
	}

	// Rename current log to timestamped backup
	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.%s", l.filePath, timestamp)

	if err := os.Rename(l.filePath, backupPath); err != nil {
		// File might not exist, that's ok
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to rename log file: %v", err)
		}
	}

	// Clean up old log files (keep last 5)
	l.cleanupOldLogs()

	// Open new log file
	return l.openLogFile()
}

// cleanupOldLogs removes old rotated log files, keeping the most recent ones
func (l *Logger) cleanupOldLogs() {
	pattern := l.filePath + ".*"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	// Keep only the last 5 rotated logs
	if len(matches) > 5 {
		// Sort by modification time (oldest first due to timestamp format)
		for i := 0; i < len(matches)-5; i++ {
			os.Remove(matches[i])
		}
	}
}

// Close closes the log file
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	log.Printf("[WARN] "+format, args...)
}

// Debug logs a debug message (only if DEBUG env var is set)
func (l *Logger) Debug(format string, args ...interface{}) {
	if os.Getenv("DEBUG") != "" {
		log.Printf("[DEBUG] "+format, args...)
	}
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	log.Fatalf("[FATAL] "+format, args...)
}

// SetupDefaultLogger initializes logging for a service with default settings
// Call this at the start of main() in each service
func SetupDefaultLogger(serviceName string) (*Logger, error) {
	return New(Config{
		ServiceName: serviceName,
		LogDir:      getLogDir(),
		MaxSizeMB:   50,
	})
}

// getLogDir returns the log directory from env or default
func getLogDir() string {
	if dir := os.Getenv("LOG_DIR"); dir != "" {
		return dir
	}
	return "/app/logs"
}
