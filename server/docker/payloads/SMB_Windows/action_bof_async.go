// server/docker/payloads/Windows/action_bof_async.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"runtime"
	"strings"
	"time"
)

// BOF async command strings are defined via template in action_bof.go
// Use bofTpl() and convenience functions to access them

// BOFAsyncCommand handles async BOF execution
type BOFAsyncCommand struct {
	tpl *BOFTemplate
}

func (c *BOFAsyncCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data if available
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
		if err == nil {
			c.tpl = &BOFTemplate{}
			if err := json.Unmarshal(decoded, c.tpl); err == nil {
				SetBOFTemplate(c.tpl.Templates)
			}
		}
	}

	osWindows := bofOSWindows()
	if osWindows == "" {
		osWindows = "windows"
	}
	if runtime.GOOS != osWindows {
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
type BOFJobsCommand struct {
	tpl *BOFTemplate
}

func (c *BOFJobsCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data if available
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
		if err == nil {
			c.tpl = &BOFTemplate{}
			if err := json.Unmarshal(decoded, c.tpl); err == nil {
				SetBOFTemplate(c.tpl.Templates)
			}
		}
	}

	osWindows := bofOSWindows()
	if osWindows == "" {
		osWindows = "windows"
	}
	if runtime.GOOS != osWindows {
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
type BOFOutputCommand struct {
	tpl *BOFTemplate
}

func (c *BOFOutputCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data if available
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
		if err == nil {
			c.tpl = &BOFTemplate{}
			if err := json.Unmarshal(decoded, c.tpl); err == nil {
				SetBOFTemplate(c.tpl.Templates)
			}
		}
	}

	osWindows := bofOSWindows()
	if osWindows == "" {
		osWindows = "windows"
	}
	if runtime.GOOS != osWindows {
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
type BOFKillCommand struct {
	tpl *BOFTemplate
}

func (c *BOFKillCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data if available
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
		if err == nil {
			c.tpl = &BOFTemplate{}
			if err := json.Unmarshal(decoded, c.tpl); err == nil {
				SetBOFTemplate(c.tpl.Templates)
			}
		}
	}

	osWindows := bofOSWindows()
	if osWindows == "" {
		osWindows = "windows"
	}
	if runtime.GOOS != osWindows {
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
	osWindows := bofOSWindows()
	if osWindows == "" {
		osWindows = "windows"
	}
	if runtime.GOOS != osWindows {
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
	asyncPrefix := bofAsyncCmdPrefix()
	if asyncPrefix == "" {
		asyncPrefix = "bof-async "
	}
	if cmd.Command != "" && strings.HasPrefix(cmd.Command, asyncPrefix) {
		argString := strings.TrimPrefix(cmd.Command, asyncPrefix)
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
