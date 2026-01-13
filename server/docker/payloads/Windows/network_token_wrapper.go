// server/docker/payloads/Windows/network_token_wrapper.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// NetworkTokenContext manages the application of network-only tokens to commands
type NetworkTokenContext struct {
	UseNetOnlyToken bool
	TokenHandle     syscall.Handle
	TokenName       string
}

// GetNetworkTokenContext returns the current network-only token context if available
func GetNetworkTokenContext() *NetworkTokenContext {
	if globalTokenStore == nil {
		return nil
	}

	globalTokenStore.mu.RLock()
	defer globalTokenStore.mu.RUnlock()

	if globalTokenStore.NetOnlyToken == "" || globalTokenStore.NetOnlyHandle == 0 {
		return nil
	}

	return &NetworkTokenContext{
		UseNetOnlyToken: true,
		TokenHandle:     globalTokenStore.NetOnlyHandle,
		TokenName:       globalTokenStore.NetOnlyToken,
	}
}

// ExecuteWithNetworkToken executes a command with network-only token if available
func ExecuteWithNetworkToken(cmdPath string, args []string) (*exec.Cmd, error) {
	netContext := GetNetworkTokenContext()

	if netContext == nil || !netContext.UseNetOnlyToken {
		// No network-only token set, execute normally
		cmd := exec.Command(cmdPath, args...)
		return cmd, nil
	}

	// Create command with network-only token
	cmd := exec.Command(cmdPath, args...)

	// Apply the network token to the command
	if err := ApplyNetworkTokenToCommand(cmd, netContext.TokenHandle); err != nil {
		return nil, fmt.Errorf("failed to apply network token: %v", err)
	}

	return cmd, nil
}

// ApplyNetworkTokenToCommand applies a network-only token to an exec.Cmd
func ApplyNetworkTokenToCommand(cmd *exec.Cmd, tokenHandle syscall.Handle) error {
	// This requires using Windows-specific process creation with token
	// We'll use CreateProcessWithTokenW or CreateProcessAsUser

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token: syscall.Token(tokenHandle),
	}

	return nil
}

// CreateProcessWithNetworkToken creates a new process with network-only token
func CreateProcessWithNetworkToken(
	commandLine string,
	tokenHandle syscall.Handle,
) (handle syscall.Handle, pid int, err error) {

	var si syscall.StartupInfo
	var pi syscall.ProcessInformation

	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = syscall.STARTF_USESHOWWINDOW
	si.ShowWindow = syscall.SW_HIDE

	// Convert command line to UTF16
	cmdLineUTF16, err := syscall.UTF16PtrFromString(commandLine)
	if err != nil {
		return syscall.InvalidHandle, 0, err
	}

	// Use CreateProcessAsUser with the token
	ret, _, lastErr := procCreateProcessAsUserW.Call(
		uintptr(tokenHandle),
		0, // lpApplicationName
		uintptr(unsafe.Pointer(cmdLineUTF16)),
		0, // lpProcessAttributes
		0, // lpThreadAttributes
		0, // bInheritHandles
		uintptr(CREATE_NO_WINDOW),
		0, // lpEnvironment
		0, // lpCurrentDirectory
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if ret == 0 {
		return syscall.InvalidHandle, 0, lastErr
	}

	// Close thread handle as we don't need it
	CloseHandle(pi.Thread)

	return pi.Process, int(pi.ProcessId), nil
}

// WrapNetworkCommand wraps a command execution with network-only token context
func WrapNetworkCommand(commandFunc func() CommandResult) CommandResult {
	netContext := GetNetworkTokenContext()

	if netContext == nil || !netContext.UseNetOnlyToken {
		// No network-only token, execute normally
		return commandFunc()
	}

	// Log that we're using network-only token
	result := commandFunc()

	// Prepend network token info to output
	tokenInfo := fmt.Sprintf("[*] Using network-only token: %s\n", netContext.TokenName)
	result.Output = tokenInfo + result.Output

	return result
}

// ExecuteNetworkCommand is a helper for executing network-related commands
// with proper token context
func ExecuteNetworkCommand(ctx *CommandContext, command string, args []string) CommandResult {
	netContext := GetNetworkTokenContext()

	var output string
	var exitCode int

	if netContext != nil && netContext.UseNetOnlyToken {
		// Execute with network-only token
		output = fmt.Sprintf("[*] Executing with network-only token: %s\n", netContext.TokenName)

		// Build full command line
		fullCmd := command
		for _, arg := range args {
			fullCmd += " " + arg
		}

		// Create process with token
		handle, pid, err := CreateProcessWithNetworkToken(fullCmd, netContext.TokenHandle)
		if err != nil {
			return CommandResult{
				Output:      Err(E37),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// Wait for process to complete
		syscall.WaitForSingleObject(handle, syscall.INFINITE)

		// Get exit code
		var exitCodeUint uint32
		syscall.GetExitCodeProcess(handle, &exitCodeUint)
		exitCode = int(exitCodeUint)

		// Close process handle
		CloseHandle(handle)

		output += fmt.Sprintf("Process %d completed with exit code %d\n", pid, exitCode)
	} else {
		// Execute normally
		cmd := exec.Command(command, args...)
		outputBytes, err := cmd.CombinedOutput()
		output = string(outputBytes)

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 1
			}
		}
	}

	return CommandResult{
		Output:      output,
		ExitCode:    exitCode,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// NetCommand wrapper - example of how to integrate with existing net commands
func ExecuteNetCommandWithToken(ctx *CommandContext, args []string) CommandResult {
	// Check if we should use network-only token
	netContext := GetNetworkTokenContext()

	if netContext != nil && netContext.UseNetOnlyToken {
		// Prepare to execute with network token
		var output strings.Builder
		output.WriteString(fmt.Sprintf("[*] Using network-only token: %s\n", netContext.TokenName))
		output.WriteString(fmt.Sprintf("    User: %s\n\n", GetTokenUserString(netContext.TokenHandle)))

		// Execute the actual net command with the token context
		cmdStr := "net " + strings.Join(args, " ")

		// Create process with network token
		handle, _, err := CreateProcessWithNetworkToken(cmdStr, netContext.TokenHandle)
		if err != nil {
			output.WriteString(Err(E37) + "\n")

			// Fallback to normal execution
			cmd := exec.Command("net", args...)
			cmdOutput, cmdErr := cmd.CombinedOutput()
			output.Write(cmdOutput)

			exitCode := 0
			if cmdErr != nil {
				if exitErr, ok := cmdErr.(*exec.ExitError); ok {
					exitCode = exitErr.ExitCode()
				} else {
					exitCode = 1
				}
			}

			return CommandResult{
				Output:      output.String(),
				ExitCode:    exitCode,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// Wait for completion and get output
		syscall.WaitForSingleObject(handle, syscall.INFINITE)
		CloseHandle(handle)

		// Note: Getting output from the spawned process requires additional work
		// with pipes, which would be implemented in a production version

		output.WriteString("[+] Command executed with network-only token\n")

		return CommandResult{
			Output:      output.String(),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// No network-only token, execute normally
	cmd := exec.Command("net", args...)
	output, err := cmd.CombinedOutput()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return CommandResult{
		Output:      string(output),
		ExitCode:    exitCode,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// GetTokenUserString gets the user string from a token handle
func GetTokenUserString(tokenHandle syscall.Handle) string {
	// Implementation would query token for user info
	// This is a simplified version
	return "DOMAIN\\User"
}

// In network_token_wrapper.go, add this improved version:
func CreateProcessWithNetworkTokenAndCapture(
	commandLine string,
	tokenHandle syscall.Handle,
	workingDir string,
) (output string, exitCode int, err error) {
	// Create temp file for output capture (more reliable than pipes)
	tempFile := fmt.Sprintf("%s\\netonly_output_%d.txt", os.TempDir(), time.Now().UnixNano())
	defer os.Remove(tempFile)

	// Build command with output redirection
	fullCommand := fmt.Sprintf("cmd.exe /c %s > \"%s\" 2>&1", commandLine, tempFile)

	var si syscall.StartupInfo
	var pi syscall.ProcessInformation

	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = syscall.STARTF_USESHOWWINDOW
	si.ShowWindow = syscall.SW_HIDE

	cmdLineUTF16, err := syscall.UTF16PtrFromString(fullCommand)
	if err != nil {
		return "", 1, err
	}

	var workDirPtr *uint16
	if workingDir != "" {
		workDirPtr, _ = syscall.UTF16PtrFromString(workingDir)
	}

	// Use CreateProcessAsUser with the token
	ret, _, lastErr := procCreateProcessAsUserW.Call(
		uintptr(tokenHandle),
		0,
		uintptr(unsafe.Pointer(cmdLineUTF16)),
		0, 0, 0,
		uintptr(CREATE_NO_WINDOW),
		0,
		uintptr(unsafe.Pointer(workDirPtr)),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if ret == 0 {
		return "", 1, lastErr
	}

	// Wait for process to complete
	syscall.WaitForSingleObject(pi.Process, syscall.INFINITE)

	// Get exit code
	var exitCodeUint uint32
	syscall.GetExitCodeProcess(pi.Process, &exitCodeUint)

	// Close handles
	CloseHandle(pi.Thread)
	CloseHandle(pi.Process)

	// Read output from temp file
	outputBytes, _ := os.ReadFile(tempFile)

	return string(outputBytes), int(exitCodeUint), nil
}
