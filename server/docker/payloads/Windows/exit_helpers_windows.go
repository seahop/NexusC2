// server/docker/payloads/Windows/exit_helpers_windows.go

//go:build windows
// +build windows

package main

import (
	"syscall"
)

// Exit helper template indices - reuse CLR template indices from clr_exit_prevention.go
// These must match server-side templates/persistence.go
const (
	idxExitDllKernel32         = 102 // kernel32.dll (same as idxClrDllKernel32)
	idxExitProcTerminateProcess = 109 // TerminateProcess (same as idxClrApiTerminateProcess)
	idxExitProcGetCurrentProcess = 110 // GetCurrentProcess (same as idxClrApiGetCurrentProc)
)

// Exit helper string accessors using CLR template lookups
func ehDllKernel32() string         { return getClrTpl(idxExitDllKernel32) }
func ehProcGetCurrentProcess() string { return getClrTpl(idxExitProcGetCurrentProcess) }
func ehProcTerminateProcess() string  { return getClrTpl(idxExitProcTerminateProcess) }

// forceTerminateWindows forcefully terminates the process on Windows
func forceTerminateWindows() {
	kernel32 := syscall.NewLazyDLL(ehDllKernel32())
	getCurrentProcess := kernel32.NewProc(ehProcGetCurrentProcess())
	terminateProcess := kernel32.NewProc(ehProcTerminateProcess())

	handle, _, _ := getCurrentProcess.Call()
	terminateProcess.Call(handle, 0)
}
