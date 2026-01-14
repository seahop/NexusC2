// server/docker/payloads/SMB_Windows/exit_helpers_windows.go

//go:build windows
// +build windows

package main

import (
	"syscall"
)

// Exit helper strings (constructed to avoid static signatures)
var (
	// DLL names
	ehDllKernel32 = string([]byte{0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c}) // kernel32.dll

	// Proc names
	ehProcGetCurrentProcess = string([]byte{0x47, 0x65, 0x74, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73}) // GetCurrentProcess
	ehProcTerminateProcess  = string([]byte{0x54, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73})       // TerminateProcess
)

// forceTerminateWindows forcefully terminates the process on Windows
func forceTerminateWindows() {
	kernel32 := syscall.NewLazyDLL(ehDllKernel32)
	getCurrentProcess := kernel32.NewProc(ehProcGetCurrentProcess)
	terminateProcess := kernel32.NewProc(ehProcTerminateProcess)

	handle, _, _ := getCurrentProcess.Call()
	terminateProcess.Call(handle, 0)
}
