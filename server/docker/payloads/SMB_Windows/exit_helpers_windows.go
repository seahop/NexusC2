// server/docker/payloads/Windows/exit_helpers_windows.go

//go:build windows
// +build windows

package main

import (
	"syscall"
)

// forceTerminateWindows forcefully terminates the process on Windows
func forceTerminateWindows() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	terminateProcess := kernel32.NewProc("TerminateProcess")

	handle, _, _ := getCurrentProcess.Call()
	terminateProcess.Call(handle, 0)
}
