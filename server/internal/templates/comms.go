// internal/templates/comms.go
package templates

// TypeComms is the command type identifier for communications template
const TypeComms = 27

// GetCommsTemplate returns the communications template for polling/HTTP strings
// This template is sent during handshake to provide protocol-related strings
func GetCommsTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// HTTP headers (710-716)
	tpl[IdxCommsUserAgent] = "User-Agent"
	tpl[IdxCommsContentType] = "Content-Type"
	tpl[IdxCommsPadPre] = "X-Pad-Pre"
	tpl[IdxCommsPadApp] = "X-Pad-App"
	tpl[IdxCommsMetaId] = "id"
	tpl[IdxCommsEncryption] = "encryption"
	tpl[IdxCommsEncRsaAes] = "rsa+aes"

	// Polling protocol (720-728)
	tpl[IdxPollAppJson] = "application/json"
	tpl[IdxPollStatus] = "status"
	tpl[IdxPollRekey] = "rekey"
	tpl[IdxPollNoCommands] = "no_commands"
	tpl[IdxPollAgentId] = "agent_id"
	tpl[IdxPollResults] = "results"
	tpl[IdxPollType] = "type"
	tpl[IdxPollPayload] = "payload"
	tpl[IdxPollHandshakeResp] = "handshake_response"

	// Transform type codes (760-769)
	tpl[IdxTransBase64] = "a"
	tpl[IdxTransBase64URL] = "b"
	tpl[IdxTransHex] = "c"
	tpl[IdxTransGzip] = "d"
	tpl[IdxTransNetBIOS] = "e"
	tpl[IdxTransXOR] = "f"
	tpl[IdxTransPrepend] = "g"
	tpl[IdxTransAppend] = "h"
	tpl[IdxTransRandPre] = "i"
	tpl[IdxTransRandApp] = "j"

	// Charset codes (770-773)
	tpl[IdxCharsetNum] = "1"
	tpl[IdxCharsetAlpha] = "2"
	tpl[IdxCharsetAlnum] = "3"
	tpl[IdxCharsetHex] = "4"

	// Command queue strings (780-786)
	tpl[IdxCqWordWindows] = "windows"
	tpl[IdxCqShellCmd] = "cmd"
	tpl[IdxCqShellCmdArg] = "/c"
	tpl[IdxCqShellSh] = "sh"
	tpl[IdxCqShellShArg] = "-c"
	tpl[IdxCqCmdDownload] = "download"
	tpl[IdxCqCmdUpload] = "upload"

	// Windows common API strings (1020-1051)
	// DLL names
	tpl[IdxWcDllAdvapi32] = "advapi32.dll"
	tpl[IdxWcDllKernel32] = "kernel32.dll"
	tpl[IdxWcDllNtdll] = "ntdll.dll"
	tpl[IdxWcDllUser32] = "user32.dll"
	tpl[IdxWcDllPsapi] = "psapi.dll"

	// Advapi32 function names
	tpl[IdxWcFnGetUserNameW] = "GetUserNameW"
	tpl[IdxWcFnOpenProcessToken] = "OpenProcessToken"
	tpl[IdxWcFnOpenThreadToken] = "OpenThreadToken"
	tpl[IdxWcFnDuplicateTokenEx] = "DuplicateTokenEx"
	tpl[IdxWcFnImpersonateLoggedOnUser] = "ImpersonateLoggedOnUser"
	tpl[IdxWcFnRevertToSelf] = "RevertToSelf"
	tpl[IdxWcFnGetTokenInformation] = "GetTokenInformation"
	tpl[IdxWcFnLookupAccountSidW] = "LookupAccountSidW"
	tpl[IdxWcFnLogonUserW] = "LogonUserW"
	tpl[IdxWcFnLogonUserExW] = "LogonUserExW"
	tpl[IdxWcFnCreateProcessAsUserW] = "CreateProcessAsUserW"
	tpl[IdxWcFnCreateProcessWithTokenW] = "CreateProcessWithTokenW"
	tpl[IdxWcFnAdjustTokenPrivileges] = "AdjustTokenPrivileges"
	tpl[IdxWcFnLookupPrivilegeValueW] = "LookupPrivilegeValueW"

	// Kernel32 function names
	tpl[IdxWcFnOpenProcess] = "OpenProcess"
	tpl[IdxWcFnCloseHandle] = "CloseHandle"
	tpl[IdxWcFnGetCurrentProcess] = "GetCurrentProcess"
	tpl[IdxWcFnGetCurrentProcessId] = "GetCurrentProcessId"
	tpl[IdxWcFnGetCurrentThread] = "GetCurrentThread"
	tpl[IdxWcFnTerminateProcess] = "TerminateProcess"
	tpl[IdxWcFnGetExitCodeProcess] = "GetExitCodeProcess"
	tpl[IdxWcFnWaitForSingleObject] = "WaitForSingleObject"
	tpl[IdxWcFnCreateToolhelp32Snapshot] = "CreateToolhelp32Snapshot"
	tpl[IdxWcFnProcess32FirstW] = "Process32FirstW"
	tpl[IdxWcFnProcess32NextW] = "Process32NextW"
	tpl[IdxWcFnGetEnvironmentStringsW] = "GetEnvironmentStringsW"
	tpl[IdxWcFnFreeEnvironmentStringsW] = "FreeEnvironmentStringsW"

	return &CommandTemplate{
		Version:   1,
		Type:      TypeComms,
		Templates: tpl,
		Params:    []string{},
	}
}
