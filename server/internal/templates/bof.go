// internal/templates/bof.go
package templates

// GetBOFTemplate returns a template for BOF commands
// This covers bof, bof-async, bof-jobs, bof-output, bof-kill commands
func GetBOFTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Command names (350-359)
	tpl[IdxBofCmdName] = "bof"
	tpl[IdxBofCmdAsync] = "bof-async"
	tpl[IdxBofCmdJobs] = "bof-jobs"
	tpl[IdxBofCmdOutput] = "bof-output"
	tpl[IdxBofCmdKill] = "bof-kill"
	tpl[IdxBofCmdAsyncPrefix] = "bof-async "
	tpl[IdxBofCmdAsyncStatus] = "bof-async-status"
	tpl[IdxBofCmdAsyncOutput] = "bof-async-output"
	tpl[IdxBofOSWindows] = "windows"

	// Job status values (360-364)
	tpl[IdxBofStatusRunning] = "running"
	tpl[IdxBofStatusCompleted] = "completed"
	tpl[IdxBofStatusCrashed] = "crashed"
	tpl[IdxBofStatusKilled] = "killed"
	tpl[IdxBofStatusTimeout] = "timeout"

	// Output markers (365-369) - Using numeric codes to avoid fingerprintable strings
	// Format: <code>|job_id|... where code is: 1=STARTED, 2=COMPLETED, 3=CRASHED, 4=KILLED, 5=TIMEOUT, 6=OUTPUT
	tpl[IdxBofAsyncStarted] = "1"  // Was BOF_ASYNC_STARTED
	tpl[IdxBofAsyncPrefix] = ""    // No prefix needed with numeric codes
	tpl[IdxBofChunkPrefix] = "|C_" // Shortened from |CHUNK_
	tpl[IdxBofChunkSeparator] = "\n--\n"
	tpl[IdxBofPipeSep] = "|"

	// Final status markers (370-374) - Numeric codes
	tpl[IdxBofFinalCompleted] = "2" // Was COMPLETED
	tpl[IdxBofFinalCrashed] = "3"   // Was CRASHED
	tpl[IdxBofFinalKilled] = "4"    // Was KILLED
	tpl[IdxBofFinalTimeout] = "5"   // Was TIMEOUT
	tpl[IdxBofFinalOutput] = "6"    // Was OUTPUT

	// Misc strings (375-377)
	tpl[IdxBofTruncYes] = "YES"
	tpl[IdxBofTruncDots] = "..."
	tpl[IdxBofTruncatedMsg] = " (OUTPUT TRUNCATED - exceeded 10MB limit)"

	// Output message fragments (378-387)
	tpl[IdxBofJobPrefix] = "Job "
	tpl[IdxBofStillRunning] = " is still running\n"
	tpl[IdxBofChunksSent] = "Chunks sent: "
	tpl[IdxBofSpaceParen] = " ("
	tpl[IdxBofNoBufferedOut] = ") has no buffered output\n"
	tpl[IdxBofOutputForJob] = "Output for job "
	tpl[IdxBofChunksSentParen] = " (chunks sent: "
	tpl[IdxBofCloseColonNL] = "):\n"
	tpl[IdxBofCloseParen] = ")"

	// IPC path for network operations (388)
	tpl[IdxBofIPCPath] = "\\IPC$"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeBof,
		Templates: tpl,
		Params:    []string{},
	}
}

// GetCOFFLoaderTemplate returns a template containing all COFF loader strings
// for BOF (Beacon Object File) execution - Windows API names, DLL names, etc.
func GetCOFFLoaderTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// DLL names (870-874)
	tpl[IdxCoffDllKernel32] = "kernel32.dll"
	tpl[IdxCoffDllNtdll] = "ntdll.dll"
	tpl[IdxCoffDllUser32] = "user32.dll"
	tpl[IdxCoffDllWs2_32] = "ws2_32.dll"
	tpl[IdxCoffDllAdvapi32] = "advapi32.dll"

	// Prefixes/suffixes (875-878)
	tpl[IdxCoffPrefixImp] = "__imp_"
	tpl[IdxCoffSuffixDll] = ".dll"
	tpl[IdxCoffPrefixUs] = "_"
	tpl[IdxCoffSectionBss] = ".bss"

	// Kernel32 API names (880-917)
	tpl[IdxCoffApiFreeLibrary] = "FreeLibrary"
	tpl[IdxCoffApiLoadLibraryA] = "LoadLibraryA"
	tpl[IdxCoffApiGetProcAddress] = "GetProcAddress"
	tpl[IdxCoffApiGetModuleHandleA] = "GetModuleHandleA"
	tpl[IdxCoffApiGetModuleFileNameA] = "GetModuleFileNameA"
	tpl[IdxCoffApiVirtualAlloc] = "VirtualAlloc"
	tpl[IdxCoffApiVirtualFree] = "VirtualFree"
	tpl[IdxCoffApiVirtualProtect] = "VirtualProtect"
	tpl[IdxCoffApiSetLastError] = "SetLastError"
	tpl[IdxCoffApiGetCurrentProcess] = "GetCurrentProcess"
	tpl[IdxCoffApiGetProcessHeap] = "GetProcessHeap"
	tpl[IdxCoffApiHeapAlloc] = "HeapAlloc"
	tpl[IdxCoffApiHeapFree] = "HeapFree"
	tpl[IdxCoffApiWideCharToMultiByte] = "WideCharToMultiByte"
	tpl[IdxCoffApiGetCurrentThread] = "GetCurrentThread"
	tpl[IdxCoffApiGetThreadContext] = "GetThreadContext"
	tpl[IdxCoffApiSetThreadContext] = "SetThreadContext"
	tpl[IdxCoffApiSuspendThread] = "SuspendThread"
	tpl[IdxCoffApiResumeThread] = "ResumeThread"
	tpl[IdxCoffApiCreateThread] = "CreateThread"
	tpl[IdxCoffApiExitThread] = "ExitThread"
	tpl[IdxCoffApiGetSystemTime] = "GetSystemTime"
	tpl[IdxCoffApiGetLocalTime] = "GetLocalTime"
	tpl[IdxCoffApiGetFileAttributesA] = "GetFileAttributesA"
	tpl[IdxCoffApiSetFileAttributesA] = "SetFileAttributesA"
	tpl[IdxCoffApiCreateFileA] = "CreateFileA"
	tpl[IdxCoffApiReadFile] = "ReadFile"
	tpl[IdxCoffApiWriteFile] = "WriteFile"
	tpl[IdxCoffApiCloseHandle] = "CloseHandle"
	tpl[IdxCoffApiGetFileSize] = "GetFileSize"
	tpl[IdxCoffApiGetFileSizeEx] = "GetFileSizeEx"
	tpl[IdxCoffApiFileTimeToSystemTime] = "FileTimeToSystemTime"
	tpl[IdxCoffApiSystemTimeToTzSpecific] = "SystemTimeToTzSpecificLocalTime"
	tpl[IdxCoffApiFindFirstFileA] = "FindFirstFileA"
	tpl[IdxCoffApiFindNextFileA] = "FindNextFileA"
	tpl[IdxCoffApiFindClose] = "FindClose"
	tpl[IdxCoffApiGetLastError] = "GetLastError"
	tpl[IdxCoffApiRtlCopyMemory] = "RtlCopyMemory"

	// MSVCRT/String functions (918-927)
	tpl[IdxCoffFnStrlen] = "strlen"
	tpl[IdxCoffFnStrcmp] = "strcmp"
	tpl[IdxCoffFnStrncmp] = "strncmp"
	tpl[IdxCoffFnStricmp] = "_stricmp"
	tpl[IdxCoffFnStrnicmp] = "_strnicmp"
	tpl[IdxCoffFnStrcpy] = "strcpy"
	tpl[IdxCoffFnStrncpy] = "strncpy"
	tpl[IdxCoffFnStrcat] = "strcat"
	tpl[IdxCoffFnStrncat] = "strncat"
	tpl[IdxCoffFnStrstr] = "strstr"

	// Memory functions (928-935)
	tpl[IdxCoffFnCalloc] = "calloc"
	tpl[IdxCoffFnMalloc] = "malloc"
	tpl[IdxCoffFnFree] = "free"
	tpl[IdxCoffFnRealloc] = "realloc"
	tpl[IdxCoffFnMemcpy] = "memcpy"
	tpl[IdxCoffFnMemset] = "memset"
	tpl[IdxCoffFnMemmove] = "memmove"
	tpl[IdxCoffFnMemcmp] = "memcmp"

	// Printf functions (936-938)
	tpl[IdxCoffFnVsnprintf] = "vsnprintf"
	tpl[IdxCoffFnVsnprintfU] = "_vsnprintf"
	tpl[IdxCoffFnSprintf] = "sprintf"

	// User32 functions (939-946)
	tpl[IdxCoffApiMessageBoxA] = "MessageBoxA"
	tpl[IdxCoffApiMessageBoxW] = "MessageBoxW"
	tpl[IdxCoffApiGetDesktopWindow] = "GetDesktopWindow"
	tpl[IdxCoffApiGetForegroundWnd] = "GetForegroundWindow"
	tpl[IdxCoffApiGetWindowTextA] = "GetWindowTextA"
	tpl[IdxCoffApiGetWindowTextW] = "GetWindowTextW"
	tpl[IdxCoffApiFindWindowA] = "FindWindowA"
	tpl[IdxCoffApiFindWindowW] = "FindWindowW"

	// WS2_32 functions (947-968)
	tpl[IdxCoffApiWSAStartup] = "WSAStartup"
	tpl[IdxCoffApiWSACleanup] = "WSACleanup"
	tpl[IdxCoffApiWSAGetLastErr] = "WSAGetLastError"
	tpl[IdxCoffApiSocket] = "socket"
	tpl[IdxCoffApiClosesocket] = "closesocket"
	tpl[IdxCoffApiBind] = "bind"
	tpl[IdxCoffApiListen] = "listen"
	tpl[IdxCoffApiAccept] = "accept"
	tpl[IdxCoffApiConnect] = "connect"
	tpl[IdxCoffApiSend] = "send"
	tpl[IdxCoffApiRecv] = "recv"
	tpl[IdxCoffApiSendto] = "sendto"
	tpl[IdxCoffApiRecvfrom] = "recvfrom"
	tpl[IdxCoffApiSelect] = "select"
	tpl[IdxCoffApiGethostbyname] = "gethostbyname"
	tpl[IdxCoffApiGethostbyaddr] = "gethostbyaddr"
	tpl[IdxCoffApiInet_addr] = "inet_addr"
	tpl[IdxCoffApiInet_ntoa] = "inet_ntoa"
	tpl[IdxCoffApiHtons] = "htons"
	tpl[IdxCoffApiHtonl] = "htonl"
	tpl[IdxCoffApiNtohs] = "ntohs"
	tpl[IdxCoffApiNtohl] = "ntohl"

	// Advapi32 functions (969-977)
	tpl[IdxCoffApiRegOpenKeyExA] = "RegOpenKeyExA"
	tpl[IdxCoffApiRegCloseKey] = "RegCloseKey"
	tpl[IdxCoffApiRegQueryValueExA] = "RegQueryValueExA"
	tpl[IdxCoffApiRegSetValueExA] = "RegSetValueExA"
	tpl[IdxCoffApiOpenProcessToken] = "OpenProcessToken"
	tpl[IdxCoffApiGetTokenInformation] = "GetTokenInformation"
	tpl[IdxCoffApiSetTokenInformation] = "SetTokenInformation"
	tpl[IdxCoffApiDuplicateTokenEx] = "DuplicateTokenEx"
	tpl[IdxCoffApiCreateProcessAsUserA] = "CreateProcessAsUserA"

	// Beacon API functions (978-990)
	tpl[IdxCoffFnBeaconOutput] = "BeaconOutput"
	tpl[IdxCoffFnBeaconDataParse] = "BeaconDataParse"
	tpl[IdxCoffFnBeaconDataInt] = "BeaconDataInt"
	tpl[IdxCoffFnBeaconDataShort] = "BeaconDataShort"
	tpl[IdxCoffFnBeaconDataLength] = "BeaconDataLength"
	tpl[IdxCoffFnBeaconDataExtract] = "BeaconDataExtract"
	tpl[IdxCoffFnBeaconPrintf] = "BeaconPrintf"
	tpl[IdxCoffFnBeaconFormatAlloc] = "BeaconFormatAlloc"
	tpl[IdxCoffFnBeaconFormatFree] = "BeaconFormatFree"
	tpl[IdxCoffFnBeaconFormatAppend] = "BeaconFormatAppend"
	tpl[IdxCoffFnBeaconFormatPrintf] = "BeaconFormatPrintf"
	tpl[IdxCoffFnBeaconFormatToStr] = "BeaconFormatToString"
	tpl[IdxCoffFnBeaconFormatInt] = "BeaconFormatInt"

	// Helper functions (991-999)
	tpl[IdxCoffFnBofstart] = "bofstart"
	tpl[IdxCoffFnInternalPrintf] = "internal_printf"
	tpl[IdxCoffFnPrintoutput] = "printoutput"
	tpl[IdxCoffFnIntAlloc] = "intAlloc"
	tpl[IdxCoffFnIntFree] = "intFree"
	tpl[IdxCoffFnIntMemset] = "intMemset"
	tpl[IdxCoffFnIntMemcpy] = "intMemcpy"
	tpl[IdxCoffFnIntRealloc] = "intRealloc"
	tpl[IdxCoffFnIntStrlen] = "intStrlen"

	// Helper functions continued (1000-1008)
	tpl[IdxCoffFnIntStrcmp] = "intStrcmp"
	tpl[IdxCoffFnIntStrncmp] = "intStrncmp"
	tpl[IdxCoffFnIntStrcpy] = "intStrcpy"
	tpl[IdxCoffFnIntStrncpy] = "intStrncpy"
	tpl[IdxCoffFnIntStrcat] = "intStrcat"
	tpl[IdxCoffFnIntStrncat] = "intStrncat"
	tpl[IdxCoffFnToWideChar] = "toWideChar"
	tpl[IdxCoffFnUtf8ToUtf16] = "Utf8ToUtf16"
	tpl[IdxCoffFnUtf16ToUtf8] = "Utf16ToUtf8"

	// Patches strings (1010-1013) - for AMSI/ETW bypass
	tpl[IdxPatchAmsiDll] = "amsi.dll"
	tpl[IdxPatchAmsiScanBuffer] = "AmsiScanBuffer"
	tpl[IdxPatchEtwEventWrite] = "EtwEventWrite"
	tpl[IdxPatchNtProtectVirtMem] = "NtProtectVirtualMemory"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeBof,
		Templates: tpl,
		Params:    []string{},
	}
}
