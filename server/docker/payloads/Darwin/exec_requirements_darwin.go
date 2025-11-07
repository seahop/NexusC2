// server/docker/payloads/Darwin/safety_checks.go
//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
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

	// Check domain (Active Directory binding)
	if safetyDomain != "" {
		if !checkDomain(safetyDomain) {
			return false
		}
	}

	// Check file existence
	if safetyFilePath != "" {
		mustExist := safetyFileMustExist == "true"
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

	// Also check using scutil for local hostname
	if !strings.EqualFold(hostname, expected) {
		cmd := exec.Command("scutil", "--get", "LocalHostName")
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
		username := os.Getenv("USER")
		if username == "" {
			username = os.Getenv("LOGNAME")
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
	cmd := exec.Command("dsconfigad", "-show")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for "Active Directory Domain = domain.com"
		if strings.HasPrefix(line, "Active Directory Domain") {
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
	cmd := exec.Command("dscl", "localhost", "-list", "/Active Directory")
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
		"/etc/krb5.conf",
		"/Library/Preferences/edu.mit.Kerberos",
	}

	for _, path := range configPaths {
		if data, err := os.ReadFile(path); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToLower(line), "default_realm") {
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
	cmd := exec.Command("dscl", "localhost", "-read", "/")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Parse output for Open Directory server
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "ServerConnection") {
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
	if strings.HasPrefix(path, "~/") {
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
	cmd := exec.Command("ps", "aux")
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
	cmd = exec.Command("pgrep", "-i", processName)
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
	killDate, err := time.Parse("2006-01-02 15:04:05", killDateStr)
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
