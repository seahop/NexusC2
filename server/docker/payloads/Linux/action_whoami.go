// server/docker/payloads/Linux/action_whoami.go

//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"
)

type WhoamiCommand struct{}

func (c *WhoamiCommand) Name() string {
	return "whoami"
}

func (c *WhoamiCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	var output strings.Builder

	// Default behavior for non-impersonated context
	currentUser, err := user.Current()
	if err != nil {
		// Fallback to environment variables
		username := c.getUsernameFromEnv()
		hostname := c.getHostname()
		if username != "" {
			output.WriteString(fmt.Sprintf("%s@%s", username, hostname))
		} else {
			output.WriteString("Unknown user")
		}
	} else {
		// Unix/Darwin format: username
		output.WriteString(currentUser.Username)

		// Add UID/GID info for verbose mode
		if len(args) > 0 && (args[0] == "-v" || args[0] == "--verbose") {
			output.WriteString(fmt.Sprintf("\nUID: %s", currentUser.Uid))
			output.WriteString(fmt.Sprintf("\nGID: %s", currentUser.Gid))
			output.WriteString(fmt.Sprintf("\nHome: %s", currentUser.HomeDir))
			output.WriteString(fmt.Sprintf("\nShell: %s", os.Getenv("SHELL")))
		}
	}

	// Add groups info if requested
	if len(args) > 0 && (args[0] == "-g" || args[0] == "--groups") {
		if currentUser != nil {
			if groups, err := currentUser.GroupIds(); err == nil && len(groups) > 0 {
				output.WriteString("\nGroups: ")
				output.WriteString(strings.Join(groups, ", "))
			}
		}
	}

	return CommandResult{
		Output:      output.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// getUsernameFromEnv tries to get username from environment variables
func (c *WhoamiCommand) getUsernameFromEnv() string {
	if username := os.Getenv("USER"); username != "" {
		return username
	}
	if username := os.Getenv("LOGNAME"); username != "" {
		return username
	}
	return ""
}

// getHostname safely gets the hostname
func (c *WhoamiCommand) getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		// Try environment variable
		if hostname := os.Getenv("HOSTNAME"); hostname != "" {
			return hostname
		}
		return "unknown"
	}
	return hostname
}
