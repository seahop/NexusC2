// server/docker/payloads/Windows/action_whoami.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"
)

// WhoamiTemplate matches the server's CommandTemplate structure
type WhoamiTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// Template indices - must match server's common.go
const (
	idxWaCmdName   = 590
	idxWaWindows   = 591
	idxWaFlagV     = 592
	idxWaFlagG     = 593
	idxWaBackslash = 594
)

// Global whoami template storage
var (
	whoamiTemplate   []string
	whoamiTemplateMu sync.RWMutex
)

// SetWhoamiTemplate stores the whoami template for use
func SetWhoamiTemplate(templates []string) {
	whoamiTemplateMu.Lock()
	whoamiTemplate = templates
	whoamiTemplateMu.Unlock()
}

// waTpl retrieves a whoami template string by index
func waTpl(idx int) string {
	whoamiTemplateMu.RLock()
	defer whoamiTemplateMu.RUnlock()
	if whoamiTemplate != nil && idx < len(whoamiTemplate) {
		return whoamiTemplate[idx]
	}
	return ""
}

// Convenience functions for whoami template values
func waWindows() string   { return waTpl(idxWaWindows) }
func waFlagV() string     { return waTpl(idxWaFlagV) }
func waFlagG() string     { return waTpl(idxWaFlagG) }
func waBackslash() string { return waTpl(idxWaBackslash) }

type WhoamiCommand struct {
	tpl *WhoamiTemplate
}

func (c *WhoamiCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data if available
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		if decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data); err == nil {
			c.tpl = &WhoamiTemplate{}
			if err := json.Unmarshal(decoded, c.tpl); err == nil && c.tpl.Templates != nil {
				SetWhoamiTemplate(c.tpl.Templates)
			}
		}
	}

	var output strings.Builder

	// Check for Windows token impersonation first
	if runtime.GOOS == waWindows() {
		// Use the stored metadata from the token store
		if user, domain, isImpersonating := GetImpersonatedUser(ctx); isImpersonating {
			output.WriteString(fmt.Sprintf("%s\\%s", domain, user))
			if len(args) > 0 && args[0] == waFlagV() {
				output.WriteString("|" + WImpersn)
			}
			return CommandResult{
				Output:      output.String(),
				ExitCode:    0,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
	}

	// Default behavior for non-impersonated context
	currentUser, err := user.Current()
	if err != nil {
		// Fallback to environment variables
		username := c.getUsernameFromEnv()
		hostname := c.getHostname()

		if username != "" {
			output.WriteString(fmt.Sprintf("%s\\%s", hostname, username))
		} else {
			output.WriteString(Err(E19))
		}
	} else {
		// Format based on OS
		if runtime.GOOS == waWindows() {
			// Windows format: DOMAIN\Username
			parts := strings.Split(currentUser.Username, waBackslash())
			if len(parts) == 2 {
				output.WriteString(currentUser.Username)
			} else {
				hostname := c.getHostname()
				output.WriteString(fmt.Sprintf("%s\\%s", hostname, currentUser.Username))
			}
		} else {
			// Unix format: username
			output.WriteString(currentUser.Username)
		}

		// Add UID/GID info for verbose mode (compact format: v|uid|gid|home|shell)
		if len(args) > 0 && args[0] == waFlagV() {
			shell := os.Getenv(EnvShell())
			if shell == "" {
				shell = WUnknown
			}
			output.WriteString(fmt.Sprintf("\n%s|%s|%s|%s|%s", WVerbose, currentUser.Uid, currentUser.Gid, currentUser.HomeDir, shell))
		}
	}

	// Add groups info if requested (compact format: g|group1,group2,group3)
	if len(args) > 0 && args[0] == waFlagG() {
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
	if username := os.Getenv(EnvUsername()); username != "" {
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
		if compname := os.Getenv(EnvComputername()); compname != "" {
			return compname
		}
		if hostname := os.Getenv(EnvHostname()); hostname != "" {
			return hostname
		}
		return WUnknown
	}
	return hostname
}
