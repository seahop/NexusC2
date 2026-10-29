// server/docker/payloads/Darwin/action_rekey.go

//go:build darwin
// +build darwin

package main

import (
	// "log"
	"time"
)

type RekeyCommand struct{}

func (c *RekeyCommand) Execute(ctx *CommandContext, args []string) CommandResult {

	// Note: The actual rekey logic is now handled in polling.go
	// when it receives the "rekey_required" status.
	// This function is kept for compatibility but shouldn't be
	// called directly anymore since rekey needs special handling
	// before decryption can occur.

	// If this is somehow called directly (shouldn't happen with new logic),
	// we still perform the rekey

	// Stop existing polling first
	StopPolling()

	// Perform handshake refresh
	err := refreshHandshake()
	if err != nil {
		return CommandResult{
			Error:       err,
			ErrorString: Err(E31),
			Output:      Err(E31),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      Err(S5),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
