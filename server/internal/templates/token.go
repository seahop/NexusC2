// internal/templates/token.go
package templates

// GetTokenTemplate returns a template for token commands
// This covers token, steal-token, make-token commands
func GetTokenTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Command name (450)
	tpl[IdxTokCmdName] = "token"

	// Verbs (451-464)
	tpl[IdxTokVerbCreate] = "create"
	tpl[IdxTokVerbSteal] = "steal"
	tpl[IdxTokVerbStore] = "store"
	tpl[IdxTokVerbUse] = "use"
	tpl[IdxTokVerbImpersonate] = "impersonate"
	tpl[IdxTokVerbNetonly] = "netonly"
	tpl[IdxTokVerbList] = "list"
	tpl[IdxTokVerbStored] = "stored"
	tpl[IdxTokVerbCurrent] = "current"
	tpl[IdxTokVerbStatus] = "status"
	tpl[IdxTokVerbRemove] = "remove"
	tpl[IdxTokVerbClear] = "clear"
	tpl[IdxTokVerbRevert] = "revert"
	tpl[IdxTokVerbRev2self] = "rev2self"

	// Subcommand actions (465-466)
	tpl[IdxTokActSet] = "set"
	tpl[IdxTokActProcesses] = "processes"

	// Logon types (467-475)
	tpl[IdxTokLogonNetwork] = "network"
	tpl[IdxTokLogonBatch] = "batch"
	tpl[IdxTokLogonService] = "service"
	tpl[IdxTokLogonNetCleartext] = "network_cleartext"
	tpl[IdxTokLogonNetClear] = "network_clear"
	tpl[IdxTokLogonNewCreds] = "new_credentials"
	tpl[IdxTokLogonNewCredsAlt] = "newcreds"
	tpl[IdxTokLogonInteractive] = "interactive"

	// Source identifiers (476-479)
	tpl[IdxTokSourceStolen] = "s"
	tpl[IdxTokSourceCreated] = "c"
	tpl[IdxTokStolenCmp] = "stolen"
	tpl[IdxTokCreatedCmp] = "created"

	// Token types (480-481)
	tpl[IdxTokTypeImpersonation] = "impersonation"
	tpl[IdxTokTypePrimary] = "primary"

	// Utility strings (482-496)
	tpl[IdxTokUnknownLower] = "unknown"
	tpl[IdxTokUnknown] = "Unknown"
	tpl[IdxTokBackslash] = "\\"
	tpl[IdxTokNewline] = "\n"
	tpl[IdxTokUnderscore] = "_"
	tpl[IdxTokSpace] = " "
	tpl[IdxTokColon] = ":"
	tpl[IdxTokPipe] = "|"
	tpl[IdxTokNone] = "(none)"
	tpl[IdxTokDots] = "..."
	tpl[IdxTokAtSign] = "@"
	tpl[IdxTokDot] = "."
	tpl[IdxTokComma] = ","
	tpl[IdxTokMode0] = "0"
	tpl[IdxTokMode1] = "1"

	// Output format strings (497-516)
	tpl[IdxTokTokenInfo] = "Token Info:\n"
	tpl[IdxTokProcessUser] = "Process User: "
	tpl[IdxTokImpTokenPrefix] = "\nImpersonating Token: "
	tpl[IdxTokUserPrefix] = "  User: "
	tpl[IdxTokSourcePrefix] = "  Source: "
	tpl[IdxTokProcessPrefix] = "  Process: "
	tpl[IdxTokPidPrefix] = " (PID: "
	tpl[IdxTokPidSuffix] = ")\n"
	tpl[IdxTokLogonPrefix] = "  Logon Type: "
	tpl[IdxTokNoActiveImp] = "\nNo active impersonation\n"
	tpl[IdxTokNetOnlyTokPre] = "\nNetwork-Only Token: "
	tpl[IdxTokOrigUserPre] = "\nOriginal User: "
	tpl[IdxTokNetOnlyHdr] = "NetOnly:\n"
	tpl[IdxTokActiveNetPre] = "Active NetOnly Token: "
	tpl[IdxTokUserPre2] = "User: "
	tpl[IdxTokSourcePre2] = "Source: "
	tpl[IdxTokProcessPre2] = "Process: "
	tpl[IdxTokLogonPre2] = "Logon Type: "
	tpl[IdxTokNetOnlyToksHdr] = "\nNetOnly Tokens:\n"
	tpl[IdxTokIndent2] = "  "

	return &CommandTemplate{
		Version:   2,
		Type:      TypeToken,
		Templates: tpl,
		Params:    []string{},
	}
}

// GetRev2SelfTemplate returns a template for rev2self command
func GetRev2SelfTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Command/argument strings (520-521)
	tpl[IdxR2sCmdName] = "rev2self"
	tpl[IdxR2sArgAll] = "/all"

	// Path strings (522-524)
	tpl[IdxR2sUncPrefix] = "\\\\"
	tpl[IdxR2sBackslash] = "\\"
	tpl[IdxR2sIpcSuffix] = "\\IPC$"

	// Output strings (525-541)
	tpl[IdxR2sUnknown] = "Unknown"
	tpl[IdxR2sNewline] = "\n"
	tpl[IdxR2sNoImperson] = "No active impersonation detected"
	tpl[IdxR2sCurUser] = "Current user: "
	tpl[IdxR2sImpReverted] = "\n    Impersonation reverted:\n"
	tpl[IdxR2sWas] = "    Was: "
	tpl[IdxR2sNow] = "    Now: "
	tpl[IdxR2sNetOnlyClr] = "\n    Network-only token cleared: "
	tpl[IdxR2sDisconnected] = "\n    Disconnected "
	tpl[IdxR2sNetConns] = " network connection(s)\n"
	tpl[IdxR2sSharePrefix] = "      - "
	tpl[IdxR2sAndMore] = "      ... and "
	tpl[IdxR2sMore] = " more\n"
	tpl[IdxR2sNoNetConns] = "\n    Note: No active network connections found to disconnect\n"
	tpl[IdxR2sSmbCache] = "    (SMB cache may still allow one more access)\n"
	tpl[IdxR2sTokensStored] = "\n"
	tpl[IdxR2sTokensSuffix] = " token(s) stored"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeRev2Self,
		Templates: tpl,
		Params:    []string{},
	}
}
