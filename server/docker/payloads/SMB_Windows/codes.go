// server/docker/payloads/SMB_Windows/codes.go

//go:build windows
// +build windows

package main

import "fmt"

// Status codes - short codes to minimize binary signatures
const (
	// Success codes (S0-S9)
	S0 = "S0" // Generic success / OK
	S1 = "S1" // Created / stored
	S2 = "S2" // Deleted / removed
	S3 = "S3" // Updated / modified
	S4 = "S4" // Started / initiated
	S5 = "S5" // Completed / finished
	S6 = "S6" // Found / exists
	S7 = "S7" // Listed / enumerated
	S8 = "S8" // SOCKS started
	S9 = "S9" // SOCKS stopped

	// Token operations (S10-S15)
	S10 = "S10" // Token stolen
	S11 = "S11" // Token stored
	S12 = "S12" // Token switched
	S13 = "S13" // Network-only token set
	S14 = "S14" // Token cleared
	S15 = "S15" // Rekey initiated

	// Job/output status (S16-S19)
	S16 = "S16" // Job killed
	S17 = "S17" // Jobs cleaned
	S18 = "S18" // No output yet
	S19 = "S19" // Output truncated

	// Token context status (S20-S24)
	S20 = "S20" // Using network-only token
	S21 = "S21" // Using impersonation token
	S22 = "S22" // No token context (current user)
	S23 = "S23" // AMSI bypass applied
	S24 = "S24" // Impersonation warning for network shares

	// Assembly execution info (S25-S29)
	S25 = "S25" // Assembly execution started
	S26 = "S26" // Exit protection enabled
	S27 = "S27" // CLR state warning
	S28 = "S28" // Exit prevention active
	S29 = "S29" // Keychain unlocked

	// General errors (E0-E19)
	E1  = "E1"  // No arguments provided
	E2  = "E2"  // Invalid arguments
	E3  = "E3"  // Access denied / permission error
	E4  = "E4"  // Not found (file/directory/resource)
	E5  = "E5"  // Already exists
	E6  = "E6"  // Is a directory (expected file)
	E7  = "E7"  // Is a file (expected directory)
	E8  = "E8"  // Binary file detected
	E9  = "E9"  // Operation timed out
	E10 = "E10" // Read error
	E11 = "E11" // Write error
	E12 = "E12" // Network error
	E13 = "E13" // Resource busy
	E14 = "E14" // Read-only filesystem
	E15 = "E15" // Operation not permitted
	E16 = "E16" // Directory not empty
	E17 = "E17" // Invalid path
	E18 = "E18" // Decode/parse error
	E19 = "E19" // Internal error

	// Command-specific errors (E20-E39)
	E20 = "E20" // Flag requires argument
	E21 = "E21" // Unknown flag
	E22 = "E22" // Invalid value for flag
	E23 = "E23" // Missing required flag
	E24 = "E24" // Chunk transfer error
	E25 = "E25" // Execution failed
	E26 = "E26" // Job not found
	E27 = "E27" // Job already running
	E28 = "E28" // Invalid sleep value
	E29 = "E29" // Invalid jitter value
	E30 = "E30" // Session not active
	E31 = "E31" // Authentication failed
	E32 = "E32" // SOCKS no config data
	E33 = "E33" // SOCKS parse error
	E34 = "E34" // SOCKS websocket error
	E35 = "E35" // SOCKS handshake error
	E36 = "E36" // SOCKS unknown action
	E37 = "E37" // Network token exec failed
	E38 = "E38" // Failed to open process
	E39 = "E39" // Failed to open process token

	// Windows-specific errors (E40-E59)
	E40 = "E40" // Logon failed - bad credentials
	E41 = "E41" // Account disabled/locked
	E42 = "E42" // Token operation failed
	E43 = "E43" // Process operation failed
	E44 = "E44" // Memory allocation failed
	E45 = "E45" // API call failed
	E46 = "E46" // No tokens available
	E47 = "E47" // Token not found
	E48 = "E48" // Cannot remove active token
	E49 = "E49" // Invalid token handle
	E50 = "E50" // Privilege not held
	E51 = "E51" // BOF execution failed
	E52 = "E52" // Assembly execution failed
)

// Table type markers - client adds full headers
// Using generic identifiers to avoid signature detection
const (
	TJobs    = "T:A:"  // Assembly jobs table
	TBof     = "T:B:"  // BOF jobs table
	TTokens  = "T:C:"  // Process tokens table
	TStored  = "T:D:"  // Stored tokens table
	TLS      = "T:E:"  // Directory listing
	TPS      = "T:F:"  // Process listing (basic)
	TPSExt   = "T:G:"  // Process listing (extended with -x)
	TPSVerb  = "T:H:"  // Process listing (verbose with -v)
	TPSFull  = "T:I:"  // Process listing (extended + verbose)
	TPSTok   = "T:J:"  // Process token listing (steal-token --list)
	TSTok    = "T:K:"  // Stored tokens listing
	TStats   = "T:L:"  // Stats output
	TLSCount = "T:M:"  // Directory count output
)

// Row type markers - for inline data type indication
const (
	RFile = "0" // File entry
	RDir  = "1" // Directory entry
)

// Status markers - client expands these
const (
	VCurrent   = "0" // [CURRENT]
	VAccess    = "1" // [ACCESSIBLE]
	VDenied    = "2" // [ACCESS DENIED]
	VProcDeny  = "3" // [PROCESS ACCESS DENIED]
	VActive    = "4" // [ACTIVE]
	VNetOnly   = "5" // [NETONLY]
	VNA        = "6" // N/A
	VRunning   = "7" // Running
	VSleeping  = "8" // Sleeping
	VDiskSleep = "9" // Disk sleep
	VStopped   = "a" // Stopped
	VZombie    = "b" // Zombie
	VIdle      = "c" // Idle
	VPaging    = "d" // Paging
	VDead      = "e" // Dead
)

// Whoami output markers - client expands these
const (
	WVerbose = "v" // Verbose info marker: v|uid|gid|home|shell
	WGroups  = "g" // Groups marker: g|group1,group2,group3
	WImpersn = "i" // Impersonated marker (Windows)
	WUnknown = "?" // Unknown value fallback
)

// Environment variable name builders - prevents raw strings in binary
func EnvUser() string         { return string([]byte{0x55, 0x53, 0x45, 0x52}) }                                     // USER
func EnvUsername() string     { return string([]byte{0x55, 0x53, 0x45, 0x52, 0x4e, 0x41, 0x4d, 0x45}) }             // USERNAME
func EnvLogname() string      { return string([]byte{0x4c, 0x4f, 0x47, 0x4e, 0x41, 0x4d, 0x45}) }                   // LOGNAME
func EnvHostname() string     { return string([]byte{0x48, 0x4f, 0x53, 0x54, 0x4e, 0x41, 0x4d, 0x45}) }             // HOSTNAME
func EnvComputername() string { return string([]byte{0x43, 0x4f, 0x4d, 0x50, 0x55, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4d, 0x45}) } // COMPUTERNAME
func EnvShell() string        { return string([]byte{0x53, 0x48, 0x45, 0x4c, 0x4c}) }                               // SHELL

// Table returns table marker with count
func Table(tableType string, count int) string {
	return tableType + fmt.Sprintf("%d", count)
}

// Err returns error code
func Err(code string) string {
	return code
}

// ErrCtx returns error code with context (paths, values only - no text)
func ErrCtx(code, ctx string) string {
	if ctx == "" {
		return code
	}
	return code + ":" + ctx
}

// Succ returns success code
func Succ(code string) string {
	return code
}

// SuccCtx returns success code with context
func SuccCtx(code, ctx string) string {
	if ctx == "" {
		return code
	}
	return code + ":" + ctx
}
