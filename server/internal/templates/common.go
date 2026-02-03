// internal/templates/common.go
package templates

import (
	"encoding/json"
)

// CommandTemplate represents server-side template data sent to agents
// Uses arrays instead of maps to avoid string keys in agent binaries
// This is the general template for non-persistence commands
type CommandTemplate struct {
	Version   int      `json:"v"`   // Template version for future compatibility
	Type      int      `json:"t"`   // Command type identifier
	Templates []string `json:"tpl"` // Template strings indexed by position
	Params    []string `json:"p"`   // Parameters indexed by position
}

// Command type identifiers (start at 10 to not conflict with persistence types 1-4)
const (
	TypeShell          = 10
	TypeLink           = 11
	TypeSocks          = 12
	TypePs             = 13
	TypeLs             = 14
	TypeRm             = 15
	TypeHash           = 16
	TypeCmdProc        = 17
	TypeExecReq        = 18
	TypeSudoSess       = 19
	TypeBof            = 20
	TypeInlineAssembly = 21
	TypeDownload       = 22
	TypeWhoami         = 23
	TypeToken          = 24
	TypeRev2Self       = 25
	TypeKeychain       = 26
	TypeSocksHTTP      = 27
)

// MaxTemplateSize ensures all indices have values across all command types
const MaxTemplateSize = 1120

// ============================================================================
// SHELL TEMPLATE INDICES (100-119)
// ============================================================================
const (
	// Shell paths
	IdxShellPathBinBash    = 100 // /bin/bash
	IdxShellPathBinZsh     = 101 // /bin/zsh
	IdxShellPathBinSh      = 102 // /bin/sh
	IdxShellPathUsrBinBash = 103 // /usr/bin/bash
	IdxShellPathUsrBinZsh  = 104 // /usr/bin/zsh
	IdxShellPathUsrBinSh   = 105 // /usr/bin/sh
	IdxShellFallback       = 106 // sh

	// Environment
	IdxShellEnvVar = 107 // SHELL

	// Shell arguments
	IdxShellArgC = 108 // -c

	// Flags (short form only - server transforms long flags)
	IdxShellFlagSudo    = 109 // -s
	IdxShellFlagTimeout = 110 // -t

	// Output markers
	IdxShellStderrMarker = 111 // [STDERR]\n

	_shellEnd = 119
)

// ============================================================================
// LINK TEMPLATE INDICES (120-139)
// ============================================================================
const (
	// Protocol identifiers
	IdxLinkProtoSmb = 120 // smb
	IdxLinkProtoTcp = 121 // tcp

	// UNC path components
	IdxLinkUncSlashes = 122 // \\
	IdxLinkPipePath   = 123 // \pipe\

	// Network defaults
	IdxLinkLocalhost  = 124 // localhost
	IdxLinkLoopback   = 125 // 127.0.0.1
	IdxLinkDefaultPort = 126 // 4444

	// Output markers
	IdxLinkStatusPrefix = 127 // S6|
	IdxLinkPingMarker   = 128 // P
	IdxLinkQuitMarker   = 129 // Q

	// Actions
	IdxLinkActionStart = 130 // start
	IdxLinkActionStop  = 131 // stop

	// Misc
	IdxLinkDot = 132 // . (local machine for SMB)

	// Link manager protocol strings (JSON keys/values for inter-agent communication)
	IdxLinkKeyType      = 133 // type
	IdxLinkKeyPayload   = 134 // payload
	IdxLinkMsgData      = 135 // data
	IdxLinkMsgDisconn   = 136 // disconnect
	IdxLinkMsgHandshake = 137 // handshake
	IdxLinkMsgPing      = 138 // ping
	IdxLinkMsgPong      = 139 // pong

	// Extended link manager strings (140-149 - borrowed from SOCKS start)
	IdxLinkStatusActive = 340 // active
	IdxLinkStatusInact  = 341 // inactive
	IdxLinkAuthPrefix   = 342 // AUTH:
	IdxLinkAuthOK       = 343 // OK
	IdxLinkFmtList      = 344 // Active Links (%d):\n
	IdxLinkFmtRow       = 345 // [%s] %s - %s (connected: %s, last seen: %s)\n
	IdxLinkTimeFmt      = 346 // 15:04:05
	IdxLinkColon        = 347 // :
	IdxLinkPipe         = 348 // |
	IdxLinkBackslash    = 349 // \

	_linkEnd = 139 // Core link indices end at 139
)

// ============================================================================
// SOCKS TEMPLATE INDICES (140-159)
// ============================================================================
const (
	// Protocol format strings
	IdxSocksWssFmt = 140 // wss://%s:%d%s

	// SSH constants
	IdxSocksKeepalive   = 141 // keepalive@golang.org
	IdxSocksDirectTcpip = 142 // direct-tcpip

	// Actions
	IdxSocksActionStart = 143 // start
	IdxSocksActionStop  = 144 // stop

	// Errors
	IdxSocksErrUnknownChannel = 145 // unknown channel type
	IdxSocksErrLimitReached   = 146 // connection limit reached

	_socksEnd = 159
)

// ============================================================================
// PS TEMPLATE INDICES (160-199)
// ============================================================================
const (
	// Proc paths
	IdxPsProcCmdline = 160 // /proc/%d/cmdline
	IdxPsProcExe     = 161 // /proc/%d/exe
	IdxPsProcStat    = 162 // /proc/%d/stat
	IdxPsProcStatus  = 163 // /proc/%d/status
	IdxPsProcDir     = 164 // /proc

	// OS identifiers
	IdxPsOsLinux   = 165 // linux
	IdxPsOsWindows = 166 // windows
	IdxPsOsDarwin  = 167 // darwin

	// Flags (short form - server transforms)
	IdxPsFlagVerbose   = 168 // -v
	IdxPsFlagExtended  = 169 // -x
	IdxPsFlagJson      = 170 // -j
	IdxPsFlagNoTrunc   = 171 // -n
	IdxPsFlagFilter    = 172 // -f
	IdxPsFlagUser      = 173 // -u
	IdxPsFlagSort      = 174 // -s

	// Sort values
	IdxPsSortCpu    = 175 // cpu
	IdxPsSortMem    = 176 // mem
	IdxPsSortMemory = 177 // memory
	IdxPsSortName   = 178 // name
	IdxPsSortUser   = 179 // user
	IdxPsSortPid    = 180 // pid

	// Status values
	IdxPsStatusName   = 181 // Name:
	IdxPsStatusUid    = 182 // Uid:
	IdxPsStatusState  = 183 // State:
	IdxPsStatusPpid   = 184 // PPid:
	IdxPsStatusVmRss  = 185 // VmRSS:

	// Windows-specific PS strings
	IdxPsRunningAs    = 186 // Running as:
	IdxPsBackslash    = 187 // \
	IdxPsImpersonated = 188 //  (impersonated)

	_psEnd = 199
)

// ============================================================================
// LS TEMPLATE INDICES (200-239)
// ============================================================================
const (
	// Windows system paths to filter
	IdxLsWinSysVolInfo   = 200 // System Volume Information
	IdxLsWinRecycleBin   = 201 // $Recycle.Bin
	IdxLsWinConfigMsi    = 202 // Config.Msi
	IdxLsWinPagefile     = 203 // pagefile.sys
	IdxLsWinHiberfil     = 204 // hiberfil.sys
	IdxLsWinSwapfile     = 205 // swapfile.sys
	IdxLsWinDsStore      = 206 // .DS_Store
	IdxLsWinSpotlight    = 207 // .Spotlight-V100
	IdxLsWinFseventsd    = 208 // .fseventsd
	IdxLsWinTrashes      = 209 // .Trashes

	// OS identifiers
	IdxLsOsWindows = 210 // windows
	IdxLsOsLinux   = 211 // linux
	IdxLsOsDarwin  = 212 // darwin

	// Flags (short form - server transforms)
	IdxLsFlagMaxDepth = 213 // -d
	IdxLsFlagCount    = 214 // -c
	IdxLsFlagExclude  = 215 // -e
	IdxLsFlagIgnore   = 216 // -i
	IdxLsFlagFilter   = 217 // -f
	IdxLsFlagAll      = 218 // -a
	IdxLsFlagLong     = 219 // -l

	// File type markers
	IdxLsTypeDir     = 220 // d
	IdxLsTypeFile    = 221 // -
	IdxLsTypeSymlink = 222 // l

	// Additional Windows system paths
	IdxLsWinRecovery    = 223 // Recovery
	IdxLsWinProgramData = 224 // ProgramData

	// Size units and paths
	IdxLsSizeUnits = 225 // KMGTPE
	IdxLsWinRoot   = 226 // C:\

	_lsEnd = 239
)

// ============================================================================
// RM TEMPLATE INDICES (240-259)
// ============================================================================
const (
	// Flags (short form - server transforms)
	IdxRmFlagRecursive = 240 // -r
	IdxRmFlagForce     = 241 // -f

	// Error patterns
	IdxRmErrPermDenied     = 242 // permission denied
	IdxRmErrDirNotEmpty    = 243 // directory not empty
	IdxRmErrResourceBusy   = 244 // resource busy
	IdxRmErrNotExist       = 245 // does not exist
	IdxRmErrIsDirectory    = 246 // is a directory

	_rmEnd = 259
)

// ============================================================================
// HASH TEMPLATE INDICES (260-279)
// ============================================================================
const (
	// Algorithms (short form - server transforms)
	IdxHashAlgoSha256 = 260 // s (sha256)
	IdxHashAlgoMd5    = 261 // m (md5)
	IdxHashAlgoAll    = 262 // a (all/both)

	// Output prefixes
	IdxHashPrefixMd5    = 263 // MD5:
	IdxHashPrefixSha256 = 264 // SHA256:

	// Full algorithm names (for output)
	IdxHashNameSha256 = 265 // sha256
	IdxHashNameMd5    = 266 // md5

	_hashEnd = 279
)

// ============================================================================
// COMMAND PROCESSOR TEMPLATE INDICES (280-299)
// ============================================================================
const (
	// Command names
	IdxCmdProcInlineAssemblyJobs      = 280 // inline-assembly-jobs
	IdxCmdProcInlineAssemblyJobsClean = 281 // inline-assembly-jobs-clean
	IdxCmdProcInlineAssemblyJobsStats = 282 // inline-assembly-jobs-stats
	IdxCmdProcInlineAssemblyOutput    = 283 // inline-assembly-output
	IdxCmdProcInlineAssemblyOutputSp  = 284 // inline-assembly-output (with space)
	IdxCmdProcInlineAssemblyKill      = 285 // inline-assembly-kill
	IdxCmdProcInlineAssemblyKillSp    = 286 // inline-assembly-kill (with space)
	IdxCmdProcInlineAssembly          = 287 // inline-assembly
	IdxCmdProcInlineAssemblyAsync     = 288 // inline-assembly-async
	IdxCmdProcBof                     = 289 // bof
	IdxCmdProcUpload                  = 290 // upload
	IdxCmdProcDownload                = 291 // download
	IdxCmdProcAsync                   = 292 // async

	// Error message suffixes
	IdxCmdProcErrNotRegistered = 293 //  command not registered
	IdxCmdProcErrHandlerNotReg = 294 //  handler not registered

	_cmdProcEnd = 299
)

// ============================================================================
// EXEC REQUIREMENTS TEMPLATE INDICES (300-319)
// ============================================================================
const (
	// File paths
	IdxExecReqPathEtcHostname = 300 // /etc/hostname
	IdxExecReqPathSssdConf    = 301 // /etc/sssd/sssd.conf
	IdxExecReqPathSmbConf     = 302 // /etc/samba/smb.conf
	IdxExecReqPathKrb5Conf    = 303 // /etc/krb5.conf
	IdxExecReqPathIpaConf     = 304 // /etc/ipa/default.conf
	IdxExecReqPathProc        = 305 // /proc
	IdxExecReqPathTildeFwd    = 306 // ~/

	// Environment variable names
	IdxExecReqEnvUser    = 307 // USER
	IdxExecReqEnvLogname = 308 // LOGNAME

	// Config file patterns
	IdxExecReqPatternDomainsEq  = 309 // domains =
	IdxExecReqPatternDomainsEq2 = 310 // domains=
	IdxExecReqPatternWorkgroup  = 311 // workgroup
	IdxExecReqPatternRealm      = 312 // realm
	IdxExecReqPatternDefRealm   = 313 // default_realm
	IdxExecReqPatternDomainEq   = 314 // domain =
	IdxExecReqPatternDomainEq2  = 315 // domain=

	// Proc file names
	IdxExecReqProcCmdline = 316 // cmdline
	IdxExecReqProcComm    = 317 // comm

	// String literals
	IdxExecReqWordTrue    = 318 // true
	IdxExecReqTimeFmtFull = 319 // 2006-01-02 15:04:05

	// Additional environment variables (for codes.go)
	IdxExecReqEnvHostname = 320 // HOSTNAME
	IdxExecReqEnvShell    = 321 // SHELL

	// System info strings (for getSystemInfo.go)
	IdxExecReqSysInfoStartupTime  = 322 // startup_time
	IdxExecReqSysInfoStatusActive = 323 // active

	_execReqEnd = 339
)

// ============================================================================
// SUDO SESSION TEMPLATE INDICES (320-339)
// ============================================================================
const (
	// Command name
	IdxSudoSessCmdName = 320 // sudo-session

	// Subcommands
	IdxSudoSessStart           = 321 // start
	IdxSudoSessStop            = 322 // stop
	IdxSudoSessExec            = 323 // exec
	IdxSudoSessExecStateful    = 324 // exec-stateful
	IdxSudoSessEnableStateful  = 325 // enable-stateful
	IdxSudoSessDisableStateful = 326 // disable-stateful
	IdxSudoSessStatus          = 327 // status

	// Default user
	IdxSudoSessDefaultUser = 328 // root

	_sudoSessEnd = 339
)

// ============================================================================
// BOF TEMPLATE INDICES (350-399)
// ============================================================================
const (
	// Command names (350-359)
	IdxBofCmdName        = 350 // bof
	IdxBofCmdAsync       = 351 // bof-async
	IdxBofCmdJobs        = 352 // bof-jobs
	IdxBofCmdOutput      = 353 // bof-output
	IdxBofCmdKill        = 354 // bof-kill
	IdxBofCmdAsyncPrefix = 355 // bof-async (with space)
	IdxBofCmdAsyncStatus = 356 // bof-async-status
	IdxBofCmdAsyncOutput = 357 // bof-async-output
	IdxBofOSWindows      = 358 // windows

	// Job status values (360-364)
	IdxBofStatusRunning   = 360 // running
	IdxBofStatusCompleted = 361 // completed
	IdxBofStatusCrashed   = 362 // crashed
	IdxBofStatusKilled    = 363 // killed
	IdxBofStatusTimeout   = 364 // timeout

	// Output markers (365-369)
	IdxBofAsyncStarted   = 365 // BOF_ASYNC_STARTED
	IdxBofAsyncPrefix    = 366 // BOF_ASYNC_
	IdxBofChunkPrefix    = 367 // |CHUNK_
	IdxBofChunkSeparator = 368 // \n---CHUNK_SEPARATOR---\n
	IdxBofPipeSep        = 369 // |

	// Final status markers (370-374)
	IdxBofFinalCompleted = 370 // COMPLETED
	IdxBofFinalCrashed   = 371 // CRASHED
	IdxBofFinalKilled    = 372 // KILLED
	IdxBofFinalTimeout   = 373 // TIMEOUT
	IdxBofFinalOutput    = 374 // OUTPUT

	// Misc strings (375-377)
	IdxBofTruncYes      = 375 // YES
	IdxBofTruncDots     = 376 // ...
	IdxBofTruncatedMsg  = 377 // (OUTPUT TRUNCATED - exceeded 10MB limit)

	// Output message fragments (378-387)
	IdxBofJobPrefix       = 378 // Job
	IdxBofStillRunning    = 379 // is still running\n
	IdxBofChunksSent      = 380 // Chunks sent:
	IdxBofSpaceParen      = 381 // (
	IdxBofNoBufferedOut   = 382 // ) has no buffered output\n
	IdxBofOutputForJob    = 383 // Output for job
	IdxBofChunksSentParen = 384 // (chunks sent:
	IdxBofCloseColonNL    = 385 // ):\n
	IdxBofCloseParen      = 386 // )

	// IPC path (388)
	IdxBofIPCPath = 388 // \IPC$

	_bofEnd = 399
)

// ============================================================================
// INLINE ASSEMBLY TEMPLATE INDICES (400-449)
// ============================================================================
const (
	// CLR strings (400-404)
	IdxIAClrV4      = 400 // v4
	IdxIAClrV2      = 401 // v2
	IdxIAClrV2Full  = 402 // v2.0.50727
	IdxIATempPrefix = 403 // clr_output_
	IdxIATempSuffix = 404 // .txt

	// Output markers (405-406)
	IdxIAOutputStart = 405 // \n>>>\n
	IdxIAOutputEnd   = 406 // \n<<<\n

	// Runfor detection (407-408)
	IdxIARunforFlag = 407 // /runfor
	IdxIAColon      = 408 // :

	// Status messages (409-416)
	IdxIADoneMsg      = 409 // \nDone\n
	IdxIADoneExitPrev = 410 // \nDone (exit prevented)\n
	IdxIADoneAfterPre = 411 // \nDone after
	IdxIADoneAfterSuf = 412 // ds\n
	IdxIADonePre      = 413 // \nDone (
	IdxIADoneSuf      = 414 // )\n
	IdxIAExitPrevMsg  = 415 // \nExit prevented\n

	// Error detection keywords (417-418)
	IdxIAKwExit      = 417 // exit
	IdxIAKwTerminate = 418 // terminate

	// CLR corruption (419-420)
	IdxIAClrErrCode = 419 // 0x80131604
	IdxIAClrCorrupt = 420 // \nCLR corrupted (0x80131604)\n

	// Command names (421-425)
	IdxIACmdJobs   = 421 // inline-assembly-jobs
	IdxIACmdOutput = 422 // inline-assembly-output
	IdxIACmdKill   = 423 // inline-assembly-kill
	IdxIACmdClean  = 424 // inline-assembly-jobs-clean
	IdxIACmdStats  = 425 // inline-assembly-jobs-stats

	// Status strings (426-430)
	IdxIAStatusRunning   = 426 // running
	IdxIAStatusCompleted = 427 // completed
	IdxIAStatusFailed    = 428 // failed
	IdxIAStatusKilled    = 429 // killed
	IdxIAStatusTimeout   = 430 // timeout

	// Format components (431-441)
	IdxIAFmtRunningPrefix = 431 // r:
	IdxIAFmtDonePrefix    = 432 // d:
	IdxIAFmtDash          = 433 // -
	IdxIAFmtPipe          = 434 // |
	IdxIAFmtNewline       = 435 // \n
	IdxIAFmtEllipsis      = 436 // ...
	IdxIAFmtColSep        = 437 // " | "
	IdxIAFmtZero          = 438 // 0
	IdxIAFmtOne           = 439 // 1
	IdxIAFmtColonSingle   = 440 // :

	// Stats labels (442-448)
	IdxIAStatsHeader   = 442 // Stats:\n
	IdxIAStatsTotalLbl = 443 // Total Jobs:
	IdxIAStatsRunLbl   = 444 // Running:
	IdxIAStatsCompLbl  = 445 // Completed:
	IdxIAStatsFailLbl  = 446 // Failed:
	IdxIAStatsKillLbl  = 447 // Killed:
	IdxIAStatsTimeLbl  = 448 // Timeout:

	_inlineAssemblyEnd = 449
)

// ============================================================================
// TOKEN TEMPLATE INDICES (450-519)
// ============================================================================
const (
	// Command name (450)
	IdxTokCmdName = 450 // token

	// Verbs (451-464)
	IdxTokVerbCreate      = 451 // create
	IdxTokVerbSteal       = 452 // steal
	IdxTokVerbStore       = 453 // store
	IdxTokVerbUse         = 454 // use
	IdxTokVerbImpersonate = 455 // impersonate
	IdxTokVerbNetonly     = 456 // netonly
	IdxTokVerbList        = 457 // list
	IdxTokVerbStored      = 458 // stored
	IdxTokVerbCurrent     = 459 // current
	IdxTokVerbStatus      = 460 // status
	IdxTokVerbRemove      = 461 // remove
	IdxTokVerbClear       = 462 // clear
	IdxTokVerbRevert      = 463 // revert
	IdxTokVerbRev2self    = 464 // rev2self

	// Subcommand actions (465-466)
	IdxTokActSet       = 465 // set
	IdxTokActProcesses = 466 // processes

	// Logon types (467-475)
	IdxTokLogonNetwork      = 467 // network
	IdxTokLogonBatch        = 468 // batch
	IdxTokLogonService      = 469 // service
	IdxTokLogonNetCleartext = 470 // network_cleartext
	IdxTokLogonNetClear     = 471 // network_clear
	IdxTokLogonNewCreds     = 472 // new_credentials
	IdxTokLogonNewCredsAlt  = 473 // newcreds
	IdxTokLogonInteractive  = 474 // interactive

	// Source identifiers (476-479)
	IdxTokSourceStolen  = 476 // s
	IdxTokSourceCreated = 477 // c
	IdxTokStolenCmp     = 478 // stolen
	IdxTokCreatedCmp    = 479 // created

	// Token types (480-481)
	IdxTokTypeImpersonation = 480 // impersonation
	IdxTokTypePrimary       = 481 // primary

	// Utility strings (482-495)
	IdxTokUnknownLower = 482 // unknown
	IdxTokUnknown      = 483 // Unknown
	IdxTokBackslash    = 484 // \
	IdxTokNewline      = 485 // \n
	IdxTokUnderscore   = 486 // _
	IdxTokSpace        = 487 // (space)
	IdxTokColon        = 488 // :
	IdxTokPipe         = 489 // |
	IdxTokNone         = 490 // (none)
	IdxTokDots         = 491 // ...
	IdxTokAtSign       = 492 // @
	IdxTokDot          = 493 // .
	IdxTokComma        = 494 // ,
	IdxTokMode0        = 495 // 0
	IdxTokMode1        = 496 // 1

	// Output format strings (497-519)
	IdxTokTokenInfo      = 497  // Token Info:\n
	IdxTokProcessUser    = 498  // Process User:
	IdxTokImpTokenPrefix = 499  // \nImpersonating Token:
	IdxTokUserPrefix     = 500  // "  User: "
	IdxTokSourcePrefix   = 501  // "  Source: "
	IdxTokProcessPrefix  = 502  // "  Process: "
	IdxTokPidPrefix      = 503  // " (PID: "
	IdxTokPidSuffix      = 504  // ")\n"
	IdxTokLogonPrefix    = 505  // "  Logon Type: "
	IdxTokNoActiveImp    = 506  // "\nNo active impersonation\n"
	IdxTokNetOnlyTokPre  = 507  // "\nNetwork-Only Token: "
	IdxTokOrigUserPre    = 508  // "\nOriginal User: "
	IdxTokNetOnlyHdr     = 509  // "NetOnly:\n"
	IdxTokActiveNetPre   = 510  // "Active NetOnly Token: "
	IdxTokUserPre2       = 511  // "User: "
	IdxTokSourcePre2     = 512  // "Source: "
	IdxTokProcessPre2    = 513  // "Process: "
	IdxTokLogonPre2      = 514  // "Logon Type: "
	IdxTokNetOnlyToksHdr = 515  // "\nNetOnly Tokens:\n"
	IdxTokIndent2        = 516  // "  "

	_tokenEnd = 519
)

// ============================================================================
// REV2SELF TEMPLATE INDICES (520-569)
// ============================================================================
const (
	// Command/argument strings (520-521)
	IdxR2sCmdName = 520 // rev2self
	IdxR2sArgAll  = 521 // /all

	// Path strings (522-524)
	IdxR2sUncPrefix  = 522 // \\
	IdxR2sBackslash  = 523 // \
	IdxR2sIpcSuffix  = 524 // \IPC$

	// Output strings (525-549)
	IdxR2sUnknown      = 525 // Unknown
	IdxR2sNewline      = 526 // \n
	IdxR2sNoImperson   = 527 // No active impersonation detected
	IdxR2sCurUser      = 528 // "Current user: "
	IdxR2sImpReverted  = 529 // "\n    Impersonation reverted:\n"
	IdxR2sWas          = 530 // "    Was: "
	IdxR2sNow          = 531 // "    Now: "
	IdxR2sNetOnlyClr   = 532 // "\n    Network-only token cleared: "
	IdxR2sDisconnected = 533 // "\n    Disconnected "
	IdxR2sNetConns     = 534 // " network connection(s)\n"
	IdxR2sSharePrefix  = 535 // "      - "
	IdxR2sAndMore      = 536 // "      ... and "
	IdxR2sMore         = 537 // " more\n"
	IdxR2sNoNetConns   = 538 // "\n    Note: No active network connections found to disconnect\n"
	IdxR2sSmbCache     = 539 // "    (SMB cache may still allow one more access)\n"
	IdxR2sTokensStored = 540 // \n
	IdxR2sTokensSuffix = 541 // " token(s) stored"

	// DLL/API names (542-547)
	IdxR2sMprDll          = 542 // mpr.dll
	IdxR2sWNetCancelConn2 = 543 // WNetCancelConnection2W
	IdxR2sWNetOpenEnum    = 544 // WNetOpenEnumW
	IdxR2sWNetEnumRes     = 545 // WNetEnumResourceW
	IdxR2sWNetCloseEnum   = 546 // WNetCloseEnum
	IdxR2sWNetGetConn     = 547 // WNetGetConnectionW

	_rev2selfEnd = 569
)

// ============================================================================
// DOWNLOAD TEMPLATE INDICES (570-589)
// ============================================================================
const (
	// Command strings
	IdxDlCmdName   = 570 // download
	IdxDlOSWindows = 571 // windows
	IdxDlCmdPrefix = 572 // download (with trailing space)

	// Output format strings
	IdxDlChunkFmt = 573 // \nS4:
	IdxDlPipeSep  = 574 // |
	IdxDlSlash    = 575 // /

	// Windows-specific
	IdxDlAsPrefix  = 576 // Downloading as
	IdxDlBackslash = 577 // \
	IdxDlNewline   = 578 // \n

	_downloadEnd = 589
)

// ============================================================================
// WHOAMI TEMPLATE INDICES (590-609)
// ============================================================================
const (
	// Command strings
	IdxWaCmdName  = 590 // whoami
	IdxWaWindows  = 591 // windows

	// Flags
	IdxWaFlagV = 592 // -v
	IdxWaFlagG = 593 // -g

	// Misc
	IdxWaBackslash = 594 // \

	_whoamiEnd = 609
)

// ============================================================================
// KEYCHAIN TEMPLATE INDICES (610-679) - Darwin only
// ============================================================================
const (
	// Actions (610-616)
	IdxKcList   = 610 // list
	IdxKcDump   = 611 // dump
	IdxKcSearch = 612 // search
	IdxKcAdd    = 613 // add
	IdxKcDelete = 614 // delete
	IdxKcExport = 615 // export
	IdxKcUnlock = 616 // unlock

	// Flags (617-622)
	IdxKcFlagKeychain = 617 // --keychain
	IdxKcFlagService  = 618 // --service
	IdxKcFlagAccount  = 619 // --account
	IdxKcFlagLabel    = 620 // --label
	IdxKcFlagPassword = 621 // --password
	IdxKcFlagOutput   = 622 // --output

	// Parsing strings (623-630)
	IdxKcPKeychain = 623 // keychain:
	IdxKcPData     = 624 // data:
	IdxKcPPassword = 625 // password:
	IdxKcPAcct     = 626 // "acct"
	IdxKcPSvce     = 627 // "svce"
	IdxKcPDesc     = 628 // "desc"
	IdxKcPLabl     = 629 // labl
	IdxKcPSubj     = 630 // subj

	// Security tool and subcommands (631-642)
	IdxKcSecurity        = 631 // security
	IdxKcListKeychains   = 632 // list-keychains
	IdxKcDefaultKeychain = 633 // default-keychain
	IdxKcDumpKeychain    = 634 // dump-keychain
	IdxKcFindInternetPwd = 635 // find-internet-password
	IdxKcFindCertificate = 636 // find-certificate
	IdxKcFindGenericPwd  = 637 // find-generic-password
	IdxKcAddGenericPwd   = 638 // add-generic-password
	IdxKcDeleteGenericPwd = 639 // delete-generic-password
	IdxKcSecExport       = 640 // export
	IdxKcUnlockKeychain  = 641 // unlock-keychain

	// Path strings (642-644)
	IdxKcLibrary   = 642 // Library
	IdxKcKeychains = 643 // Keychains
	IdxKcKcStr     = 644 // keychain

	// Export format strings (645-646)
	IdxKcIdentities = 645 // identities
	IdxKcPkcs12     = 646 // pkcs12

	// Map key strings (647-652)
	IdxKcMKeychain    = 647 // keychain
	IdxKcMAccount     = 648 // account
	IdxKcMService     = 649 // service
	IdxKcMDescription = 650 // description
	IdxKcMData        = 651 // data
	IdxKcMPassword    = 652 // password

	_keychainEnd = 679
)

// ============================================================================
// SMB PIPE TEMPLATE INDICES (680-689) - for link_pipe_*.go
// ============================================================================
const (
	IdxLinkSmbPort   = 680 // :445
	IdxLinkIpcShare  = 681 // IPC$
	IdxLinkPipeWord  = 682 // pipe
	IdxLinkLocalWord = 683 // local
	IdxLinkSmbPipe   = 684 // smb-pipe

	_smbPipeEnd = 689
)

// ============================================================================
// PTY HELPER TEMPLATE INDICES (690-709) - for pty_helper.go
// ============================================================================
const (
	IdxPtySudo      = 690 // sudo
	IdxPtySu        = 691 // su
	IdxPtySh        = 692 // sh
	IdxPtyFlagS     = 693 // -S
	IdxPtyFlagP     = 694 // -p
	IdxPtyFlagC     = 695 // -c
	IdxPtyFlagDash  = 696 // -
	IdxPtyPassword  = 697 // Password:
	IdxPtyPasswordL = 698 // password
	IdxPtySorry     = 699 // Sorry
	IdxPtyTryAgain  = 700 // try again
	IdxPtyIncorrect = 701 // incorrect
	IdxPtyExit      = 702 // exit
	IdxPtyRoot      = 703 // root

	_ptyHelperEnd = 709
)

// ============================================================================
// COMMUNICATIONS TEMPLATE INDICES (710-759) - for polling.go and http.go
// ============================================================================
const (
	// HTTP headers (710-716)
	IdxCommsUserAgent   = 710 // User-Agent
	IdxCommsContentType = 711 // Content-Type
	IdxCommsPadPre      = 712 // X-Pad-Pre
	IdxCommsPadApp      = 713 // X-Pad-App
	IdxCommsMetaId      = 714 // id
	IdxCommsEncryption  = 715 // encryption
	IdxCommsEncRsaAes   = 716 // rsa+aes

	// Polling protocol (720-728)
	IdxPollAppJson       = 720 // application/json
	IdxPollStatus        = 721 // status
	IdxPollRekey         = 722 // rekey
	IdxPollNoCommands    = 723 // no_commands
	IdxPollAgentId       = 724 // agent_id
	IdxPollResults       = 725 // results
	IdxPollType          = 726 // type
	IdxPollPayload       = 727 // payload
	IdxPollHandshakeResp = 728 // handshake_response

	_commsEnd = 759
)

// ============================================================================
// TRANSFORM TEMPLATE INDICES (760-779) - for transforms.go
// ============================================================================
const (
	// Transform type codes (single char to minimize binary size)
	IdxTransBase64    = 760 // a
	IdxTransBase64URL = 761 // b
	IdxTransHex       = 762 // c
	IdxTransGzip      = 763 // d
	IdxTransNetBIOS   = 764 // e
	IdxTransXOR       = 765 // f
	IdxTransPrepend   = 766 // g
	IdxTransAppend    = 767 // h
	IdxTransRandPre   = 768 // i
	IdxTransRandApp   = 769 // j

	// Charset codes
	IdxCharsetNum   = 770 // 1
	IdxCharsetAlpha = 771 // 2
	IdxCharsetAlnum = 772 // 3
	IdxCharsetHex   = 773 // 4

	_transformEnd = 779
)

// ============================================================================
// COMMAND QUEUE TEMPLATE INDICES (780-799) - for command_queue.go
// ============================================================================
const (
	IdxCqWordWindows = 780 // windows
	IdxCqShellCmd    = 781 // cmd
	IdxCqShellCmdArg = 782 // /c
	IdxCqShellSh     = 783 // sh
	IdxCqShellShArg  = 784 // -c
	IdxCqCmdDownload = 785 // download
	IdxCqCmdUpload   = 786 // upload

	_cmdQueueEnd = 799
)

// ============================================================================
// INLINE ASSEMBLY WINDOWS API TEMPLATE INDICES (800-829)
// ============================================================================
const (
	// DLL names (800-803)
	IdxIADllKernel32 = 800 // kernel32.dll
	IdxIADllOle32    = 801 // ole32.dll
	IdxIADllUser32   = 802 // user32.dll
	IdxIADllMsvcrt   = 803 // msvcrt.dll

	// API function names (804-821)
	IdxIAFnGetStdHandle          = 804 // GetStdHandle
	IdxIAFnSetStdHandle          = 805 // SetStdHandle
	IdxIAFnAllocConsole          = 806 // AllocConsole
	IdxIAFnFreeConsole           = 807 // FreeConsole
	IdxIAFnGetConsoleWindow      = 808 // GetConsoleWindow
	IdxIAFnPeekNamedPipe         = 809 // PeekNamedPipe
	IdxIAFnCreateFileW           = 810 // CreateFileW
	IdxIAFnCreateFileA           = 811 // CreateFileA
	IdxIAFnCloseHandle           = 812 // CloseHandle
	IdxIAFnReadFile              = 813 // ReadFile
	IdxIAFnWriteFile             = 814 // WriteFile
	IdxIAFnCoInitializeEx        = 815 // CoInitializeEx
	IdxIAFnCoUninitialize        = 816 // CoUninitialize
	IdxIAFnFlushInstructionCache = 817 // FlushInstructionCache
	IdxIAFnShowWindow            = 818 // ShowWindow
	IdxIAFnOpenOsfhandle         = 819 // _open_osfhandle
	IdxIAFnDup2                  = 820 // _dup2
	IdxIAFnClose                 = 821 // _close

	_iaWinApiEnd = 829
)

// ============================================================================
// INLINE ASSEMBLY CORE STRINGS (830-849) - for inline_assembly.go
// ============================================================================
const (
	IdxIAOsWindows       = 830 // windows
	IdxIACmdName         = 831 // inline-assembly
	IdxIACmdNameAsync    = 832 // inline-assembly-async
	IdxIATypeExe         = 833 // EXE
	IdxIATypeDll         = 834 // DLL
	IdxIAJobPrefix       = 835 // inline_asm_%d
	IdxIATerminated      = 836 // terminated by user
	IdxIAExitCodeLabel   = 837 // Exit code:
	IdxIAFmtDoneCode     = 838 // \nDone (code: %d)\n
	IdxIAFmtStartedID    = 839 // Started (ID: %s)
	IdxIAFmtExecFail     = 840 // \n[!] Execution failed: %v\n
	IdxIAFmtExecDone     = 841 // \n[+] Execution completed (exit code: %d)\n
	IdxIAFmtAsyncStarted = 842 // Async inline assembly execution started (Job ID: %s)\n
	IdxIAFmtOutputHint   = 843 // Use 'inline-assembly-output %s' to retrieve output

	_iaCoreStringsEnd = 849
)

// ============================================================================
// WINDOWS EXEC REQUIREMENTS TEMPLATE INDICES (500-549)
// ============================================================================
const (
	// DLL names (500-501)
	IdxExecReqWinDllNetapi32 = 500 // netapi32.dll
	IdxExecReqWinDllSecur32  = 501 // secur32.dll

	// Proc names (502-504)
	IdxExecReqWinProcNetGetJoinInfo = 502 // NetGetJoinInformation
	IdxExecReqWinProcNetApiBufFree  = 503 // NetApiBufferFree
	IdxExecReqWinProcGetUserNameEx  = 504 // GetUserNameExW

	// Environment variable names (505-509)
	IdxExecReqWinEnvUsername    = 505 // USERNAME
	IdxExecReqWinEnvUserDnsDom  = 506 // USERDNSDOMAIN
	IdxExecReqWinEnvUserDomain  = 507 // USERDOMAIN
	IdxExecReqWinEnvLogonServer = 508 // LOGONSERVER
	IdxExecReqWinEnvUserProfile = 509 // USERPROFILE

	// String literals (510-514)
	IdxExecReqWinWordTrue      = 510 // true
	IdxExecReqWinWordExe       = 511 // .exe
	IdxExecReqWinPathTildeBack = 512 // ~\
	IdxExecReqWinPathTildeFwd  = 513 // ~/
	IdxExecReqWinDoubleBacksl  = 514 // \\

	// Time format strings (515-516)
	IdxExecReqWinTimeFmtFull = 515 // 2006-01-02 15:04:05
	IdxExecReqWinTimeFmtDate = 516 // 2006-01-02

	// Additional environment variables (517)
	IdxExecReqWinEnvComputername = 517 // COMPUTERNAME

	_winExecReqEnd = 549
)

// ============================================================================
// DARWIN EXEC REQUIREMENTS TEMPLATE INDICES (400-449)
// ============================================================================
const (
	// Command names
	IdxExecReqDarCmdScutil     = 400 // scutil
	IdxExecReqDarCmdDsconfigad = 401 // dsconfigad
	IdxExecReqDarCmdDscl       = 402 // dscl
	IdxExecReqDarCmdPs         = 403 // ps
	IdxExecReqDarCmdPgrep      = 404 // pgrep

	// Command arguments
	IdxExecReqDarArgGet       = 405 // --get
	IdxExecReqDarArgLocalHost = 406 // LocalHostName
	IdxExecReqDarArgShow      = 407 // -show
	IdxExecReqDarArgLocalhost = 408 // localhost
	IdxExecReqDarArgList      = 409 // -list
	IdxExecReqDarArgActiveDir = 410 // /Active Directory
	IdxExecReqDarArgRead      = 411 // -read
	IdxExecReqDarArgSlash     = 412 // /
	IdxExecReqDarArgAux       = 413 // aux
	IdxExecReqDarArgCaseI     = 414 // -i

	// Environment variable names
	IdxExecReqDarEnvUser    = 415 // USER
	IdxExecReqDarEnvLogname = 416 // LOGNAME

	// File paths
	IdxExecReqDarPathKrb5Conf    = 417 // /etc/krb5.conf
	IdxExecReqDarPathMitKerberos = 418 // /Library/Preferences/edu.mit.Kerberos
	IdxExecReqDarPathTildeFwd    = 419 // ~/

	// String patterns
	IdxExecReqDarPatternADDomain   = 420 // Active Directory Domain =
	IdxExecReqDarPatternDefRealm   = 421 // default_realm
	IdxExecReqDarPatternServerConn = 422 // ServerConnection:

	// String literals
	IdxExecReqDarWordTrue    = 423 // true
	IdxExecReqDarTimeFmtFull = 424 // 2006-01-02 15:04:05

	_darwinExecReqEnd = 449
)

// ============================================================================
// NETONLY FILE SUPPORT TEMPLATE INDICES (850-869) - Windows only
// ============================================================================
const (
	// Windows API proc name
	IdxNfProcGetDriveType = 850 // GetDriveTypeW

	// UNC path prefixes
	IdxNfUncPrefix    = 851 // \\
	IdxNfUncPrefixAlt = 852 // //

	// Drive root suffix
	IdxNfDriveRootSuffix = 853 // :\

	// Format string for network-only token message
	IdxNfFmtNetOnlyToken = 854 // Using network-only token '%s' (%s\%s) for: %s\n

	// Network token wrapper format strings (855-865)
	IdxNfFmtUsingNetToken   = 855 // Using network-only token: %s\n
	IdxNfFmtExecNetToken    = 856 // Executing with network-only token: %s\n
	IdxNfFmtProcComplete    = 857 // Process %d completed with exit code %d\n
	IdxNfFmtUser            = 858 //     User: %s\n\n
	IdxNfMsgCmdExecNetToken = 859 // Command executed with network-only token\n
	IdxNfCmdNet             = 860 // net
	IdxNfFmtCmdRedirect     = 861 // cmd.exe /c %s > "%s" 2>&1
	IdxNfFmtTempFile        = 862 // %s\netonly_output_%d.txt
	IdxNfPlaceholderUser    = 863 // DOMAIN\User

	_netOnlyFileSupportEnd = 869
)

// ============================================================================
// WINDOWS COMMON API TEMPLATE INDICES (1020-1059) - for windows_common.go
// ============================================================================
const (
	// DLL names (1020-1024)
	IdxWcDllAdvapi32 = 1020 // advapi32.dll
	IdxWcDllKernel32 = 1021 // kernel32.dll
	IdxWcDllNtdll    = 1022 // ntdll.dll
	IdxWcDllUser32   = 1023 // user32.dll
	IdxWcDllPsapi    = 1024 // psapi.dll

	// Advapi32 function names (1025-1038)
	IdxWcFnGetUserNameW            = 1025 // GetUserNameW
	IdxWcFnOpenProcessToken        = 1026 // OpenProcessToken
	IdxWcFnOpenThreadToken         = 1027 // OpenThreadToken
	IdxWcFnDuplicateTokenEx        = 1028 // DuplicateTokenEx
	IdxWcFnImpersonateLoggedOnUser = 1029 // ImpersonateLoggedOnUser
	IdxWcFnRevertToSelf            = 1030 // RevertToSelf
	IdxWcFnGetTokenInformation     = 1031 // GetTokenInformation
	IdxWcFnLookupAccountSidW       = 1032 // LookupAccountSidW
	IdxWcFnLogonUserW              = 1033 // LogonUserW
	IdxWcFnLogonUserExW            = 1034 // LogonUserExW
	IdxWcFnCreateProcessAsUserW    = 1035 // CreateProcessAsUserW
	IdxWcFnCreateProcessWithTokenW = 1036 // CreateProcessWithTokenW
	IdxWcFnAdjustTokenPrivileges   = 1037 // AdjustTokenPrivileges
	IdxWcFnLookupPrivilegeValueW   = 1038 // LookupPrivilegeValueW

	// Kernel32 function names (1039-1051)
	IdxWcFnOpenProcess              = 1039 // OpenProcess
	IdxWcFnCloseHandle              = 1040 // CloseHandle
	IdxWcFnGetCurrentProcess        = 1041 // GetCurrentProcess
	IdxWcFnGetCurrentProcessId      = 1042 // GetCurrentProcessId
	IdxWcFnGetCurrentThread         = 1043 // GetCurrentThread
	IdxWcFnTerminateProcess         = 1044 // TerminateProcess
	IdxWcFnGetExitCodeProcess       = 1045 // GetExitCodeProcess
	IdxWcFnWaitForSingleObject      = 1046 // WaitForSingleObject
	IdxWcFnCreateToolhelp32Snapshot = 1047 // CreateToolhelp32Snapshot
	IdxWcFnProcess32FirstW          = 1048 // Process32FirstW
	IdxWcFnProcess32NextW           = 1049 // Process32NextW
	IdxWcFnGetEnvironmentStringsW   = 1050 // GetEnvironmentStringsW
	IdxWcFnFreeEnvironmentStringsW  = 1051 // FreeEnvironmentStringsW

	_winCommonApiEnd = 1059
)

// ============================================================================
// SOCKS HTTP TEMPLATE INDICES (1060-1099) - HTTP-based SOCKS proxy with UDP
// ============================================================================
const (
	// TCP Actions (1060-1062)
	IdxSocksHTTPActionConnect = 1060 // connect
	IdxSocksHTTPActionData    = 1061 // data
	IdxSocksHTTPActionClose   = 1062 // close

	// TCP Status responses (1063-1066)
	IdxSocksHTTPStatusConnected = 1063 // connected
	IdxSocksHTTPStatusData      = 1064 // data
	IdxSocksHTTPStatusClosed    = 1065 // closed
	IdxSocksHTTPStatusError     = 1066 // error

	// JSON field keys (1067-1072)
	IdxSocksHTTPFieldSid    = 1067 // sid
	IdxSocksHTTPFieldStatus = 1068 // st
	IdxSocksHTTPFieldData   = 1069 // d
	IdxSocksHTTPFieldError  = 1070 // err

	// Error messages (1073-1076)
	IdxSocksHTTPErrNoData       = 1073 // no data provided
	IdxSocksHTTPErrParseFailed  = 1074 // failed to parse command data
	IdxSocksHTTPErrUnknownAct   = 1075 // unknown action
	IdxSocksHTTPErrSessNotFound = 1076 // session not found

	// UDP Actions (1080-1082)
	IdxSocksHTTPActionUDPAssoc = 1080 // udp_associate
	IdxSocksHTTPActionUDPData  = 1081 // udp_data
	IdxSocksHTTPActionUDPClose = 1082 // udp_close

	// UDP Status responses (1083-1085)
	IdxSocksHTTPStatusUDPReady  = 1083 // udp_ready
	IdxSocksHTTPStatusUDPData   = 1084 // udp_data
	IdxSocksHTTPStatusUDPClosed = 1085 // udp_closed

	// UDP JSON field keys (1086-1089)
	IdxSocksHTTPFieldDestAddr = 1086 // da (destination address)
	IdxSocksHTTPFieldDestPort = 1087 // dp (destination port)
	IdxSocksHTTPFieldFrag     = 1088 // fg (fragment number)
	IdxSocksHTTPFieldAtyp     = 1089 // at (address type)

	_socksHTTPEnd = 1099
)

// ============================================================================
// COFF LOADER TEMPLATE INDICES (870-1017) - BOF beacon API names
// ============================================================================
const (
	// DLL names (870-874)
	IdxCoffDllKernel32 = 870 // kernel32.dll
	IdxCoffDllNtdll    = 871 // ntdll.dll
	IdxCoffDllUser32   = 872 // user32.dll
	IdxCoffDllWs2_32   = 873 // ws2_32.dll
	IdxCoffDllAdvapi32 = 874 // advapi32.dll

	// Prefixes/suffixes (875-878)
	IdxCoffPrefixImp  = 875 // __imp_
	IdxCoffSuffixDll  = 876 // .dll
	IdxCoffPrefixUs   = 877 // _
	IdxCoffSectionBss = 878 // .bss

	// Kernel32 API names (880-917)
	IdxCoffApiFreeLibrary            = 880 // FreeLibrary
	IdxCoffApiLoadLibraryA           = 881 // LoadLibraryA
	IdxCoffApiGetProcAddress         = 882 // GetProcAddress
	IdxCoffApiGetModuleHandleA       = 883 // GetModuleHandleA
	IdxCoffApiGetModuleFileNameA     = 884 // GetModuleFileNameA
	IdxCoffApiVirtualAlloc           = 885 // VirtualAlloc
	IdxCoffApiVirtualFree            = 886 // VirtualFree
	IdxCoffApiVirtualProtect         = 887 // VirtualProtect
	IdxCoffApiSetLastError           = 888 // SetLastError
	IdxCoffApiGetCurrentProcess      = 889 // GetCurrentProcess
	IdxCoffApiGetProcessHeap         = 890 // GetProcessHeap
	IdxCoffApiHeapAlloc              = 891 // HeapAlloc
	IdxCoffApiHeapFree               = 892 // HeapFree
	IdxCoffApiWideCharToMultiByte    = 893 // WideCharToMultiByte
	IdxCoffApiGetCurrentThread       = 894 // GetCurrentThread
	IdxCoffApiGetThreadContext       = 895 // GetThreadContext
	IdxCoffApiSetThreadContext       = 896 // SetThreadContext
	IdxCoffApiSuspendThread          = 897 // SuspendThread
	IdxCoffApiResumeThread           = 898 // ResumeThread
	IdxCoffApiCreateThread           = 899 // CreateThread
	IdxCoffApiExitThread             = 900 // ExitThread
	IdxCoffApiGetSystemTime          = 901 // GetSystemTime
	IdxCoffApiGetLocalTime           = 902 // GetLocalTime
	IdxCoffApiGetFileAttributesA     = 903 // GetFileAttributesA
	IdxCoffApiSetFileAttributesA     = 904 // SetFileAttributesA
	IdxCoffApiCreateFileA            = 905 // CreateFileA
	IdxCoffApiReadFile               = 906 // ReadFile
	IdxCoffApiWriteFile              = 907 // WriteFile
	IdxCoffApiCloseHandle            = 908 // CloseHandle
	IdxCoffApiGetFileSize            = 909 // GetFileSize
	IdxCoffApiGetFileSizeEx          = 910 // GetFileSizeEx
	IdxCoffApiFileTimeToSystemTime   = 911 // FileTimeToSystemTime
	IdxCoffApiSystemTimeToTzSpecific = 912 // SystemTimeToTzSpecificLocalTime
	IdxCoffApiFindFirstFileA         = 913 // FindFirstFileA
	IdxCoffApiFindNextFileA          = 914 // FindNextFileA
	IdxCoffApiFindClose              = 915 // FindClose
	IdxCoffApiGetLastError           = 916 // GetLastError
	IdxCoffApiRtlCopyMemory          = 917 // RtlCopyMemory

	// MSVCRT/String functions (918-927)
	IdxCoffFnStrlen   = 918 // strlen
	IdxCoffFnStrcmp   = 919 // strcmp
	IdxCoffFnStrncmp  = 920 // strncmp
	IdxCoffFnStricmp  = 921 // _stricmp
	IdxCoffFnStrnicmp = 922 // _strnicmp
	IdxCoffFnStrcpy   = 923 // strcpy
	IdxCoffFnStrncpy  = 924 // strncpy
	IdxCoffFnStrcat   = 925 // strcat
	IdxCoffFnStrncat  = 926 // strncat
	IdxCoffFnStrstr   = 927 // strstr

	// Memory functions (928-935)
	IdxCoffFnCalloc  = 928 // calloc
	IdxCoffFnMalloc  = 929 // malloc
	IdxCoffFnFree    = 930 // free
	IdxCoffFnRealloc = 931 // realloc
	IdxCoffFnMemcpy  = 932 // memcpy
	IdxCoffFnMemset  = 933 // memset
	IdxCoffFnMemmove = 934 // memmove
	IdxCoffFnMemcmp  = 935 // memcmp

	// Printf functions (936-938)
	IdxCoffFnVsnprintf  = 936 // vsnprintf
	IdxCoffFnVsnprintfU = 937 // _vsnprintf
	IdxCoffFnSprintf    = 938 // sprintf

	// User32 functions (939-946)
	IdxCoffApiMessageBoxA      = 939 // MessageBoxA
	IdxCoffApiMessageBoxW      = 940 // MessageBoxW
	IdxCoffApiGetDesktopWindow = 941 // GetDesktopWindow
	IdxCoffApiGetForegroundWnd = 942 // GetForegroundWindow
	IdxCoffApiGetWindowTextA   = 943 // GetWindowTextA
	IdxCoffApiGetWindowTextW   = 944 // GetWindowTextW
	IdxCoffApiFindWindowA      = 945 // FindWindowA
	IdxCoffApiFindWindowW      = 946 // FindWindowW

	// WS2_32 functions (947-968)
	IdxCoffApiWSAStartup    = 947 // WSAStartup
	IdxCoffApiWSACleanup    = 948 // WSACleanup
	IdxCoffApiWSAGetLastErr = 949 // WSAGetLastError
	IdxCoffApiSocket        = 950 // socket
	IdxCoffApiClosesocket   = 951 // closesocket
	IdxCoffApiBind          = 952 // bind
	IdxCoffApiListen        = 953 // listen
	IdxCoffApiAccept        = 954 // accept
	IdxCoffApiConnect       = 955 // connect
	IdxCoffApiSend          = 956 // send
	IdxCoffApiRecv          = 957 // recv
	IdxCoffApiSendto        = 958 // sendto
	IdxCoffApiRecvfrom      = 959 // recvfrom
	IdxCoffApiSelect        = 960 // select
	IdxCoffApiGethostbyname = 961 // gethostbyname
	IdxCoffApiGethostbyaddr = 962 // gethostbyaddr
	IdxCoffApiInet_addr     = 963 // inet_addr
	IdxCoffApiInet_ntoa     = 964 // inet_ntoa
	IdxCoffApiHtons         = 965 // htons
	IdxCoffApiHtonl         = 966 // htonl
	IdxCoffApiNtohs         = 967 // ntohs
	IdxCoffApiNtohl         = 968 // ntohl

	// Advapi32 functions (969-977)
	IdxCoffApiRegOpenKeyExA        = 969 // RegOpenKeyExA
	IdxCoffApiRegCloseKey          = 970 // RegCloseKey
	IdxCoffApiRegQueryValueExA     = 971 // RegQueryValueExA
	IdxCoffApiRegSetValueExA       = 972 // RegSetValueExA
	IdxCoffApiOpenProcessToken     = 973 // OpenProcessToken
	IdxCoffApiGetTokenInformation  = 974 // GetTokenInformation
	IdxCoffApiSetTokenInformation  = 975 // SetTokenInformation
	IdxCoffApiDuplicateTokenEx     = 976 // DuplicateTokenEx
	IdxCoffApiCreateProcessAsUserA = 977 // CreateProcessAsUserA

	// Beacon API functions (978-990)
	IdxCoffFnBeaconOutput       = 978 // BeaconOutput
	IdxCoffFnBeaconDataParse    = 979 // BeaconDataParse
	IdxCoffFnBeaconDataInt      = 980 // BeaconDataInt
	IdxCoffFnBeaconDataShort    = 981 // BeaconDataShort
	IdxCoffFnBeaconDataLength   = 982 // BeaconDataLength
	IdxCoffFnBeaconDataExtract  = 983 // BeaconDataExtract
	IdxCoffFnBeaconPrintf       = 984 // BeaconPrintf
	IdxCoffFnBeaconFormatAlloc  = 985 // BeaconFormatAlloc
	IdxCoffFnBeaconFormatFree   = 986 // BeaconFormatFree
	IdxCoffFnBeaconFormatAppend = 987 // BeaconFormatAppend
	IdxCoffFnBeaconFormatPrintf = 988 // BeaconFormatPrintf
	IdxCoffFnBeaconFormatToStr  = 989 // BeaconFormatToString
	IdxCoffFnBeaconFormatInt    = 990 // BeaconFormatInt

	// Helper functions (991-999)
	IdxCoffFnBofstart       = 991 // bofstart
	IdxCoffFnInternalPrintf = 992 // internal_printf
	IdxCoffFnPrintoutput    = 993 // printoutput
	IdxCoffFnIntAlloc       = 994 // intAlloc
	IdxCoffFnIntFree        = 995 // intFree
	IdxCoffFnIntMemset      = 996 // intMemset
	IdxCoffFnIntMemcpy      = 997 // intMemcpy
	IdxCoffFnIntRealloc     = 998 // intRealloc
	IdxCoffFnIntStrlen      = 999 // intStrlen

	_coffLoaderEnd = 999
)

// ============================================================================
// COFF LOADER TEMPLATE INDICES CONTINUED (1000-1017)
// ============================================================================
const (
	IdxCoffFnIntStrcmp    = 1000 // intStrcmp
	IdxCoffFnIntStrncmp   = 1001 // intStrncmp
	IdxCoffFnIntStrcpy    = 1002 // intStrcpy
	IdxCoffFnIntStrncpy   = 1003 // intStrncpy
	IdxCoffFnIntStrcat    = 1004 // intStrcat
	IdxCoffFnIntStrncat   = 1005 // intStrncat
	IdxCoffFnToWideChar   = 1006 // toWideChar
	IdxCoffFnUtf8ToUtf16  = 1007 // Utf8ToUtf16
	IdxCoffFnUtf16ToUtf8  = 1008 // Utf16ToUtf8

	// Patches strings (used by patches.go for AMSI/ETW)
	IdxPatchAmsiDll           = 1010 // amsi.dll
	IdxPatchAmsiScanBuffer    = 1011 // AmsiScanBuffer
	IdxPatchEtwEventWrite     = 1012 // EtwEventWrite
	IdxPatchNtProtectVirtMem  = 1013 // NtProtectVirtualMemory

	_coffLoaderExtendedEnd = 1017
)

// ToJSON serializes the template to JSON bytes
func (t *CommandTemplate) ToJSON() ([]byte, error) {
	return json.Marshal(t)
}

// ParseCommandTemplate deserializes JSON to a CommandTemplate
func ParseCommandTemplate(data []byte) (*CommandTemplate, error) {
	var t CommandTemplate
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	return &t, nil
}
