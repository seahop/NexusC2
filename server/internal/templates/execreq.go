// internal/templates/execreq.go
package templates

// GetExecReqTemplate returns the exec requirements template for agents
func GetExecReqTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// File paths
	tpl[IdxExecReqPathEtcHostname] = "/etc/hostname"
	tpl[IdxExecReqPathSssdConf] = "/etc/sssd/sssd.conf"
	tpl[IdxExecReqPathSmbConf] = "/etc/samba/smb.conf"
	tpl[IdxExecReqPathKrb5Conf] = "/etc/krb5.conf"
	tpl[IdxExecReqPathIpaConf] = "/etc/ipa/default.conf"
	tpl[IdxExecReqPathProc] = "/proc"
	tpl[IdxExecReqPathTildeFwd] = "~/"

	// Environment variable names
	tpl[IdxExecReqEnvUser] = "USER"
	tpl[IdxExecReqEnvLogname] = "LOGNAME"
	tpl[IdxExecReqEnvHostname] = "HOSTNAME"
	tpl[IdxExecReqEnvShell] = "SHELL"

	// Config file patterns
	tpl[IdxExecReqPatternDomainsEq] = "domains ="
	tpl[IdxExecReqPatternDomainsEq2] = "domains="
	tpl[IdxExecReqPatternWorkgroup] = "workgroup"
	tpl[IdxExecReqPatternRealm] = "realm"
	tpl[IdxExecReqPatternDefRealm] = "default_realm"
	tpl[IdxExecReqPatternDomainEq] = "domain ="
	tpl[IdxExecReqPatternDomainEq2] = "domain="

	// Proc file names
	tpl[IdxExecReqProcCmdline] = "cmdline"
	tpl[IdxExecReqProcComm] = "comm"

	// String literals
	tpl[IdxExecReqWordTrue] = "true"
	tpl[IdxExecReqTimeFmtFull] = "2006-01-02 15:04:05"

	// System info strings (for getSystemInfo.go)
	tpl[IdxExecReqSysInfoStartupTime] = "startup_time"
	tpl[IdxExecReqSysInfoStatusActive] = "active"

	// ======================================================================
	// Windows-specific exec requirements (500-549)
	// ======================================================================

	// DLL names
	tpl[IdxExecReqWinDllNetapi32] = "netapi32.dll"
	tpl[IdxExecReqWinDllSecur32] = "secur32.dll"

	// Proc names
	tpl[IdxExecReqWinProcNetGetJoinInfo] = "NetGetJoinInformation"
	tpl[IdxExecReqWinProcNetApiBufFree] = "NetApiBufferFree"
	tpl[IdxExecReqWinProcGetUserNameEx] = "GetUserNameExW"

	// Environment variable names
	tpl[IdxExecReqWinEnvUsername] = "USERNAME"
	tpl[IdxExecReqWinEnvUserDnsDom] = "USERDNSDOMAIN"
	tpl[IdxExecReqWinEnvUserDomain] = "USERDOMAIN"
	tpl[IdxExecReqWinEnvLogonServer] = "LOGONSERVER"
	tpl[IdxExecReqWinEnvUserProfile] = "USERPROFILE"

	// String literals
	tpl[IdxExecReqWinWordTrue] = "true"
	tpl[IdxExecReqWinWordExe] = ".exe"
	tpl[IdxExecReqWinPathTildeBack] = "~\\"
	tpl[IdxExecReqWinPathTildeFwd] = "~/"
	tpl[IdxExecReqWinDoubleBacksl] = "\\\\"

	// Time format strings
	tpl[IdxExecReqWinTimeFmtFull] = "2006-01-02 15:04:05"
	tpl[IdxExecReqWinTimeFmtDate] = "2006-01-02"

	// Additional environment variables
	tpl[IdxExecReqWinEnvComputername] = "COMPUTERNAME"

	// ======================================================================
	// Darwin-specific exec requirements (400-424)
	// ======================================================================

	// Command names
	tpl[IdxExecReqDarCmdScutil] = "scutil"
	tpl[IdxExecReqDarCmdDsconfigad] = "dsconfigad"
	tpl[IdxExecReqDarCmdDscl] = "dscl"
	tpl[IdxExecReqDarCmdPs] = "ps"
	tpl[IdxExecReqDarCmdPgrep] = "pgrep"

	// Command arguments
	tpl[IdxExecReqDarArgGet] = "--get"
	tpl[IdxExecReqDarArgLocalHost] = "LocalHostName"
	tpl[IdxExecReqDarArgShow] = "-show"
	tpl[IdxExecReqDarArgLocalhost] = "localhost"
	tpl[IdxExecReqDarArgList] = "-list"
	tpl[IdxExecReqDarArgActiveDir] = "/Active Directory"
	tpl[IdxExecReqDarArgRead] = "-read"
	tpl[IdxExecReqDarArgSlash] = "/"
	tpl[IdxExecReqDarArgAux] = "aux"
	tpl[IdxExecReqDarArgCaseI] = "-i"

	// Environment variable names
	tpl[IdxExecReqDarEnvUser] = "USER"
	tpl[IdxExecReqDarEnvLogname] = "LOGNAME"

	// File paths
	tpl[IdxExecReqDarPathKrb5Conf] = "/etc/krb5.conf"
	tpl[IdxExecReqDarPathMitKerberos] = "/Library/Preferences/edu.mit.Kerberos"
	tpl[IdxExecReqDarPathTildeFwd] = "~/"

	// Config file patterns
	tpl[IdxExecReqDarPatternADDomain] = "Active Directory Domain ="
	tpl[IdxExecReqDarPatternDefRealm] = "default_realm"
	tpl[IdxExecReqDarPatternServerConn] = "ServerConnection:"

	// String literals
	tpl[IdxExecReqDarWordTrue] = "true"
	tpl[IdxExecReqDarTimeFmtFull] = "2006-01-02 15:04:05"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeExecReq,
		Templates: tpl,
		Params:    []string{},
	}
}
