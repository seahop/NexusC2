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

	return &CommandTemplate{
		Version:   2,
		Type:      TypeExecReq,
		Templates: tpl,
		Params:    []string{},
	}
}
