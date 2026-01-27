// internal/templates/sudosess.go
package templates

// GetSudoSessTemplate returns the sudo session template for agents
func GetSudoSessTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Command name
	tpl[IdxSudoSessCmdName] = "sudo-session"

	// Subcommands
	tpl[IdxSudoSessStart] = "start"
	tpl[IdxSudoSessStop] = "stop"
	tpl[IdxSudoSessExec] = "exec"
	tpl[IdxSudoSessExecStateful] = "exec-stateful"
	tpl[IdxSudoSessEnableStateful] = "enable-stateful"
	tpl[IdxSudoSessDisableStateful] = "disable-stateful"
	tpl[IdxSudoSessStatus] = "status"

	// Default user
	tpl[IdxSudoSessDefaultUser] = "root"

	// PTY helper strings (for pty_helper.go)
	tpl[IdxPtySudo] = "sudo"
	tpl[IdxPtySu] = "su"
	tpl[IdxPtySh] = "sh"
	tpl[IdxPtyFlagS] = "-S"
	tpl[IdxPtyFlagP] = "-p"
	tpl[IdxPtyFlagC] = "-c"
	tpl[IdxPtyFlagDash] = "-"
	tpl[IdxPtyPassword] = "Password:"
	tpl[IdxPtyPasswordL] = "password"
	tpl[IdxPtySorry] = "Sorry"
	tpl[IdxPtyTryAgain] = "try again"
	tpl[IdxPtyIncorrect] = "incorrect"
	tpl[IdxPtyExit] = "exit"
	tpl[IdxPtyRoot] = "root"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeSudoSess,
		Templates: tpl,
		Params:    []string{},
	}
}
