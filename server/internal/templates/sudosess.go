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

	return &CommandTemplate{
		Version:   2,
		Type:      TypeSudoSess,
		Templates: tpl,
		Params:    []string{},
	}
}
