// internal/templates/cmdproc.go
package templates

// GetCmdProcTemplate returns the command processor template for agents
func GetCmdProcTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Command names
	tpl[IdxCmdProcInlineAssemblyJobs] = "inline-assembly-jobs"
	tpl[IdxCmdProcInlineAssemblyJobsClean] = "inline-assembly-jobs-clean"
	tpl[IdxCmdProcInlineAssemblyJobsStats] = "inline-assembly-jobs-stats"
	tpl[IdxCmdProcInlineAssemblyOutput] = "inline-assembly-output"
	tpl[IdxCmdProcInlineAssemblyOutputSp] = "inline-assembly-output "
	tpl[IdxCmdProcInlineAssemblyKill] = "inline-assembly-kill"
	tpl[IdxCmdProcInlineAssemblyKillSp] = "inline-assembly-kill "
	tpl[IdxCmdProcInlineAssembly] = "inline-assembly"
	tpl[IdxCmdProcInlineAssemblyAsync] = "inline-assembly-async"
	tpl[IdxCmdProcBof] = "bof"
	tpl[IdxCmdProcUpload] = "upload"
	tpl[IdxCmdProcDownload] = "download"
	tpl[IdxCmdProcAsync] = "async"

	// Error message suffixes
	tpl[IdxCmdProcErrNotRegistered] = " command not registered"
	tpl[IdxCmdProcErrHandlerNotReg] = " handler not registered"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeCmdProc,
		Templates: tpl,
		Params:    []string{},
	}
}
