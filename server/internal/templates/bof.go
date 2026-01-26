// internal/templates/bof.go
package templates

// GetBOFTemplate returns a template for BOF commands
// This covers bof, bof-async, bof-jobs, bof-output, bof-kill commands
func GetBOFTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Command names (350-359)
	tpl[IdxBofCmdName] = "bof"
	tpl[IdxBofCmdAsync] = "bof-async"
	tpl[IdxBofCmdJobs] = "bof-jobs"
	tpl[IdxBofCmdOutput] = "bof-output"
	tpl[IdxBofCmdKill] = "bof-kill"
	tpl[IdxBofCmdAsyncPrefix] = "bof-async "
	tpl[IdxBofCmdAsyncStatus] = "bof-async-status"
	tpl[IdxBofCmdAsyncOutput] = "bof-async-output"
	tpl[IdxBofOSWindows] = "windows"

	// Job status values (360-364)
	tpl[IdxBofStatusRunning] = "running"
	tpl[IdxBofStatusCompleted] = "completed"
	tpl[IdxBofStatusCrashed] = "crashed"
	tpl[IdxBofStatusKilled] = "killed"
	tpl[IdxBofStatusTimeout] = "timeout"

	// Output markers (365-369)
	tpl[IdxBofAsyncStarted] = "BOF_ASYNC_STARTED"
	tpl[IdxBofAsyncPrefix] = "BOF_ASYNC_"
	tpl[IdxBofChunkPrefix] = "|CHUNK_"
	tpl[IdxBofChunkSeparator] = "\n---CHUNK_SEPARATOR---\n"
	tpl[IdxBofPipeSep] = "|"

	// Final status markers (370-374)
	tpl[IdxBofFinalCompleted] = "COMPLETED"
	tpl[IdxBofFinalCrashed] = "CRASHED"
	tpl[IdxBofFinalKilled] = "KILLED"
	tpl[IdxBofFinalTimeout] = "TIMEOUT"
	tpl[IdxBofFinalOutput] = "OUTPUT"

	// Misc strings (375-377)
	tpl[IdxBofTruncYes] = "YES"
	tpl[IdxBofTruncDots] = "..."
	tpl[IdxBofTruncatedMsg] = " (OUTPUT TRUNCATED - exceeded 10MB limit)"

	// Output message fragments (378-387)
	tpl[IdxBofJobPrefix] = "Job "
	tpl[IdxBofStillRunning] = " is still running\n"
	tpl[IdxBofChunksSent] = "Chunks sent: "
	tpl[IdxBofSpaceParen] = " ("
	tpl[IdxBofNoBufferedOut] = ") has no buffered output\n"
	tpl[IdxBofOutputForJob] = "Output for job "
	tpl[IdxBofChunksSentParen] = " (chunks sent: "
	tpl[IdxBofCloseColonNL] = "):\n"
	tpl[IdxBofCloseParen] = ")"

	// IPC path for network operations (388)
	tpl[IdxBofIPCPath] = "\\IPC$"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeBof,
		Templates: tpl,
		Params:    []string{},
	}
}
