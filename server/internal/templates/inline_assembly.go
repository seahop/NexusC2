// internal/templates/inline_assembly.go
package templates

// GetInlineAssemblyTemplate returns a template for inline assembly commands
// This covers inline-assembly, inline-assembly-async, inline-assembly-jobs, etc.
// Note: DLL names and API function names used in init() CANNOT be templated
func GetInlineAssemblyTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// CLR strings (400-404)
	tpl[IdxIAClrV4] = "v4"
	tpl[IdxIAClrV2] = "v2"
	tpl[IdxIAClrV2Full] = "v2.0.50727"
	tpl[IdxIATempPrefix] = "clr_output_"
	tpl[IdxIATempSuffix] = ".txt"

	// Output markers (405-406)
	tpl[IdxIAOutputStart] = "\n>>>\n"
	tpl[IdxIAOutputEnd] = "\n<<<\n"

	// Runfor detection (407-408)
	tpl[IdxIARunforFlag] = "/runfor"
	tpl[IdxIAColon] = ":"

	// Status messages (409-416)
	tpl[IdxIADoneMsg] = "\nDone\n"
	tpl[IdxIADoneExitPrev] = "\nDone (exit prevented)\n"
	tpl[IdxIADoneAfterPre] = "\nDone after "
	tpl[IdxIADoneAfterSuf] = "ds\n"
	tpl[IdxIADonePre] = "\nDone ("
	tpl[IdxIADoneSuf] = ")\n"
	tpl[IdxIAExitPrevMsg] = "\nExit prevented\n"

	// Error detection keywords (417-418)
	tpl[IdxIAKwExit] = "exit"
	tpl[IdxIAKwTerminate] = "terminate"

	// CLR corruption (419-420)
	tpl[IdxIAClrErrCode] = "0x80131604"
	tpl[IdxIAClrCorrupt] = "\nCLR corrupted (0x80131604)\n"

	// Command names (421-425)
	tpl[IdxIACmdJobs] = "inline-assembly-jobs"
	tpl[IdxIACmdOutput] = "inline-assembly-output"
	tpl[IdxIACmdKill] = "inline-assembly-kill"
	tpl[IdxIACmdClean] = "inline-assembly-jobs-clean"
	tpl[IdxIACmdStats] = "inline-assembly-jobs-stats"

	// Status strings (426-430)
	tpl[IdxIAStatusRunning] = "running"
	tpl[IdxIAStatusCompleted] = "completed"
	tpl[IdxIAStatusFailed] = "failed"
	tpl[IdxIAStatusKilled] = "killed"
	tpl[IdxIAStatusTimeout] = "timeout"

	// Format components (431-441)
	tpl[IdxIAFmtRunningPrefix] = "r:"
	tpl[IdxIAFmtDonePrefix] = "d:"
	tpl[IdxIAFmtDash] = "-"
	tpl[IdxIAFmtPipe] = "|"
	tpl[IdxIAFmtNewline] = "\n"
	tpl[IdxIAFmtEllipsis] = "..."
	tpl[IdxIAFmtColSep] = " | "
	tpl[IdxIAFmtZero] = "0"
	tpl[IdxIAFmtOne] = "1"
	tpl[IdxIAFmtColonSingle] = ":"

	// Stats labels (442-448)
	tpl[IdxIAStatsHeader] = "Stats:\n"
	tpl[IdxIAStatsTotalLbl] = "Total Jobs:     "
	tpl[IdxIAStatsRunLbl] = "Running:        "
	tpl[IdxIAStatsCompLbl] = "Completed:      "
	tpl[IdxIAStatsFailLbl] = "Failed:         "
	tpl[IdxIAStatsKillLbl] = "Killed:         "
	tpl[IdxIAStatsTimeLbl] = "Timeout:        "

	return &CommandTemplate{
		Version:   2,
		Type:      TypeInlineAssembly,
		Templates: tpl,
		Params:    []string{},
	}
}
