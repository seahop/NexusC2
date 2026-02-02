// internal/templates/inline_assembly.go
package templates

// GetInlineAssemblyTemplate returns a template for inline assembly commands
// This covers inline-assembly, inline-assembly-async, inline-assembly-jobs, etc.
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

	// DLL names (800-803)
	tpl[IdxIADllKernel32] = "kernel32.dll"
	tpl[IdxIADllOle32] = "ole32.dll"
	tpl[IdxIADllUser32] = "user32.dll"
	tpl[IdxIADllMsvcrt] = "msvcrt.dll"

	// API function names (804-821)
	tpl[IdxIAFnGetStdHandle] = "GetStdHandle"
	tpl[IdxIAFnSetStdHandle] = "SetStdHandle"
	tpl[IdxIAFnAllocConsole] = "AllocConsole"
	tpl[IdxIAFnFreeConsole] = "FreeConsole"
	tpl[IdxIAFnGetConsoleWindow] = "GetConsoleWindow"
	tpl[IdxIAFnPeekNamedPipe] = "PeekNamedPipe"
	tpl[IdxIAFnCreateFileW] = "CreateFileW"
	tpl[IdxIAFnCreateFileA] = "CreateFileA"
	tpl[IdxIAFnCloseHandle] = "CloseHandle"
	tpl[IdxIAFnReadFile] = "ReadFile"
	tpl[IdxIAFnWriteFile] = "WriteFile"
	tpl[IdxIAFnCoInitializeEx] = "CoInitializeEx"
	tpl[IdxIAFnCoUninitialize] = "CoUninitialize"
	tpl[IdxIAFnFlushInstructionCache] = "FlushInstructionCache"
	tpl[IdxIAFnShowWindow] = "ShowWindow"
	tpl[IdxIAFnOpenOsfhandle] = "_open_osfhandle"
	tpl[IdxIAFnDup2] = "_dup2"
	tpl[IdxIAFnClose] = "_close"

	// Core inline assembly strings (830-843)
	tpl[IdxIAOsWindows] = "windows"
	tpl[IdxIACmdName] = "inline-assembly"
	tpl[IdxIACmdNameAsync] = "inline-assembly-async"
	tpl[IdxIATypeExe] = "EXE"
	tpl[IdxIATypeDll] = "DLL"
	tpl[IdxIAJobPrefix] = "inline_asm_%d"
	tpl[IdxIATerminated] = "terminated by user"
	tpl[IdxIAExitCodeLabel] = "Exit code:"
	tpl[IdxIAFmtDoneCode] = "\nDone (code: %d)\n"
	tpl[IdxIAFmtStartedID] = "Started (ID: %s)"
	tpl[IdxIAFmtExecFail] = "\n[!] Execution failed: %v\n"
	tpl[IdxIAFmtExecDone] = "\n[+] Execution completed (exit code: %d)\n"
	tpl[IdxIAFmtAsyncStarted] = "Async inline assembly execution started (Job ID: %s)\n"
	tpl[IdxIAFmtOutputHint] = "Use 'inline-assembly-output %s' to retrieve output"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeInlineAssembly,
		Templates: tpl,
		Params:    []string{},
	}
}
