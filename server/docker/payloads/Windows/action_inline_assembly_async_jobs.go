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
			Output:      Err(E1),
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
				Output:      ErrCtx(E26, jobID),
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

	// Build compact response - client formats
	// Format: job_id|status|truncated(0/1)|duration_or_running|buffer_bytes|output
	var result strings.Builder

	truncatedFlag := "0"
	if truncated {
		truncatedFlag = "1"
	}

	var durationStr string
	if status == "running" {
		duration := time.Since(job.StartTime).Round(time.Second)
		durationStr = fmt.Sprintf("r:%s:%d", duration, bufferSize)
	} else if job.EndTime != nil {
		duration := job.EndTime.Sub(job.StartTime).Round(time.Second)
		durationStr = fmt.Sprintf("d:%s", duration)
	} else {
		durationStr = "-"
	}

	result.WriteString(fmt.Sprintf("%s|%s|%s|%s\n", job.ID, status, truncatedFlag, durationStr))

	// Add the actual output
	if output == "" {
		result.WriteString(Succ(S18))
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
			Output:   Err(E1),
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
			Output:   Succ(S0),
			ExitCode: 0,
		}
	}

	var output strings.Builder
	output.WriteString(Table(TJobs, len(jobs)) + "\n")

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
			Output:   ErrCtx(E26, jobID),
			ExitCode: 1,
		}
	}

	job.OutputMutex.Lock()
	output := job.Output.String()
	status := job.Status
	truncated := job.OutputTruncated
	job.OutputMutex.Unlock()

	// Compact output format - client expands
	// Format: status_code|job_id|truncated(0/1)|output
	truncatedFlag := "0"
	if truncated {
		truncatedFlag = "1"
	}

	if output == "" {
		// S18 = no output yet
		output = fmt.Sprintf("%s|%s|%s|%s|", Succ(S18), job.ID, status, truncatedFlag)
	} else {
		output = fmt.Sprintf("%s|%s|%s|%s\n%s", Succ(S5), job.ID, status, truncatedFlag, output)
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
			Output:   ErrCtx(E26, jobID),
			ExitCode: 1,
		}
	}

	if job.Status != "running" {
		return CommandResult{
			Output:   ErrCtx(E27, job.ID),
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
			Output:   SuccCtx(S2, job.ID),
			ExitCode: 0,
			JobID:    jobID,
		}
	default:
		return CommandResult{
			Output:   Err(E47),
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
			Output:   Succ(S0),
			ExitCode: 0,
		}
	}

	return CommandResult{
		Output:   SuccCtx(S17, fmt.Sprintf("%d", cleaned)),
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
			Output:   ErrCtx(E26, jobID),
			ExitCode: 1,
		}
	}

	if job.Status == "running" {
		return CommandResult{
			Output:   ErrCtx(E27, job.ID),
			ExitCode: 1,
		}
	}

	assemblyJobManager.RemoveJob(job.ID)

	return CommandResult{
		Output:   SuccCtx(S2, job.ID),
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
			Output:   Succ(S0),
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
	output.WriteString("Stats:\n")
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
