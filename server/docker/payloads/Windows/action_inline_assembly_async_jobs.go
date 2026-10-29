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
	// Msg names
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
func iasStatusRunning() string { return iaTpl(idxIAStatusRunning) }

func iasStatusCompleted() string { return iaTpl(idxIAStatusCompleted) }

func iasStatusFailed() string { return iaTpl(idxIAStatusFailed) }

func iasStatusKilled() string { return iaTpl(idxIAStatusKilled) }

func iasStatusTimeout() string { return iaTpl(idxIAStatusTimeout) }

func iasFmtRunningPrefix() string { return iaTpl(idxIAFmtRunningPrefix) }

func iasFmtDonePrefix() string { return iaTpl(idxIAFmtDonePrefix) }

func iasFmtDash() string { return iaTpl(idxIAFmtDash) }

func iasFmtPipe() string { return iaTpl(idxIAFmtPipe) }

func iasFmtNewline() string { return iaTpl(idxIAFmtNewline) }

func iasFmtEllipsis() string { return iaTpl(idxIAFmtEllipsis) }

func iasFmtColSep() string { return iaTpl(idxIAFmtColSep) }

func iasFmtZero() string { return iaTpl(idxIAFmtZero) }

func iasFmtOne() string { return iaTpl(idxIAFmtOne) }

func iasFmtColon() string { return iaTpl(idxIAFmtColon) }

func iasStatsHeader() string { return iaTpl(idxIAStatsHeader) }

func iasStatsTotalLbl() string { return iaTpl(idxIAStatsTotalLbl) }

func iasStatsRunLbl() string { return iaTpl(idxIAStatsRunLbl) }

func iasStatsCompLbl() string { return iaTpl(idxIAStatsCompLbl) }

func iasStatsFailLbl() string { return iaTpl(idxIAStatsFailLbl) }

func iasStatsKillLbl() string { return iaTpl(idxIAStatsKillLbl) }

func iasStatsTimeLbl() string { return iaTpl(idxIAStatsTimeLbl) }

// NativeJob represents an async assembly execution job
type NativeJob struct {
	ID              string
	CID       string
	DID     int
	AID         string
	Name            string
	Status          string // "running", "completed", "failed", "killed"
	StartTime       time.Time
	EndTime         *time.Time
	Output          strings.Builder
	Error           error
	CancelChan      chan bool
	OutputMutex     sync.Mutex
	Cmd         Msg
	OutputTruncated bool
	TotalBytesSent  int
	Process         *os.Process
	CredCtx    *NativeCredCtx
}

// NativeJobMgr manages async assembly jobs
type NativeJobMgr struct {
	jobs map[string]*NativeJob
	mu   sync.RWMutex
}

var assemblyJobManager = &NativeJobMgr{
	jobs: make(map[string]*NativeJob),
}

// NativeJobsMsg lists running assembly jobs
type NativeJobsMsg struct{}

func (c *NativeJobsMsg) execute(ctx *OpCtx, args []string) OpResult {
	return executeAssemblyJobsList()
}

// NativeOutputMsg retrieves output from an assembly job
type NativeOutputMsg struct{}

func (c *NativeOutputMsg) execute(ctx *OpCtx, args []string) OpResult {
	if len(args) == 0 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	jobID := args[0]

	// Get the job
	job, exists := GetAssemblyJob(jobID)
	if !exists {
		// Try partial match
		jobs := assemblyJobManager.listJobs()
		for _, j := range jobs {
			if strings.HasPrefix(j.ID, jobID) {
				job = j
				exists = true
				break
			}
		}

		if !exists {
			return OpResult{
				Output:      ErrCtx(E26, jobID),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
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

	return OpResult{
		Output:      result.String(),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}

// NativeStopMsg terminates an assembly job
type NativeStopMsg struct{}

func (c *NativeStopMsg) execute(ctx *OpCtx, args []string) OpResult {
	if len(args) < 1 {
		return OpResult{
			Output:   Err(E1),
			EC: 1,
		}
	}

	jobID := args[0]
	return executeAssemblyKillJob(jobID)
}

// executeAssemblyJobsList lists all assembly jobs
func executeAssemblyJobsList() OpResult {
	jobs := assemblyJobManager.listJobs()

	if len(jobs) == 0 {
		return OpResult{
			Output:   Succ(S0),
			EC: 0,
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

	return OpResult{
		Output:   output.String(),
		EC: 0,
	}
}

// executeAssemblyGetOutput retrieves output from a job
func executeAssemblyGetOutput(jobID string) OpResult {
	job := assemblyJobManager.getJob(jobID)
	if job == nil {
		// Try partial match
		jobs := assemblyJobManager.listJobs()
		for _, j := range jobs {
			if strings.HasPrefix(j.ID, jobID) {
				job = j
				break
			}
		}
	}

	if job == nil {
		return OpResult{
			Output:   ErrCtx(E26, jobID),
			EC: 1,
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

	return OpResult{
		Output:   output,
		EC: 0,
		JobID:    jobID,
	}
}

// executeAssemblyKillJob terminates a running job
func executeAssemblyKillJob(jobID string) OpResult {
	job := assemblyJobManager.getJob(jobID)
	if job == nil {
		// Try partial match
		jobs := assemblyJobManager.listJobs()
		for _, j := range jobs {
			if strings.HasPrefix(j.ID, jobID) {
				job = j
				break
			}
		}
	}

	if job == nil {
		return OpResult{
			Output:   ErrCtx(E26, jobID),
			EC: 1,
		}
	}

	if job.Status != iasStatusRunning() {
		return OpResult{
			Output:   ErrCtx(E27, job.ID),
			EC: 1,
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

		return OpResult{
			Output:   SuccCtx(S2, job.ID),
			EC: 0,
			JobID:    jobID,
		}
	default:
		return OpResult{
			Output:   Err(E47),
			EC: 1,
		}
	}
}

// Helper methods for NativeJobMgr
func (ajm *NativeJobMgr) addJob(job *NativeJob) {
	ajm.mu.Lock()
	defer ajm.mu.Unlock()
	ajm.jobs[job.ID] = job
}

func (ajm *NativeJobMgr) getJob(jobID string) *NativeJob {
	ajm.mu.RLock()
	defer ajm.mu.RUnlock()
	return ajm.jobs[jobID]
}

func (ajm *NativeJobMgr) listJobs() []*NativeJob {
	ajm.mu.RLock()
	defer ajm.mu.RUnlock()

	jobs := make([]*NativeJob, 0, len(ajm.jobs))
	for _, job := range ajm.jobs {
		jobs = append(jobs, job)
	}
	return jobs
}

func (ajm *NativeJobMgr) removeJob(jobID string) {
	ajm.mu.Lock()
	defer ajm.mu.Unlock()
	delete(ajm.jobs, jobID)
}

func (ajm *NativeJobMgr) cleanupOldJobs(maxAge time.Duration) {
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

// cleanupCompletedJobs removes all completed jobs and returns count
func (ajm *NativeJobMgr) cleanupCompletedJobs() int {
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

// NativeCleanMsg cleans up completed/killed assembly jobs
type NativeCleanMsg struct{}

func (c *NativeCleanMsg) execute(ctx *OpCtx, args []string) OpResult {
	if len(args) == 0 {
		// Clean all non-running jobs
		return executeAssemblyJobsCleanAll()
	}
	// Clean specific job
	return executeAssemblyJobsCleanSpecific(args[0])
}

func executeAssemblyJobsCleanAll() OpResult {
	cleaned := assemblyJobManager.cleanupCompletedJobs()

	if cleaned == 0 {
		return OpResult{
			Output:   Succ(S0),
			EC: 0,
		}
	}

	return OpResult{
		Output:   SuccCtx(S17, fmt.Sprintf("%d", cleaned)),
		EC: 0,
	}
}

func executeAssemblyJobsCleanSpecific(jobID string) OpResult {
	job := assemblyJobManager.getJob(jobID)
	if job == nil {
		// Try partial match
		jobs := assemblyJobManager.listJobs()
		for _, j := range jobs {
			if strings.HasPrefix(j.ID, jobID) {
				job = j
				break
			}
		}
	}

	if job == nil {
		return OpResult{
			Output:   ErrCtx(E26, jobID),
			EC: 1,
		}
	}

	if job.Status == iasStatusRunning() {
		return OpResult{
			Output:   ErrCtx(E27, job.ID),
			EC: 1,
		}
	}

	assemblyJobManager.removeJob(job.ID)

	return OpResult{
		Output:   SuccCtx(S2, job.ID),
		EC: 0,
	}
}

// NativeStatsMsg shows job statistics
type NativeStatsMsg struct{}

func (c *NativeStatsMsg) execute(ctx *OpCtx, args []string) OpResult {
	return executeAssemblyJobsStats()
}

func executeAssemblyJobsStats() OpResult {
	jobs := assemblyJobManager.listJobs()

	if len(jobs) == 0 {
		return OpResult{
			Output:   Succ(S0),
			EC: 0,
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

	return OpResult{
		Output:   output.String(),
		EC: 0,
	}
}

// GetAssemblyJob is a helper function to get a job by ID
func GetAssemblyJob(jobID string) (*NativeJob, bool) {
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
			assemblyJobManager.cleanupOldJobs(24 * time.Hour)
		}
	}()
}
