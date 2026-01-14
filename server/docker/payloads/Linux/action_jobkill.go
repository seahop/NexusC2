// server/docker/payloads/Linux/action_jobkill.go

//go:build linux
// +build linux

package main

import (
	"fmt"
	"time"
)

type JobKillCommand struct{}

func (c *JobKillCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse command line into arguments
	// Note: args is already split for us, we receive just the filename
	if len(args) == 0 {
		return CommandResult{
			Error:       fmt.Errorf(Err(E1)),
			ErrorString: Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	filename := args[0]
	foundJob := false

	// Check both activeDownloads and activeUploads using the filename
	commandQueue.mu.Lock()
	defer commandQueue.mu.Unlock()

	// Check and cleanup downloads
	if download, exists := commandQueue.activeDownloads[filename]; exists {
		download.InProgress = false
		delete(commandQueue.activeDownloads, filename)
		foundJob = true
	}

	// Check and cleanup uploads
	if upload, exists := commandQueue.activeUploads[filename]; exists {
		upload.Chunks = nil
		delete(commandQueue.activeUploads, filename)
		foundJob = true
	}

	// Look for job in activeJobs to mark as complete
	for jobID, job := range commandQueue.activeJobs {
		if job.Filename == filename {
			job.Active = false
			// Save the modified job back to the map
			commandQueue.activeJobs[jobID] = job
			foundJob = true
		}
	}

	if !foundJob {
		return CommandResult{
			Error:       fmt.Errorf(ErrCtx(E26, filename)),
			ErrorString: ErrCtx(E26, filename),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      SuccCtx(S2, filename),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
