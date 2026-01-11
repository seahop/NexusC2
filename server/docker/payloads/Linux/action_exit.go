// server/docker/payloads/Linux/action_exit.go

//go:build linux
// +build linux

package main

import (
	"os"
	"time"
)

type ExitCommand struct{}

func (c *ExitCommand) Name() string {
	return "exit"
}

func (c *ExitCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Clean up active jobs
	commandQueue.mu.Lock()
	// Clean up downloads
	for filename, download := range commandQueue.activeDownloads {
		download.InProgress = false
		delete(commandQueue.activeDownloads, filename)
	}
	// Clean up uploads
	for filename := range commandQueue.activeUploads {
		delete(commandQueue.activeUploads, filename)
	}
	// Mark all jobs as inactive
	for id, job := range commandQueue.activeJobs {
		job.Active = false
		commandQueue.activeJobs[id] = job
	}
	commandQueue.mu.Unlock()

	// Let the server know we're exiting
	result := CommandResult{
		Output:      Succ(S5),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}

	// Schedule the actual exit after we return the result
	go func() {
		time.Sleep(2 * time.Second)

		// Try normal exit first
		os.Exit(0)

		// If we're still here after a moment, try platform-specific termination
		time.Sleep(1 * time.Second)

		// Last resort - panic
		panic("Failed to exit gracefully")
	}()

	return result
}
