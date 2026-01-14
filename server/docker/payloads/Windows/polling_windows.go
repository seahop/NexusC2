// server/docker/payloads/Windows/polling_windows.go
//go:build windows
// +build windows

package main

import (
	"time"
)

// Polling windows strings (constructed to avoid static signatures)
var (
	pwStatusRunning = string([]byte{0x72, 0x75, 0x6e, 0x6e, 0x69, 0x6e, 0x67}) // running
)

// startAsyncBOFChecker starts a simple cleanup routine for BOF jobs
// All output sending is now handled through ResultManager in the main polling loop
func startAsyncBOFChecker() {
	// Just start the cleanup routine
	go cleanupBOFJobs()
}

// cleanupBOFJobs periodically removes old completed jobs from memory
func cleanupBOFJobs() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-pollingShutdown:
			// fmt.Println("[BOF Cleanup] Shutting down")
			return
		case <-ticker.C:
			// Clean up jobs that have been completed for more than 1 hour
			bofJobManager.mu.Lock()
			now := time.Now()
			cleaned := 0
			for id, job := range bofJobManager.jobs {
				if job.Status != pwStatusRunning && job.EndTime != nil {
					if now.Sub(*job.EndTime) > 1*time.Hour {
						delete(bofJobManager.jobs, id)
						cleaned++
					}
				}
			}
			bofJobManager.mu.Unlock()

			if cleaned > 0 {
			}
		}
	}
}
