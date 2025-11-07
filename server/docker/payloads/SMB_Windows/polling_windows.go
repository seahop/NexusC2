// server/docker/payloads/Windows/polling_windows.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"time"
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
			fmt.Println("[BOF Cleanup] Shutting down")
			return
		case <-ticker.C:
			// Clean up jobs that have been completed for more than 1 hour
			bofJobManager.mu.Lock()
			now := time.Now()
			cleaned := 0
			for id, job := range bofJobManager.jobs {
				if job.Status != "running" && job.EndTime != nil {
					if now.Sub(*job.EndTime) > 1*time.Hour {
						delete(bofJobManager.jobs, id)
						cleaned++
					}
				}
			}
			bofJobManager.mu.Unlock()

			if cleaned > 0 {
				fmt.Printf("[BOF Cleanup] Removed %d old completed job(s)\n", cleaned)
			}
		}
	}
}
