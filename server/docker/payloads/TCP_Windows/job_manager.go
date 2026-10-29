// server/docker/payloads/SMB_Windows/job_manager.go

//go:build windows
// +build windows

package main

import (
	"fmt"
	"time"
)

// PCfg stores communications-related template strings
type PCfg struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// Global comms template storage for job manager (uses SafeTemplate for memory zeroing)
var globalCommsTpl *SafeTemplate

// Job manager template index constant
const idxJmTypeDownload = 785 // download - matches server's IdxCqCmdDownload

// setCommsTemplate stores the comms template (converts to SafeTemplate)
func setCommsTemplate(tpl *PCfg) {
	// zero old template before replacing
	if globalCommsTpl != nil {
		globalCommsTpl.zero()
	}
	globalCommsTpl = NewSecureTemplateFromSlices(tpl.Version, tpl.Type, tpl.Templates, tpl.Params)
}

// jmTpl safely retrieves a template string by index for job manager
func jmTpl(idx int) string {
	return globalCommsTpl.Get(idx)
}

// commsTpl alias for compatibility with shared code (command_queue.go, transforms.go)
func commsTpl(idx int) string {
	return globalCommsTpl.Get(idx)
}

// createJob creates a new job with specified type and filename
func (cq *WorkQueue) createJob(jobType string, filename string) string {
	cq.mu.Lock()
	defer cq.mu.Unlock()

	jobID := fmt.Sprintf("%s_%d", jobType, time.Now().UnixNano())
	cq.activeJobs[jobID] = WI{
		ID:        jobID,
		StartTime: time.Now(),
		Filename:  filename,
		Active:    true,
		Type:      jobType,
	}

	return jobID
}

// completeJob marks a job as completed
func (cq *WorkQueue) completeJob(jobID string) {
	cq.mu.Lock()
	defer cq.mu.Unlock()

	if job, exists := cq.activeJobs[jobID]; exists {
		job.Active = false
		cq.activeJobs[jobID] = job
	}
}

// killJob terminates an active job
func (cq *WorkQueue) killJob(jobID string) error {
	cq.mu.Lock()
	defer cq.mu.Unlock()

	job, exists := cq.activeJobs[jobID]
	if !exists {
		return fmt.Errorf(ErrCtx(E26, jobID))
	}

	// Remove from active downloads if it's a download job
	if job.Type == jmTpl(idxJmTypeDownload) {
		delete(cq.activeDownloads, job.Filename)
	}

	delete(cq.activeJobs, jobID)
	return nil
}

// addOrUpdateDownload adds or updates a download operation
func (cq *WorkQueue) addOrUpdateDownload(filename string, filepath string, totalChunks int) {
	cq.mu.Lock()
	defer cq.mu.Unlock()

	if downloadInfo, exists := cq.activeDownloads[filename]; exists {
		downloadInfo.LastUpdate = time.Now()
		if !downloadInfo.InProgress {
			downloadInfo.InProgress = true
		}
	} else {
		cq.activeDownloads[filename] = &FI{
			FilePath:    filepath,
			TotalChunks: totalChunks,
			NextChunk:   1,
			LastUpdate:  time.Now(),
			InProgress:  true,
		}
	}
}

// updateDownloadProgress updates the progress of a download operation
func (cq *WorkQueue) updateDownloadProgress(filename string, chunkNum int) {
	cq.mu.Lock()
	defer cq.mu.Unlock()

	if downloadInfo, exists := cq.activeDownloads[filename]; exists {
		downloadInfo.NextChunk = chunkNum + 1
		downloadInfo.LastUpdate = time.Now()
		if downloadInfo.NextChunk > downloadInfo.TotalChunks {
			downloadInfo.InProgress = false
		}
	}
}
