// sever/docker/payloads/Darwin/actions_queue.go

//go:build darwin
// +build darwin

package main

import (
	"sync"
)

const maxResultQueueSize = 1000 // Prevent unbounded memory growth during network outages

type OutputManager struct {
	mu      sync.Mutex
	results []*OpResult
}

func NewResultManager() *OutputManager {
	return &OutputManager{
		results: make([]*OpResult, 0, 100), // Pre-allocate reasonable capacity
	}
}

func (rm *OutputManager) addResult(result *OpResult) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// If queue is full, drop oldest results (FIFO)
	// This prevents memory exhaustion during prolonged network outages
	// while preserving most recent command outputs
	if len(rm.results) >= maxResultQueueSize {
		// Drop oldest 10% to avoid frequent single-item drops
		dropCount := maxResultQueueSize / 10
		if dropCount < 1 {
			dropCount = 1
		}
		rm.results = rm.results[dropCount:]
	}

	rm.results = append(rm.results, result)
	return nil
}

func (rm *OutputManager) hasResults() bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	return len(rm.results) > 0
}

func (rm *OutputManager) getPendingResults() []OpResp {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if len(rm.results) == 0 {
		return nil
	}

	responses := make([]OpResp, len(rm.results))
	for i, result := range rm.results {

		responses[i] = OpResp{
			Cmd:      result.Cmd.Cmd,
			CID:    result.Cmd.CID,
			DID:  result.Cmd.DID,
			AID:      result.Cmd.AID,
			Filename:     result.Cmd.Filename,
			CurrentChunk: result.Cmd.CurrentChunk,
			TotalChunks:  result.Cmd.TotalChunks,
			Data:         result.Cmd.Data,
			Output:       result.Output,
			EC:     result.EC,
			Timestamp:    result.Done,
		}
		if result.Error != nil {
			responses[i].Error = result.Error.Error()
		}
	}

	// Clear the results after retrieving them
	rm.results = make([]*OpResult, 0)

	return responses
}
