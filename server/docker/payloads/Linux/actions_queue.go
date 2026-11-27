// server/docker/payloads/Linux/actions_queue.go

//go:build linux
// +build linux

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

func estimateResultSize(r *OpResult) int {
	s := len(r.Output) + len(r.Cmd.Data) + 256
	if r.Error != nil {
		s += len(r.Error.Error())
	}
	return s
}

func (rm *OutputManager) getPendingResults(maxBytes int) []OpResp {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if len(rm.results) == 0 {
		return nil
	}

	if maxBytes <= 0 {
		responses := make([]OpResp, len(rm.results))
		for i, result := range rm.results {
			responses[i] = resultToResp(result)
		}
		rm.results = make([]*OpResult, 0)
		return responses
	}

	var responses []OpResp
	usedBytes := 0
	for i, result := range rm.results {
		est := estimateResultSize(result)
		if len(responses) > 0 && usedBytes+est > maxBytes {
			rm.results = rm.results[i:]
			return responses
		}
		responses = append(responses, resultToResp(result))
		usedBytes += est
	}

	rm.results = make([]*OpResult, 0)
	return responses
}

func resultToResp(result *OpResult) OpResp {
	resp := OpResp{
		Cmd:          result.Cmd.Cmd,
		CID:          result.Cmd.CID,
		DID:          result.Cmd.DID,
		AID:          result.Cmd.AID,
		Filename:     result.Cmd.Filename,
		CurrentChunk: result.Cmd.CurrentChunk,
		TotalChunks:  result.Cmd.TotalChunks,
		Data:         result.Cmd.Data,
		Output:       result.Output,
		EC:           result.EC,
		Timestamp:    result.Done,
	}
	if result.Error != nil {
		resp.Error = result.Error.Error()
	}
	return resp
}
