// server/docker/payloads/Windows/actions_queue.go
//go:build windows
// +build windows

package main

import (
	"sync"
)

type ResultManager struct {
	mu      sync.Mutex
	results []*CommandResult
}

func NewResultManager() *ResultManager {
	return &ResultManager{
		results: make([]*CommandResult, 0),
	}
}

func (rm *ResultManager) AddResult(result *CommandResult) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.results = append(rm.results, result)
	return nil
}

func (rm *ResultManager) HasResults() bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	return len(rm.results) > 0
}

func (rm *ResultManager) GetPendingResults() []CommandResponse {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if len(rm.results) == 0 {
		return nil
	}

	// ADD DEBUG LOGGING HERE

	responses := make([]CommandResponse, len(rm.results))
	for i, result := range rm.results {
		// ADD DEBUG FOR EACH RESULT

		responses[i] = CommandResponse{
			Command:      result.Command.Command,
			CommandID:    result.Command.CommandID,
			CommandDBID:  result.Command.CommandDBID,
			AgentID:      result.Command.AgentID,
			Filename:     result.Command.Filename,
			CurrentChunk: result.Command.CurrentChunk,
			TotalChunks:  result.Command.TotalChunks,
			Data:         result.Command.Data,
			Output:       result.Output,
			ExitCode:     result.ExitCode,
			Timestamp:    result.CompletedAt,
		}
		if result.Error != nil {
			responses[i].Error = result.Error.Error()
		}
	}

	// Clear the results after retrieving them
	rm.results = make([]*CommandResult, 0)

	return responses
}
