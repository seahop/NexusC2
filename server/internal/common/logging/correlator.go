// server/internal/common/logging/correlator.go
package logging

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// CommandExecution represents a correlated command and its output
type CommandExecution struct {
	CommandID    interface{} `json:"command_id"`
	AgentID      string      `json:"agent_id"`
	Username     string      `json:"username,omitempty"`
	Command      string      `json:"command"`
	CommandTime  time.Time   `json:"command_time"`
	Output       string      `json:"output,omitempty"`
	OutputTime   *time.Time  `json:"output_time,omitempty"`
	OutputSize   int         `json:"output_size,omitempty"`
	ResponseTime float64     `json:"response_time_seconds,omitempty"` // Time between command and output
	Status       string      `json:"status"`                          // "sent", "completed", "error", "pending"

	// Enhanced fields from LogEntry
	Hostname   string `json:"hostname,omitempty"`
	ExternalIP string `json:"external_ip,omitempty"`
	InternalIP string `json:"internal_ip,omitempty"`
	OS         string `json:"os,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
}

// LogCorrelator correlates command logs with their outputs
type LogCorrelator struct {
	executions map[string]*CommandExecution // Key is "agentID:commandID"
	byTime     []*CommandExecution
}

// NewLogCorrelator creates a new log correlator
func NewLogCorrelator() *LogCorrelator {
	return &LogCorrelator{
		executions: make(map[string]*CommandExecution),
		byTime:     make([]*CommandExecution, 0),
	}
}

// ProcessLogFile reads and correlates logs from a file
func (lc *LogCorrelator) ProcessLogFile(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue // Skip malformed entries
		}
		lc.ProcessEntry(entry)
	}

	return scanner.Err()
}

// ProcessEntry processes a single log entry
func (lc *LogCorrelator) ProcessEntry(entry LogEntry) {
	switch entry.Type {
	case "command":
		lc.processCommand(entry)
	case "output":
		lc.processOutput(entry)
	case "error":
		lc.processError(entry)
	}
}

// processCommand handles command log entries
func (lc *LogCorrelator) processCommand(entry LogEntry) {
	// Create a key for this command
	key := lc.makeKey(entry.AgentID, entry.CommandID)

	// Check if we already have this command
	if exec, exists := lc.executions[key]; exists {
		// Update with any missing info
		if entry.Username != "" && exec.Username == "" {
			exec.Username = entry.Username
		}
		if entry.Hostname != "" && exec.Hostname == "" {
			exec.Hostname = entry.Hostname
		}
		if entry.ExternalIP != "" && exec.ExternalIP == "" {
			exec.ExternalIP = entry.ExternalIP
		}
		if entry.InternalIP != "" && exec.InternalIP == "" {
			exec.InternalIP = entry.InternalIP
		}
		if entry.OS != "" && exec.OS == "" {
			exec.OS = entry.OS
		}
		if entry.SessionID != "" && exec.SessionID == "" {
			exec.SessionID = entry.SessionID
		}
		return
	}

	// Create new execution entry
	exec := &CommandExecution{
		CommandID:   entry.CommandID,
		AgentID:     entry.AgentID,
		Username:    entry.Username,
		Command:     entry.Command,
		CommandTime: entry.Timestamp,
		Status:      "sent",
		// Add enhanced fields
		Hostname:   entry.Hostname,
		ExternalIP: entry.ExternalIP,
		InternalIP: entry.InternalIP,
		OS:         entry.OS,
		SessionID:  entry.SessionID,
	}

	lc.executions[key] = exec
	lc.byTime = append(lc.byTime, exec)
}

// processOutput handles output log entries
func (lc *LogCorrelator) processOutput(entry LogEntry) {
	key := lc.makeKey(entry.AgentID, entry.CommandID)

	if exec, exists := lc.executions[key]; exists {
		exec.Output = entry.Output
		exec.OutputTime = &entry.Timestamp
		exec.OutputSize = entry.OutputSize
		exec.Status = "completed"

		// Calculate response time
		if exec.OutputTime != nil {
			exec.ResponseTime = exec.OutputTime.Sub(exec.CommandTime).Seconds()
		}
	} else {
		// Output without command - create partial entry
		outputTime := entry.Timestamp
		exec := &CommandExecution{
			CommandID:  entry.CommandID,
			AgentID:    entry.AgentID,
			Output:     entry.Output,
			OutputTime: &outputTime,
			OutputSize: entry.OutputSize,
			Status:     "completed",
		}
		lc.executions[key] = exec
		lc.byTime = append(lc.byTime, exec)
	}
}

// processError handles error log entries
func (lc *LogCorrelator) processError(entry LogEntry) {
	key := fmt.Sprintf("%s:error:%d", entry.AgentID, entry.Timestamp.Unix())

	exec := &CommandExecution{
		AgentID:     entry.AgentID,
		Command:     entry.Command,
		CommandTime: entry.Timestamp,
		Output:      entry.Error,
		Status:      "error",
	}

	lc.executions[key] = exec
	lc.byTime = append(lc.byTime, exec)
}

// makeKey creates a unique key for command correlation
func (lc *LogCorrelator) makeKey(agentID string, commandID interface{}) string {
	return fmt.Sprintf("%s:%v", agentID, commandID)
}

// GetExecutions returns all correlated executions
func (lc *LogCorrelator) GetExecutions() []*CommandExecution {
	seen := make(map[string]*CommandExecution)
	deduplicated := make([]*CommandExecution, 0)

	// Process all executions, using command ID as the primary deduplication key
	for _, exec := range lc.byTime {
		// Create a unique key based on agent ID and command ID
		// This ensures each command is only counted once
		var dedupKey string

		// If we have a command ID, use it for deduplication
		if exec.CommandID != nil && exec.CommandID != "" && exec.CommandID != 0 {
			dedupKey = fmt.Sprintf("%s:%v", exec.AgentID, exec.CommandID)
		} else {
			// Fallback to command + timestamp if no command ID
			dedupKey = fmt.Sprintf("%s:%s:%d",
				exec.AgentID,
				exec.Command,
				exec.CommandTime.Unix())
		}

		if existing, exists := seen[dedupKey]; exists {
			// If we already have this command, keep the one with more information
			// Prefer completed over sent status
			if exec.Status == "completed" && existing.Status != "completed" {
				seen[dedupKey] = exec
			} else if exec.Status == existing.Status {
				// If same status, keep the one with more fields populated
				if exec.Output != "" && existing.Output == "" {
					seen[dedupKey] = exec
				} else if exec.Username != "" && existing.Username == "" {
					// Update missing fields
					existing.Username = exec.Username
				}
			}
		} else {
			seen[dedupKey] = exec
		}
	}

	// Convert map to slice
	for _, exec := range seen {
		deduplicated = append(deduplicated, exec)
	}

	// Sort by command time
	sort.Slice(deduplicated, func(i, j int) bool {
		return deduplicated[i].CommandTime.Before(deduplicated[j].CommandTime)
	})

	return deduplicated
}

// GetExecutionsByAgent returns executions for a specific agent
func (lc *LogCorrelator) GetExecutionsByAgent(agentID string) []*CommandExecution {
	executions := lc.GetExecutions() // This already deduplicates
	var results []*CommandExecution

	for _, exec := range executions {
		if exec.AgentID == agentID {
			results = append(results, exec)
		}
	}
	return results
}

// GetPendingExecutions returns commands without outputs
func (lc *LogCorrelator) GetPendingExecutions() []*CommandExecution {
	var pending []*CommandExecution

	for _, exec := range lc.GetExecutions() {
		if exec.Status == "sent" && exec.OutputTime == nil {
			pending = append(pending, exec)
		}
	}
	return pending
}

// GetStats returns statistics about the executions
func (lc *LogCorrelator) GetStats() map[string]interface{} {
	executions := lc.GetExecutions() // Use deduplicated list

	totalCommands := len(executions)
	completedCommands := 0
	pendingCommands := 0
	errorCommands := 0
	totalResponseTime := 0.0
	minResponseTime := 999999.0
	maxResponseTime := 0.0

	for _, exec := range executions {
		switch exec.Status {
		case "completed":
			completedCommands++
			if exec.ResponseTime > 0 {
				totalResponseTime += exec.ResponseTime
				if exec.ResponseTime < minResponseTime {
					minResponseTime = exec.ResponseTime
				}
				if exec.ResponseTime > maxResponseTime {
					maxResponseTime = exec.ResponseTime
				}
			}
		case "sent":
			pendingCommands++
		case "error":
			errorCommands++
		}
	}

	avgResponseTime := 0.0
	if completedCommands > 0 {
		avgResponseTime = totalResponseTime / float64(completedCommands)
	}

	if minResponseTime == 999999.0 {
		minResponseTime = 0
	}

	return map[string]interface{}{
		"total_commands":     totalCommands,
		"completed_commands": completedCommands,
		"pending_commands":   pendingCommands,
		"error_commands":     errorCommands,
		"avg_response_time":  avgResponseTime,
		"min_response_time":  minResponseTime,
		"max_response_time":  maxResponseTime,
	}
}

// FormatExecution formats an execution for display
func FormatExecution(exec *CommandExecution) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("=== Command Execution ===\n"))
	sb.WriteString(fmt.Sprintf("Command ID: %v\n", exec.CommandID))
	sb.WriteString(fmt.Sprintf("Agent ID: %s\n", exec.AgentID))

	if exec.Username != "" {
		sb.WriteString(fmt.Sprintf("User: %s\n", exec.Username))
	}

	// Add enhanced fields if available
	if exec.Hostname != "" {
		sb.WriteString(fmt.Sprintf("Hostname: %s\n", exec.Hostname))
	}
	if exec.ExternalIP != "" || exec.InternalIP != "" {
		sb.WriteString(fmt.Sprintf("IPs: %s / %s\n", exec.ExternalIP, exec.InternalIP))
	}
	if exec.OS != "" {
		sb.WriteString(fmt.Sprintf("OS: %s\n", exec.OS))
	}
	if exec.SessionID != "" {
		sb.WriteString(fmt.Sprintf("Session: %s\n", exec.SessionID))
	}

	sb.WriteString(fmt.Sprintf("Command: %s\n", exec.Command))
	sb.WriteString(fmt.Sprintf("Sent: %s\n", exec.CommandTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Status: %s\n", exec.Status))

	if exec.OutputTime != nil {
		sb.WriteString(fmt.Sprintf("Output received: %s\n", exec.OutputTime.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Response time: %.3f seconds\n", exec.ResponseTime))
		sb.WriteString(fmt.Sprintf("Output size: %d bytes\n", exec.OutputSize))

		if exec.Output != "" {
			sb.WriteString("Output:\n")
			sb.WriteString(exec.Output)
			if !strings.HasSuffix(exec.Output, "\n") {
				sb.WriteString("\n")
			}
		}
	} else if exec.Status == "sent" {
		sb.WriteString("Output: [Pending]\n")
	}

	return sb.String()
}
