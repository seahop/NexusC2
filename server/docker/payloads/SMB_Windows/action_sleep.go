// server/docker/payloads/Windows/action_sleep.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type SleepCommand struct{}

func (c *SleepCommand) Name() string {
	return "sleep"
}

// parseDuration parses duration strings like "1h2m3s", "5m30s", "60s"
func parseDuration(input string) (int, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return 0, fmt.Errorf("empty duration")
	}

	var totalSeconds int
	var currentNumber string

	for i := 0; i < len(input); i++ {
		char := input[i]

		if unicode.IsDigit(rune(char)) {
			currentNumber += string(char)
			continue
		}

		if currentNumber == "" {
			return 0, fmt.Errorf("invalid duration format")
		}

		value, err := strconv.Atoi(currentNumber)
		if err != nil {
			return 0, fmt.Errorf("invalid number in duration: %v", err)
		}

		switch char {
		case 'h':
			totalSeconds += value * 3600
		case 'm':
			totalSeconds += value * 60
		case 's':
			totalSeconds += value
		default:
			return 0, fmt.Errorf("invalid unit '%c' in duration", char)
		}

		currentNumber = ""
	}

	// Handle case where there are trailing numbers without a unit
	if currentNumber != "" {
		value, err := strconv.Atoi(currentNumber)
		if err != nil {
			return 0, fmt.Errorf("invalid number in duration: %v", err)
		}
		// Assume seconds if no unit specified
		totalSeconds += value
	}

	return totalSeconds, nil
}

func (c *SleepCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Validate arguments
	if len(args) == 0 || len(args) > 2 {
		return CommandResult{
			Error:       fmt.Errorf("usage: sleep <duration> [jitter_percent]"),
			ErrorString: "usage: sleep <duration> [jitter_percent] (e.g., sleep 1m30s 15)",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Parse the duration
	seconds, err := parseDuration(args[0])
	if err != nil {
		return CommandResult{
			Error:       fmt.Errorf("invalid duration: %v", err),
			ErrorString: fmt.Sprintf("invalid duration: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Validate the sleep value
	if seconds < 1 {
		return CommandResult{
			Error:       fmt.Errorf("sleep duration must be at least 1 second"),
			ErrorString: "sleep duration must be at least 1 second",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Handle optional jitter parameter
	var jitterStr string
	if len(args) == 2 {
		// Parse jitter percentage
		jitterValue, err := strconv.ParseFloat(args[1], 64)
		if err != nil {
			return CommandResult{
				Error:       fmt.Errorf("invalid jitter percentage: %v", err),
				ErrorString: fmt.Sprintf("invalid jitter percentage: %v", err),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		if jitterValue < 0 || jitterValue > 100 {
			return CommandResult{
				Error:       fmt.Errorf("jitter percentage must be between 0 and 100"),
				ErrorString: "jitter percentage must be between 0 and 100",
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		jitter = fmt.Sprintf("%.1f", jitterValue)
		jitterStr = fmt.Sprintf(" and jitter to %.1f%%", jitterValue)
	}

	// Update the global sleep value
	sleep = strconv.Itoa(seconds)

	// Format output message
	var output string
	if seconds >= 3600 {
		hours := seconds / 3600
		minutes := (seconds % 3600) / 60
		secs := seconds % 60
		if minutes > 0 || secs > 0 {
			output = fmt.Sprintf("Sleep interval updated to %dh%dm%ds (%d seconds)%s",
				hours, minutes, secs, seconds, jitterStr)
		} else {
			output = fmt.Sprintf("Sleep interval updated to %dh (%d seconds)%s",
				hours, seconds, jitterStr)
		}
	} else if seconds >= 60 {
		minutes := seconds / 60
		secs := seconds % 60
		if secs > 0 {
			output = fmt.Sprintf("Sleep interval updated to %dm%ds (%d seconds)%s",
				minutes, secs, seconds, jitterStr)
		} else {
			output = fmt.Sprintf("Sleep interval updated to %dm (%d seconds)%s",
				minutes, seconds, jitterStr)
		}
	} else {
		output = fmt.Sprintf("Sleep interval updated to %ds%s", seconds, jitterStr)
	}

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
