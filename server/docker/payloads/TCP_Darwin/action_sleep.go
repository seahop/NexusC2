// server/docker/payloads/Linux/action_sleep.go

//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type IntervalMsg struct{}

// parseDuration parses duration strings like "1h2m3s", "5m30s", "60s"
func parseDuration(input string) (int, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return 0, fmt.Errorf(E22)
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
			return 0, fmt.Errorf(E22)
		}

		value, err := strconv.Atoi(currentNumber)
		if err != nil {
			return 0, fmt.Errorf(E22)
		}

		switch char {
		case 'h':
			totalSeconds += value * 3600
		case 'm':
			totalSeconds += value * 60
		case 's':
			totalSeconds += value
		default:
			return 0, fmt.Errorf(E22)
		}

		currentNumber = ""
	}

	// Handle case where there are trailing numbers without a unit
	if currentNumber != "" {
		value, err := strconv.Atoi(currentNumber)
		if err != nil {
			return 0, fmt.Errorf(E22)
		}
		// Assume seconds if no unit specified
		totalSeconds += value
	}

	return totalSeconds, nil
}

func (c *IntervalMsg) execute(ctx *OpCtx, args []string) OpResult {
	// Validate arguments
	if len(args) == 0 || len(args) > 2 {
		return OpResult{
			Error:       fmt.Errorf(Err(E2)),
			EStr: Err(E2),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Parse the duration
	seconds, err := parseDuration(args[0])
	if err != nil {
		return OpResult{
			Error:       fmt.Errorf(Err(E28)),
			EStr: Err(E28),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Validate the sleep value
	if seconds < 1 {
		return OpResult{
			Error:       fmt.Errorf(Err(E28)),
			EStr: Err(E28),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Handle optional jitter parameter
	if len(args) == 2 {
		// Parse jitter percentage
		jitterValue, err := strconv.ParseFloat(args[1], 64)
		if err != nil {
			return OpResult{
				Error:       fmt.Errorf(Err(E29)),
				EStr: Err(E29),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}
		if jitterValue < 0 || jitterValue > 100 {
			return OpResult{
				Error:       fmt.Errorf(Err(E29)),
				EStr: Err(E29),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}
		jitter = fmt.Sprintf("%.1f", jitterValue)
	}

	// Update the global sleep value
	sleep = strconv.Itoa(seconds)

	// Format output message - minimal
	output := SuccCtx(S3, fmt.Sprintf("%ds/%s%%", seconds, jitter))

	return OpResult{
		Output:      output,
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}
