// internal/common/utils/retry.go
package utils

import (
	"log"
	"runtime"
	"runtime/debug"
	"time"
)

// RetryWithExponentialBackoff attempts an operation with exponential backoff.
// It retries up to 30 times (~5 minutes total) with delays from 1s to 30s.
func RetryWithExponentialBackoff(operation func() error) error {
	maxRetries := 30
	baseDelay := 1 * time.Second
	maxDelay := 30 * time.Second
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		err := operation()
		if err == nil {
			return nil
		}
		lastErr = err
		delay := baseDelay * time.Duration(1<<uint(attempt))
		if delay > maxDelay {
			delay = maxDelay
		}
		log.Printf("Attempt %d failed: %v. Retrying in %v...", attempt+1, err, delay)
		time.Sleep(delay)
	}
	return lastErr
}

// ConfigureRuntime sets GOMAXPROCS and GC percentage for optimal performance.
func ConfigureRuntime() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetGCPercent(100)
	log.Printf("Runtime configured: GOMAXPROCS=%d", runtime.GOMAXPROCS(0))
}
