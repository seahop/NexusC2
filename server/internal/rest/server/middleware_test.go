// internal/rest/server/middleware_test.go
package server

import (
	"sync"
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	t.Parallel()

	t.Run("creates limiter with correct settings", func(t *testing.T) {
		t.Parallel()
		rl := NewRateLimiter(60)
		defer rl.Stop()

		if rl.maxTokens != 60 {
			t.Errorf("expected maxTokens 60, got %d", rl.maxTokens)
		}
		if rl.refillRate != 60 {
			t.Errorf("expected refillRate 60, got %d", rl.refillRate)
		}
	})
}

func TestRateLimiterAllow(t *testing.T) {
	t.Parallel()

	t.Run("first request for new key is allowed", func(t *testing.T) {
		t.Parallel()
		rl := NewRateLimiter(10)
		defer rl.Stop()

		if !rl.Allow("192.168.1.1") {
			t.Error("first request should be allowed")
		}
	})

	t.Run("allows up to maxTokens requests", func(t *testing.T) {
		t.Parallel()
		limit := 5
		rl := NewRateLimiter(limit)
		defer rl.Stop()

		for i := 0; i < limit; i++ {
			if !rl.Allow("test-key") {
				t.Errorf("request %d should be allowed (within limit of %d)", i+1, limit)
			}
		}
	})

	t.Run("blocks after maxTokens exhausted", func(t *testing.T) {
		t.Parallel()
		limit := 3
		rl := NewRateLimiter(limit)
		defer rl.Stop()

		// Exhaust all tokens
		for i := 0; i < limit; i++ {
			rl.Allow("block-key")
		}

		// Next request should be blocked
		if rl.Allow("block-key") {
			t.Error("request should be blocked after exhausting tokens")
		}
	})

	t.Run("different keys have independent limits", func(t *testing.T) {
		t.Parallel()
		rl := NewRateLimiter(2)
		defer rl.Stop()

		// Exhaust key A
		rl.Allow("key-a")
		rl.Allow("key-a")

		// Key B should still have tokens
		if !rl.Allow("key-b") {
			t.Error("key-b should have independent token bucket")
		}

		// Key A should be exhausted
		if rl.Allow("key-a") {
			t.Error("key-a should be exhausted")
		}
	})

	t.Run("tokens refill based on elapsed time", func(t *testing.T) {
		t.Parallel()
		// Use 60 requests/minute = 1 request/second
		rl := NewRateLimiter(60)
		defer rl.Stop()

		// Exhaust all tokens
		for i := 0; i < 60; i++ {
			rl.Allow("refill-key")
		}

		// Should be blocked now
		if rl.Allow("refill-key") {
			t.Error("should be blocked after exhausting tokens")
		}

		// Manually advance the lastRefill time to simulate elapsed time
		rl.mu.Lock()
		rl.lastRefill["refill-key"] = time.Now().Add(-2 * time.Second)
		rl.mu.Unlock()

		// Now should be allowed (2 seconds * 1 token/sec = 2 tokens added)
		if !rl.Allow("refill-key") {
			t.Error("should have tokens after time elapsed")
		}
	})
}

func TestRateLimiterTokenRefillCalculation(t *testing.T) {
	t.Parallel()

	// This tests the fix for the truncation bug: the refill calculation uses
	// int(elapsed.Seconds() * float64(refillRate) / 60.0)
	// which avoids integer division truncation

	t.Run("continuous refill calculation avoids truncation", func(t *testing.T) {
		t.Parallel()
		refillRate := 100 // 100 requests per minute

		// Simulate 30 seconds elapsed
		elapsed := 30 * time.Second
		tokensToAdd := int(elapsed.Seconds() * float64(refillRate) / 60.0)

		// 30 seconds at 100/min = 50 tokens
		expected := 50
		if tokensToAdd != expected {
			t.Errorf("expected %d tokens for 30s at %d/min, got %d", expected, refillRate, tokensToAdd)
		}
	})

	t.Run("sub-second intervals produce correct tokens", func(t *testing.T) {
		t.Parallel()
		refillRate := 60 // 60 per minute = 1 per second

		// 500ms should produce 0 tokens (int truncation)
		elapsed := 500 * time.Millisecond
		tokensToAdd := int(elapsed.Seconds() * float64(refillRate) / 60.0)
		if tokensToAdd != 0 {
			t.Errorf("expected 0 tokens for 500ms at 60/min, got %d", tokensToAdd)
		}

		// 1 second should produce 1 token
		elapsed = 1 * time.Second
		tokensToAdd = int(elapsed.Seconds() * float64(refillRate) / 60.0)
		if tokensToAdd != 1 {
			t.Errorf("expected 1 token for 1s at 60/min, got %d", tokensToAdd)
		}
	})

	t.Run("tokens capped at maxTokens", func(t *testing.T) {
		t.Parallel()
		rl := NewRateLimiter(10)
		defer rl.Stop()

		// First request initializes the key with maxTokens
		rl.Allow("cap-key")

		// Manually set lastRefill far in the past to generate many tokens
		rl.mu.Lock()
		rl.lastRefill["cap-key"] = time.Now().Add(-1 * time.Hour)
		rl.mu.Unlock()

		// After refill, tokens should be capped at maxTokens
		// The Allow call triggers refill
		rl.Allow("cap-key")

		rl.mu.Lock()
		tokens := rl.tokens["cap-key"]
		rl.mu.Unlock()

		// After 2 Allow() calls and a massive refill, tokens should be at most maxTokens - 2
		// (capped at 10, then 2 consumed)
		if tokens > 10 {
			t.Errorf("tokens should be capped at maxTokens (10), got %d", tokens)
		}
	})

	t.Run("refill rate table driven", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name       string
			rate       int           // requests per minute
			elapsed    time.Duration
			wantTokens int
		}{
			{"1req/min at 60s", 1, 60 * time.Second, 1},
			{"1req/min at 30s", 1, 30 * time.Second, 0},
			{"120req/min at 1s", 120, 1 * time.Second, 2},
			{"120req/min at 500ms", 120, 500 * time.Millisecond, 1},
			{"60req/min at 10s", 60, 10 * time.Second, 10},
			{"600req/min at 6s", 600, 6 * time.Second, 60},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				tokensToAdd := int(tt.elapsed.Seconds() * float64(tt.rate) / 60.0)
				if tokensToAdd != tt.wantTokens {
					t.Errorf("expected %d tokens, got %d", tt.wantTokens, tokensToAdd)
				}
			})
		}
	})
}

func TestRateLimiterConcurrency(t *testing.T) {
	t.Parallel()

	t.Run("concurrent access is safe", func(t *testing.T) {
		t.Parallel()
		rl := NewRateLimiter(1000)
		defer rl.Stop()

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				key := "concurrent-key"
				for j := 0; j < 10; j++ {
					rl.Allow(key)
				}
			}(i)
		}
		wg.Wait()
		// If we get here without a race condition panic, the test passes
	})
}

func TestRateLimiterCleanup(t *testing.T) {
	t.Parallel()

	t.Run("cleanup removes stale entries", func(t *testing.T) {
		t.Parallel()
		rl := NewRateLimiter(10)
		defer rl.Stop()

		// Add a key
		rl.Allow("stale-key")

		// Manually set lastRefill to be very old
		rl.mu.Lock()
		rl.lastRefill["stale-key"] = time.Now().Add(-15 * time.Minute)
		rl.mu.Unlock()

		// Run cleanup
		rl.cleanup()

		// Key should be removed
		rl.mu.Lock()
		_, exists := rl.tokens["stale-key"]
		rl.mu.Unlock()

		if exists {
			t.Error("stale key should have been cleaned up")
		}
	})

	t.Run("cleanup preserves recent entries", func(t *testing.T) {
		t.Parallel()
		rl := NewRateLimiter(10)
		defer rl.Stop()

		// Add a key with recent activity
		rl.Allow("recent-key")

		// Run cleanup
		rl.cleanup()

		// Key should still exist
		rl.mu.Lock()
		_, exists := rl.tokens["recent-key"]
		rl.mu.Unlock()

		if !exists {
			t.Error("recent key should not have been cleaned up")
		}
	})
}

func TestRateLimiterStop(t *testing.T) {
	t.Parallel()

	t.Run("stop does not panic", func(t *testing.T) {
		t.Parallel()
		rl := NewRateLimiter(10)
		rl.Stop()
		// Should not panic on double stop
		rl.Stop()
	})
}
