// internal/common/progress/tracker.go

package progress

import (
	"sync"
	"time"
)

type Stats struct {
	Filename    string
	Total       int64
	Current     int64
	Percentage  float64
	Speed       float64 // bytes per second
	TimeElapsed time.Duration
	TimeLeft    time.Duration
}

type Tracker struct {
	mu          sync.RWMutex
	stats       map[string]*Stats       // Changed from progress to stats
	subscribers map[chan Stats]struct{} // Added subscribers
}

func NewTracker() *Tracker {
	return &Tracker{
		stats:       make(map[string]*Stats),
		subscribers: make(map[chan Stats]struct{}),
	}
}

func (t *Tracker) UpdateProgress(filename string, currentBytes int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if stats, exists := t.stats[filename]; exists {
		stats.Current = currentBytes
		// Let track() handle the calculations
	}
}

func (t *Tracker) Subscribe() chan Stats {
	ch := make(chan Stats, 10)
	t.mu.Lock()
	t.subscribers[ch] = struct{}{}
	t.mu.Unlock()
	return ch
}

func (t *Tracker) Unsubscribe(ch chan Stats) {
	t.mu.Lock()
	delete(t.subscribers, ch)
	t.mu.Unlock()
	close(ch)
}

func (t *Tracker) StartTracking(filename string, totalSize int64) {
	t.mu.Lock()
	t.stats[filename] = &Stats{
		Filename: filename,
		Total:    totalSize,
		Current:  0,
	}
	t.mu.Unlock()
	go t.track(filename)
}

func (t *Tracker) track(filename string) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	start := time.Now()
	var lastBytes int64

	for {
		<-ticker.C

		t.mu.RLock()
		stats, exists := t.stats[filename]
		if !exists {
			t.mu.RUnlock()
			return
		}

		elapsed := time.Since(start)
		speed := float64(stats.Current-lastBytes) / elapsed.Seconds()
		percentage := float64(stats.Current) / float64(stats.Total) * 100
		timeLeft := time.Duration(float64(stats.Total-stats.Current) / speed * float64(time.Second))

		stats.Speed = speed
		stats.Percentage = percentage
		stats.TimeElapsed = elapsed
		stats.TimeLeft = timeLeft

		// Make a copy for broadcasting
		statsCopy := *stats
		t.mu.RUnlock()

		// Broadcast updates
		t.broadcast(statsCopy)

		lastBytes = stats.Current
	}
}

func (t *Tracker) broadcast(stats Stats) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for ch := range t.subscribers {
		select {
		case ch <- stats:
		default:
			// Skip if channel is blocked
		}
	}
}

func (t *Tracker) GetProgress(filename string) (*Stats, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	stats, exists := t.stats[filename] // Changed from t.progress to t.stats
	if !exists {
		return nil, false
	}
	// Return a copy to avoid race conditions
	statsCopy := *stats
	return &statsCopy, true
}
