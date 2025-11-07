// internal/agent/cache/result_cache.go
package cache

import (
	"container/list"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// ResultCache implements an LRU cache for agent results
type ResultCache struct {
	maxSize      int
	ttl          time.Duration
	items        map[string]*cacheItem
	evictionList *list.List
	mu           sync.RWMutex

	// Metrics
	hits      atomic.Uint64
	misses    atomic.Uint64
	evictions atomic.Uint64

	// Background cleanup
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// cacheItem represents a cached item
type cacheItem struct {
	key         string
	value       interface{}
	size        int
	expiry      time.Time
	element     *list.Element
	accessCount atomic.Uint64
}

// NewResultCache creates a new result cache
func NewResultCache(maxSize int, ttl time.Duration) *ResultCache {
	cache := &ResultCache{
		maxSize:      maxSize,
		ttl:          ttl,
		items:        make(map[string]*cacheItem),
		evictionList: list.New(),
		stopChan:     make(chan struct{}),
	}

	// Start background cleanup
	cache.wg.Add(1)
	go cache.cleanupExpired()

	return cache
}

// Get retrieves a value from cache
func (rc *ResultCache) Get(ctx context.Context, key string) (interface{}, bool) {
	rc.mu.RLock()
	item, exists := rc.items[key]
	rc.mu.RUnlock()

	if !exists {
		rc.misses.Add(1)
		return nil, false
	}

	// Check expiry
	if time.Now().After(item.expiry) {
		rc.mu.Lock()
		rc.removeElement(item.element)
		rc.mu.Unlock()
		rc.misses.Add(1)
		return nil, false
	}

	// Move to front (MRU)
	rc.mu.Lock()
	rc.evictionList.MoveToFront(item.element)
	rc.mu.Unlock()

	item.accessCount.Add(1)
	rc.hits.Add(1)

	return item.value, true
}

// Set adds or updates a value in cache
func (rc *ResultCache) Set(key string, value interface{}, sizeHint int) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Check if exists
	if item, exists := rc.items[key]; exists {
		// Update existing
		item.value = value
		item.expiry = time.Now().Add(rc.ttl)
		item.size = sizeHint
		rc.evictionList.MoveToFront(item.element)
		return
	}

	// Create new item
	item := &cacheItem{
		key:    key,
		value:  value,
		size:   sizeHint,
		expiry: time.Now().Add(rc.ttl),
	}

	// Add to front
	element := rc.evictionList.PushFront(item)
	item.element = element
	rc.items[key] = item

	// Check if need to evict
	if rc.evictionList.Len() > rc.maxSize {
		rc.evictOldest()
	}
}

// SetWithTTL adds value with custom TTL
func (rc *ResultCache) SetWithTTL(key string, value interface{}, ttl time.Duration) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if item, exists := rc.items[key]; exists {
		item.value = value
		item.expiry = time.Now().Add(ttl)
		rc.evictionList.MoveToFront(item.element)
		return
	}

	item := &cacheItem{
		key:    key,
		value:  value,
		expiry: time.Now().Add(ttl),
	}

	element := rc.evictionList.PushFront(item)
	item.element = element
	rc.items[key] = item

	if rc.evictionList.Len() > rc.maxSize {
		rc.evictOldest()
	}
}

// Delete removes item from cache
func (rc *ResultCache) Delete(key string) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	item, exists := rc.items[key]
	if !exists {
		return false
	}

	rc.removeElement(item.element)
	return true
}

// evictOldest removes LRU item
func (rc *ResultCache) evictOldest() {
	oldest := rc.evictionList.Back()
	if oldest != nil {
		rc.removeElement(oldest)
		rc.evictions.Add(1)
	}
}

// removeElement removes element from cache
func (rc *ResultCache) removeElement(element *list.Element) {
	item := element.Value.(*cacheItem)
	delete(rc.items, item.key)
	rc.evictionList.Remove(element)
}

// cleanupExpired runs background cleanup
func (rc *ResultCache) cleanupExpired() {
	defer rc.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rc.stopChan:
			return
		case <-ticker.C:
			rc.removeExpired()
		}
	}
}

// removeExpired removes expired items
func (rc *ResultCache) removeExpired() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	now := time.Now()
	var toRemove []*list.Element

	for element := rc.evictionList.Back(); element != nil; element = element.Prev() {
		item := element.Value.(*cacheItem)
		if now.After(item.expiry) {
			toRemove = append(toRemove, element)
		}
	}

	for _, element := range toRemove {
		rc.removeElement(element)
		rc.evictions.Add(1)
	}

	if len(toRemove) > 0 {
		log.Printf("[ResultCache] Cleaned %d expired items", len(toRemove))
	}
}

// GetMetrics returns cache metrics
func (rc *ResultCache) GetMetrics() map[string]interface{} {
	rc.mu.RLock()
	size := rc.evictionList.Len()
	rc.mu.RUnlock()

	hits := rc.hits.Load()
	misses := rc.misses.Load()
	total := hits + misses

	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	return map[string]interface{}{
		"size":      size,
		"max_size":  rc.maxSize,
		"hits":      hits,
		"misses":    misses,
		"evictions": rc.evictions.Load(),
		"hit_rate":  fmt.Sprintf("%.2f%%", hitRate),
		"ttl":       rc.ttl,
	}
}

// Flush clears all items
func (rc *ResultCache) Flush() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.items = make(map[string]*cacheItem)
	rc.evictionList.Init()

	log.Printf("[ResultCache] Cache flushed")
}

// Stop gracefully stops the cache
func (rc *ResultCache) Stop() {
	close(rc.stopChan)
	rc.wg.Wait()
	rc.Flush()
}

// AgentResultCache extends ResultCache for agent-specific caching
type AgentResultCache struct {
	*ResultCache
	db *sql.DB
}

// NewAgentResultCache creates agent-specific cache
func NewAgentResultCache(maxSize int, ttl time.Duration, db *sql.DB) *AgentResultCache {
	return &AgentResultCache{
		ResultCache: NewResultCache(maxSize, ttl),
		db:          db,
	}
}

// GetWithFallback tries cache first, then database
func (arc *AgentResultCache) GetWithFallback(ctx context.Context, key string) (interface{}, error) {
	// Try cache first
	if value, found := arc.Get(ctx, key); found {
		return value, nil
	}

	// Fallback to database
	if arc.db == nil {
		return nil, fmt.Errorf("cache miss and no database configured")
	}

	var data json.RawMessage
	query := `SELECT data FROM agent_cache WHERE key = $1 AND expiry > NOW()`

	err := arc.db.QueryRowContext(ctx, query, key).Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("key not found")
		}
		return nil, err
	}

	var value interface{}
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}

	// Cache for next time
	arc.Set(key, value, len(data))

	return value, nil
}

// SaveToDatabase persists cache item to database
func (arc *AgentResultCache) SaveToDatabase(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if arc.db == nil {
		return fmt.Errorf("database not configured")
	}

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO agent_cache (key, data, expiry) 
		VALUES ($1, $2, $3)
		ON CONFLICT (key) 
		DO UPDATE SET data = $2, expiry = $3`

	expiry := time.Now().Add(ttl)
	_, err = arc.db.ExecContext(ctx, query, key, data, expiry)

	return err
}
