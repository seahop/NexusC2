// server/internal/websocket/pool/buffer_pool.go
package pool

import (
	"sync"
)

// BufferPool manages reusable byte buffers to reduce GC pressure
type BufferPool struct {
	pools map[int]*sync.Pool
}

var (
	instance *BufferPool
	once     sync.Once
)

// GetBufferPool returns the singleton buffer pool instance
func GetBufferPool() *BufferPool {
	once.Do(func() {
		instance = &BufferPool{
			pools: map[int]*sync.Pool{
				1024:    {New: func() interface{} { b := make([]byte, 1024); return &b }},    // 1KB
				4096:    {New: func() interface{} { b := make([]byte, 4096); return &b }},    // 4KB
				16384:   {New: func() interface{} { b := make([]byte, 16384); return &b }},   // 16KB
				65536:   {New: func() interface{} { b := make([]byte, 65536); return &b }},   // 64KB
				262144:  {New: func() interface{} { b := make([]byte, 262144); return &b }},  // 256KB
				1048576: {New: func() interface{} { b := make([]byte, 1048576); return &b }}, // 1MB
				4194304: {New: func() interface{} { b := make([]byte, 4194304); return &b }}, // 4MB
			},
		}
	})
	return instance
}

// Get retrieves a buffer of at least the requested size
func (bp *BufferPool) Get(size int) *[]byte {
	// Find the smallest pool that fits
	for _, poolSize := range []int{1024, 4096, 16384, 65536, 262144, 1048576, 4194304} {
		if size <= poolSize {
			return bp.pools[poolSize].Get().(*[]byte)
		}
	}
	// If no pool is large enough, allocate a new buffer
	b := make([]byte, size)
	return &b
}

// Put returns a buffer to the appropriate pool
func (bp *BufferPool) Put(buf *[]byte) {
	if buf == nil {
		return
	}

	size := cap(*buf)
	// Clear the buffer before returning to pool
	*buf = (*buf)[:0]

	if pool, ok := bp.pools[size]; ok {
		pool.Put(buf)
	}
	// If buffer doesn't match any pool size, let GC handle it
}
