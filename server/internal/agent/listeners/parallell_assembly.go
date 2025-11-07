// internal/agent/listeners/parallel_assembly.go

package listeners

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

type chunk struct {
	index int
	data  []byte
}

func assembleFileParallel(chunkDir, destPath string, totalChunks int, progressCh chan<- int64) error {
	// Create destination file
	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %v", err)
	}
	defer destFile.Close()

	// Create worker pool
	numWorkers := runtime.NumCPU()
	jobs := make(chan chunk, totalChunks)
	results := make(chan chunk, totalChunks)
	errors := make(chan error, 1)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				chunkPath := filepath.Join(chunkDir, fmt.Sprintf("chunk_%d", job.index))
				data, err := os.ReadFile(chunkPath)
				if err != nil {
					select {
					case errors <- fmt.Errorf("failed to read chunk %d: %v", job.index, err):
					default:
					}
					return
				}
				results <- chunk{index: job.index, data: data}
			}
		}()
	}

	// Feed jobs to workers
	go func() {
		for i := 0; i < totalChunks; i++ {
			jobs <- chunk{index: i}
		}
		close(jobs)
	}()

	// Create a goroutine to wait for workers and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Create a buffer to hold chunks that arrive out of order
	buffer := make(map[int][]byte)
	nextChunk := 0
	var bytesWritten int64

	// Process results and write to file in order
	for result := range results {
		select {
		case err := <-errors:
			return err
		default:
			buffer[result.index] = result.data

			// Write any chunks that are next in sequence
			for {
				if data, ok := buffer[nextChunk]; ok {
					n, err := destFile.Write(data)
					if err != nil {
						return fmt.Errorf("failed to write chunk %d: %v", nextChunk, err)
					}

					bytesWritten += int64(n)
					if progressCh != nil {
						progressCh <- bytesWritten
					}

					delete(buffer, nextChunk)
					nextChunk++
				} else {
					break
				}
			}
		}
	}

	// Check if we wrote all chunks
	if nextChunk != totalChunks {
		return fmt.Errorf("incomplete file assembly: wrote %d of %d chunks", nextChunk, totalChunks)
	}

	return nil
}
