// internal/common/streaming/chunks.go

package streaming

import (
	"io"
	"os"
	"sync"
)

type ChunkStream struct {
	file      *os.File
	chunkSize int
	mu        sync.Mutex
}

func NewChunkStream(filePath string, chunkSize int) (*ChunkStream, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	return &ChunkStream{
		file:      file,
		chunkSize: chunkSize,
	}, nil
}

func (cs *ChunkStream) Stream(done chan struct{}) (<-chan []byte, <-chan error) {
	chunks := make(chan []byte)
	errChan := make(chan error, 1)

	go func() {
		defer cs.file.Close()
		defer close(chunks)
		defer close(errChan)

		buffer := make([]byte, cs.chunkSize)
		for {
			select {
			case <-done:
				return
			default:
				cs.mu.Lock()
				n, err := cs.file.Read(buffer)
				cs.mu.Unlock()

				if n > 0 {
					// Make a copy of the data to avoid buffer reuse issues
					chunk := make([]byte, n)
					copy(chunk, buffer[:n])
					chunks <- chunk
				}

				if err == io.EOF {
					return
				}
				if err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	return chunks, errChan
}

func (cs *ChunkStream) Close() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.file.Close()
}
