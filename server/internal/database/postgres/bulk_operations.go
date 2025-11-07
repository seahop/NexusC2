// internal/database/postgres/bulk_operations.go
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"
)

// BulkOperator handles bulk database operations
type BulkOperator struct {
	db            *sql.DB
	batchSize     int
	maxRetries    int
	preparedStmts map[string]*sql.Stmt
}

// NewBulkOperator creates a new bulk operator
func NewBulkOperator(db *sql.DB, batchSize int) (*BulkOperator, error) {
	// Use default batch size if not specified
	if batchSize <= 0 {
		batchSize = 100
	}

	bo := &BulkOperator{
		db:            db,
		batchSize:     batchSize,
		maxRetries:    3,
		preparedStmts: make(map[string]*sql.Stmt),
	}

	// Prepare commonly used statements
	if err := bo.prepareStatements(); err != nil {
		return nil, err
	}

	return bo, nil
}

// prepareStatements prepares commonly used bulk statements
func (bo *BulkOperator) prepareStatements() error {
	// These are templates that will be built dynamically
	// based on batch size
	return nil
}

// BulkInsertResults performs optimized bulk insert of agent results
func (bo *BulkOperator) BulkInsertResults(ctx context.Context, results []ResultData) error {
	if len(results) == 0 {
		return nil
	}

	startTime := time.Now()
	totalInserted := 0

	// Process in batches
	for i := 0; i < len(results); i += bo.batchSize {
		end := i + bo.batchSize
		if end > len(results) {
			end = len(results)
		}

		batch := results[i:end]
		if err := bo.insertResultBatch(ctx, batch); err != nil {
			// Try individual inserts as fallback
			log.Printf("[BulkOperator] Batch insert failed, falling back to individual inserts: %v", err)
			for _, result := range batch {
				if err := bo.insertSingleResult(ctx, result); err != nil {
					log.Printf("[BulkOperator] Failed to insert result %d: %v", result.CommandID, err)
				} else {
					totalInserted++
				}
			}
		} else {
			totalInserted += len(batch)
		}
	}

	duration := time.Since(startTime)
	log.Printf("[BulkOperator] Inserted %d/%d results in %v (%.2f results/sec)",
		totalInserted, len(results), duration,
		float64(totalInserted)/duration.Seconds())

	return nil
}

// insertResultBatch inserts a batch of results
func (bo *BulkOperator) insertResultBatch(ctx context.Context, batch []ResultData) error {
	tx, err := bo.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Build the bulk insert query
	valueStrings := make([]string, 0, len(batch))
	valueArgs := make([]interface{}, 0, len(batch)*3)

	for i, result := range batch {
		valueStrings = append(valueStrings,
			fmt.Sprintf("($%d, $%d, $%d)", i*3+1, i*3+2, i*3+3))
		valueArgs = append(valueArgs, result.CommandID, result.Output, result.Timestamp)
	}

	query := fmt.Sprintf(`
		INSERT INTO results (command_id, output, timestamp) 
		VALUES %s 
		ON CONFLICT (command_id) 
		DO UPDATE SET 
			output = EXCLUDED.output,
			timestamp = EXCLUDED.timestamp`,
		strings.Join(valueStrings, ","))

	if _, err := tx.ExecContext(ctx, query, valueArgs...); err != nil {
		return fmt.Errorf("bulk insert failed: %w", err)
	}

	return tx.Commit()
}

// insertSingleResult inserts a single result (fallback)
func (bo *BulkOperator) insertSingleResult(ctx context.Context, result ResultData) error {
	query := `
		INSERT INTO results (command_id, output, timestamp) 
		VALUES ($1, $2, $3) 
		ON CONFLICT (command_id) 
		DO UPDATE SET 
			output = EXCLUDED.output,
			timestamp = EXCLUDED.timestamp`

	_, err := bo.db.ExecContext(ctx, query, result.CommandID, result.Output, result.Timestamp)
	return err
}

// BulkUpdateAgentStatus performs bulk update of agent statuses
func (bo *BulkOperator) BulkUpdateAgentStatus(ctx context.Context, updates []AgentStatusUpdate) error {
	if len(updates) == 0 {
		return nil
	}

	startTime := time.Now()

	tx, err := bo.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Use CASE statements for bulk update
	agentIDs := make([]string, 0, len(updates))
	whenClauses := make([]string, 0, len(updates))
	statusClauses := make([]string, 0, len(updates))
	metadataClauses := make([]string, 0, len(updates))

	for _, update := range updates {
		agentIDs = append(agentIDs, fmt.Sprintf("'%s'", update.AgentID))
		whenClauses = append(whenClauses,
			fmt.Sprintf("WHEN newclientID = '%s' THEN '%s'::timestamp",
				update.AgentID, update.LastSeen.Format(time.RFC3339)))
		statusClauses = append(statusClauses,
			fmt.Sprintf("WHEN newclientID = '%s' THEN '%s'",
				update.AgentID, update.Status))
		if update.Metadata != "" {
			metadataClauses = append(metadataClauses,
				fmt.Sprintf("WHEN newclientID = '%s' THEN metadata || '%s'::jsonb",
					update.AgentID, update.Metadata))
		}
	}

	query := fmt.Sprintf(`
		UPDATE connections 
		SET 
			lastSEEN = CASE %s END,
			status = CASE %s END
			%s
		WHERE newclientID IN (%s)`,
		strings.Join(whenClauses, " "),
		strings.Join(statusClauses, " "),
		func() string {
			if len(metadataClauses) > 0 {
				return fmt.Sprintf(", metadata = CASE %s ELSE metadata END",
					strings.Join(metadataClauses, " "))
			}
			return ""
		}(),
		strings.Join(agentIDs, ","))

	if _, err := tx.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("bulk update failed: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	duration := time.Since(startTime)
	log.Printf("[BulkOperator] Updated %d agent statuses in %v", len(updates), duration)

	return nil
}

// BulkInsertCommands inserts multiple commands efficiently
func (bo *BulkOperator) BulkInsertCommands(ctx context.Context, commands []CommandData) ([]int, error) {
	if len(commands) == 0 {
		return nil, nil
	}

	commandIDs := make([]int, 0, len(commands))

	// Process in batches
	for i := 0; i < len(commands); i += bo.batchSize {
		end := i + bo.batchSize
		if end > len(commands) {
			end = len(commands)
		}

		batch := commands[i:end]
		ids, err := bo.insertCommandBatch(ctx, batch)
		if err != nil {
			return commandIDs, err
		}
		commandIDs = append(commandIDs, ids...)
	}

	return commandIDs, nil
}

// insertCommandBatch inserts a batch of commands
func (bo *BulkOperator) insertCommandBatch(ctx context.Context, batch []CommandData) ([]int, error) {
	tx, err := bo.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	commandIDs := make([]int, 0, len(batch))

	// Use a prepared statement for batch inserts
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO commands (agent_id, command, parameters, priority, status) 
		VALUES ($1, $2, $3, $4, $5) 
		RETURNING id`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	for _, cmd := range batch {
		var id int
		err := stmt.QueryRowContext(ctx,
			cmd.AgentID, cmd.Command, cmd.Parameters, cmd.Priority, cmd.Status,
		).Scan(&id)
		if err != nil {
			return commandIDs, err
		}
		commandIDs = append(commandIDs, id)
	}

	return commandIDs, tx.Commit()
}

// Close closes all prepared statements
func (bo *BulkOperator) Close() error {
	for _, stmt := range bo.preparedStmts {
		if err := stmt.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Data structures for bulk operations

type ResultData struct {
	CommandID int
	Output    string
	Timestamp time.Time
}

type AgentStatusUpdate struct {
	AgentID  string
	LastSeen time.Time
	Status   string
	Metadata string // JSON string
}

type CommandData struct {
	AgentID    string
	Command    string
	Parameters string // JSON string
	Priority   int
	Status     string
}
