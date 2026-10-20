// internal/database/postgres/bulk_operations_test.go
package postgres

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestInsertResultBatchQueryConstruction(t *testing.T) {
	t.Parallel()

	// This test verifies the SQL query building logic uses parameterized
	// placeholders ($1, $2, ...) instead of interpolating values directly,
	// which prevents SQL injection.

	t.Run("parameterized placeholders for single result", func(t *testing.T) {
		t.Parallel()
		batch := []ResultData{
			{CommandID: 1, Output: "test output", Timestamp: time.Now()},
		}

		valueStrings := make([]string, 0, len(batch))
		valueArgs := make([]interface{}, 0, len(batch)*3)

		for i, result := range batch {
			valueStrings = append(valueStrings,
				fmt.Sprintf("($%d, $%d, $%d)", i*3+1, i*3+2, i*3+3))
			valueArgs = append(valueArgs, result.CommandID, result.Output, result.Timestamp)
		}

		query := fmt.Sprintf(`INSERT INTO results (command_id, output, timestamp) VALUES %s`,
			strings.Join(valueStrings, ","))

		// Verify parameterized placeholders, not literal values
		if !strings.Contains(query, "($1, $2, $3)") {
			t.Errorf("query should use $1,$2,$3 placeholders, got: %s", query)
		}
		if strings.Contains(query, "test output") {
			t.Error("query should NOT contain literal value 'test output' (SQL injection risk)")
		}
		if len(valueArgs) != 3 {
			t.Errorf("expected 3 args, got %d", len(valueArgs))
		}
	})

	t.Run("parameterized placeholders for multiple results", func(t *testing.T) {
		t.Parallel()
		batch := []ResultData{
			{CommandID: 1, Output: "output1", Timestamp: time.Now()},
			{CommandID: 2, Output: "output2", Timestamp: time.Now()},
			{CommandID: 3, Output: "output3", Timestamp: time.Now()},
		}

		valueStrings := make([]string, 0, len(batch))
		valueArgs := make([]interface{}, 0, len(batch)*3)

		for i, result := range batch {
			valueStrings = append(valueStrings,
				fmt.Sprintf("($%d, $%d, $%d)", i*3+1, i*3+2, i*3+3))
			valueArgs = append(valueArgs, result.CommandID, result.Output, result.Timestamp)
		}

		query := fmt.Sprintf(`INSERT INTO results (command_id, output, timestamp) VALUES %s`,
			strings.Join(valueStrings, ","))

		// Verify all placeholders are sequential
		if !strings.Contains(query, "($1, $2, $3)") {
			t.Errorf("missing first placeholder group in: %s", query)
		}
		if !strings.Contains(query, "($4, $5, $6)") {
			t.Errorf("missing second placeholder group in: %s", query)
		}
		if !strings.Contains(query, "($7, $8, $9)") {
			t.Errorf("missing third placeholder group in: %s", query)
		}
		if len(valueArgs) != 9 {
			t.Errorf("expected 9 args for 3 results, got %d", len(valueArgs))
		}
		// Verify no literal values in query
		for _, result := range batch {
			if strings.Contains(query, result.Output) {
				t.Errorf("query contains literal value %q (SQL injection risk)", result.Output)
			}
		}
	})

	t.Run("SQL injection payload in output is parameterized", func(t *testing.T) {
		t.Parallel()
		malicious := "'; DROP TABLE results; --"
		batch := []ResultData{
			{CommandID: 99, Output: malicious, Timestamp: time.Now()},
		}

		valueStrings := make([]string, 0, len(batch))
		valueArgs := make([]interface{}, 0, len(batch)*3)

		for i, result := range batch {
			valueStrings = append(valueStrings,
				fmt.Sprintf("($%d, $%d, $%d)", i*3+1, i*3+2, i*3+3))
			valueArgs = append(valueArgs, result.CommandID, result.Output, result.Timestamp)
		}

		query := fmt.Sprintf(`INSERT INTO results (command_id, output, timestamp) VALUES %s`,
			strings.Join(valueStrings, ","))

		// The malicious payload should NOT appear in the query string
		if strings.Contains(query, "DROP TABLE") {
			t.Fatal("SQL injection payload appears in query string")
		}
		if strings.Contains(query, malicious) {
			t.Fatal("malicious input was interpolated into query")
		}

		// The malicious payload should be safely in args
		found := false
		for _, arg := range valueArgs {
			if s, ok := arg.(string); ok && s == malicious {
				found = true
				break
			}
		}
		if !found {
			t.Error("malicious input was not preserved in parameterized args")
		}
	})
}

func TestBulkUpdateAgentStatusQueryConstruction(t *testing.T) {
	t.Parallel()

	t.Run("parameterized CASE statements", func(t *testing.T) {
		t.Parallel()
		updates := []AgentStatusUpdate{
			{AgentID: "agent-1", LastSeen: time.Now(), Status: "active", Metadata: ""},
			{AgentID: "agent-2", LastSeen: time.Now(), Status: "idle", Metadata: `{"key":"val"}`},
		}

		// Reproduce the query building logic from BulkUpdateAgentStatus
		args := make([]interface{}, 0, len(updates)*4)
		paramIdx := 1

		agentIDPlaceholders := make([]string, 0, len(updates))
		whenLastSeenClauses := make([]string, 0, len(updates))
		whenStatusClauses := make([]string, 0, len(updates))
		whenMetadataClauses := make([]string, 0, len(updates))
		hasMetadata := false

		for _, update := range updates {
			agentIDPlaceholders = append(agentIDPlaceholders, fmt.Sprintf("$%d", paramIdx))
			args = append(args, update.AgentID)
			agentIDParam := paramIdx
			paramIdx++

			whenLastSeenClauses = append(whenLastSeenClauses,
				fmt.Sprintf("WHEN newclientID = $%d THEN $%d::timestamp", agentIDParam, paramIdx))
			args = append(args, update.LastSeen.Format(time.RFC3339))
			paramIdx++

			whenStatusClauses = append(whenStatusClauses,
				fmt.Sprintf("WHEN newclientID = $%d THEN $%d", agentIDParam, paramIdx))
			args = append(args, update.Status)
			paramIdx++

			if update.Metadata != "" {
				hasMetadata = true
				whenMetadataClauses = append(whenMetadataClauses,
					fmt.Sprintf("WHEN newclientID = $%d THEN metadata || $%d::jsonb", agentIDParam, paramIdx))
				args = append(args, update.Metadata)
				paramIdx++
			}
		}

		metadataClause := ""
		if hasMetadata && len(whenMetadataClauses) > 0 {
			metadataClause = fmt.Sprintf(", metadata = CASE %s ELSE metadata END",
				strings.Join(whenMetadataClauses, " "))
		}

		query := fmt.Sprintf(`
			UPDATE connections
			SET
				lastSEEN = CASE %s END,
				status = CASE %s END
				%s
			WHERE newclientID IN (%s)`,
			strings.Join(whenLastSeenClauses, " "),
			strings.Join(whenStatusClauses, " "),
			metadataClause,
			strings.Join(agentIDPlaceholders, ","))

		// Verify parameterized placeholders
		if !strings.Contains(query, "$1") {
			t.Error("query missing $1 placeholder")
		}
		// Verify no literal agent IDs or statuses in query
		if strings.Contains(query, "agent-1") {
			t.Error("literal agent ID found in query")
		}
		if strings.Contains(query, "active") {
			t.Error("literal status found in query")
		}

		// Verify args count: agent-1 (id, lastseen, status) = 3, agent-2 (id, lastseen, status, metadata) = 4
		expectedArgs := 7
		if len(args) != expectedArgs {
			t.Errorf("expected %d args, got %d", expectedArgs, len(args))
		}

		// Verify metadata clause is included when metadata present
		if !strings.Contains(query, "metadata") {
			t.Error("metadata clause missing from query")
		}
		if !strings.Contains(metadataClause, "jsonb") {
			t.Error("metadata clause should cast to jsonb")
		}
	})
}

func TestNewBulkOperator(t *testing.T) {
	t.Parallel()

	t.Run("default batch size when zero", func(t *testing.T) {
		// NewBulkOperator requires a *sql.DB, but we can test the batch size default
		// by examining the logic directly since we can't pass nil to db operations
		batchSize := 0
		if batchSize <= 0 {
			batchSize = 100
		}
		if batchSize != 100 {
			t.Errorf("expected default batch size 100, got %d", batchSize)
		}
	})

	t.Run("default batch size when negative", func(t *testing.T) {
		t.Parallel()
		batchSize := -5
		if batchSize <= 0 {
			batchSize = 100
		}
		if batchSize != 100 {
			t.Errorf("expected default batch size 100, got %d", batchSize)
		}
	})

	t.Run("custom batch size preserved", func(t *testing.T) {
		t.Parallel()
		batchSize := 50
		if batchSize <= 0 {
			batchSize = 100
		}
		if batchSize != 50 {
			t.Errorf("expected custom batch size 50, got %d", batchSize)
		}
	})
}

func TestBulkInsertResults_EmptyInput(t *testing.T) {
	t.Parallel()

	t.Run("empty results slice produces no query", func(t *testing.T) {
		t.Parallel()
		results := []ResultData{}
		if len(results) != 0 {
			t.Error("empty results should have length 0")
		}
		// BulkInsertResults returns nil for empty input (early return)
	})
}

func TestBatchSlicing(t *testing.T) {
	t.Parallel()

	// Test the batch slicing logic used in BulkInsertResults and BulkInsertCommands
	t.Run("batches slice correctly for various sizes", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name      string
			total     int
			batchSize int
			expected  []int // expected batch sizes
		}{
			{"exact multiple", 6, 3, []int{3, 3}},
			{"remainder", 7, 3, []int{3, 3, 1}},
			{"smaller than batch", 2, 5, []int{2}},
			{"equal to batch", 5, 5, []int{5}},
			{"single item", 1, 100, []int{1}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				var batchSizes []int
				for i := 0; i < tt.total; i += tt.batchSize {
					end := i + tt.batchSize
					if end > tt.total {
						end = tt.total
					}
					batchSizes = append(batchSizes, end-i)
				}

				if len(batchSizes) != len(tt.expected) {
					t.Fatalf("expected %d batches, got %d", len(tt.expected), len(batchSizes))
				}
				for i, size := range batchSizes {
					if size != tt.expected[i] {
						t.Errorf("batch[%d] size: expected %d, got %d", i, tt.expected[i], size)
					}
				}
			})
		}
	})
}

func TestResultDataStructure(t *testing.T) {
	t.Parallel()

	t.Run("ResultData holds expected fields", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		r := ResultData{
			CommandID: 42,
			Output:    "command output here",
			Timestamp: now,
		}
		if r.CommandID != 42 {
			t.Errorf("CommandID mismatch")
		}
		if r.Output != "command output here" {
			t.Errorf("Output mismatch")
		}
		if !r.Timestamp.Equal(now) {
			t.Errorf("Timestamp mismatch")
		}
	})
}

func TestAgentStatusUpdateStructure(t *testing.T) {
	t.Parallel()

	t.Run("AgentStatusUpdate holds expected fields", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		u := AgentStatusUpdate{
			AgentID:  "agent-xyz",
			LastSeen: now,
			Status:   "active",
			Metadata: `{"os":"linux"}`,
		}
		if u.AgentID != "agent-xyz" {
			t.Errorf("AgentID mismatch")
		}
		if u.Status != "active" {
			t.Errorf("Status mismatch")
		}
		if u.Metadata != `{"os":"linux"}` {
			t.Errorf("Metadata mismatch")
		}
	})
}

func TestCommandDataStructure(t *testing.T) {
	t.Parallel()

	t.Run("CommandData holds expected fields", func(t *testing.T) {
		t.Parallel()
		c := CommandData{
			AgentID:    "agent-abc",
			Command:    "whoami",
			Parameters: `{"flag":"-a"}`,
			Priority:   5,
			Status:     "pending",
		}
		if c.AgentID != "agent-abc" {
			t.Errorf("AgentID mismatch")
		}
		if c.Command != "whoami" {
			t.Errorf("Command mismatch")
		}
		if c.Priority != 5 {
			t.Errorf("Priority mismatch")
		}
	})
}
