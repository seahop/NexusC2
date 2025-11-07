// internal/agent/handlers/handlers.go
package handlers

import (
	"c2/internal/agent/tasks"
	"database/sql"
)

type AgentHandler struct {
	db        *sql.DB
	taskQueue *tasks.TaskQueue
}

func NewAgentHandler(db *sql.DB, taskQueue *tasks.TaskQueue) *AgentHandler {
	return &AgentHandler{
		db:        db,
		taskQueue: taskQueue,
	}
}

// Placeholder method to illustrate functionality
func (ah *AgentHandler) HandleAgent(agentID string) {
	ah.taskQueue.AddTask("Task for agent " + agentID)
}
