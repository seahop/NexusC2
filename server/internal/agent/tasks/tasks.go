// internal/agent/tasks/tasks.go
package tasks

import "log"

type TaskQueue struct {
	tasks chan string
}

func NewTaskQueue() *TaskQueue {
	return &TaskQueue{
		tasks: make(chan string, 100),
	}
}

func (tq *TaskQueue) Process() {
	for task := range tq.tasks {
		log.Printf("Processing task: %s", task)
	}
}

func (tq *TaskQueue) AddTask(task string) {
	tq.tasks <- task
}
