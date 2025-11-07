// internal/common/interfaces/command_buffer.go
package interfaces

type CommandBuffer interface {
	GetCommand(clientID string) ([]string, bool)
	StoreCommand(clientID string, command string, username string)
	DeleteCommand(clientID string)
	BroadcastResult(result map[string]interface{}) error
	BroadcastLastSeen(agentID string, timestamp int64) error
	QueueDownloadCommand(clientID string, downloadCmd map[string]interface{}) error
	QueueUploadNextChunk(agentID string, chunkDir string) error
}
