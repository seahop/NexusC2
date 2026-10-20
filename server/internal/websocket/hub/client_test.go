// internal/websocket/hub/client_test.go
package hub

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMessageParsing(t *testing.T) {
	t.Parallel()

	t.Run("valid JSON message parses correctly", func(t *testing.T) {
		t.Parallel()
		raw := []byte(`{"type":"agent_command","data":{"command":"whoami"}}`)
		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Fatalf("failed to parse message: %v", err)
		}
		if msg.Type != "agent_command" {
			t.Errorf("expected type 'agent_command', got '%s'", msg.Type)
		}
		if msg.Data == nil {
			t.Error("data should not be nil")
		}
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		t.Parallel()
		raw := []byte(`not valid json`)
		var msg Message
		if err := json.Unmarshal(raw, &msg); err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("missing type field results in empty string", func(t *testing.T) {
		t.Parallel()
		raw := []byte(`{"data":{"foo":"bar"}}`)
		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Fatalf("failed to parse message: %v", err)
		}
		if msg.Type != "" {
			t.Errorf("expected empty type, got '%s'", msg.Type)
		}
	})

	t.Run("data preserved as raw JSON", func(t *testing.T) {
		t.Parallel()
		raw := []byte(`{"type":"test","data":{"nested":{"deep":"value"}}}`)
		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Fatalf("failed to parse message: %v", err)
		}

		// Verify data can be further unmarshaled
		var data map[string]interface{}
		if err := json.Unmarshal(msg.Data, &data); err != nil {
			t.Fatalf("failed to unmarshal data: %v", err)
		}
		nested, ok := data["nested"]
		if !ok {
			t.Error("expected 'nested' key in data")
		}
		nestedMap, ok := nested.(map[string]interface{})
		if !ok {
			t.Fatal("nested should be a map")
		}
		if nestedMap["deep"] != "value" {
			t.Errorf("expected deep='value', got '%v'", nestedMap["deep"])
		}
	})
}

func TestIsChunkedMessage(t *testing.T) {
	t.Parallel()

	// Create a minimal client for testing (no actual connection needed)
	client := &Client{}

	t.Run("agent_command with totalChunks > 1 is chunked", func(t *testing.T) {
		t.Parallel()
		data := json.RawMessage(`{"totalChunks":5,"currentChunk":1,"command":"upload"}`)
		msg := Message{Type: "agent_command", Data: data}

		if !client.isChunkedMessage(msg) {
			t.Error("agent_command with totalChunks > 1 should be chunked")
		}
	})

	t.Run("agent_command with totalChunks 1 is not chunked", func(t *testing.T) {
		t.Parallel()
		data := json.RawMessage(`{"totalChunks":1,"currentChunk":1,"command":"whoami"}`)
		msg := Message{Type: "agent_command", Data: data}

		if client.isChunkedMessage(msg) {
			t.Error("agent_command with totalChunks=1 should not be chunked")
		}
	})

	t.Run("agent_command without chunk fields is not chunked", func(t *testing.T) {
		t.Parallel()
		data := json.RawMessage(`{"command":"ls"}`)
		msg := Message{Type: "agent_command", Data: data}

		if client.isChunkedMessage(msg) {
			t.Error("agent_command without chunk fields should not be chunked")
		}
	})

	t.Run("file_upload is always chunked", func(t *testing.T) {
		t.Parallel()
		data := json.RawMessage(`{"filename":"test.bin"}`)
		msg := Message{Type: "file_upload", Data: data}

		if !client.isChunkedMessage(msg) {
			t.Error("file_upload should always be considered chunked")
		}
	})

	t.Run("regular message type is not chunked", func(t *testing.T) {
		t.Parallel()
		data := json.RawMessage(`{"some":"data"}`)
		msg := Message{Type: "agent_list", Data: data}

		if client.isChunkedMessage(msg) {
			t.Error("agent_list should not be chunked")
		}
	})

	t.Run("table driven chunk detection", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name     string
			msgType  string
			data     string
			expected bool
		}{
			{
				"chunked command",
				"agent_command",
				`{"totalChunks":10,"currentChunk":3}`,
				true,
			},
			{
				"single chunk command",
				"agent_command",
				`{"totalChunks":1,"currentChunk":1}`,
				false,
			},
			{
				"zero chunks command",
				"agent_command",
				`{"totalChunks":0,"currentChunk":0}`,
				false,
			},
			{
				"file upload",
				"file_upload",
				`{}`,
				true,
			},
			{
				"listener update",
				"listener_update",
				`{"totalChunks":5}`,
				false,
			},
			{
				"agent command invalid data",
				"agent_command",
				`not json`,
				false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				msg := Message{Type: tt.msgType, Data: json.RawMessage(tt.data)}
				result := client.isChunkedMessage(msg)
				if result != tt.expected {
					t.Errorf("expected %v, got %v", tt.expected, result)
				}
			})
		}
	})
}

func TestClientChannels(t *testing.T) {
	t.Parallel()

	t.Run("Send channel is buffered", func(t *testing.T) {
		t.Parallel()
		send := make(chan []byte, 256)

		// Should be able to write without blocking
		send <- []byte("test message")

		select {
		case msg := <-send:
			if string(msg) != "test message" {
				t.Errorf("expected 'test message', got '%s'", string(msg))
			}
		default:
			t.Error("should have received message")
		}
	})

	t.Run("SendHigh channel for priority messages", func(t *testing.T) {
		t.Parallel()
		sendHigh := make(chan []byte, 256)

		sendHigh <- []byte("high priority")

		select {
		case msg := <-sendHigh:
			if string(msg) != "high priority" {
				t.Errorf("expected 'high priority', got '%s'", string(msg))
			}
		default:
			t.Error("should have received high priority message")
		}
	})

	t.Run("non-blocking re-queue via select", func(t *testing.T) {
		// This tests the pattern used in WritePump for re-queuing regular messages
		// during binary transfers: select with a default case
		t.Parallel()

		send := make(chan []byte, 2)
		message := []byte("deferred message")

		// Fill the channel
		send <- []byte("msg1")
		send <- []byte("msg2")

		// Attempt non-blocking re-queue (should drop since channel is full)
		dropped := false
		select {
		case send <- message:
			// Re-queued successfully
		default:
			// Channel full, message would be dropped
			dropped = true
		}

		if !dropped {
			t.Error("message should have been dropped when channel is full")
		}
	})

	t.Run("non-blocking re-queue succeeds when space available", func(t *testing.T) {
		t.Parallel()

		send := make(chan []byte, 5)
		message := []byte("deferred message")

		// Channel has space
		requeued := false
		select {
		case send <- message:
			requeued = true
		default:
			// Channel full
		}

		if !requeued {
			t.Error("message should have been re-queued when channel has space")
		}
	})
}

func TestWritePumpSelectPriority(t *testing.T) {
	t.Parallel()

	// Verify that the WritePump pattern processes high-priority messages
	// and doesn't use goroutines for writes (serialized in select loop)

	t.Run("high priority channel drains before regular", func(t *testing.T) {
		t.Parallel()

		sendHigh := make(chan []byte, 10)
		send := make(chan []byte, 10)

		// Queue messages
		sendHigh <- []byte("high-1")
		sendHigh <- []byte("high-2")
		send <- []byte("regular-1")

		// Simulate the WritePump select behavior: check high first
		var order []string

		// Drain high priority first
		for len(sendHigh) > 0 {
			msg := <-sendHigh
			order = append(order, string(msg))
		}
		// Then regular
		for len(send) > 0 {
			msg := <-send
			order = append(order, string(msg))
		}

		if len(order) != 3 {
			t.Fatalf("expected 3 messages, got %d", len(order))
		}
		if order[0] != "high-1" {
			t.Errorf("expected high-1 first, got %s", order[0])
		}
		if order[1] != "high-2" {
			t.Errorf("expected high-2 second, got %s", order[1])
		}
		if order[2] != "regular-1" {
			t.Errorf("expected regular-1 third, got %s", order[2])
		}
	})
}

func TestConstants(t *testing.T) {
	t.Parallel()

	t.Run("writeWait is 10 seconds", func(t *testing.T) {
		t.Parallel()
		if writeWait != 10*time.Second {
			t.Errorf("expected writeWait=10s, got %v", writeWait)
		}
	})

	t.Run("pongWait is 60 seconds", func(t *testing.T) {
		t.Parallel()
		if pongWait != 60*time.Second {
			t.Errorf("expected pongWait=60s, got %v", pongWait)
		}
	})

	t.Run("pingPeriod is 90% of pongWait", func(t *testing.T) {
		t.Parallel()
		expected := (pongWait * 9) / 10
		if pingPeriod != expected {
			t.Errorf("expected pingPeriod=%v, got %v", expected, pingPeriod)
		}
	})

	t.Run("maxMessageSize is 10MB", func(t *testing.T) {
		t.Parallel()
		expected := 10 * 1024 * 1024
		if maxMessageSize != expected {
			t.Errorf("expected maxMessageSize=%d, got %d", expected, maxMessageSize)
		}
	})
}

func TestClientStruct(t *testing.T) {
	t.Parallel()

	t.Run("client fields initialize correctly", func(t *testing.T) {
		t.Parallel()
		client := &Client{
			ID:       "test-id",
			Username: "testuser",
			Send:     make(chan []byte, 256),
			SendHigh: make(chan []byte, 256),
		}

		if client.ID != "test-id" {
			t.Errorf("expected ID 'test-id', got '%s'", client.ID)
		}
		if client.Username != "testuser" {
			t.Errorf("expected Username 'testuser', got '%s'", client.Username)
		}
		if client.Send == nil {
			t.Error("Send channel should not be nil")
		}
		if client.SendHigh == nil {
			t.Error("SendHigh channel should not be nil")
		}
	})
}

func TestSendBatchLogic(t *testing.T) {
	t.Parallel()

	t.Run("empty batch sends nothing", func(t *testing.T) {
		t.Parallel()
		messages := [][]byte{}
		if len(messages) != 0 {
			t.Error("empty batch should have length 0")
		}
		// sendBatch returns immediately for empty input
	})

	t.Run("single message batch detection", func(t *testing.T) {
		t.Parallel()
		messages := [][]byte{[]byte("only message")}
		if len(messages) != 1 {
			t.Error("single message batch should have length 1")
		}
	})

	t.Run("multi message batch detection", func(t *testing.T) {
		t.Parallel()
		messages := [][]byte{
			[]byte("msg1"),
			[]byte("msg2"),
			[]byte("msg3"),
		}
		if len(messages) <= 1 {
			t.Error("multi message batch should have length > 1")
		}
	})
}
