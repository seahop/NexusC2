# File Transfers

## Overview

NexusC2 implements bidirectional file transfer between the server and agents using a chunked transfer protocol. This allows efficient transfer of large files while maintaining progress tracking and supporting resumption on network interruptions.

**Transfer Types:**
- **Upload** (Server → Agent): Push files to agent filesystem
- **Download** (Agent → Server): Pull files from agent filesystem

**Key Features:**
- Chunked transfer with configurable sizes
- In-memory and disk-based chunk assembly
- Progress tracking and status reporting
- UNC path support for Windows network shares
- Automatic cleanup of temporary files

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    UPLOAD FLOW (Server → Agent)                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  GUI Client                                                     │
│      │                                                          │
│      │ 1. Select file + destination path                        │
│      ▼                                                          │
│  WebSocket Service                                              │
│      │  - Receives file chunks from client                      │
│      │  - Assembles complete file in /app/uploads               │
│      │  - Notifies Agent Handler via gRPC                       │
│      ▼                                                          │
│  Agent Handler Service                                          │
│      │  - Reads assembled file                                  │
│      │  - Splits into 512KB chunks                              │
│      │  - Queues first chunk for agent                          │
│      │  - Stores remaining chunks on disk                       │
│      ▼                                                          │
│  Agent (Payload)                                                │
│      │  - Receives chunk in GET response                        │
│      │  - Stores chunk in memory map                            │
│      │  - When all chunks received, assembles file              │
│      │  - Writes to destination path                            │
│      ▼                                                          │
│  Destination File                                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                  DOWNLOAD FLOW (Agent → Server)                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  GUI Client                                                     │
│      │                                                          │
│      │ 1. Issue download command with path                      │
│      ▼                                                          │
│  Agent (Payload)                                                │
│      │  - Opens file, calculates total chunks                   │
│      │  - Reads first 512KB chunk                               │
│      │  - Returns chunk with POST results                       │
│      ▼                                                          │
│  Agent Handler Service                                          │
│      │  - Receives chunk in POST request                        │
│      │  - Writes chunk to temp file (.partN)                    │
│      │  - Queues "download_continue" for next chunk             │
│      ▼                                                          │
│  Agent (Payload)                                                │
│      │  - Receives download_continue command                    │
│      │  - Seeks to offset, reads next chunk                     │
│      │  - Returns chunk with POST results                       │
│      │  ... repeats until all chunks sent ...                   │
│      ▼                                                          │
│  Server (Download Tracker)                                      │
│      │  - Assembles all .partN files in order                   │
│      │  - Writes final file to /app/downloads                   │
│      │  - Updates downloads.json manifest                       │
│      │  - Cleans up temp files                                  │
│      ▼                                                          │
│  GUI Client                                                     │
│      │  - Receives download notification                        │
│      │  - Can fetch file from downloads list                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Upload (Server → Agent)

### Chunk Configuration

| Property | Value |
|----------|-------|
| Chunk Size | 512 KB (524,288 bytes) |
| Encoding | Base64 |
| Storage | In-memory (agent), disk (server) |

### Server-Side Processing

#### Step 1: GUI Client Upload

The GUI client sends file chunks to the WebSocket service:

```json
{
  "type": "file_upload",
  "data": {
    "upload_id": "uuid",
    "agent_id": "target-agent-uuid",
    "file_name": "payload.exe",
    "remote_path": "C:\\Windows\\Temp\\payload.exe",
    "chunk_num": 0,
    "total_chunks": 10,
    "chunk_data": "<base64 encoded data>",
    "file_size": 5242880
  }
}
```

#### Step 2: WebSocket Service Assembly

1. Creates temp directory: `/app/temp/{upload_id}/`
2. Writes each chunk to: `chunk_0`, `chunk_1`, etc.
3. When all chunks received, assembles to: `/app/uploads/{filename}_{timestamp}.ext`
4. Notifies Agent Handler via gRPC `HandleUpload`

#### Step 3: Agent Handler Processing

1. Reads assembled file from `/app/uploads/`
2. Calculates total chunks (512KB each)
3. Queues first chunk to agent's command buffer
4. Stores remaining chunks to disk: `/app/temp/{filename}/chunk_N`
5. Saves metadata for chunk continuation

**Metadata Structure:**
```json
{
  "agent_id": "agent-uuid",
  "command_db_id": 42,
  "original_filename": "payload.exe",
  "current_filename": "payload_20250115_103000.exe",
  "remote_path": "C:\\Windows\\Temp\\payload.exe",
  "total_chunks": 10,
  "chunk_dir": "/app/temp/payload_20250115_103000.exe",
  "current_chunk": 0
}
```

### Agent-Side Processing

#### Chunk Reception

Chunks arrive in GET poll responses as commands:

```json
{
  "command_type": 16,
  "command": "upload",
  "filename": "payload_20250115_103000.exe",
  "remote_path": "C:\\Windows\\Temp\\payload.exe",
  "current_chunk": 0,
  "total_chunks": 10,
  "data": "<base64 encoded chunk>"
}
```

#### In-Memory Assembly

The agent maintains active uploads in memory:

```go
type UploadInfo struct {
    Chunks      map[int][]byte  // Chunk index → data
    TotalChunks int
    RemotePath  string
    Filename    string
    StartTime   time.Time
    LastUpdate  time.Time
}
```

**Processing Steps:**
1. Base64 decode chunk data
2. Store in `Chunks` map by index
3. Update `LastUpdate` timestamp
4. If last chunk received:
   - Create parent directories (with network share support)
   - Write chunks in order to destination file
   - Clear chunks from memory as written
   - Clean up tracking state

### Path Resolution

The agent supports multiple path formats:

| Format | Example | Handling |
|--------|---------|----------|
| Absolute (Unix) | `/etc/config` | Used directly |
| Absolute (Windows) | `C:\Windows\Temp` | Used directly |
| UNC Path | `\\server\share\file` | Special handling for network auth |
| Relative | `payload.exe` | Joined with working directory |

**UNC Path Handling:**
```go
// Normalize to backslashes for UNC
workingDir = strings.ReplaceAll(workingDir, "/", "\\")
if !strings.HasSuffix(workingDir, "\\") {
    workingDir += "\\"
}
remotePath = workingDir + args[0]
```

---

## Download (Agent → Server)

### Chunk Configuration

| Property | Value |
|----------|-------|
| Chunk Size | 512 KB (524,288 bytes) |
| Encoding | Base64 |
| Buffer Pool | Reusable 512KB buffers |

### Agent-Side Processing

#### Initial Command

When the agent receives a download command:

```go
// Buffer pool for memory efficiency
var downloadBufferPool = sync.Pool{
    New: func() interface{} {
        buf := make([]byte, 512*1024) // 512KB
        return &buf
    },
}
```

**Processing Steps:**
1. Resolve path (absolute, relative, or UNC)
2. Open file, get size information
3. Calculate total chunks
4. Read first chunk using pooled buffer
5. Base64 encode and return with metadata
6. Register download with internal tracker

#### Chunk Continuation

When server requests next chunk via `download_continue`:

```go
func GetNextFileChunk(filePath string, chunkNumber int, originalCmd Command) (*CommandResult, error) {
    file, err := NetworkAwareOpenFile(filePath, os.O_RDONLY, 0)
    // ...

    // Seek to correct position
    offset := int64(chunkNumber-1) * chunkSize
    file.Seek(offset, 0)

    // Read chunk using buffer pool
    bufPtr := downloadBufferPool.Get().(*[]byte)
    defer downloadBufferPool.Put(bufPtr)
    chunk := *bufPtr
    n, err := file.Read(chunk)

    // Encode and return
    encodedData := base64.StdEncoding.EncodeToString(chunk[:n])
    // ...
}
```

### Server-Side Processing

#### Download Tracker

The server tracks in-progress downloads:

```go
type DownloadTracker struct {
    mu              sync.RWMutex
    ongoing         map[string]map[int]bool  // filename → received chunks
    tempPath        string                    // /app/temp
    destPath        string                    // /app/downloads
    manifestManager *ManifestManager
}
```

#### Chunk Storage

Each chunk is stored as a separate file:

```
/app/temp/
├── payload.exe.part1
├── payload.exe.part2
├── payload.exe.part3
...
```

#### File Assembly

When all chunks received:

```go
func (dt *DownloadTracker) assembleFile(filename string, totalChunks int) error {
    destPath := filepath.Join(dt.destPath, filename)
    outFile, err := os.Create(destPath)

    // Assemble chunks in order
    for i := 1; i <= totalChunks; i++ {
        chunkPath := filepath.Join(dt.tempPath, fmt.Sprintf("%s.part%d", filename, i))
        chunkData, _ := os.ReadFile(chunkPath)
        outFile.Write(chunkData)
        os.Remove(chunkPath)  // Clean up as we go
    }

    // Add to manifest
    dt.manifestManager.AddDownload(filename)
    return nil
}
```

### Downloads Manifest

Completed downloads are tracked in `/app/downloads/downloads.json`:

```json
{
  "downloads": [
    {
      "filename": "secrets.txt",
      "size": 1024,
      "timestamp": "2025-01-15T10:30:00Z"
    },
    {
      "filename": "config.ini",
      "size": 2048,
      "timestamp": "2025-01-15T11:00:00Z"
    }
  ]
}
```

---

## Progress Tracking

### Upload Progress

The server tracks upload progress in real-time:

```go
type ProgressStats struct {
    Filename   string
    Current    int64
    Total      int64
    Percentage float64
    Speed      float64  // bytes per second
}
```

**Logged Output:**
```
[Progress] File: payload.exe, Current: 1048576/5242880 bytes (20.00%), Speed: 2.50 MB/s
```

### Download Progress

Downloads report progress via command output:

```
S4:1/10   → "Progress: 1/10"
S4:2/10   → "Progress: 2/10"
...
S5:payload.exe → "File successfully written: payload.exe"
```

---

## Error Handling

### Upload Errors

| Error Code | Description |
|------------|-------------|
| E1 | Missing arguments (no path specified) |
| E11 | Failed to create file or write data |
| E24 | Missing chunk data or incomplete upload |

### Download Errors

| Error Code | Description |
|------------|-------------|
| E1 | Missing arguments (no path specified) |
| E6 | Path is a directory (not a file) |
| E10 | Cannot read file (permissions, not found) |
| E24 | No data returned (empty chunk) |

### Recovery Behavior

- **Timeout**: Stale uploads are cleaned up based on `LastUpdate` timestamp
- **Interruption**: Partial downloads remain as `.partN` files until retry
- **Memory Pressure**: Agent clears chunks from memory as they're written

---

## Network Share Support

### Windows UNC Paths

The agent supports Windows network shares via `NetworkAwareOpenFile`:

```go
// Handles paths like \\server\share\path\file.txt
func NetworkAwareOpenFile(path string, flag int, perm os.FileMode) (*os.File, error)

// Creates directories on network shares
func NetworkAwareMkdirAll(path string, perm os.FileMode) error
```

**Features:**
- Automatic authentication with current user token
- Network-only impersonation support
- SMB share traversal

---

## Data Flow Summary

### Upload (Server → Agent)

```
1. GUI sends file chunks to WebSocket (100KB chunks)
2. WebSocket assembles file in /app/uploads
3. WebSocket notifies Agent Handler via gRPC
4. Agent Handler reads file, splits to 512KB chunks
5. Agent Handler queues first chunk to command buffer
6. Agent Handler stores remaining chunks on disk
7. Agent receives chunk in GET response
8. Agent stores chunk in memory map
9. Agent Handler queues next chunk (repeat 6-8)
10. Agent assembles all chunks to destination file
```

### Download (Agent → Server)

```
1. GUI issues download command
2. Agent receives command in GET response
3. Agent opens file, reads first 512KB chunk
4. Agent returns chunk in POST results
5. Server stores chunk as .part1 file
6. Server queues download_continue command
7. Agent receives continue, reads next chunk
8. Agent returns chunk in POST results
9. Server stores chunk (repeat 6-8)
10. Server assembles all parts to final file
11. Server updates downloads.json manifest
12. GUI notified of completed download
```

---

## Related Files

| Component | File Path |
|-----------|-----------|
| Agent Upload Handler | `server/docker/payloads/Linux/action_upload.go` |
| Agent Download Handler | `server/docker/payloads/Linux/action_download.go` |
| Server Upload Handler | `server/internal/agent/server/upload.go` |
| Server Download Tracker | `server/internal/agent/listeners/handle_downloads.go` |
| WebSocket Upload Handler | `server/internal/websocket/handlers/upload.go` |
| WebSocket File Operations | `server/internal/websocket/handlers/file_operations.go` |
| Server Upload Tracker | `server/internal/agent/listeners/upload_tracker.go` |
| Downloads Manifest | `server/internal/agent/listeners/manifest.go` |
