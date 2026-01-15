# Beacon Object File (BOF) Execution

## Overview

NexusC2 supports execution of Beacon Object Files (BOFs), which are position-independent COFF (Common Object File Format) objects that run directly in the agent's process memory. BOFs provide a lightweight mechanism for executing post-exploitation capabilities without dropping executables to disk.

**Key Features:**
- In-memory COFF loading and execution
- Cobalt Strike-compatible Beacon API implementation
- Synchronous and asynchronous execution modes
- Token impersonation support for network operations
- Large output chunking and streaming

**Platform:** Windows only (x86_64)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      BOF EXECUTION FLOW                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  GUI Client                                                     │
│      │                                                          │
│      │ 1. Select BOF file + arguments                           │
│      ▼                                                          │
│  WebSocket Service                                              │
│      │  - Base64 encode BOF bytes                               │
│      │  - Split into chunks if >512KB                           │
│      │  - Queue as 'bof' or 'bof-async' command                 │
│      ▼                                                          │
│  Agent (Windows Payload)                                        │
│      │  - Receive BOF via GET poll                              │
│      │  - Reassemble chunks if multi-part                       │
│      │  - Parse COFF headers and sections                       │
│      │  - Allocate RWX memory                                   │
│      │  - Resolve imports (Beacon API + Windows API)            │
│      │  - Apply relocations                                     │
│      │  - Execute entry point ("go" function)                   │
│      │  - Capture output via Beacon API                         │
│      ▼                                                          │
│  Server                                                         │
│      │  - Receive output in POST results                        │
│      │  - Display to GUI client                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## COFF Loader

### Parsing COFF Files

The loader uses the `pecoff` library to parse COFF object files:

```go
// Load function signature
func Load(coffBytes []byte, argBytes []byte) (string, error)
func LoadWithTimeout(coffBytes []byte, argBytes []byte, timeout time.Duration) (string, error)
```

### Memory Allocation

| Stage | Memory Protection |
|-------|-------------------|
| Initial allocation | `PAGE_READWRITE` |
| Section loading | `PAGE_READWRITE` |
| After relocation | `PAGE_EXECUTE_READ` (executable sections) |
| Cleanup | `VirtualFree` |

### Section Handling

The loader processes standard COFF sections:

| Section | Purpose |
|---------|---------|
| `.text` | Executable code |
| `.data` | Initialized data |
| `.rdata` | Read-only data |
| `.bss` | Uninitialized data (zero-filled) |

---

## Symbol Resolution

### Dynamic Function Resolution

BOFs can import Windows APIs using the `LIBRARY$Function` naming convention:

```c
// BOF code example
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(...);
```

The loader resolves these to actual function addresses via `GetProcAddress`.

### Supported Libraries

| Library | Common Functions |
|---------|------------------|
| kernel32.dll | LoadLibraryA, GetProcAddress, VirtualAlloc, CreateFileA, etc. |
| ntdll.dll | RtlCopyMemory |
| user32.dll | MessageBoxA, FindWindowA, GetWindowTextA |
| ws2_32.dll | WSAStartup, socket, connect, send, recv |
| advapi32.dll | RegOpenKeyExA, OpenProcessToken, DuplicateTokenEx |

### Internal Function Implementations

The loader provides custom implementations for standard C library functions:

| Function | Implementation |
|----------|----------------|
| strlen | Memory-safe length calculation |
| strcmp/strncmp | Byte-by-byte comparison |
| strcpy/strncpy | Safe string copy |
| memcpy/memset/memmove | Memory operations |
| malloc/calloc/free/realloc | Heap management |
| vsnprintf/sprintf | Formatted output |

---

## Beacon API

### Output Functions

| Function | Description |
|----------|-------------|
| `BeaconOutput(type, data, len)` | Write output to buffer |
| `BeaconPrintf(type, fmt, ...)` | Formatted output |

**Output Types:**
- `CALLBACK_OUTPUT` (0x00) - Standard output
- `CALLBACK_OUTPUT_OEM` (0x1e) - OEM character set
- `CALLBACK_OUTPUT_UTF8` (0x20) - UTF-8 encoded

### Data Parsing

| Function | Description |
|----------|-------------|
| `BeaconDataParse(parser, buffer, size)` | Initialize data parser |
| `BeaconDataInt(parser)` | Extract 4-byte integer |
| `BeaconDataShort(parser)` | Extract 2-byte integer |
| `BeaconDataLength(parser)` | Get remaining data length |
| `BeaconDataExtract(parser, size)` | Extract raw bytes |

### Format Functions

| Function | Description |
|----------|-------------|
| `BeaconFormatAlloc(format, maxsz)` | Allocate format buffer |
| `BeaconFormatFree(format)` | Free format buffer |
| `BeaconFormatAppend(format, data, len)` | Append data |
| `BeaconFormatPrintf(format, fmt, ...)` | Formatted append |
| `BeaconFormatToString(format, size)` | Get formatted string |
| `BeaconFormatInt(format, value)` | Append integer |

---

## Argument Packing

### Format Specification

BOF arguments use a type-prefixed format:

| Prefix | Type | Description |
|--------|------|-------------|
| `b` | Binary | Raw binary data (base64) |
| `i` | Int32 | 4-byte signed integer |
| `s` | Int16 | 2-byte signed integer |
| `z` | String | Null-terminated ANSI string |
| `Z` | WString | Null-terminated wide string (UTF-16) |

### Example Usage

```bash
# String argument
bof dir.x64.o z"C:\Windows\System32"

# Integer argument
bof enumerate.o i1234

# Wide string argument
bof search.o Z"C:\Users\*"

# Multiple arguments
bof netuser.o z"administrator" z"DOMAIN"
```

---

## Synchronous Execution

### Command Format

```json
{
  "command_type": 13,
  "command": "bof z\"argument\"",
  "data": "<base64 BOF bytes>",
  "filename": "dir.x64.o"
}
```

### Execution Flow

1. Base64 decode BOF bytes
2. Parse arguments (if provided)
3. Apply token context (if impersonating)
4. Load and execute COFF
5. Capture output via global buffer
6. Return result immediately

### Output Chunking

Large outputs are automatically split:

| Setting | Value |
|---------|-------|
| Max chunk size | 100 KB |
| Max single response | 500 KB |
| Chunks per batch | 10 |

---

## Asynchronous Execution

### Command Format

```json
{
  "command_type": 17,
  "command": "bof-async z\"argument\"",
  "data": "<base64 BOF bytes>",
  "filename": "longrunning.x64.o"
}
```

### Job Management

Async BOFs run as managed jobs with streaming output:

```go
type BOFJob struct {
    ID              string
    Name            string
    Status          string  // running, completed, crashed, killed, timeout
    StartTime       time.Time
    EndTime         *time.Time
    Output          strings.Builder
    ChunkIndex      int
    TotalBytesSent  int
    OutputTruncated bool
    TokenContext    *TokenContext
}
```

### Job Commands

| Command | Description |
|---------|-------------|
| `bof-async-list` | List all BOF jobs |
| `bof-async-output <job_id>` | Get job output |
| `bof-async-kill <job_id>` | Kill running job |

### Streaming Configuration

| Setting | Value |
|---------|-------|
| Output check interval | 1 second |
| Flush interval | 30 seconds |
| Min send interval | 10 seconds |
| Min output before send | 50 KB |
| Max total output | 10 MB |
| Timeout | 30 minutes |

### Output Format

Async output uses a structured format:

```
BOF_ASYNC_STARTED|<job_id>|<bof_name>
BOF_ASYNC_OUTPUT|<job_id>|CHUNK_<n>|<output_data>
BOF_ASYNC_COMPLETED|<job_id>|CHUNK_<n>|<final_output>
```

Status markers:
- `COMPLETED` - BOF finished successfully
- `CRASHED` - BOF threw exception
- `KILLED` - Job was cancelled
- `TIMEOUT` - Exceeded 30-minute limit

---

## Token Context

### Impersonation Support

BOFs execute under the current token context:

| Token Type | Behavior |
|------------|----------|
| No impersonation | Runs as agent process identity |
| Regular impersonation | Uses active stolen/created token |
| Network-only token | Uses token for network operations |

### Token Application

```go
// Token is duplicated for each BOF execution
func ensureTokenContextForBOF() func() {
    // Duplicate token to avoid invalidating global handle
    err := DuplicateTokenEx(sourceToken, TOKEN_ALL_ACCESS, ...)

    // Apply to current thread
    err = ImpersonateLoggedOnUser(dupToken)

    // Return cleanup function
    return func() {
        RevertToSelf()
        CloseHandle(dupToken)
    }
}
```

### Network Share Access

For BOFs accessing network shares with netonly tokens:

1. Token context is captured before job starts
2. Token is duplicated for the BOF thread
3. Impersonation applied immediately before execution
4. Network resources tracked for cleanup
5. Impersonation reverted after completion

---

## Multi-Chunk BOF Transfer

### Chunked Upload

Large BOF files are split for transfer:

```go
type BOFChunkInfo struct {
    Filename    string
    TotalChunks int
    Chunks      map[int]string  // chunk number -> base64 data
    ReceivedAt  time.Time
}
```

### Reassembly

1. First chunk creates tracking entry
2. Subsequent chunks stored in map
3. When all chunks received:
   - Concatenate base64 strings
   - Decode combined data
   - Execute BOF normally

---

## Thread Safety

### Execution Mutex

BOF execution is serialized to prevent conflicts:

```go
var bofExecutionMutex sync.Mutex

func executeBOFPlatform(bofBytes []byte, args []byte) (string, error) {
    bofExecutionMutex.Lock()
    defer bofExecutionMutex.Unlock()

    // ... execution logic
}
```

### Output Buffer

Global output buffer protected by mutex:

```go
var bofOutputBuffer []byte
var bofOutputMutex sync.Mutex
```

---

## Error Handling

### Error Codes

| Code | Description |
|------|-------------|
| E2 | Invalid COFF data (too small) |
| E18 | Base64 decode failure |
| E25 | BOF execution error |
| E47 | Job not found |
| E51 | BOF crashed/panic |

### Recovery

- Panics are caught via `recover()`
- Crashed jobs marked with status
- Final output includes crash message
- Token context properly cleaned up

---

## Limitations

| Limitation | Description |
|------------|-------------|
| Platform | Windows x64 only |
| Concurrency | One BOF at a time (mutex) |
| Output size | 10 MB max for async |
| Timeout | 30 minutes max for async |
| DLL hooks | May be detected by EDR |
| Memory | RWX memory allocation visible |

---

## Related Files

| Component | File Path |
|-----------|-----------|
| COFF Loader | `server/docker/payloads/Windows/coff_loader.go` |
| BOF Command | `server/docker/payloads/Windows/action_bof.go` |
| BOF Platform | `server/docker/payloads/Windows/action_bof_windows.go` |
| BOF Async | `server/docker/payloads/Windows/action_bof_async_windows.go` |
| BOF Arguments | `server/docker/payloads/Windows/action_bof_args_windows.go` |
| WebSocket Handler | `server/internal/websocket/handlers/bof_handler.go` |
