# API: Payloads

[← Back to API Overview](/docs/api/)

---

## POST /api/v1/payloads/build

Build a payload binary. This is a synchronous operation - the response is the binary file.

**Authentication:** Required

**Request Body:**
```json
{
  "listener": "string",           // Required: Listener name to connect to
  "os": "string",                 // Required: "windows", "linux", "darwin"
  "arch": "string",               // Required: "amd64", "arm64"
  "language": "string",           // Optional: "go" (default), "goproject" (export source)
  "payload_type": "string",       // Optional: "http" (default), "smb"
  "pipe_name": "string",          // Required if payload_type="smb": Pipe name
  "safety_checks": {              // Optional: All fields optional
    "hostname": "string",         // Must match target hostname
    "username": "string",         // Must match target username
    "domain": "string",           // Must match target domain
    "file_check": {
      "path": "string",           // File path to check
      "must_exist": true          // true=must exist, false=must not exist
    },
    "process": "string",          // Process must be running
    "kill_date": "string",        // Payload expires after (YYYY-MM-DD)
    "working_hours": {
      "start": "string",          // Start time (HH:MM)
      "end": "string"             // End time (HH:MM)
    }
  }
}
```

**Example (Basic):**
```json
{
  "listener": "https-listener",
  "os": "windows",
  "arch": "amd64"
}
```

**Example (With Safety Checks):**
```json
{
  "listener": "https-listener",
  "os": "windows",
  "arch": "amd64",
  "safety_checks": {
    "hostname": "TARGET-PC",
    "domain": "CORP",
    "kill_date": "2025-12-31",
    "working_hours": {
      "start": "09:00",
      "end": "17:00"
    }
  }
}
```

**Response (200 OK):**
- Content-Type: `application/octet-stream`
- Content-Disposition: `attachment; filename="payload_windows_amd64.exe"`
- X-Build-Duration: `45s`
- Body: Binary file data

**Errors:**
- `400 Bad Request`: Invalid parameters or missing listener
- `500 Internal Server Error`: Build failed
