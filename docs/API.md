# NexusC2 REST API Documentation

## Overview

The NexusC2 REST API provides programmatic access to all C2 operations. The API uses JWT (JSON Web Token) authentication and communicates over HTTPS on port 8443.

**Base URL**: `https://<server>:8443/api/v1`

## Authentication

All endpoints (except `/auth/cert-login` and `/auth/refresh`) require a valid JWT access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

### Token Lifecycle

1. **Login** with username using certificate-based authentication to receive an access token (1h) and refresh token (24h)
2. **Use access token** for API requests
3. **Refresh** the access token before expiry using the refresh token
4. **Logout** to invalidate the refresh token

### Certificate-Based Authentication

NexusC2 uses TLS certificate-based authentication. If you have access to the server certificate, you can authenticate with just a username. Users are auto-provisioned on first login.

```bash
# Login using the server certificate
./nexus-api.py --cert ../server/certs/api_server.crt login -u operator1

# Or set certificate path via environment variable
export NEXUS_API_CERT="../server/certs/api_server.crt"
./nexus-api.py login -u operator1
```

---

## Endpoints

### Authentication

#### POST /api/v1/auth/cert-login

Authenticate using TLS certificate trust. If you can establish a TLS connection (have the server certificate), you can authenticate with just a username. Users are auto-provisioned on first login.

**Request Body:**
```json
{
  "username": "string"     // Required: Your username/operator name
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "a1b2c3d4e5f6...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "username": "operator1"
}
```

**Errors:**
- `400 Bad Request`: Username is required
- `403 Forbidden`: User account is inactive
- `500 Internal Server Error`: Authentication failed

---

#### POST /api/v1/auth/refresh

Get a new access token using a refresh token.

**Request Body:**
```json
{
  "refresh_token": "string"    // Required: Current refresh token
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "f6e5d4c3b2a1...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "username": "admin"
}
```

**Note:** The old refresh token is invalidated and a new one is issued.

**Errors:**
- `401 Unauthorized`: Invalid or expired refresh token
- `403 Forbidden`: User account is inactive

---

#### POST /api/v1/auth/logout

Invalidate a refresh token.

**Authentication:** Required

**Request Body:**
```json
{
  "refresh_token": "string"    // Required: Refresh token to invalidate
}
```

**Response (200 OK):**
```json
{
  "message": "logged out successfully"
}
```

---

#### GET /api/v1/auth/me

Get current user information.

**Authentication:** Required

**Response (200 OK):**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "admin"
}
```

---

### Agents

#### GET /api/v1/agents

List all agents with optional filtering and pagination.

**Authentication:** Required

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | int | 1 | Page number |
| limit | int | 50 | Results per page (max: 100) |
| status | string | - | Filter: "active", "inactive", "all" |
| os | string | - | Filter by OS (e.g., "windows", "linux") |
| search | string | - | Search hostname, username, IP |

**Response (200 OK):**
```json
{
  "agents": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "client_id": "abc123",
      "protocol": "https",
      "external_ip": "203.0.113.50",
      "internal_ip": "192.168.1.100",
      "username": "CORP\\jsmith",
      "hostname": "WORKSTATION01",
      "process": "explorer.exe",
      "pid": "1234",
      "arch": "amd64",
      "os": "windows",
      "last_seen": "2025-01-08T12:30:00Z",
      "alias": "target-1",
      "tags": [
        {"name": "high-value", "color": "#FF0000"},
        {"name": "domain-admin", "color": "#4A90E2"}
      ]
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 125
  }
}
```

---

#### GET /api/v1/agents/:id

Get detailed information about a specific agent.

**Authentication:** Required

**URL Parameters:**
- `id` (required): Agent UUID

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "client_id": "abc123",
  "protocol": "https",
  "external_ip": "203.0.113.50",
  "internal_ip": "192.168.1.100",
  "username": "CORP\\jsmith",
  "hostname": "WORKSTATION01",
  "process": "explorer.exe",
  "pid": "1234",
  "arch": "amd64",
  "os": "windows",
  "last_seen": "2025-01-08T12:30:00Z",
  "alias": "target-1",
  "note": "Primary target",
  "tags": [
    {"name": "high-value", "color": "#FF0000"}
  ]
}
```

**Errors:**
- `404 Not Found`: Agent not found

---

#### DELETE /api/v1/agents/:id

Remove (soft delete) an agent.

**Authentication:** Required

**URL Parameters:**
- `id` (required): Agent UUID

**Response (200 OK):**
```json
{
  "message": "agent removed successfully"
}
```

**Errors:**
- `404 Not Found`: Agent not found

---

#### PATCH /api/v1/agents/:id

Update agent properties (alias, note).

**Authentication:** Required

**URL Parameters:**
- `id` (required): Agent UUID

**Request Body:**
```json
{
  "alias": "string",    // Optional: New alias/nickname
  "note": "string"      // Optional: Agent notes
}
```

**Response (200 OK):**
```json
{
  "message": "agent updated successfully"
}
```

**Errors:**
- `404 Not Found`: Agent not found

---

#### POST /api/v1/agents/:id/tags

Add a tag to an agent.

**Authentication:** Required

**URL Parameters:**
- `id` (required): Agent UUID

**Request Body:**
```json
{
  "tag": "string",      // Required: Tag name
  "color": "string"     // Optional: Hex color (default: "#4A90E2")
}
```

**Response (200 OK):**
```json
{
  "message": "tag added successfully",
  "tags": [
    {"name": "high-value", "color": "#FF0000"},
    {"name": "new-tag", "color": "#4A90E2"}
  ]
}
```

---

#### DELETE /api/v1/agents/:id/tags/:tag

Remove a tag from an agent.

**Authentication:** Required

**URL Parameters:**
- `id` (required): Agent UUID
- `tag` (required): Tag name (URL encoded)

**Response (200 OK):**
```json
{
  "message": "tag removed successfully",
  "tags": [
    {"name": "high-value", "color": "#FF0000"}
  ]
}
```

---

### Commands

#### POST /api/v1/agents/:id/commands

Send a command to an agent.

**Authentication:** Required

**URL Parameters:**
- `id` (required): Agent UUID

**Request Body:**
```json
{
  "command": "string",    // Required: Command to execute
  "data": "string"        // Optional: Additional data/arguments
}
```

**Response (200 OK):**
```json
{
  "command_id": "cmd-550e8400-e29b-41d4",
  "db_id": 1234,
  "status": "sent",
  "timestamp": "2025-01-08T12:30:00Z"
}
```

**Response (202 Accepted):** Agent offline, command queued
```json
{
  "command_id": "cmd-550e8400-e29b-41d4",
  "db_id": 1234,
  "status": "queued",
  "message": "command queued, agent will receive on next check-in"
}
```

**Errors:**
- `404 Not Found`: Agent not found

---

#### GET /api/v1/agents/:id/commands

Get command history for an agent.

**Authentication:** Required

**URL Parameters:**
- `id` (required): Agent UUID

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | int | 1 | Page number |
| limit | int | 50 | Results per page (max: 100) |

**Response (200 OK):**
```json
{
  "commands": [
    {
      "id": 1234,
      "username": "admin",
      "guid": "550e8400-e29b-41d4-a716-446655440000",
      "command": "whoami",
      "timestamp": "2025-01-08T12:30:00Z",
      "output": "CORP\\jsmith"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 25
  }
}
```

---

#### GET /api/v1/agents/:id/commands/latest

Get the most recent command for an agent with its output. Useful for polling command results after sending a command.

**Authentication:** Required

**URL Parameters:**
- `id` (required): Agent UUID

**Response (200 OK):**
```json
{
  "command": {
    "id": 1234,
    "username": "admin",
    "guid": "550e8400-e29b-41d4-a716-446655440000",
    "command": "whoami",
    "timestamp": "2025-01-08T12:30:00Z"
  },
  "outputs": [
    {
      "output": "CORP\\jsmith",
      "timestamp": "2025-01-08T12:30:05Z"
    }
  ],
  "has_output": true,
  "status": "completed"
}
```

**Status Values:**
- `completed`: Output has been received
- `pending`: Command sent, waiting for output

**Errors:**
- `404 Not Found`: No commands found for agent

---

#### GET /api/v1/commands/:id

Get a specific command with all outputs.

**Authentication:** Required

**URL Parameters:**
- `id` (required): Command database ID

**Response (200 OK):**
```json
{
  "command": {
    "id": 1234,
    "username": "admin",
    "guid": "550e8400-e29b-41d4-a716-446655440000",
    "command": "dir C:\\",
    "timestamp": "2025-01-08T12:30:00Z"
  },
  "outputs": [
    {
      "output": " Volume in drive C has no label...",
      "timestamp": "2025-01-08T12:30:05Z"
    }
  ]
}
```

**Errors:**
- `400 Bad Request`: Invalid command ID
- `404 Not Found`: Command not found

---

#### DELETE /api/v1/agents/:id/commands/queue

Clear pending commands for an agent.

**Authentication:** Required

**URL Parameters:**
- `id` (required): Agent UUID

**Response (200 OK):**
```json
{
  "message": "queue cleared"
}
```

---

### Listeners

#### GET /api/v1/listeners

List all configured listeners.

**Authentication:** Required

**Response (200 OK):**
```json
{
  "listeners": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "https-listener",
      "protocol": "HTTPS",
      "port": "443",
      "ip": "0.0.0.0",
      "pipe_name": "",
      "get_profile": "microsoft-graph-get",
      "post_profile": "microsoft-graph-post",
      "server_response_profile": "microsoft-graph-response"
    },
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "name": "smb-listener",
      "protocol": "SMB",
      "port": "",
      "ip": "",
      "pipe_name": "spoolss",
      "get_profile": "default-get",
      "post_profile": "default-post",
      "server_response_profile": "default-response"
    }
  ]
}
```

---

#### GET /api/v1/listeners/:name

Get a specific listener by name.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Listener name

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "https-listener",
  "protocol": "HTTPS",
  "port": "443",
  "ip": "0.0.0.0",
  "pipe_name": "",
  "get_profile": "microsoft-graph-get",
  "post_profile": "microsoft-graph-post",
  "server_response_profile": "microsoft-graph-response"
}
```

**Errors:**
- `404 Not Found`: Listener not found

---

#### POST /api/v1/listeners

Create a new listener with optional malleable profile bindings.

**Authentication:** Required

**Request Body:**
```json
{
  "name": "string",                    // Required: Unique listener name
  "protocol": "string",                // Required: "HTTP", "HTTPS", "SMB", or "RPC"
  "port": 443,                         // Required for HTTP/HTTPS: Port number (1-65535)
  "ip": "string",                      // Optional: Bind IP (default: "0.0.0.0")
  "pipe_name": "string",               // Required for SMB: Named pipe name
  "get_profile": "string",             // Optional: GET malleable profile name (default: "default-get")
  "post_profile": "string",            // Optional: POST malleable profile name (default: "default-post")
  "server_response_profile": "string"  // Optional: Server response profile name (default: "default-response")
}
```

**Example (HTTPS with default profiles):**
```json
{
  "name": "https-listener",
  "protocol": "HTTPS",
  "port": 443,
  "ip": "0.0.0.0"
}
```

**Example (HTTPS with Microsoft Graph profiles):**
```json
{
  "name": "ms-graph-listener",
  "protocol": "HTTPS",
  "port": 443,
  "ip": "0.0.0.0",
  "get_profile": "microsoft-graph-get",
  "post_profile": "microsoft-graph-post",
  "server_response_profile": "microsoft-graph-response"
}
```

**Example (SMB):**
```json
{
  "name": "smb-listener",
  "protocol": "SMB",
  "pipe_name": "spoolss"
}
```

**Response (201 Created):**
```json
{
  "message": "listener created successfully",
  "listener": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "ms-graph-listener",
    "protocol": "HTTPS",
    "port": "443",
    "ip": "0.0.0.0",
    "pipe_name": "",
    "get_profile": "microsoft-graph-get",
    "post_profile": "microsoft-graph-post",
    "server_response_profile": "microsoft-graph-response"
  }
}
```

**Errors:**
- `400 Bad Request`: Invalid protocol, port, missing required fields, or unknown profile name

---

#### DELETE /api/v1/listeners/:name

Delete a listener.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Listener name

**Response (200 OK):**
```json
{
  "message": "listener deleted successfully"
}
```

**Errors:**
- `404 Not Found`: Listener not found

---

### Malleable Profiles

Malleable profiles define HTTP request/response patterns for agent communication, allowing traffic to blend in with legitimate services (AWS S3, Microsoft Graph, etc.).

**Profile Sources:**
- **Static profiles** are defined in `server/config.toml` and loaded at server startup
- **Dynamic profiles** can be uploaded at runtime via the API or client UI without restarting the server

**Creating Custom Profiles:**
1. Download the template: `GET /api/v1/profiles/template` or use the client (Tools > Upload Profiles)
2. Edit the template file (`server/docker/templates/listener_template.toml`) to define your custom profiles
3. Upload via API (`POST /api/v1/profiles/upload`) or the client UI
4. Create a listener using your new profiles

Each profile type serves a specific purpose:
- **GET profiles**: Define how agents poll for commands (path, method, headers, client ID parameter)
- **POST profiles**: Define how agents send results back (path, method, content type, client ID parameter)
- **Server Response profiles**: Define how the server responds to agents (content type, JSON field names, headers)

#### GET /api/v1/profiles

List all available malleable profiles.

**Authentication:** Required

**Response (200 OK):**
```json
{
  "get_profiles": [
    {
      "name": "default-get",
      "path": "/api/v1/status",
      "method": "GET"
    },
    {
      "name": "microsoft-graph-get",
      "path": "/v1.0/me/drive/root/children",
      "method": "GET"
    }
  ],
  "post_profiles": [
    {
      "name": "default-post",
      "path": "/api/v1/data",
      "method": "POST"
    },
    {
      "name": "microsoft-graph-post",
      "path": "/v1.0/me/drive/items",
      "method": "PUT"
    }
  ],
  "server_response_profiles": [
    {
      "name": "default-response",
      "content_type": "application/json"
    },
    {
      "name": "microsoft-graph-response",
      "content_type": "application/json; odata.metadata=minimal"
    }
  ]
}
```

---

#### GET /api/v1/profiles/get

List all GET request profiles.

**Authentication:** Required

**Response (200 OK):**
```json
{
  "profiles": [
    {
      "name": "default-get",
      "path": "/api/v1/status",
      "method": "GET",
      "headers": [
        {"name": "Accept", "value": "application/json"}
      ],
      "params": [
        {"name": "client", "location": "query", "type": "clientID_param", "format": "%CLIENTID%"}
      ]
    },
    {
      "name": "microsoft-graph-get",
      "path": "/v1.0/me/drive/root/children",
      "method": "GET",
      "headers": [
        {"name": "Authorization", "value": "Bearer %CLIENTID%"}
      ],
      "params": [
        {"name": "Authorization", "location": "header", "type": "clientID_param", "format": "Bearer %CLIENTID%"}
      ]
    }
  ]
}
```

---

#### GET /api/v1/profiles/get/:name

Get a specific GET profile by name.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Profile name

**Response (200 OK):**
```json
{
  "name": "microsoft-graph-get",
  "path": "/v1.0/me/drive/root/children",
  "method": "GET",
  "headers": [
    {"name": "Authorization", "value": "Bearer %CLIENTID%"}
  ],
  "params": [
    {"name": "Authorization", "location": "header", "type": "clientID_param", "format": "Bearer %CLIENTID%"}
  ]
}
```

**Errors:**
- `404 Not Found`: Profile not found

---

#### GET /api/v1/profiles/post

List all POST request profiles.

**Authentication:** Required

**Response (200 OK):**
```json
{
  "profiles": [
    {
      "name": "default-post",
      "path": "/api/v1/data",
      "method": "POST",
      "content_type": "application/json",
      "headers": [],
      "params": [
        {"name": "client", "location": "query", "type": "clientID_param", "format": "%CLIENTID%"}
      ]
    },
    {
      "name": "microsoft-graph-post",
      "path": "/v1.0/me/drive/items",
      "method": "PUT",
      "content_type": "application/json",
      "headers": [
        {"name": "Authorization", "value": "Bearer %CLIENTID%"}
      ],
      "params": []
    }
  ]
}
```

---

#### GET /api/v1/profiles/post/:name

Get a specific POST profile by name.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Profile name

**Response (200 OK):**
```json
{
  "name": "microsoft-graph-post",
  "path": "/v1.0/me/drive/items",
  "method": "PUT",
  "content_type": "application/json",
  "headers": [
    {"name": "Authorization", "value": "Bearer %CLIENTID%"}
  ],
  "params": []
}
```

**Errors:**
- `404 Not Found`: Profile not found

---

#### GET /api/v1/profiles/server-response

List all server response profiles.

**Authentication:** Required

**Response (200 OK):**
```json
{
  "profiles": [
    {
      "name": "default-response",
      "content_type": "application/json",
      "status_field": "status",
      "data_field": "data",
      "command_id_field": "id",
      "rekey_value": "refresh",
      "headers": [
        {"name": "Cache-Control", "value": "no-store"}
      ]
    },
    {
      "name": "microsoft-graph-response",
      "content_type": "application/json; odata.metadata=minimal",
      "status_field": "@odata.context",
      "data_field": "value",
      "command_id_field": "@odata.nextLink",
      "rekey_value": "TokenExpired",
      "headers": [
        {"name": "x-ms-ags-diagnostic", "value": "{\"ServerInfo\":{\"DataCenter\":\"West US\"}}"}
      ]
    }
  ]
}
```

---

#### GET /api/v1/profiles/server-response/:name

Get a specific server response profile by name.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Profile name

**Response (200 OK):**
```json
{
  "name": "microsoft-graph-response",
  "content_type": "application/json; odata.metadata=minimal",
  "status_field": "@odata.context",
  "data_field": "value",
  "command_id_field": "@odata.nextLink",
  "rekey_value": "TokenExpired",
  "headers": [
    {"name": "x-ms-ags-diagnostic", "value": "{\"ServerInfo\":{\"DataCenter\":\"West US\"}}"}
  ]
}
```

**Errors:**
- `404 Not Found`: Profile not found

---

#### GET /api/v1/profiles/names

Get just the profile names (useful for dropdowns/selection lists).

**Authentication:** Required

**Response (200 OK):**
```json
{
  "get_profiles": ["default-get", "microsoft-graph-get", "aws-s3-get"],
  "post_profiles": ["default-post", "microsoft-graph-post", "aws-s3-post"],
  "server_response_profiles": ["default-response", "microsoft-graph-response", "aws-s3-response"]
}
```

---

#### GET /api/v1/profiles/template

Download the profile template file for creating custom profiles.

**Authentication:** Required

**Response (200 OK):**
- Content-Type: `application/toml`
- Content-Disposition: `attachment; filename=listener_template.toml`
- Body: TOML template content

---

#### POST /api/v1/profiles/upload

Upload and validate new malleable profiles at runtime. Profiles are added to the running configuration immediately (hot-loaded).

**Authentication:** Required

**Content Types Supported:**
- `application/toml` or `text/plain`: Raw TOML content in request body
- `multipart/form-data`: File upload with form field `profile`

**Request (Raw TOML):**
```toml
[[http_profiles.get]]
name = "custom-get"
path = "/api/custom/check"
method = "GET"
[[http_profiles.get.params]]
name = "id"
location = "query"
type = "clientID_param"
format = "%CLIENTID%"

[[http_profiles.post]]
name = "custom-post"
path = "/api/custom/data"
method = "POST"
content_type = "application/json"
[[http_profiles.post.params]]
name = "id"
location = "query"
type = "clientID_param"
format = "%CLIENTID%"

[[http_profiles.server_response]]
name = "custom-response"
content_type = "application/json"
```

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "Profiles uploaded successfully",
  "get_profiles_added": ["custom-get"],
  "post_profiles_added": ["custom-post"],
  "server_response_added": ["custom-response"],
  "errors": []
}
```

**Response (200 OK) - Partial Success:**
```json
{
  "status": "partial",
  "message": "Profiles uploaded successfully",
  "get_profiles_added": ["custom-get"],
  "post_profiles_added": [],
  "server_response_added": [],
  "errors": ["POST profile 'default-post': profile with name 'default-post' already exists"]
}
```

**Errors:**
- `400 Bad Request`: Invalid TOML syntax or no profiles added

---

#### DELETE /api/v1/profiles/get/:name

Delete a GET profile by name.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Profile name

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "GET profile deleted"
}
```

**Errors:**
- `404 Not Found`: GET profile not found

---

#### DELETE /api/v1/profiles/post/:name

Delete a POST profile by name.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Profile name

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "POST profile deleted"
}
```

**Errors:**
- `404 Not Found`: POST profile not found

---

#### DELETE /api/v1/profiles/server-response/:name

Delete a server response profile by name.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Profile name

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "Server response profile deleted"
}
```

**Errors:**
- `404 Not Found`: Server response profile not found

---

### Payloads

#### POST /api/v1/payloads/build

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

---

### Events (Server-Sent Events)

#### GET /api/v1/events

Subscribe to real-time events via SSE (Server-Sent Events).

**Authentication:** Required

**Response:** SSE stream with events:

```
event: connected
data: {"message":"Connected to event stream","client_id":"user-123456789"}

event: agent_connection
data: {"event":"agent_connection","newclientID":"550e8400...","hostname":"WORKSTATION01",...}

event: command_result
data: {"agent_id":"550e8400...","command_id":"cmd-123","output":"result..."}

event: heartbeat
data: {"timestamp":1704718200}
```

**Event Types:**
| Event | Description |
|-------|-------------|
| connected | Connection established |
| agent_connection | New agent connected |
| agent_update | Agent status changed |
| command_result | Command output received |
| listener_update | Listener state changed |
| heartbeat | Keep-alive (every 30s) |

---

### Health

#### GET /health

Health check endpoint (no authentication required).

**Response (200 OK):**
```json
{
  "status": "healthy",
  "goroutines": 15,
  "memory_mb": 42,
  "sse_clients": 3,
  "grpc_connected": true
}
```

---

## Error Responses

All errors follow a consistent format:

```json
{
  "error": "error message"
}
```

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 202 | Accepted (queued) |
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Invalid/expired token |
| 403 | Forbidden - Account inactive |
| 404 | Not Found - Resource doesn't exist |
| 429 | Too Many Requests - Rate limited |
| 500 | Internal Server Error |

---

## Rate Limiting

The API implements rate limiting per IP address:
- Default: 100 requests per minute
- When exceeded, returns `429 Too Many Requests` with:
```json
{
  "error": "rate limit exceeded",
  "retry_after": 60
}
```

---

## User Management

### Auto-Provisioning

Users are automatically created on first login via certificate-based authentication. Anyone with access to the server certificate can authenticate:

```bash
# First login creates the user automatically
./nexus-api.py --cert ../server/certs/api_server.crt login -u newoperator

# User "newoperator" now exists in the database
```

### Viewing Users

Connect to the PostgreSQL database to manage users:

```bash
docker exec -it database psql -U postgres -d ops

# List all API users
SELECT username, created_at, last_login, is_active FROM api_users;

# Deactivate a user
UPDATE api_users SET is_active = false WHERE username = 'oldoperator';
```

### Environment Variables

The REST API uses the following environment variables:

| Variable | Description |
|----------|-------------|
| `JWT_SECRET` | Secret key for signing JWT tokens (generated during setup) |

These are automatically set in `server/docker/db/.secrets/.env` during setup.
