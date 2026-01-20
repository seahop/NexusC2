---
title: "API: Listeners"
description: "Listener management endpoints for creating, listing, and deleting listeners."
weight: 53
---
[← Back to API Overview](/docs/api/)

---

## GET /api/v1/listeners

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

## GET /api/v1/listeners/:name

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

## POST /api/v1/listeners

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

## DELETE /api/v1/listeners/:name

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
