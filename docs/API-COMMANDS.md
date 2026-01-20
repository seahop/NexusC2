# API: Commands

[← Back to API Overview](/docs/api/)

---

## POST /api/v1/agents/:id/commands

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

## GET /api/v1/agents/:id/commands

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

## GET /api/v1/agents/:id/commands/latest

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

## GET /api/v1/commands/:id

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

## DELETE /api/v1/agents/:id/commands/queue

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
