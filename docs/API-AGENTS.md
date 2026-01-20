# API: Agents

[← Back to API Overview](/docs/api/)

---

## GET /api/v1/agents

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

## GET /api/v1/agents/:id

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

## DELETE /api/v1/agents/:id

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

## PATCH /api/v1/agents/:id

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

## POST /api/v1/agents/:id/tags

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

## DELETE /api/v1/agents/:id/tags/:tag

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
