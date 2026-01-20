# API: Events & Health

[← Back to API Overview](/docs/api/)

---

## GET /api/v1/events

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

## GET /health

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
