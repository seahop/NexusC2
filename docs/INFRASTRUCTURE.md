# Docker Infrastructure & Services

## Overview

NexusC2 runs as a containerized microservices architecture using Docker Compose. The system consists of five services that communicate via an internal bridge network and gRPC.

---

## Network Topology

```
┌──────────────────────────────────────────────────────────────────────┐
│                     HOST NETWORK                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Agent Handler Service                                         │ │
│  │  gRPC: 0.0.0.0:50051                                          │ │
│  │  (network_mode: host)                                          │ │
│  └────────────────────────────────────────────────────────────────┘ │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ gRPC via host.docker.internal:50051
┌────────────────────────────┴─────────────────────────────────────────┐
│              DOCKER BRIDGE NETWORK: c2_internal                      │
│              Subnet: 172.28.0.0/16                                   │
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐      │
│  │   Database      │  │   WebSocket     │  │   REST API      │      │
│  │  172.28.0.2     │  │  172.28.0.3     │  │  172.28.0.6     │      │
│  │  Port: 5432     │  │  Port: 3131     │  │  Port: 8443     │      │
│  │  (internal)     │  │  (exposed)      │  │  (exposed)      │      │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘      │
│           │                    │                    │                │
│           └────────────────────┼────────────────────┘                │
│                      SQL Queries                                     │
│                                                                      │
│  ┌─────────────────┐                                                │
│  │    Builder      │  (on-demand, privileged)                       │
│  │  172.28.0.5     │                                                │
│  └─────────────────┘                                                │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Services

### 1. Database (PostgreSQL)

**Purpose:** Persistent storage for all C2 data

| Property | Value |
|----------|-------|
| IP Address | 172.28.0.2 |
| Port | 5432 (internal only) |
| Image | Alpine 3.20 + PostgreSQL |
| Database | `ops` |
| User | `postgres` |

**Configuration:**
- Authentication: SCRAM-SHA-256
- Max Connections: 200
- Shared Buffers: 256MB
- Effective Cache Size: 1GB
- Work Memory: 16MB

**Health Check:**
```yaml
test: ["CMD", "pg_isready", "-U", "postgres"]
interval: 10s
timeout: 5s
retries: 5
```

---

### 2. WebSocket Service

**Purpose:** Real-time communication with GUI clients

| Property | Value |
|----------|-------|
| IP Address | 172.28.0.3 |
| Port | 3131 (HTTPS/WSS) |
| Binary | `/app/websocket-service` |
| User | nexus (UID 1001) |

**Responsibilities:**
- WebSocket connections from GUI clients
- Real-time event broadcasting
- Payload generation orchestration
- File transfer coordination
- SOCKS proxy management

**Key Components:**
- **Hub**: Central message broker for all clients
- **Stream Manager**: gRPC connection to Agent Handler
- **Builder Integration**: Docker orchestration for payload builds

**Volumes:**
```yaml
- /shared:/shared              # Inter-container communication
- ./downloads:/app/downloads   # Downloaded files from agents
- ./uploads:/app/uploads       # Files to upload to agents
- ./temp:/app/temp             # Temporary files
- ./logs:/app/logs             # Service logs
- ./payloads:/app/payloads:ro  # Payload templates (read-only)
- /var/run/docker.sock:/var/run/docker.sock  # Docker operations
```

---

### 3. Agent Handler Service

**Purpose:** Manage agent connections and command distribution

| Property | Value |
|----------|-------|
| Network | Host mode (not containerized network) |
| Port | 50051 (gRPC) |
| Binary | `/app/agent-handler-service` |
| User | nexus (UID 1001) |

**Responsibilities:**
- Accept incoming agent connections via gRPC
- Track active agents and their state
- Distribute commands to agents
- Process agent results
- Manage HTTP/HTTPS/SMB listeners

**Key Components:**
- **gRPC Server**: Bidirectional streaming with agents
- **Command Queue**: Per-agent command buffers
- **Listener Manager**: HTTP/HTTPS/TCP listeners
- **Result Cache**: 1000 items, 5-minute TTL

**Performance Optimizations:**
- Database Pool Optimizer (auto-scaling connections)
- Bulk Operator (100-item batch writes)
- Circuit Breaker (5 failure threshold)
- Priority Queue for task processing

---

### 4. REST API Service

**Purpose:** HTTP API for programmatic access

| Property | Value |
|----------|-------|
| IP Address | 172.28.0.6 |
| Port | 8443 (HTTPS) |
| Framework | Gin (Go) |
| User | nexus (UID 1001) |

**Responsibilities:**
- JWT authentication
- RESTful endpoints for all operations
- Proxy operations through WebSocket service
- Server-Sent Events (SSE) for real-time updates

**WebSocket Proxy:**
All REST operations are proxied through WebSocket to ensure events broadcast to GUI clients:
```
REST API → wss://172.28.0.3:3131/ws → WebSocket Hub → All Clients
```

**Authentication:**
- Access tokens: 1 hour expiry
- Refresh tokens: 24 hours expiry
- Separate `api_users` table from GUI users

---

### 5. Builder Service

**Purpose:** Compile agent payloads on-demand

| Property | Value |
|----------|-------|
| IP Address | 172.28.0.5 |
| Container Name | builder |
| Base Image | golang:1.25-alpine |
| Restart Policy | never (manual execution) |
| Privileged | Yes |

**Capabilities:**
- Go compilation with Garble obfuscation
- Multi-platform support (Windows, Linux, Darwin)
- Project export for external compilation
- Anti-sandbox toggle configuration

**Volumes (Read-Only Templates):**
```yaml
- ./payloads/Darwin:/build/Darwin:ro
- ./payloads/Linux:/build/Linux:ro
- ./payloads/Windows:/build/Windows:ro
- ./payloads/shared:/build/shared:ro
```

---

## Inter-Service Communication

### gRPC (Port 50051)

Used for real-time agent communication:

```protobuf
service AgentService {
  rpc BiDiStream(stream Message) returns (stream Message);
  rpc NotifyNewConnection(ConnectionNotification) returns (Empty);
  rpc HandleUpload(UploadRequest) returns (UploadResponse);
  rpc AgentCheckinNotification(CheckinRequest) returns (Empty);
}
```

**Connections:**
- WebSocket → Agent Handler: `host.docker.internal:50051`
- REST API → Agent Handler: `host.docker.internal:50051`

### WebSocket Proxy

REST API proxies operations to WebSocket for event broadcasting:

```
Environment: WS_PROXY_URL=wss://172.28.0.3:3131/ws
```

### Database Connections

All services connect to PostgreSQL via bridge network:

| Service | Connection Pool |
|---------|-----------------|
| WebSocket | 50 open, 25 idle |
| REST API | 50 open, 25 idle |
| Agent Handler | Auto-optimized |

---

## Database Schema

### Core Tables

#### connections
Primary agent tracking table.

| Column | Type | Description |
|--------|------|-------------|
| newclientID | UUID | Unique agent identifier (PK) |
| clientID | VARCHAR | Original client ID from build |
| protocol | VARCHAR | Connection protocol (HTTP/HTTPS/SMB) |
| extIP | VARCHAR | External IP address |
| intIP | VARCHAR | Internal IP address |
| username | VARCHAR | Current user |
| hostname | VARCHAR | Machine name |
| process | VARCHAR | Process name |
| pid | INTEGER | Process ID |
| arch | VARCHAR | Architecture (amd64, arm64) |
| os | VARCHAR | Operating system |
| secret1 | VARCHAR | Current encryption key |
| secret2 | VARCHAR | Previous encryption key |
| lastSEEN | TIMESTAMP | Last check-in time |
| alias | VARCHAR | Custom agent name |
| deleted_at | TIMESTAMP | Soft delete timestamp |
| parent_clientID | UUID | Parent agent (for linked agents) |
| link_type | VARCHAR | Link type (e.g., "smb") |
| hop_count | INTEGER | Distance from initial agent |

#### commands
Command audit log.

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL | Primary key |
| username | VARCHAR | Operator who issued command |
| guid | UUID | Target agent |
| command | TEXT | Command text |
| timestamp | TIMESTAMP | When issued |

#### command_outputs
Command execution results.

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL | Primary key |
| command_id | INTEGER | FK to commands |
| output | TEXT | Command output |
| timestamp | TIMESTAMP | When received |

#### listeners
Active listener configuration.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| name | VARCHAR | Listener name |
| protocol | VARCHAR | HTTP/HTTPS/TCP |
| port | INTEGER | Listen port |
| ip | VARCHAR | Bind address |
| pipe_name | VARCHAR | Named pipe (SMB only) |

#### inits
Payload initialization data.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| clientID | VARCHAR | Client ID for payload |
| type | VARCHAR | Payload type |
| secret | VARCHAR | Initial secret |
| os | VARCHAR | Target OS |
| arch | VARCHAR | Target architecture |
| RSAkey | TEXT | RSA private key |
| protocol | VARCHAR | Communication protocol |

### Link Management Tables

#### link_routes
Multi-hop routing paths.

| Column | Type | Description |
|--------|------|-------------|
| source_guid | UUID | Source agent |
| destination_guid | UUID | Target agent |
| next_hop_guid | UUID | Next hop in path |
| hop_count | INTEGER | Total hops |

#### link_routing
SMB routing table.

| Column | Type | Description |
|--------|------|-------------|
| edge_clientID | UUID | Edge agent |
| routing_id | VARCHAR | Local routing ID |
| linked_clientID | UUID | Linked agent |
| link_type | VARCHAR | Link type |

### Authentication Tables

#### api_users
REST API user accounts.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| username | VARCHAR | Unique username |
| password_hash | VARCHAR | Bcrypt hash |
| created_at | TIMESTAMP | Account creation |
| last_login | TIMESTAMP | Last login time |
| is_active | BOOLEAN | Account status |

#### api_tokens
Refresh token storage.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| user_id | UUID | FK to api_users |
| refresh_token_hash | VARCHAR | Token hash |
| expires_at | TIMESTAMP | Expiration time |
| created_at | TIMESTAMP | Creation time |

---

## Volume Mounts

### Shared Directories

| Path | Purpose | Mounted In |
|------|---------|------------|
| `/shared` | Inter-container artifacts | All services |
| `./downloads` | Files from agents | WebSocket, REST, Agent Handler |
| `./uploads` | Files for agents | WebSocket, REST, Agent Handler |
| `./temp` | Temporary processing | All services |
| `./logs` | Service logs | All services |

### Persistence

| Volume | Type | Purpose |
|--------|------|---------|
| `postgres_data` | Named volume | Database persistence |
| `./payloads` | Bind mount | Payload templates |

### Docker Socket

```yaml
/var/run/docker.sock:/var/run/docker.sock
```

Mounted in WebSocket, REST API, and Builder for Docker operations (payload building).

---

## Health Checks & Dependencies

### Startup Order

```
1. Database         (no dependencies)
      ↓
2. Agent Handler    (depends: database healthy)
      ↓
3. WebSocket        (depends: database healthy)
      ↓
4. REST API         (depends: database healthy, websocket healthy)
```

### Health Check Summary

| Service | Method | Endpoint/Command |
|---------|--------|------------------|
| Database | pg_isready | Port 5432 |
| WebSocket | HTTPS GET | https://localhost:3131/health |
| Agent Handler | netcat | 127.0.0.1:50051 |
| REST API | HTTPS GET | https://localhost:8443/health |

### Retry Strategy

All health checks:
- Interval: 10 seconds
- Timeout: 5 seconds
- Retries: 5

Agent Handler additionally has:
- Start period: 10 seconds (grace period)

---

## Configuration Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Service definitions |
| `config.toml` | Server configuration |
| `.env` | Environment variables |
| `db/.secrets/.env` | Database credentials |
| `agent.yaml` | Agent handler config |

---

## Related Files

| Component | File Path |
|-----------|-----------|
| Docker Compose | `server/docker/docker-compose.yml` |
| Database Schema | `server/docker/db/create-tables.sql` |
| Database Init | `server/docker/db/init.sql` |
| WebSocket Entry | `server/cmd/websocket/main.go` |
| Agent Handler Entry | `server/cmd/agent-handler/main.go` |
| REST API Entry | `server/cmd/rest-api/main.go` |
| gRPC Definitions | `server/proto/service/agent.proto` |
| Builder Dockerfile | `server/docker/Dockerfile.builder` |
