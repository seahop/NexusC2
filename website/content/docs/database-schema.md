---
title: "Database Schema"
description: "Complete reference for the NexusC2 PostgreSQL database tables and structure."
weight: 2.1
---
## Overview

NexusC2 uses PostgreSQL for persistent storage. The database contains tables for agent tracking, command history, listener configuration, authentication, and link routing.

**Connection Details:**
- Database: `ops`
- User: `postgres`
- Port: 5432 (internal only)
- Authentication: SCRAM-SHA-256

For service architecture and how components connect to the database, see [Infrastructure](INFRASTRUCTURE.md).

---

## Core Tables

### connections

Primary agent tracking table.

| Column | Type | Description |
|--------|------|-------------|
| newclientid | UUID | Unique agent identifier (PK) |
| clientid | VARCHAR | Original client ID from build |
| protocol | VARCHAR | Connection protocol (HTTP/HTTPS/SMB) |
| proto | VARCHAR | Protocol variant |
| extip | VARCHAR | External IP address |
| intip | VARCHAR | Internal IP address |
| username | VARCHAR | Current user |
| hostname | VARCHAR | Machine name |
| process | VARCHAR | Process name |
| pid | VARCHAR | Process ID |
| arch | VARCHAR | Architecture (amd64, arm64) |
| os | VARCHAR | Operating system |
| secret1 | VARCHAR | Current encryption key |
| secret2 | VARCHAR | Previous encryption key |
| lastseen | TIMESTAMP | Last check-in time |
| alias | VARCHAR | Custom agent name |
| note | TEXT | Operator notes |
| deleted_at | TIMESTAMP | Soft delete timestamp |
| parent_clientid | UUID | Parent agent (for linked agents) |
| link_type | VARCHAR(20) | Link type (e.g., "smb") |
| hop_count | INTEGER | Distance from initial agent (default: 0) |

---

### commands

Command audit log.

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL | Primary key |
| username | VARCHAR(255) | Operator who issued command |
| guid | VARCHAR(255) | Target agent |
| command | TEXT | Command text |
| timestamp | TIMESTAMP | When issued |

---

### command_outputs

Command execution results.

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL | Primary key |
| command_id | INTEGER | FK to commands |
| output | TEXT | Command output |
| timestamp | TIMESTAMP | When received |

---

### listeners

Active listener configuration.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| name | VARCHAR | Listener name |
| protocol | VARCHAR | HTTP/HTTPS/SMB |
| port | VARCHAR | Listen port |
| ip | VARCHAR | Bind address |
| pipe_name | VARCHAR | Named pipe (SMB only) |
| get_profile | VARCHAR(100) | GET request profile (default: "default-get") |
| post_profile | VARCHAR(100) | POST request profile (default: "default-post") |
| server_response_profile | VARCHAR(100) | Server response profile (default: "default-response") |
| smb_profile | VARCHAR(100) | SMB transform profile |

---

### inits

Payload initialization data. Stores RSA keys and secrets for new agents before they connect.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| clientid | UUID | Client ID for payload |
| type | VARCHAR | Payload type |
| secret | VARCHAR | Initial secret |
| os | VARCHAR | Target OS |
| arch | VARCHAR | Target architecture |
| rsakey | VARCHAR | RSA private key |
| smb_profile | VARCHAR(100) | SMB profile name (for SMB agents) |
| smb_xor_key | VARCHAR(32) | Per-build unique XOR key (for SMB agents) |

---

## Link Management Tables

### link_routes

Multi-hop routing paths for linked agents.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| source_guid | UUID | Source agent |
| destination_guid | UUID | Target agent |
| next_hop_guid | UUID | Next hop in path |
| hop_count | INTEGER | Total hops |
| route_created | TIMESTAMP | When route was created |
| last_used | TIMESTAMP | Last time route was used |
| status | VARCHAR(50) | Route status (default: "active") |

---

### link_routing

SMB routing table. Maps local routing IDs to linked agent UUIDs.

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL | Primary key |
| edge_clientid | UUID | Edge agent |
| routing_id | VARCHAR(16) | Local routing ID |
| linked_clientid | UUID | Linked agent |
| link_type | VARCHAR(20) | Link type (default: "smb") |
| smb_profile | VARCHAR(100) | SMB profile name |
| smb_xor_key | VARCHAR(32) | Per-build unique XOR key |
| status | VARCHAR(20) | "active" or "disconnected" |
| created_at | TIMESTAMP | When link was established |
| last_seen | TIMESTAMP | Last activity |

---

## Agent Management Tables

### agent_aliases

Custom agent aliases for easier identification.

| Column | Type | Description |
|--------|------|-------------|
| guid | TEXT | Agent GUID (PK) |
| alias | TEXT | Custom alias |
| updated_at | TIMESTAMP | Last update time |

---

### agent_tags

Tags for organizing and filtering agents.

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL | Primary key |
| agent_guid | UUID | FK to connections |
| tag_name | VARCHAR(100) | Tag name |
| tag_color | VARCHAR(7) | Hex color (default: "#4A90E2") |
| created_at | TIMESTAMP | When tag was added |

---

## Authentication Tables

### api_users

REST API user accounts.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key (auto-generated) |
| username | VARCHAR(255) | Unique username |
| password_hash | VARCHAR(255) | Bcrypt hash |
| created_at | TIMESTAMP | Account creation |
| last_login | TIMESTAMP | Last login time |
| is_active | BOOLEAN | Account status (default: true) |

---

### api_tokens

Refresh token storage for JWT authentication.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| user_id | UUID | FK to api_users |
| refresh_token_hash | VARCHAR | Token hash |
| expires_at | TIMESTAMP | Expiration time |
| created_at | TIMESTAMP | Creation time |

---

### user_sessions

GUI client session tracking.

| Column | Type | Description |
|--------|------|-------------|
| sesion_id | UUID | Session ID (PK) |
| username | VARCHAR | Username |
| login_time | TIMESTAMP | When session started |
| logout_time | TIMESTAMP | When session ended |

---

## Querying the Database

To connect to the database directly:

```bash
# From the host machine
docker exec -it database psql -U postgres -d ops

# Common queries
\dt                              # List all tables
\d connections                   # Describe connections table
SELECT * FROM connections;       # List all agents
SELECT * FROM listeners;         # List all listeners
```

---

## Related Documentation

- [Infrastructure](INFRASTRUCTURE.md) - Service architecture and deployment
- [Linked Agents](LINKED-AGENTS.md) - SMB link routing details
- [Encryption](ENCRYPTION.md) - Secret key management
