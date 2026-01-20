---
title: "Features"
description: "Explore the powerful capabilities of NexusC2 - from cross-platform agents to advanced pivoting techniques."
---

## Cross-Platform Agent Support

NexusC2 supports agents on **Windows**, **Linux**, and **macOS**, each with platform-specific capabilities:

| Platform | Architectures | Output Format | Key Features |
|----------|---------------|---------------|--------------|
| **Windows** | amd64, arm64 | .exe | BOF execution, .NET assembly, token manipulation |
| **Linux** | amd64, arm64 | .bin | Persistence mechanisms, sudo sessions |
| **macOS** | amd64, arm64 | .bin | Keychain access, launch agent persistence |

---

## Encrypted Communications

All communications between agents and the server use **AES-256-GCM** encryption with:

- **RSA-4096** key exchange during handshake
- **Per-session rotating secrets** derived via HKDF
- **HMAC-SHA256** message authentication
- **Counter-based key rotation** for forward secrecy

The encryption ensures that even if network traffic is captured, it cannot be decrypted without access to the session keys.

---

## In-Memory Execution

### Beacon Object Files (BOF)

Execute compiled C object files directly in memory on Windows agents:

- **No disk artifacts** - code runs entirely in agent's memory space
- **Beacon compatibility** - supports common Beacon API functions
- **Async execution** - long-running BOFs don't block the agent
- **Output capture** - results streamed back to operator

### .NET Assembly Execution

Run .NET assemblies without writing to disk:

- **CLR hosting** - dynamically loads the .NET runtime
- **Version support** - .NET Framework 4.x and .NET Core
- **Argument passing** - full command-line argument support
- **Exit prevention** - hooks Environment.Exit to prevent agent crash

### CNA Script Compatibility

Import existing Cobalt Strike Aggressor (CNA) scripts to extend NexusC2 with third-party BOF collections:

- **Script loading** - parse and register commands from CNA files
- **BOF mapping** - auto-locate BOF files relative to script
- **Argument packing** - supports `bof_pack` for typed arguments
- **Popular collections** - compatible with TrustedSec, Outflank, and community BOFs
- **Persistence** - loaded scripts remembered between sessions

```
cna-load /path/to/trustedsec/SA.cna
cna-list
```

See the [CNA Import Guide](/howto/import-cna-scripts/) for detailed instructions.

---

## Network Pivoting

### SOCKS5 Proxy

Create SOCKS5 proxies through agents to access internal networks:

```
Operator → SSH Tunnel → Server → Agent → Internal Network
```

- **Full SOCKS5 support** - TCP connect and UDP associate
- **Authentication** - username/password if required
- **Dynamic port forwarding** - access any internal host/port
- **Multiple concurrent tunnels** - one per agent

### SMB Agent Linking

Chain agents together via SMB named pipes for deep network access:

```
Server ← HTTP → Edge Agent ← SMB → Internal Agent ← SMB → Deep Agent
```

- **Multi-hop support** - unlimited chain depth
- **Automatic routing** - commands flow to correct agent
- **Bi-directional** - results propagate back through chain
- **Named pipe flexibility** - custom pipe names for evasion

---

## REST API

Full-featured API for automation and integration. NexusC2 includes a Python CLI client (`scripts/nexus-api.py`) for easy API access:

```bash
# Login using server certificate (saves token for future requests)
./nexus-api.py --cert ../server/certs/api_server.crt login -u operator1

# Or set certificate path via environment variable
export NEXUS_API_CERT="../server/certs/api_server.crt"
./nexus-api.py login -u operator1

# List all agents
./nexus-api.py agents list
./nexus-api.py agents list --status active --os windows

# Send commands
./nexus-api.py command <agent_id> "whoami"
./nexus-api.py command <agent_id> "ps -x"

# Get command output
./nexus-api.py latest <agent_id>
./nexus-api.py output <command_id>

# Manage listeners
./nexus-api.py listeners list
./nexus-api.py listeners create -n my-https -P HTTPS -p 443

# Build payloads
./nexus-api.py payload build -l https-listener -o windows -a amd64
./nexus-api.py payload build -l https-listener -o linux -a arm64 --language goproject

# Stream real-time events
./nexus-api.py events
```

API capabilities:
- **Agent management** - list, interact, update, tag, remove
- **Command execution** - send, queue, history, output retrieval
- **Listener control** - create, modify, delete HTTP/HTTPS/SMB
- **Payload generation** - build with safety checks (kill date, hostname, etc.)
- **Event streaming** - SSE for real-time agent/command updates
- **Certificate-based authentication** - JWT tokens with TLS client certificate verification

---

## GUI Client

Modern graphical interface built with Fyne:

- **Multi-platform** - runs on Windows, Linux, macOS
- **Real-time updates** - WebSocket connection to server
- **Tab-based interface** - manage multiple agents simultaneously
- **File browser** - visual file system navigation
- **Log viewer** - searchable, filterable event history

---

## Payload Generation

Generate customized payloads through the GUI or API:

| Option | Values |
|--------|--------|
| **Platform** | Windows, Linux, macOS |
| **Architecture** | amd64, arm64 |
| **Language** | Go (compiled binary), GoProject (source export) |
| **Connection** | Direct (HTTP/HTTPS), SMB (named pipes) |

Output formats:
- **Windows**: `.exe` executable
- **Linux/macOS**: `.bin` binary
- **GoProject**: `.zip` containing full source code and build scripts

Payloads are compiled on-demand with embedded configuration, ensuring each build is unique. The GoProject option exports the complete agent source for manual compilation or customization.

---

## File Operations

Comprehensive file transfer capabilities:

- **Upload** - send files to agent with chunked transfer
- **Download** - retrieve files with progress tracking
- **Browse** - visual file system exploration
- **Delete** - remove files and directories

Large files are automatically chunked (64KB) with SHA-256 integrity verification.

---

## Token Manipulation (Windows)

Advanced Windows token operations:

| Command | Description |
|---------|-------------|
| `steal_token` | Steal token from running process |
| `make_token` | Create token with credentials |
| `rev2self` | Revert to original token |
| `getprivs` | Enable token privileges |

---

## Persistence Mechanisms

Platform-appropriate persistence options:

**Windows:**
- Registry run keys
- Scheduled tasks
- Services

**Linux:**
- Cron jobs
- Systemd services
- Profile scripts

**macOS:**
- Launch agents
- Login items

---

## Malleable Profiles

Customize traffic patterns and network signatures using `config.toml`:

- **HTTP routes** - Custom URIs, methods, and parameters
- **Server headers** - Masquerade as nginx, Apache, IIS
- **Payload defaults** - Sleep intervals, jitter, user agents
- **Protocol keywords** - Rename commands to avoid detection
- **SMB settings** - Named pipe names and field customization

See [Malleable Profiles](/docs/malleable-profiles/) for complete documentation.

---

## Security Features

- **TLS everywhere** - all server communications encrypted
- **JWT authentication** - secure API access
- **Role-based access** - operator permission levels
- **Audit logging** - complete operation history
- **Containerized** - isolated Docker deployment
