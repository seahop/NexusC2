---
title: "Malleable Profiles"
description: "Customize traffic patterns, HTTP signatures, and payload behavior using config.toml profiles."
weight: 3
---

## Overview

NexusC2 uses a malleable profile system defined in `server/config.toml` that allows extensive customization of:

- **HTTP traffic patterns** - Custom URIs, methods, and parameters
- **Server headers** - Masquerade as legitimate web servers
- **Payload behavior** - Sleep intervals, jitter, HTTP headers
- **Protocol signatures** - Rename command keywords to avoid detection
- **SMB link settings** - Named pipe names and field customization

Changes to `config.toml` take effect when the server restarts and are baked into generated payloads at build time.

---

## Configuration File Location

```
server/config.toml
```

The file uses [TOML format](https://toml.io/) for human-readable configuration.

---

## Server Configuration

### WebSocket Service

```toml
[websocket]
port = "3131"
cert_file = "/app/certs/ws_server.crt"
key_file = "/app/certs/ws_server.key"
```

| Option | Description | Default |
|--------|-------------|---------|
| `port` | WebSocket service port for GUI clients | 3131 |
| `cert_file` | TLS certificate path | /app/certs/ws_server.crt |
| `key_file` | TLS private key path | /app/certs/ws_server.key |

### REST API Service

```toml
[rest_api]
port = "8443"
cert_file = "/app/certs/api_server.crt"
key_file = "/app/certs/api_server.key"

[rest_api.jwt]
access_expiry = "1h"
refresh_expiry = "24h"

[rest_api.rate_limit]
requests_per_minute = 100

[rest_api.cors]
allowed_origins = ["*"]
```

| Option | Description | Default |
|--------|-------------|---------|
| `port` | REST API HTTPS port | 8443 |
| `access_expiry` | JWT access token lifetime | 1h |
| `refresh_expiry` | JWT refresh token lifetime | 24h |
| `requests_per_minute` | Rate limit per IP | 100 |
| `allowed_origins` | CORS allowed origins | ["*"] |

### Listener Certificates

```toml
[web_server]
cert_file = "/app/certs/web_server.crt"
key_file = "/app/certs/web_server.key"

[rpc_server]
cert_file = "/app/certs/rpc_server.crt"
key_file = "/app/certs/rpc_server.key"
```

---

## HTTP Route Customization

Define custom HTTP routes for agent communication. This allows you to mimic legitimate API endpoints.

### GET-type Handlers

Used by agents to check for pending commands.

```toml
[[http_routes.get_handlers]]
path = "/api/v1/myget"
method = "PUT"           # Custom HTTP verb (default: GET)
enabled = true
auth_required = true

[[http_routes.get_handlers.params]]
name = "client"
type = "clientID_param"
format = "%CLIENTID%"
```

### POST-type Handlers

Used by agents to send command output and check-in data.

```toml
[[http_routes.post_handlers]]
path = "/api/v1/mypost"
method = "BLAH"          # Custom HTTP verb (default: POST)
enabled = true
auth_required = true

[[http_routes.post_handlers.params]]
name = "client"
type = "clientID_param"
format = "%CLIENTID%"
```

### Route Options

| Option | Description |
|--------|-------------|
| `path` | URI path for the endpoint |
| `method` | HTTP method (can be any string) |
| `enabled` | Enable/disable the route |
| `auth_required` | Require valid agent authentication |
| `params` | Parameter definitions with name, type, format |

### Example: Mimic Microsoft API

```toml
[[http_routes.get_handlers]]
path = "/v1.0/me/drive/root/children"
method = "GET"
enabled = true
auth_required = true

[[http_routes.post_handlers]]
path = "/v1.0/me/drive/items"
method = "POST"
enabled = true
auth_required = true
```

---

## Redirect Site

Configure where unauthorized requests are redirected:

```toml
[redirect_site]
url = "https://google.com"
```

Requests that fail authentication or hit undefined routes are redirected here, making the server appear as a legitimate redirector.

---

## Server Headers

Customize HTTP response headers to masquerade as legitimate servers:

```toml
[server_headers]
server = "nginx/1.18.0"
strict_transport_security = "max-age=31536000; includeSubDomains"
x_frame_options = "DENY"
x_content_type_options = "nosniff"
```

| Header | Purpose |
|--------|---------|
| `server` | Server identification string |
| `strict_transport_security` | HSTS policy |
| `x_frame_options` | Clickjacking protection |
| `x_content_type_options` | MIME sniffing prevention |

### Example: Mimic Apache

```toml
[server_headers]
server = "Apache/2.4.41 (Ubuntu)"
x_powered_by = "PHP/7.4.3"
```

### Example: Mimic IIS

```toml
[server_headers]
server = "Microsoft-IIS/10.0"
x_powered_by = "ASP.NET"
x_aspnet_version = "4.0.30319"
```

---

## Payload Configuration

### Sleep and Jitter

Control agent callback behavior:

```toml
[payload_config]
sleep = 20      # Base sleep interval in seconds
jitter = 10     # Random variance percentage (0-100)
```

With `sleep = 20` and `jitter = 10`, agents will callback every 18-22 seconds (±10%).

### HTTP Headers

Customize the HTTP headers agents send:

```toml
[payload_config.http_headers]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
content_type = "application/json"

[[payload_config.http_headers.custom_headers]]
name = "X-Custom-Header"
value = "custom-value"

[[payload_config.http_headers.custom_headers]]
name = "X-Forward-For"
value = "127.0.0.1"

[[payload_config.http_headers.custom_headers]]
name = "Accept"
value = "*/*"

[[payload_config.http_headers.custom_headers]]
name = "Accept-Language"
value = "en-US,en;q=0.9"

[[payload_config.http_headers.custom_headers]]
name = "Connection"
value = "close"
```

### Example: Chrome User Agent

```toml
[payload_config.http_headers]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
```

### Example: macOS Safari

```toml
[payload_config.http_headers]
user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
```

---

## Malleable Commands

Rename internal command keywords to avoid signature detection:

```toml
[payload_config.malleable_commands]
# Change 'rekey' command to avoid detection
rekey = "bloop"

# JSON field names for rekey response
rekey_status_field = "status"
rekey_data_field = "data"
rekey_id_field = "id"
```

### How It Works

1. The string `rekey` is replaced with your custom value (`bloop`) in:
   - Agent binary (compiled in)
   - Network traffic (cleartext command field)

2. JSON response structure:
   ```json
   // Default
   {"status": "bloop", "data": "", "id": 1}

   // Custom fields
   {"x": "bloop", "y": "", "z": 1}
   ```

### Example: Custom Field Names

```toml
[payload_config.malleable_commands]
rekey = "sync"
rekey_status_field = "x"
rekey_data_field = "y"
rekey_id_field = "z"
```

---

## SMB Link Configuration

Settings for SMB-based agent linking (lateral movement):

### Connection Settings

```toml
[smb_link]
connection_timeout = 30        # Seconds
max_message_size = 1048576     # 1MB
heartbeat_interval = 60        # Seconds
```

### Named Pipe Presets

Preconfigured pipe names that mimic legitimate Windows services:

```toml
[[smb_link.pipe_presets]]
name = "spoolss"
description = "Print Spooler Service"

[[smb_link.pipe_presets]]
name = "srvsvc"
description = "Server Service"

[[smb_link.pipe_presets]]
name = "wkssvc"
description = "Workstation Service"

[[smb_link.pipe_presets]]
name = "netlogon"
description = "Netlogon Service"

[[smb_link.pipe_presets]]
name = "lsarpc"
description = "LSA RPC"

[[smb_link.pipe_presets]]
name = "samr"
description = "SAM RPC"

[[smb_link.pipe_presets]]
name = "browser"
description = "Computer Browser"
```

### Malleable SMB Fields

Customize JSON field names in the encrypted link protocol:

```toml
[smb_link.malleable]
link_data_field = "ld"              # Linked agent data in POST
link_commands_field = "lc"          # Commands for linked agents
link_handshake_field = "lh"         # Initial handshake
link_handshake_response_field = "lr" # Handshake response
routing_id_field = "r"              # Routing identifier
payload_field = "p"                 # Encrypted payload
```

---

## Complete Example Profile

Here's a complete profile mimicking Microsoft Graph API traffic:

```toml
[websocket]
port = "3131"
cert_file = "/app/certs/ws_server.crt"
key_file = "/app/certs/ws_server.key"

[rest_api]
port = "8443"
cert_file = "/app/certs/api_server.crt"
key_file = "/app/certs/api_server.key"

[rest_api.jwt]
access_expiry = "1h"
refresh_expiry = "24h"

[redirect_site]
url = "https://login.microsoftonline.com"

[[http_routes.get_handlers]]
path = "/v1.0/me/drive/root/children"
method = "GET"
enabled = true
auth_required = true
[[http_routes.get_handlers.params]]
name = "session"
type = "clientID_param"
format = "%CLIENTID%"

[[http_routes.post_handlers]]
path = "/v1.0/me/drive/items"
method = "POST"
enabled = true
auth_required = true

[server_headers]
server = "Microsoft-IIS/10.0"
x_powered_by = "ASP.NET"

[payload_config]
sleep = 60
jitter = 20

[payload_config.http_headers]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
content_type = "application/json"

[[payload_config.http_headers.custom_headers]]
name = "Authorization"
value = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."

[payload_config.malleable_commands]
rekey = "refresh"
rekey_status_field = "token_type"
rekey_data_field = "access_token"
rekey_id_field = "expires_in"
```

---

## Applying Changes

After modifying `config.toml`:

1. **Restart the server:**
   ```bash
   cd server/docker
   docker-compose down
   docker-compose up -d
   ```

2. **Regenerate payloads:**
   Existing payloads will continue using old settings. Generate new payloads to use updated configuration.

---

## Related Documentation

- [Infrastructure]({{< ref "infrastructure.md" >}}) - Server architecture overview
- [Payload Generation]({{< ref "payload-generation.md" >}}) - Building agents with profile settings
- [API Documentation]({{< ref "api.md" >}}) - REST API reference
