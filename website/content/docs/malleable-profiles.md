---
title: "Malleable Profiles"
description: "Customize traffic patterns, HTTP signatures, and payload behavior using config.toml profiles."
weight: 3
---

## Overview

NexusC2 uses a malleable profile system defined in `server/config.toml` that allows extensive customization of:

- **HTTP traffic patterns** - Custom URIs, methods, and parameters
- **Data transforms** - Encode, compress, and obfuscate traffic
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

## HTTP Profiles System

NexusC2 uses a named profile system for flexible traffic customization. Instead of directly embedding routes, you define reusable profiles that can be mixed and matched when creating listeners.

### Profile Types

| Profile Type | Purpose |
|--------------|---------|
| `http_profiles.get` | How agents poll for commands |
| `http_profiles.post` | How agents send results |
| `http_profiles.server_response` | How server responds to agents |

### Profile Binding

When creating a listener, you bind profiles together:
- **GET Profile**: Controls command polling requests
- **POST Profile**: Controls result submission requests
- **Server Response Profile**: Controls server responses (transforms, headers)

Payloads built for that listener are compiled with the bound configuration.

---

## Data Transforms

Transforms allow you to modify how data is encoded, compressed, and placed in HTTP requests/responses. This enables traffic to blend with legitimate services.

### Transform Types

| Type | Description | Required Options |
|------|-------------|------------------|
| `base64` | Standard Base64 encoding | None |
| `base64url` | URL-safe Base64 (no +/= characters) | None |
| `hex` | Hexadecimal encoding | None |
| `gzip` | Gzip compression | None |
| `netbios` | NetBIOS nibble encoding (each byte becomes 2 chars a-p) | None |
| `xor` | XOR with key | `value` (the XOR key) |
| `prepend` | Add static prefix | `value` (prefix string) |
| `append` | Add static suffix | `value` (suffix string) |
| `random_prepend` | Add random prefix | `length`, optional `charset` |
| `random_append` | Add random suffix | `length`, optional `charset` |

### Charsets for Random Transforms

| Charset | Characters |
|---------|------------|
| `numeric` | 0-9 |
| `alpha` | a-zA-Z |
| `alphanumeric` | a-zA-Z0-9 (default) |
| `hex` | 0-9a-f |

### Output Locations

| Location | Format | Description |
|----------|--------|-------------|
| Body | `output = "body"` | HTTP request/response body |
| Header | `output = "header:X-Custom"` | HTTP header with name |
| Cookie | `output = "cookie:session"` | HTTP cookie with name |
| Query | `output = "query:param"` | URL query parameter |
| URI Append | `output = "uri_append"` | Append to URI path |

### Transform Chain Execution

Transforms are applied **in order** for outgoing data:
```
Raw data -> Transform 1 -> Transform 2 -> ... -> Final output
```

Transforms are reversed **in opposite order** when extracting:
```
Received data -> Reverse Transform N -> ... -> Reverse Transform 1 -> Original data
```

---

## DataBlock Configuration

DataBlocks define where data goes and how it's transformed. They're used in:
- `http_profiles.get.client_id` - ClientID placement for GET requests
- `http_profiles.post.client_id` - ClientID placement for POST requests
- `http_profiles.post.data` - POST body transforms
- `http_profiles.server_response.data` - Server response transforms

### DataBlock Structure

```toml
[http_profiles.get.client_id]
output = "cookie:session_id"         # Where to place the data

[[http_profiles.get.client_id.transforms]]
type = "base64url"                   # Transform 1: URL-safe base64

[[http_profiles.get.client_id.transforms]]
type = "prepend"                     # Transform 2: Add prefix
value = "sess_"
```

### Example: ClientID in Cookie

```toml
[[http_profiles.get]]
name = "cookie-auth-get"
path = "/api/status"
method = "GET"

# ClientID goes in a cookie after base64url encoding
[http_profiles.get.client_id]
output = "cookie:auth_token"
[[http_profiles.get.client_id.transforms]]
type = "base64url"
```

Result: `Cookie: auth_token=dXVpZC1oZXJl`

### Example: ClientID in Header

```toml
[[http_profiles.get]]
name = "header-auth-get"
path = "/api/v2/check"
method = "GET"

# ClientID goes in Authorization header
[http_profiles.get.client_id]
output = "header:X-Request-ID"
[[http_profiles.get.client_id.transforms]]
type = "base64"
[[http_profiles.get.client_id.transforms]]
type = "prepend"
value = "token_"
```

Result: `X-Request-ID: token_dXVpZC1oZXJl`

### Example: POST Body Transforms

```toml
[[http_profiles.post]]
name = "compressed-post"
path = "/upload"
method = "POST"

# POST body is gzipped, then base64 encoded, with random padding
[http_profiles.post.data]
output = "body"
[[http_profiles.post.data.transforms]]
type = "gzip"
[[http_profiles.post.data.transforms]]
type = "base64"
[[http_profiles.post.data.transforms]]
type = "random_prepend"
length = 16
charset = "hex"
[[http_profiles.post.data.transforms]]
type = "random_append"
length = 16
charset = "hex"
```

### Example: Server Response Transforms

```toml
[[http_profiles.server_response]]
name = "js-response"
content_type = "application/javascript"

# Response looks like minified JavaScript
[http_profiles.server_response.data]
output = "body"
[[http_profiles.server_response.data.transforms]]
type = "base64"
[[http_profiles.server_response.data.transforms]]
type = "prepend"
value = "/*! Library v1.0 */var _0x="
[[http_profiles.server_response.data.transforms]]
type = "append"
value = ";(function(){})();"
```

---

## Complete Profile Examples

### Example 1: CDN/Analytics Style

Mimics CDN asset requests with Google Analytics-style session cookies:

```toml
# GET Profile - Looks like jQuery CDN request
[[http_profiles.get]]
name = "cdn-jquery-get"
path = "/libs/jquery/3.6.0/jquery.min.js"
method = "GET"
[[http_profiles.get.headers]]
name = "Accept"
value = "application/javascript, */*;q=0.8"
[[http_profiles.get.headers]]
name = "Accept-Encoding"
value = "gzip, deflate, br"
[[http_profiles.get.headers]]
name = "Referer"
value = "https://www.example.com/"

# Legacy params fallback for initial handshake
[[http_profiles.get.params]]
name = "v"
location = "query"
type = "clientID_param"
format = "%CLIENTID%"

# After handshake, clientID in cookie
[http_profiles.get.client_id]
output = "cookie:_ga_session"
[[http_profiles.get.client_id.transforms]]
type = "base64url"
[[http_profiles.get.client_id.transforms]]
type = "prepend"
value = "GA1.2."

# POST Profile - Analytics beacon
[[http_profiles.post]]
name = "cdn-analytics-post"
path = "/collect"
method = "POST"
content_type = "application/x-www-form-urlencoded"

[[http_profiles.post.params]]
name = "v"
location = "query"
type = "clientID_param"
format = "%CLIENTID%"

[http_profiles.post.client_id]
output = "cookie:_ga_session"
[[http_profiles.post.client_id.transforms]]
type = "base64url"
[[http_profiles.post.client_id.transforms]]
type = "prepend"
value = "GA1.2."

[http_profiles.post.data]
output = "body"
[[http_profiles.post.data.transforms]]
type = "gzip"
[[http_profiles.post.data.transforms]]
type = "base64"
[[http_profiles.post.data.transforms]]
type = "random_prepend"
length = 8
charset = "alphanumeric"
[[http_profiles.post.data.transforms]]
type = "random_append"
length = 8
charset = "alphanumeric"

# Server Response - Looks like JS file
[[http_profiles.server_response]]
name = "cdn-analytics-response"
content_type = "application/javascript; charset=utf-8"
[[http_profiles.server_response.headers]]
name = "Cache-Control"
value = "public, max-age=31536000"

[http_profiles.server_response.data]
output = "body"
[[http_profiles.server_response.data.transforms]]
type = "base64"
[[http_profiles.server_response.data.transforms]]
type = "prepend"
value = "/*! jQuery v3.6.0 | (c) OpenJS Foundation */"
```

### Example 2: Header-Only Auth Style

All data in headers - minimal body footprint:

```toml
[[http_profiles.get]]
name = "header-auth-get"
path = "/api/v2/health"
method = "GET"

[http_profiles.get.client_id]
output = "header:X-Correlation-ID"
[[http_profiles.get.client_id.transforms]]
type = "base64url"

[[http_profiles.post]]
name = "header-auth-post"
path = "/api/v2/telemetry"
method = "POST"

[http_profiles.post.client_id]
output = "header:X-Correlation-ID"
[[http_profiles.post.client_id.transforms]]
type = "base64url"

[http_profiles.post.data]
output = "header:X-Telemetry-Data"
[[http_profiles.post.data.transforms]]
type = "gzip"
[[http_profiles.post.data.transforms]]
type = "base64"

[[http_profiles.server_response]]
name = "header-auth-response"
content_type = "application/json"

[http_profiles.server_response.data]
output = "header:X-Response-Data"
[[http_profiles.server_response.data.transforms]]
type = "base64"
```

### Example 3: NetBIOS Encoding

Uses NetBIOS nibble encoding (legacy compatibility):

```toml
[[http_profiles.get]]
name = "netbios-get"
path = "/dns/query"
method = "GET"

[http_profiles.get.client_id]
output = "query:name"
[[http_profiles.get.client_id.transforms]]
type = "netbios"

[[http_profiles.server_response]]
name = "netbios-response"
content_type = "application/dns-message"

[http_profiles.server_response.data]
output = "body"
[[http_profiles.server_response.data.transforms]]
type = "netbios"
```

### Example 4: XOR Masking with Hex Encoding

Additional obfuscation layer with XOR:

```toml
[[http_profiles.post]]
name = "xor-hex-post"
path = "/metrics"
method = "POST"

[http_profiles.post.data]
output = "body"
[[http_profiles.post.data.transforms]]
type = "xor"
value = "secretkey123"
[[http_profiles.post.data.transforms]]
type = "hex"
[[http_profiles.post.data.transforms]]
type = "prepend"
value = "metrics="

[[http_profiles.server_response]]
name = "xor-hex-response"
content_type = "text/plain"

[http_profiles.server_response.data]
output = "body"
[[http_profiles.server_response.data.transforms]]
type = "xor"
value = "secretkey123"
[[http_profiles.server_response.data.transforms]]
type = "hex"
```

---

## Transform Flow Diagram

```
AGENT -> SERVER (Request)
+------------------------------------------------------------------+
|  Raw Data (e.g., clientID or command output)                     |
|       |                                                          |
|       v                                                          |
|  AES-GCM Encrypt (for POST data)                                 |
|       |                                                          |
|       v                                                          |
|  Transform Chain: gzip -> base64 -> prepend -> random_append     |
|       |                                                          |
|       v                                                          |
|  Place in Output Location (body/header/cookie/query)             |
|       |                                                          |
|       v                                                          |
|  HTTP Request                                                    |
+------------------------------------------------------------------+

SERVER -> AGENT (Response)
+------------------------------------------------------------------+
|  Response Data (JSON with status/commands)                       |
|       |                                                          |
|       v                                                          |
|  XOR Encrypt (with rotating secret)                              |
|       |                                                          |
|       v                                                          |
|  Transform Chain: base64 -> prepend(JS comment)                  |
|       |                                                          |
|       v                                                          |
|  HTTP Response                                                   |
+------------------------------------------------------------------+

SERVER EXTRACTION (Reverse)
+------------------------------------------------------------------+
|  Extract from Location (body/header/cookie/query)                |
|       |                                                          |
|       v                                                          |
|  Reverse Transforms: strip_append -> strip_prepend -> base64 -> gunzip |
|       |                                                          |
|       v                                                          |
|  AES-GCM Decrypt                                                 |
|       |                                                          |
|       v                                                          |
|  Original Data                                                   |
+------------------------------------------------------------------+
```

---

## Random Padding Headers

When using `random_prepend` or `random_append`, the agent sends padding lengths in headers so the server knows how much to strip:

| Header | Purpose |
|--------|---------|
| `X-Pad-Pre` | Length of random prepend |
| `X-Pad-App` | Length of random append |

These headers are automatically added by the agent and read by the server during transform reversal.

---

## Legacy vs Transform Mode

**Legacy Mode** (no DataBlocks):
- ClientID in query parameters or parsed from URL/headers via `params`
- POST body is JSON with `data` field
- Server response is JSON-wrapped with random keys

**Transform Mode** (with DataBlocks):
- ClientID placed via transform chain into configured output location
- POST body is transformed directly (no JSON wrapper)
- Server response is transformed directly (no JSON wrapper)

Both modes are fully supported. A profile without DataBlocks uses legacy mode automatically.

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

With `sleep = 20` and `jitter = 10`, agents will callback every 18-22 seconds (+/-10%).

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
name = "Accept"
value = "*/*"
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

```toml
[[smb_link.pipe_presets]]
name = "spoolss"
description = "Print Spooler Service"

[[smb_link.pipe_presets]]
name = "srvsvc"
description = "Server Service"
```

### Malleable SMB Fields

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

## Dynamic Profile Loading

Profiles can be added to a running NexusC2 server without restarting. This enables:
- Rapid iteration during profile development
- Deploying new traffic patterns without downtime
- Automation and scripting of profile management

### The nexus-api.py Script

NexusC2 includes a comprehensive CLI tool for API interaction at `scripts/nexus-api.py`. This is the recommended way to interact with profiles programmatically.

**Setup:**
```bash
# Create and activate a virtual environment (recommended)
cd scripts
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install requests

# Login with certificate (credentials saved to ~/.nexus_api_env)
./nexus-api.py --cert ../server/certs/api_server.crt login -u operator1

# Or set certificate path via environment variable
export NEXUS_API_CERT="../server/certs/api_server.crt"
./nexus-api.py login -u operator1
```

### Getting the Template

Download the profile template to start customizing:

```bash
./nexus-api.py profiles template -o my-profiles.toml
```

The template is also available at `server/docker/templates/listener_template.toml` and `server/docker/templates/listener_test_transforms.toml`.

### Creating Custom Profiles

Profiles use TOML format with three coordinated profile types:

```toml
# GET Profile - How agents poll for commands
[[http_profiles.get]]
name = "custom-get"
path = "/api/status"
method = "GET"

[http_profiles.get.client_id]
output = "header:X-Session-ID"
[[http_profiles.get.client_id.transforms]]
type = "base64url"

# POST Profile - How agents send results
[[http_profiles.post]]
name = "custom-post"
path = "/api/submit"
method = "POST"
content_type = "application/json"

[http_profiles.post.client_id]
output = "header:X-Session-ID"
[[http_profiles.post.client_id.transforms]]
type = "base64url"

[http_profiles.post.data]
output = "body"
[[http_profiles.post.data.transforms]]
type = "gzip"
[[http_profiles.post.data.transforms]]
type = "base64"

# Server Response Profile - How server responds
[[http_profiles.server_response]]
name = "custom-response"
content_type = "application/json"

[http_profiles.server_response.data]
output = "body"
[[http_profiles.server_response.data.transforms]]
type = "base64"
```

### Uploading Profiles

**Via nexus-api.py:**
```bash
./nexus-api.py profiles upload my-profiles.toml
```

**Output (success):**
```
Status: success
Message: Successfully added 3 profile(s)

GET profiles added:
  + custom-get

POST profiles added:
  + custom-post

Server Response profiles added:
  + custom-response
```

**Output (partial success with errors):**
```
Status: partial
Message: Some profiles added with errors

GET profiles added:
  + custom-get

Errors:
  ! POST profile 'custom-post': path is required
```

### Uploading via Client

1. Navigate to **Tools > Upload Profiles**
2. Select your `.toml` file
3. Review the upload confirmation showing added profiles
4. New profiles appear immediately in listener creation dropdowns

### Validation

Profiles are validated before being added:

| Profile Type | Required Fields |
|--------------|-----------------|
| GET | `name`, `path` |
| POST | `name`, `path` |
| Server Response | `name` |

Additional validations:
- Duplicate names are rejected
- Invalid transform types are rejected
- Params must have `name`, `location`, and `type`

### Synchronization

When profiles are uploaded:
1. **Validation** - TOML parsed, profiles validated
2. **Config Update** - Profiles added to in-memory configuration
3. **Service Sync** - Agent-handler receives profiles via gRPC
4. **Client Broadcast** - All connected clients notified of new profiles

New profiles are immediately available for:
- Creating new listeners
- Building new payloads

**Note:** Existing listeners and deployed payloads continue using their compiled profiles.

### Managing Profiles

**List all profiles:**
```bash
./nexus-api.py profiles list
```

**List specific profile types:**
```bash
./nexus-api.py profiles list-get
./nexus-api.py profiles list-post
./nexus-api.py profiles list-response
```

**List profile names only:**
```bash
./nexus-api.py profiles names
```

**Get profile details:**
```bash
./nexus-api.py profiles get get custom-get
./nexus-api.py profiles get post custom-post
./nexus-api.py profiles get response custom-response
```

**Delete a profile:**
```bash
./nexus-api.py profiles delete get custom-get
./nexus-api.py profiles delete post custom-post
./nexus-api.py profiles delete response custom-response
```

### Creating Listeners with Custom Profiles

After uploading profiles, bind them to a listener:

```bash
./nexus-api.py listeners create \
  -n my-listener \
  -P HTTPS \
  -p 443 \
  --get-profile custom-get \
  --post-profile custom-post \
  --response-profile custom-response
```

### Best Practices

1. **Use consistent naming** - Name related profiles similarly (e.g., `linkedin-get`, `linkedin-post`, `linkedin-response`)
2. **Test transforms locally** - Verify encoding/decoding works before deploying
3. **Coordinate profile sets** - GET, POST, and Response profiles should use compatible transforms
4. **Version your profiles** - Keep profile TOML files in version control
5. **Document custom profiles** - Note the purpose and traffic pattern being mimicked

### nexus-api.py Reference

For complete API documentation, see the script help:
```bash
./nexus-api.py --help
./nexus-api.py profiles --help
```

Environment variables supported:
- `NEXUS_API_URL` - API base URL (default: https://localhost:8443)
- `NEXUS_API_TOKEN` - JWT access token (saved after login)
- `NEXUS_API_CERT` - Path to server certificate for TLS verification (e.g., `server/certs/api_server.crt`)

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
