---
title: "Malleable Profiles"
description: "Customize traffic patterns, HTTP signatures, and payload behavior using config.toml profiles."
weight: 3
---
Customize traffic patterns, HTTP signatures, and payload behavior using config.toml profiles.

## Overview

NexusC2 uses a malleable profile system defined in `server/config.toml` that allows extensive customization of:

- **HTTP traffic patterns** - Custom URIs, methods, and parameters
- **Data transforms** - Encode, compress, and obfuscate traffic
- **Server headers** - Masquerade as legitimate web servers
- **Payload behavior** - Sleep intervals, jitter, HTTP headers
- **Protocol signatures** - Rename command keywords to avoid detection
- **SMB link settings** - Named pipe names and field customization

Changes to `config.toml` take effect when the server restarts and are baked into generated payloads at build time.

## Configuration File Location

```
server/config.toml
```

The file uses [TOML format](https://toml.io/) for human-readable configuration.

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
| `xor` | XOR with key (see note below) | `value` (the XOR key) |
| `prepend` | Add static prefix | `value` (prefix string) |
| `append` | Add static suffix | `value` (suffix string) |
| `random_prepend` | Add random prefix | `length`, optional `charset` |
| `random_append` | Add random suffix | `length`, optional `charset` |

> **HTTP XOR Keys:** For HTTP/HTTPS profiles, `xor` transforms use the **static key from config.toml**. Both the agent and server use the same key defined in the profile. This keeps the implementation simple and reliable.
>
> **Note:** The transform XOR key is separate from the communication encryption. Agent traffic is encrypted with a rotating per-connection secret derived from the agent's unique ID and session keys. The transform XOR is an additional obfuscation layer applied on top of the encrypted data.
>
> **SMB is different:** SMB profiles use per-build unique XOR keys for enhanced isolation. See [SMB Transforms](/docs/smb-transforms/) for details.

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

For complete, ready-to-use profile examples including CDN/Analytics style, Header-Only auth, NetBIOS encoding, and XOR masking, see [Profile Examples](/docs/profile-examples/).

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

For SMB named pipe configuration including connection settings, pipe presets, malleable fields, and pipe traffic transforms (with per-build unique XOR keys), see [SMB Transforms](/docs/smb-transforms/).

---

## Dynamic Profile Loading

Profiles can be added to a running NexusC2 server without restarting. For complete documentation on profile management including the nexus-api.py CLI tool, uploading, validation, and best practices, see [Profile Management](/docs/profile-management/).

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

**Profile Sub-Pages:**
- [Profile Examples](/docs/profile-examples/) - Complete, ready-to-use profile examples
- [SMB Transforms](/docs/smb-transforms/) - Named pipe traffic obfuscation
- [Profile Management](/docs/profile-management/) - Upload and manage profiles via CLI

**Other Documentation:**
- [Infrastructure](/docs/infrastructure/) - Server architecture overview
- [Payload Generation](/docs/payload-generation/) - Building agents with profile settings
- [API Documentation](/docs/api/) - REST API reference
