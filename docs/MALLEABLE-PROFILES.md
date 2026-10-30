# Malleable Profiles

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
> **SMB is different:** SMB profiles use per-build unique XOR keys for enhanced isolation. See [SMB Transforms](SMB-TRANSFORMS.md) for details.

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

For complete, ready-to-use profile examples including CDN/Analytics style, Header-Only auth, NetBIOS encoding, and XOR masking, see [Profile Examples](PROFILE-EXAMPLES.md).

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

For SMB named pipe configuration including connection settings, pipe presets, malleable fields, and pipe traffic transforms (with per-build unique XOR keys), see [SMB Transforms](SMB-TRANSFORMS.md).

---

## Profile Inheritance

Profiles support a `base` field that lets child profiles inherit settings from a parent. Only the fields you specify in the child are overridden; everything else comes from the parent.

### Inherited Fields

| Profile Type | Inheritable Fields |
|--------------|-------------------|
| GET | `path`, `method`, `headers`, `params`, `client_id` |
| POST | `path`, `method`, `content_type`, `headers`, `params`, `client_id`, `data`, `pad_pre_header`, `pad_app_header` |
| Server Response | `content_type`, `status_field`, `data_field`, `command_id_field`, `rekey_value`, `headers`, `data`, `pad_pre_header`, `pad_app_header` |

### Example

```toml
# Base profile with common settings
[[http_profiles.get]]
name = "base-api-get"
path = "/api/v2/status"
method = "GET"
[[http_profiles.get.headers]]
name = "Accept"
value = "application/json"
[http_profiles.get.client_id]
output = "header:X-Request-ID"
[[http_profiles.get.client_id.transforms]]
type = "base64url"

# Child profile - inherits everything, overrides only the path
[[http_profiles.get]]
name = "custom-api-get"
base = "base-api-get"
path = "/api/v2/check"
```

The child `custom-api-get` inherits `method`, `headers`, and `client_id` from `base-api-get`, but uses its own `path`.

> **Note:** The base profile must be defined before any child profiles that reference it. If the base profile is not found, validation will fail.

---

## Profile Variants

Variants group a GET, POST, and server response profile into a named set. Operators select a variant at build time to control the agent's traffic shape without having to specify each profile individually.

### Defining Variants

```toml
[[http_profiles.variants]]
name = "cdn-style"
get_profile = "cdn-jquery-get"
post_profile = "cdn-analytics-post"
server_response_profile = "cdn-analytics-response"

[[http_profiles.variants]]
name = "api-style"
get_profile = "header-auth-get"
post_profile = "header-auth-post"
server_response_profile = "header-auth-response"
```

### Using Variants at Build Time

When building a payload via the REST API, specify `profile_variant` instead of individual profiles:

```bash
curl -sk -X POST https://localhost:8443/api/payloads/build \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listener": "my-https-listener",
    "os": "windows",
    "arch": "amd64",
    "profile_variant": "cdn-style"
  }'
```

The server resolves the variant to its component GET, POST, and server response profiles automatically.

### Listing Variants

```bash
# Via REST API
curl -sk https://localhost:8443/api/profiles/variants \
  -H "Authorization: Bearer $TOKEN"
```

---

## TCP Link Configuration

TCP profiles define how data is obfuscated for TCP-based agent linking, similar to how SMB profiles work for named pipe communication.

### Connection Settings

```toml
[tcp_link]
default_port = 4444
connection_timeout = 30        # Seconds
max_message_size = 10485760    # 10MB
heartbeat_interval = 60        # Seconds
```

### Malleable TCP Fields

```toml
[tcp_link.malleable]
link_data_field = "ld"
link_commands_field = "lc"
link_handshake_field = "lh"
link_handshake_response_field = "lr"
link_unlink_field = "lu"
routing_id_field = "r"
payload_field = "p"
```

### TCP Profiles

TCP profiles use the same DataBlock transform system as SMB profiles:

```toml
[[tcp_link.profiles]]
name = "default-tcp"

[[tcp_link.profiles]]
name = "obfuscated-tcp"
[tcp_link.profiles.data]
output = "body"
[[tcp_link.profiles.data.transforms]]
type = "gzip"
[[tcp_link.profiles.data.transforms]]
type = "xor"
value = "tcp_transform_key"    # Replaced with per-build unique key
[[tcp_link.profiles.data.transforms]]
type = "base64"
```

Like SMB profiles, TCP profiles use **per-build unique XOR keys** when using the `xor` transform. The key defined in the profile serves as a fallback.

**Supported transforms for TCP profiles:** `base64`, `base64url`, `hex`, `gzip`, `netbios`, `xor`, `prepend`, `append`, `random_prepend`, `random_append`

### Creating a TCP Listener

```bash
./scripts/nexus-api.py listeners create \
  -n tcp-listener \
  -P TCP \
  -p 4444 \
  --tcp-profile obfuscated-tcp
```

---

## Dynamic Profile Loading

Profiles can be added to a running NexusC2 server without restarting. For complete documentation on profile management including the nexus-api.py CLI tool, uploading, validation, and best practices, see [Profile Management](PROFILE-MANAGEMENT.md).

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
- [Profile Examples](PROFILE-EXAMPLES.md) - Complete, ready-to-use profile examples
- [SMB Transforms](SMB-TRANSFORMS.md) - Named pipe traffic obfuscation
- [Profile Management](PROFILE-MANAGEMENT.md) - Upload and manage profiles via CLI

**Other Documentation:**
- [Infrastructure](INFRASTRUCTURE.md) - Server architecture overview
- [Payload Generation](PAYLOAD-GENERATION.md) - Building agents with profile settings
- [API Documentation](API.md) - REST API reference
