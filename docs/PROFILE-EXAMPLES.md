# Profile Examples

## Overview

This page provides complete, ready-to-use profile examples that demonstrate different traffic patterns. Each example includes coordinated GET, POST, and server response profiles.

For transform reference and profile structure details, see [Malleable Profiles](MALLEABLE-PROFILES.md).

---

## Example 1: CDN/Analytics Style

Mimics CDN asset requests with Google Analytics-style session cookies. Traffic appears as jQuery library requests and analytics beacons.

**Use Case:** Blend with legitimate CDN and analytics traffic.

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

---

## Example 2: Header-Only Auth Style

All data transmitted in HTTP headers with minimal body footprint. Useful when body inspection is more likely.

**Use Case:** Environments with strict body inspection but permissive header policies.

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

---

## Example 3: NetBIOS Encoding

Uses NetBIOS nibble encoding where each byte becomes two characters (a-p). Makes traffic resemble DNS or NetBIOS name resolution.

**Use Case:** Legacy network environments or DNS-over-HTTP scenarios.

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

---

## Example 4: XOR Masking with Hex Encoding

Additional obfuscation layer using XOR encryption followed by hex encoding. Data appears as hex-encoded metrics.

**Use Case:** Additional encryption layer for sensitive environments.

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

## Tips for Creating Custom Profiles

1. **Coordinate all three profiles** - GET, POST, and server response should use compatible transforms and naming conventions.

2. **Match your target environment** - Research what legitimate traffic looks like in your target network and mimic those patterns.

3. **Test transforms locally** - Verify encoding/decoding works correctly before deployment.

4. **Use consistent naming** - Name related profiles similarly (e.g., `linkedin-get`, `linkedin-post`, `linkedin-response`).

5. **Consider header sizes** - Some proxies have header size limits. Test with realistic payloads.

6. **Version your profiles** - Keep profile TOML files in version control for reproducibility.

---

## Related Documentation

- [Malleable Profiles](MALLEABLE-PROFILES.md) - Transform reference and profile structure
- [Profile Management](PROFILE-MANAGEMENT.md) - Upload and manage profiles via CLI
- [SMB Transforms](SMB-TRANSFORMS.md) - Named pipe traffic obfuscation
