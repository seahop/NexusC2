# Profile Management

## Overview

Profiles can be added to a running NexusC2 server without restarting. This enables:
- Rapid iteration during profile development
- Deploying new traffic patterns without downtime
- Automation and scripting of profile management

For profile structure and transform reference, see [Malleable Profiles](/docs/malleable-profiles/).

---

## The nexus-api.py Script

NexusC2 includes a comprehensive CLI tool for API interaction at `scripts/nexus-api.py`. This is the recommended way to interact with profiles programmatically.

### Setup

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

---

## Getting the Template

Download the profile template to start customizing:

```bash
./nexus-api.py profiles template -o my-profiles.toml
```

The template is also available at:
- `server/docker/templates/listener_template.toml`
- `server/docker/templates/listener_test_transforms.toml`

---

## Creating Custom Profiles

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

For complete examples, see [Profile Examples](/docs/profile-examples/).

---

## Uploading Profiles

### Via nexus-api.py

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

### Via GUI Client

1. Navigate to **Tools > Upload Profiles**
2. Select your `.toml` file
3. Review the upload confirmation showing added profiles
4. New profiles appear immediately in listener creation dropdowns

---

## Validation

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

---

## Synchronization

When profiles are uploaded:
1. **Validation** - TOML parsed, profiles validated
2. **Config Update** - Profiles added to in-memory configuration
3. **Service Sync** - Agent-handler receives profiles via gRPC
4. **Client Broadcast** - All connected clients notified of new profiles

New profiles are immediately available for:
- Creating new listeners
- Building new payloads

**Note:** Existing listeners and deployed payloads continue using their compiled profiles.

---

## Managing Profiles

### List Profiles

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

### Get Profile Details

```bash
./nexus-api.py profiles get get custom-get
./nexus-api.py profiles get post custom-post
./nexus-api.py profiles get response custom-response
```

### Delete a Profile

```bash
./nexus-api.py profiles delete get custom-get
./nexus-api.py profiles delete post custom-post
./nexus-api.py profiles delete response custom-response
```

---

## Creating Listeners with Custom Profiles

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

---

## Best Practices

1. **Use consistent naming** - Name related profiles similarly (e.g., `linkedin-get`, `linkedin-post`, `linkedin-response`)
2. **Test transforms locally** - Verify encoding/decoding works before deploying
3. **Coordinate profile sets** - GET, POST, and Response profiles should use compatible transforms
4. **Version your profiles** - Keep profile TOML files in version control
5. **Document custom profiles** - Note the purpose and traffic pattern being mimicked

---

## nexus-api.py Reference

For complete API documentation, see the script help:
```bash
./nexus-api.py --help
./nexus-api.py profiles --help
```

**Environment variables supported:**
- `NEXUS_API_URL` - API base URL (default: https://localhost:8443)
- `NEXUS_API_TOKEN` - JWT access token (saved after login)
- `NEXUS_API_CERT` - Path to server certificate for TLS verification

---

## Related Documentation

- [Malleable Profiles](/docs/malleable-profiles/) - Profile structure and transforms
- [Profile Examples](/docs/profile-examples/) - Complete profile examples
- [API Documentation](/docs/api/) - REST API reference
