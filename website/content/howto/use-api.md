---
title: "Use the API"
description: "Automate NexusC2 operations using the REST API."
weight: 3
---

## Overview

The NexusC2 REST API enables automation, scripting, and integration with other tools. This guide covers authentication and common operations.

## Prerequisites

- NexusC2 server running
- API port accessible (default: 8080)
- Valid credentials

## Authentication

### Step 1: Get a Token

*Screenshot placeholder: Show API request in terminal*

Authenticate to receive a JWT token:

```bash
curl -X POST https://your-server:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires": "2024-01-16T12:00:00Z"
}
```

### Step 2: Use the Token

Include the token in subsequent requests:

```bash
export TOKEN="eyJhbGciOiJIUzI1NiIs..."

curl -H "Authorization: Bearer $TOKEN" \
  https://your-server:8080/api/agents
```

## Common Operations

### List Agents

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://your-server:8080/api/agents
```

### Get Agent Details

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://your-server:8080/api/agents/{agent_id}
```

### Execute Command

```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://your-server:8080/api/agents/{agent_id}/commands \
  -d '{"command": "whoami"}'
```

### Get Command Results

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://your-server:8080/api/agents/{agent_id}/results
```

## Python Example

```python
import requests

BASE_URL = "https://your-server:8080/api"

# Authenticate
resp = requests.post(f"{BASE_URL}/login", json={
    "username": "admin",
    "password": "your-password"
}, verify=False)
token = resp.json()["token"]

headers = {"Authorization": f"Bearer {token}"}

# List agents
agents = requests.get(f"{BASE_URL}/agents", headers=headers, verify=False)
print(agents.json())

# Execute command on first agent
if agents.json():
    agent_id = agents.json()[0]["id"]
    requests.post(
        f"{BASE_URL}/agents/{agent_id}/commands",
        headers=headers,
        json={"command": "whoami"},
        verify=False
    )
```

## Error Handling

| Status Code | Meaning |
|-------------|---------|
| 200 | Success |
| 401 | Invalid or expired token |
| 403 | Insufficient permissions |
| 404 | Resource not found |
| 500 | Server error |

## Rate Limiting

The API has built-in rate limiting:

- 100 requests per minute per user
- 1000 requests per hour per user

Exceed these limits and you'll receive a `429 Too Many Requests` response.

## Next Steps

- [Documentation: REST API]({{< ref "/docs/api.md" >}}) - Complete API reference
- [Create a Listener]({{< ref "create-listener.md" >}}) - Set up infrastructure
