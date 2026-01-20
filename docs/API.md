# NexusC2 REST API Documentation

## Overview

The NexusC2 REST API provides programmatic access to all C2 operations. The API uses JWT (JSON Web Token) authentication and communicates over HTTPS on port 8443.

**Base URL**: `https://<server>:8443/api/v1`

## Authentication

All endpoints (except `/auth/cert-login` and `/auth/refresh`) require a valid JWT access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

### Token Lifecycle

1. **Login** with username using certificate-based authentication to receive an access token (1h) and refresh token (24h)
2. **Use access token** for API requests
3. **Refresh** the access token before expiry using the refresh token
4. **Logout** to invalidate the refresh token

### Certificate-Based Authentication

NexusC2 uses TLS certificate-based authentication. If you have access to the server certificate, you can authenticate with just a username. Users are auto-provisioned on first login.

```bash
# Login using the server certificate
./nexus-api.py --cert ../server/certs/api_server.crt login -u operator1

# Or set certificate path via environment variable
export NEXUS_API_CERT="../server/certs/api_server.crt"
./nexus-api.py login -u operator1
```

---

## Endpoint Categories

The API is organized into the following categories:

| Category | Description |
|----------|-------------|
| [Agents](/docs/api-agents/) | List, manage, and interact with connected agents |
| [Commands](/docs/api-commands/) | Send commands and retrieve results |
| [Listeners](/docs/api-listeners/) | Create and manage network listeners |
| [Profiles](/docs/api-profiles/) | Malleable profile management |
| [Payloads](/docs/api-payloads/) | Build agent payloads |
| [Events](/docs/api-events/) | SSE subscription, health checks, user management |

---

## Authentication Endpoints

### POST /api/v1/auth/cert-login

Authenticate using TLS certificate trust. If you can establish a TLS connection (have the server certificate), you can authenticate with just a username. Users are auto-provisioned on first login.

**Request Body:**
```json
{
  "username": "string"     // Required: Your username/operator name
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "a1b2c3d4e5f6...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "username": "operator1"
}
```

**Errors:**
- `400 Bad Request`: Username is required
- `403 Forbidden`: User account is inactive
- `500 Internal Server Error`: Authentication failed

---

### POST /api/v1/auth/refresh

Get a new access token using a refresh token.

**Request Body:**
```json
{
  "refresh_token": "string"    // Required: Current refresh token
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "f6e5d4c3b2a1...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "username": "admin"
}
```

**Note:** The old refresh token is invalidated and a new one is issued.

**Errors:**
- `401 Unauthorized`: Invalid or expired refresh token
- `403 Forbidden`: User account is inactive

---

### POST /api/v1/auth/logout

Invalidate a refresh token.

**Authentication:** Required

**Request Body:**
```json
{
  "refresh_token": "string"    // Required: Refresh token to invalidate
}
```

**Response (200 OK):**
```json
{
  "message": "logged out successfully"
}
```

---

### GET /api/v1/auth/me

Get current user information.

**Authentication:** Required

**Response (200 OK):**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "admin"
}
```

---

## Error Responses

All errors follow a consistent format:

```json
{
  "error": "error message"
}
```

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 202 | Accepted (queued) |
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Invalid/expired token |
| 403 | Forbidden - Account inactive |
| 404 | Not Found - Resource doesn't exist |
| 429 | Too Many Requests - Rate limited |
| 500 | Internal Server Error |

---

## Rate Limiting

The API implements rate limiting per IP address:
- Default: 100 requests per minute
- When exceeded, returns `429 Too Many Requests` with:
```json
{
  "error": "rate limit exceeded",
  "retry_after": 60
}
```
