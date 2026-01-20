---
title: "API: Profiles"
description: "Malleable profile endpoints for listing, uploading, and managing HTTP traffic profiles."
weight: 54
---
[← Back to API Overview](/docs/api/)

---

Malleable profiles define HTTP request/response patterns for agent communication, allowing traffic to blend in with legitimate services (AWS S3, Microsoft Graph, etc.).

**Profile Sources:**
- **Static profiles** are defined in `server/config.toml` and loaded at server startup
- **Dynamic profiles** can be uploaded at runtime via the API or client UI without restarting the server

**Creating Custom Profiles:**
1. Download the template: `GET /api/v1/profiles/template` or use the client (Tools > Upload Profiles)
2. Edit the template file (`server/docker/templates/listener_template.toml`) to define your custom profiles
3. Upload via API (`POST /api/v1/profiles/upload`) or the client UI
4. Create a listener using your new profiles

Each profile type serves a specific purpose:
- **GET profiles**: Define how agents poll for commands (path, method, headers, client ID parameter)
- **POST profiles**: Define how agents send results back (path, method, content type, client ID parameter)
- **Server Response profiles**: Define how the server responds to agents (content type, JSON field names, headers)

---

## GET /api/v1/profiles

List all available malleable profiles.

**Authentication:** Required

**Response (200 OK):**
```json
{
  "get_profiles": [
    {
      "name": "default-get",
      "path": "/api/v1/status",
      "method": "GET"
    },
    {
      "name": "microsoft-graph-get",
      "path": "/v1.0/me/drive/root/children",
      "method": "GET"
    }
  ],
  "post_profiles": [
    {
      "name": "default-post",
      "path": "/api/v1/data",
      "method": "POST"
    },
    {
      "name": "microsoft-graph-post",
      "path": "/v1.0/me/drive/items",
      "method": "PUT"
    }
  ],
  "server_response_profiles": [
    {
      "name": "default-response",
      "content_type": "application/json"
    },
    {
      "name": "microsoft-graph-response",
      "content_type": "application/json; odata.metadata=minimal"
    }
  ]
}
```

---

## GET /api/v1/profiles/get

List all GET request profiles.

**Authentication:** Required

**Response (200 OK):**
```json
{
  "profiles": [
    {
      "name": "default-get",
      "path": "/api/v1/status",
      "method": "GET",
      "headers": [
        {"name": "Accept", "value": "application/json"}
      ],
      "params": [
        {"name": "client", "location": "query", "type": "clientID_param", "format": "%CLIENTID%"}
      ]
    },
    {
      "name": "microsoft-graph-get",
      "path": "/v1.0/me/drive/root/children",
      "method": "GET",
      "headers": [
        {"name": "Authorization", "value": "Bearer %CLIENTID%"}
      ],
      "params": [
        {"name": "Authorization", "location": "header", "type": "clientID_param", "format": "Bearer %CLIENTID%"}
      ]
    }
  ]
}
```

---

## GET /api/v1/profiles/get/:name

Get a specific GET profile by name.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Profile name

**Response (200 OK):**
```json
{
  "name": "microsoft-graph-get",
  "path": "/v1.0/me/drive/root/children",
  "method": "GET",
  "headers": [
    {"name": "Authorization", "value": "Bearer %CLIENTID%"}
  ],
  "params": [
    {"name": "Authorization", "location": "header", "type": "clientID_param", "format": "Bearer %CLIENTID%"}
  ]
}
```

**Errors:**
- `404 Not Found`: Profile not found

---

## GET /api/v1/profiles/post

List all POST request profiles.

**Authentication:** Required

**Response (200 OK):**
```json
{
  "profiles": [
    {
      "name": "default-post",
      "path": "/api/v1/data",
      "method": "POST",
      "content_type": "application/json",
      "headers": [],
      "params": [
        {"name": "client", "location": "query", "type": "clientID_param", "format": "%CLIENTID%"}
      ]
    },
    {
      "name": "microsoft-graph-post",
      "path": "/v1.0/me/drive/items",
      "method": "PUT",
      "content_type": "application/json",
      "headers": [
        {"name": "Authorization", "value": "Bearer %CLIENTID%"}
      ],
      "params": []
    }
  ]
}
```

---

## GET /api/v1/profiles/post/:name

Get a specific POST profile by name.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Profile name

**Response (200 OK):**
```json
{
  "name": "microsoft-graph-post",
  "path": "/v1.0/me/drive/items",
  "method": "PUT",
  "content_type": "application/json",
  "headers": [
    {"name": "Authorization", "value": "Bearer %CLIENTID%"}
  ],
  "params": []
}
```

**Errors:**
- `404 Not Found`: Profile not found

---

## GET /api/v1/profiles/server-response

List all server response profiles.

**Authentication:** Required

**Response (200 OK):**
```json
{
  "profiles": [
    {
      "name": "default-response",
      "content_type": "application/json",
      "status_field": "status",
      "data_field": "data",
      "command_id_field": "id",
      "rekey_value": "refresh",
      "headers": [
        {"name": "Cache-Control", "value": "no-store"}
      ]
    },
    {
      "name": "microsoft-graph-response",
      "content_type": "application/json; odata.metadata=minimal",
      "status_field": "@odata.context",
      "data_field": "value",
      "command_id_field": "@odata.nextLink",
      "rekey_value": "TokenExpired",
      "headers": [
        {"name": "x-ms-ags-diagnostic", "value": "{\"ServerInfo\":{\"DataCenter\":\"West US\"}}"}
      ]
    }
  ]
}
```

---

## GET /api/v1/profiles/server-response/:name

Get a specific server response profile by name.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Profile name

**Response (200 OK):**
```json
{
  "name": "microsoft-graph-response",
  "content_type": "application/json; odata.metadata=minimal",
  "status_field": "@odata.context",
  "data_field": "value",
  "command_id_field": "@odata.nextLink",
  "rekey_value": "TokenExpired",
  "headers": [
    {"name": "x-ms-ags-diagnostic", "value": "{\"ServerInfo\":{\"DataCenter\":\"West US\"}}"}
  ]
}
```

**Errors:**
- `404 Not Found`: Profile not found

---

## GET /api/v1/profiles/names

Get just the profile names (useful for dropdowns/selection lists).

**Authentication:** Required

**Response (200 OK):**
```json
{
  "get_profiles": ["default-get", "microsoft-graph-get", "aws-s3-get"],
  "post_profiles": ["default-post", "microsoft-graph-post", "aws-s3-post"],
  "server_response_profiles": ["default-response", "microsoft-graph-response", "aws-s3-response"]
}
```

---

## GET /api/v1/profiles/template

Download the profile template file for creating custom profiles.

**Authentication:** Required

**Response (200 OK):**
- Content-Type: `application/toml`
- Content-Disposition: `attachment; filename=listener_template.toml`
- Body: TOML template content

---

## POST /api/v1/profiles/upload

Upload and validate new malleable profiles at runtime. Profiles are added to the running configuration immediately (hot-loaded).

**Authentication:** Required

**Content Types Supported:**
- `application/toml` or `text/plain`: Raw TOML content in request body
- `multipart/form-data`: File upload with form field `profile`

**Request (Raw TOML):**
```toml
[[http_profiles.get]]
name = "custom-get"
path = "/api/custom/check"
method = "GET"
[[http_profiles.get.params]]
name = "id"
location = "query"
type = "clientID_param"
format = "%CLIENTID%"

[[http_profiles.post]]
name = "custom-post"
path = "/api/custom/data"
method = "POST"
content_type = "application/json"
[[http_profiles.post.params]]
name = "id"
location = "query"
type = "clientID_param"
format = "%CLIENTID%"

[[http_profiles.server_response]]
name = "custom-response"
content_type = "application/json"
```

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "Profiles uploaded successfully",
  "get_profiles_added": ["custom-get"],
  "post_profiles_added": ["custom-post"],
  "server_response_added": ["custom-response"],
  "errors": []
}
```

**Response (200 OK) - Partial Success:**
```json
{
  "status": "partial",
  "message": "Profiles uploaded successfully",
  "get_profiles_added": ["custom-get"],
  "post_profiles_added": [],
  "server_response_added": [],
  "errors": ["POST profile 'default-post': profile with name 'default-post' already exists"]
}
```

**Errors:**
- `400 Bad Request`: Invalid TOML syntax or no profiles added

---

## DELETE /api/v1/profiles/get/:name

Delete a GET profile by name.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Profile name

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "GET profile deleted"
}
```

**Errors:**
- `404 Not Found`: GET profile not found

---

## DELETE /api/v1/profiles/post/:name

Delete a POST profile by name.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Profile name

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "POST profile deleted"
}
```

**Errors:**
- `404 Not Found`: POST profile not found

---

## DELETE /api/v1/profiles/server-response/:name

Delete a server response profile by name.

**Authentication:** Required

**URL Parameters:**
- `name` (required): Profile name

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "Server response profile deleted"
}
```

**Errors:**
- `404 Not Found`: Server response profile not found
