---
title: "Create a Listener"
description: "Learn how to create and configure HTTP/HTTPS listeners for agent communication."
weight: 1
---

## Overview

Listeners are the communication endpoints that agents connect back to. This guide walks you through creating your first listener.

## Prerequisites

- NexusC2 server running
- GUI client connected
- Network access to the listener port

## Steps

### Step 1: Open the Listeners Panel

*Screenshot placeholder: Show the main GUI with Listeners tab highlighted*

Navigate to the **Listeners** tab in the main interface.

### Step 2: Click "New Listener"

*Screenshot placeholder: Show the New Listener button*

Click the **New Listener** button to open the configuration dialog.

### Step 3: Configure Listener Settings

*Screenshot placeholder: Show the listener configuration dialog*

Configure the following settings:

| Setting | Description | Example |
|---------|-------------|---------|
| **Name** | Friendly name for the listener | `https-primary` |
| **Type** | Protocol type | `HTTPS` |
| **Host** | Bind address | `0.0.0.0` |
| **Port** | Listen port | `443` |
| **Callback Host** | Agent callback address | `c2.example.com` |

### Step 4: SSL Certificate (HTTPS only)

*Screenshot placeholder: Show SSL configuration options*

For HTTPS listeners, configure SSL:

- **Auto-generate**: Creates a self-signed certificate
- **Custom**: Upload your own certificate and key

### Step 5: Start the Listener

*Screenshot placeholder: Show the started listener*

Click **Start** to activate the listener. The status indicator should turn green.

## Verification

Test that your listener is accessible:

```bash
curl -k https://your-server:443/
```

You should receive a response (even if it's an error page).

## Next Steps

- [Create a Payload]({{< ref "create-payload.md" >}}) - Generate an agent for this listener
- [Documentation: Infrastructure]({{< ref "/docs/infrastructure.md" >}}) - Learn about listener architecture
