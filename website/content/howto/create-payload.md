---
title: "Create a Payload"
description: "Generate custom payloads for Windows, Linux, and macOS targets."
weight: 2
---

## Overview

Payloads are the agents that execute on target systems and connect back to your listener. This guide shows how to generate payloads for different platforms.

## Prerequisites

- Active listener configured
- Target OS and architecture known
- Delivery method planned

## Steps

### Step 1: Open Payload Generator

*Screenshot placeholder: Show the Payloads tab*

Navigate to the **Payloads** tab in the GUI.

### Step 2: Select Target Platform

*Screenshot placeholder: Show platform selection dropdown*

Choose your target:

| Platform | Architectures | Output Format |
|----------|---------------|---------------|
| **Windows** | amd64, arm64 | .exe |
| **Linux** | amd64, arm64 | .bin |
| **macOS** | amd64, arm64 | .bin |

### Step 3: Select Listener

*Screenshot placeholder: Show listener selection*

Choose which listener this payload should connect to.

### Step 4: Configure Options

*Screenshot placeholder: Show advanced options*

Configure advanced options:

| Option | Description | Default |
|--------|-------------|---------|
| **Sleep** | Callback interval | 5 seconds |
| **Jitter** | Random variance | 20% |
| **Kill Date** | Expiration date | None |

### Step 5: Generate

*Screenshot placeholder: Show the generate button and download*

Click **Generate** and download your payload.

## Language Options

### Go (Compiled Binary)

Standard compiled executable for your target platform:

**Windows:**
```bash
# Transfer and execute
.\payload.exe
```

**Linux/macOS:**
```bash
chmod +x payload.bin
./payload.bin
```

### GoProject (Source Export)

Exports the complete agent source code as a `.zip` file:

- Full Go source code
- Build scripts for all platforms
- Allows manual compilation and customization
- Useful for advanced evasion or modifications

```bash
# Extract and build manually
unzip payload_goproject.zip
cd payload
go build -o agent
```

## Testing Your Payload

1. Deploy to a test system
2. Watch the Agents panel for new connections
3. Verify the agent checks in

## Security Considerations

- Store payloads securely
- Use kill dates for time-limited operations
- Consider AV evasion techniques for real engagements

## Next Steps

- [Create a Listener]({{< ref "create-listener.md" >}}) - Set up listener first
- [Documentation: Payload Generation]({{< ref "/docs/payload-generation.md" >}}) - Detailed payload options
