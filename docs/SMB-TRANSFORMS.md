# SMB Transforms

## Overview

SMB transforms define how data is obfuscated when traveling through named pipes between the server and SMB agents. The parent HTTPS agent simply relays the opaque, transformed blobs without needing to understand them.

For general HTTP profile transforms, see [Malleable Profiles](MALLEABLE-PROFILES.md).

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

Customize the JSON field names used in the link protocol:

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

## How SMB Transforms Work

When an SMB agent is built and linked to an HTTPS agent:

1. The SMB profile's transforms are embedded in the SMB agent at build time
2. Commands from the server are transformed before being sent through the named pipe
3. The SMB agent reverses the transforms to extract the original data
4. Results from the SMB agent are transformed before being sent back
5. The server reverses the transforms to read the results

The HTTPS (edge) agent acts as a transparent relay - it never decrypts or modifies the pipe payloads.

---

## Per-Build Unique XOR Keys

When using the `xor` transform, NexusC2 generates a **unique 12-character key for each SMB agent build**. This provides:

- **Agent isolation**: Even if one agent's key is compromised, others remain secure
- **No shared secrets**: Each SMB agent has its own XOR key embedded at build time
- **Automatic key management**: The server tracks each agent's unique key in the database

The XOR key from the profile configuration (e.g., `"smb_transform_key"`) serves as a fallback for backward compatibility. New builds always generate unique keys.

---

## Profile Structure

```toml
[[smb_link.profiles]]
name = "profile-name"
[smb_link.profiles.data]
output = "body"
[[smb_link.profiles.data.transforms]]
type = "transform_type"
# ... transform options
```

---

## Available Profiles

### Default Profile (No Transforms)

```toml
[[smb_link.profiles]]
name = "default-smb"
```

No transforms applied - data is transmitted as-is. Backward compatible with legacy deployments.

### NetBIOS Profile

```toml
[[smb_link.profiles]]
name = "netbios-smb"
[smb_link.profiles.data]
output = "body"
[[smb_link.profiles.data.transforms]]
type = "netbios"
```

Uses NetBIOS nibble encoding (each byte becomes 2 characters a-p). Makes traffic resemble NetBIOS name resolution.

### Binary Obfuscation Profile

```toml
[[smb_link.profiles]]
name = "binary-smb"
[smb_link.profiles.data]
output = "body"
[[smb_link.profiles.data.transforms]]
type = "gzip"
[[smb_link.profiles.data.transforms]]
type = "xor"
value = "smb_transform_key"    # Replaced with per-build unique key
[[smb_link.profiles.data.transforms]]
type = "random_prepend"
length = 8
charset = "hex"
[[smb_link.profiles.data.transforms]]
type = "random_append"
length = 8
charset = "hex"
```

Full obfuscation chain:
1. **gzip** - Compresses the data
2. **xor** - XORs with a unique per-build key
3. **random_prepend** - Adds 8 random hex bytes before the data
4. **random_append** - Adds 8 random hex bytes after the data

---

## Transform Flow

```
SERVER -> SMB AGENT (Commands)
+------------------------------------------------------------------+
|  JSON Command                                                     |
|       |                                                          |
|       v                                                          |
|  Apply Transforms: gzip -> xor(unique_key) -> random_prepend/append |
|       |                                                          |
|       v                                                          |
|  Opaque Binary Blob                                              |
|       |                                                          |
|       v                                                          |
|  HTTPS Agent Relays via Named Pipe                               |
|       |                                                          |
|       v                                                          |
|  SMB Agent Reverses: strip_random -> xor(unique_key) -> gunzip   |
|       |                                                          |
|       v                                                          |
|  Original JSON Command                                           |
+------------------------------------------------------------------+

SMB AGENT -> SERVER (Results)
+------------------------------------------------------------------+
|  JSON Results                                                     |
|       |                                                          |
|       v                                                          |
|  Apply Transforms: gzip -> xor(unique_key) -> random_prepend/append |
|       |                                                          |
|       v                                                          |
|  Opaque Binary Blob                                              |
|       |                                                          |
|       v                                                          |
|  HTTPS Agent Relays via Named Pipe                               |
|       |                                                          |
|       v                                                          |
|  Server Reverses: strip_random -> xor(unique_key) -> gunzip      |
|       |                                                          |
|       v                                                          |
|  Original JSON Results                                           |
+------------------------------------------------------------------+
```

---

## Creating Custom SMB Profiles

You can create custom SMB profiles with any combination of supported transforms:

```toml
[[smb_link.profiles]]
name = "custom-smb"
[smb_link.profiles.data]
output = "body"
[[smb_link.profiles.data.transforms]]
type = "gzip"
[[smb_link.profiles.data.transforms]]
type = "xor"
value = "my_custom_key"
[[smb_link.profiles.data.transforms]]
type = "base64"
```

**Supported transforms for SMB profiles:**
- `base64`, `base64url`, `hex`, `gzip`, `netbios`
- `xor` (with `value` option - replaced with per-build unique key)
- `prepend`, `append` (with `value` option)
- `random_prepend`, `random_append` (with `length` and optional `charset`)

---

## Binding SMB Profiles to Listeners

When creating an SMB listener, specify which profile to use:

```bash
./scripts/nexus-api.py listeners create \
  -n smb-listener \
  -P SMB \
  --pipe-name spoolss \
  --smb-profile binary-smb
```

Payloads built for that listener will use the specified SMB profile's transforms.

---

## Related Documentation

- [Linked Agents](LINKED-AGENTS.md) - SMB agent architecture and link management
- [Malleable Profiles](MALLEABLE-PROFILES.md) - HTTP profile transforms
- [Profile Management](PROFILE-MANAGEMENT.md) - Upload and manage profiles via CLI
