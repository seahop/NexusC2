# SMB Transforms

## Overview

SMB transforms define how data is obfuscated when traveling through named pipes between the server and SMB agents. The parent HTTPS agent simply relays the opaque, transformed blobs without needing to understand them.

For general HTTP profile transforms, see [Malleable Profiles](/docs/malleable-profiles/).

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

## Per-Build Unique XOR Keys (SMB Only)

When using the `xor` transform in SMB profiles, NexusC2 generates a **unique 12-character key for each SMB agent build**.

This provides:

- **Agent isolation**: Even if one agent's key is compromised, others remain secure
- **No shared secrets**: Each SMB agent has its own XOR key embedded at build time
- **Automatic key management**: The server tracks each agent's unique key in the database

The XOR key from the profile configuration (e.g., `"smb_transform_key"`) serves as a fallback for backward compatibility. New SMB builds always generate unique keys.

> **Note:** HTTP/HTTPS profiles use **static XOR keys** from config.toml for simpler operation. The key you define in the profile is used by both agent and server. See [Malleable Profiles](/docs/malleable-profiles/) for HTTP profile details.

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

## Common Windows Named Pipe Profiles

The following profiles mimic legitimate Windows SMB traffic patterns. Each uses a named pipe commonly found in enterprise environments.

### Print Spooler (spoolss)

The Print Spooler service is present on nearly every Windows system. Traffic patterns include job submissions, printer queries, and status updates.

```toml
[[smb_link.pipe_presets]]
name = "spoolss"
description = "Print Spooler Service - Printer management and job submission"

[[smb_link.profiles]]
name = "spoolss-profile"
[smb_link.profiles.data]
output = "body"
# Mimic print job data structure
[[smb_link.profiles.data.transforms]]
type = "gzip"
[[smb_link.profiles.data.transforms]]
type = "xor"
value = "spoolss_key"
[[smb_link.profiles.data.transforms]]
type = "prepend"
value = "\u0000\u0000\u0000\u0001"    # RPC version header
[[smb_link.profiles.data.transforms]]
type = "append"
value = "\u0000\u0000\u0000\u0000"    # Null terminator padding
```

**Why it blends:** Print spooler traffic is frequent, expected to carry binary data (print jobs), and rarely inspected deeply.

---

### Server Service (srvsvc)

Used for share enumeration, session management, and server info queries. One of the most common pipes in any domain environment.

```toml
[[smb_link.pipe_presets]]
name = "srvsvc"
description = "Server Service - Share and session management"

[[smb_link.profiles]]
name = "srvsvc-profile"
[smb_link.profiles.data]
output = "body"
# Mimic DCE/RPC structure
[[smb_link.profiles.data.transforms]]
type = "gzip"
[[smb_link.profiles.data.transforms]]
type = "xor"
value = "srvsvc_key"
[[smb_link.profiles.data.transforms]]
type = "prepend"
value = "\u0005\u0000\u0000\u0003"    # DCE/RPC request header
[[smb_link.profiles.data.transforms]]
type = "random_append"
length = 4
charset = "binary"
```

**Why it blends:** Admin tools, Group Policy, and login scripts constantly query srvsvc for share information.

---

### Workstation Service (wkssvc)

Provides workstation configuration and domain membership information. Common in domain-joined environments.

```toml
[[smb_link.pipe_presets]]
name = "wkssvc"
description = "Workstation Service - Domain and workstation info"

[[smb_link.profiles]]
name = "wkssvc-profile"
[smb_link.profiles.data]
output = "body"
[[smb_link.profiles.data.transforms]]
type = "gzip"
[[smb_link.profiles.data.transforms]]
type = "xor"
value = "wkssvc_key"
[[smb_link.profiles.data.transforms]]
type = "prepend"
value = "\u0005\u0000\u0000\u0003\u0010\u0000\u0000\u0000"    # DCE/RPC bind header
```

**Why it blends:** Used by `net` commands, domain tools, and management software.

---

### Security Account Manager (samr)

Handles user and group enumeration. Heavily used by authentication and identity management systems.

```toml
[[smb_link.pipe_presets]]
name = "samr"
description = "Security Account Manager - User and group enumeration"

[[smb_link.profiles]]
name = "samr-profile"
[smb_link.profiles.data]
output = "body"
[[smb_link.profiles.data.transforms]]
type = "gzip"
[[smb_link.profiles.data.transforms]]
type = "xor"
value = "samr_key"
[[smb_link.profiles.data.transforms]]
type = "prepend"
value = "\u0005\u0000\u000b\u0003"    # RPC bind
[[smb_link.profiles.data.transforms]]
type = "random_prepend"
length = 4
charset = "binary"
[[smb_link.profiles.data.transforms]]
type = "append"
value = "\u0000\u0000"
```

**Why it blends:** Active Directory queries, user lookups, and authentication flows use samr constantly.

---

### Local Security Authority (lsarpc)

Handles security policy queries, SID lookups, and trust relationships. Critical for domain operations.

```toml
[[smb_link.pipe_presets]]
name = "lsarpc"
description = "Local Security Authority - Policy and SID resolution"

[[smb_link.profiles]]
name = "lsarpc-profile"
[smb_link.profiles.data]
output = "body"
[[smb_link.profiles.data.transforms]]
type = "gzip"
[[smb_link.profiles.data.transforms]]
type = "xor"
value = "lsarpc_key"
[[smb_link.profiles.data.transforms]]
type = "prepend"
value = "\u0005\u0000\u0000\u0003\u0010\u0000\u0000\u0000"
[[smb_link.profiles.data.transforms]]
type = "random_append"
length = 8
charset = "binary"
```

**Why it blends:** Every domain authentication involves lsarpc for SID-to-name translation.

---

### Netlogon Service (netlogon)

Authenticates users and computers in a domain. High-volume traffic during login hours.

```toml
[[smb_link.pipe_presets]]
name = "netlogon"
description = "Netlogon Service - Domain authentication"

[[smb_link.profiles]]
name = "netlogon-profile"
[smb_link.profiles.data]
output = "body"
[[smb_link.profiles.data.transforms]]
type = "gzip"
[[smb_link.profiles.data.transforms]]
type = "xor"
value = "netlogon_key"
[[smb_link.profiles.data.transforms]]
type = "prepend"
value = "\u0000\u0000\u0000\u0000\u0004\u0000"    # Netlogon authenticator structure
[[smb_link.profiles.data.transforms]]
type = "random_append"
length = 12
charset = "binary"
```

**Why it blends:** Domain controllers see constant netlogon traffic; workstations query during login, GPO updates, and periodic reauth.

---

### Service Control Manager (svcctl)

Manages Windows services remotely. Used by SCCM, management tools, and admins.

```toml
[[smb_link.pipe_presets]]
name = "svcctl"
description = "Service Control Manager - Remote service management"

[[smb_link.profiles]]
name = "svcctl-profile"
[smb_link.profiles.data]
output = "body"
[[smb_link.profiles.data.transforms]]
type = "gzip"
[[smb_link.profiles.data.transforms]]
type = "xor"
value = "svcctl_key"
[[smb_link.profiles.data.transforms]]
type = "prepend"
value = "\u0005\u0000\u0000\u0003"    # DCE/RPC request
[[smb_link.profiles.data.transforms]]
type = "append"
value = "\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000"
```

**Why it blends:** Management tools like SCCM, Intune connectors, and PowerShell remoting use svcctl heavily.

---

### Task Scheduler (atsvc)

Schedules and manages tasks remotely. Used by enterprise job schedulers and management systems.

```toml
[[smb_link.pipe_presets]]
name = "atsvc"
description = "Task Scheduler Service - Remote task management"

[[smb_link.profiles]]
name = "atsvc-profile"
[smb_link.profiles.data]
output = "body"
[[smb_link.profiles.data.transforms]]
type = "gzip"
[[smb_link.profiles.data.transforms]]
type = "xor"
value = "atsvc_key"
[[smb_link.profiles.data.transforms]]
type = "prepend"
value = "\u0005\u0000\u0000\u0003\u0010\u0000"
[[smb_link.profiles.data.transforms]]
type = "random_append"
length = 6
charset = "binary"
```

**Why it blends:** Scheduled tasks are common for updates, backups, and maintenance scripts.

---

### Browser Service (browser)

Legacy but still present for network browsing and master browser elections.

```toml
[[smb_link.pipe_presets]]
name = "browser"
description = "Computer Browser Service - Network discovery"

[[smb_link.profiles]]
name = "browser-profile"
[smb_link.profiles.data]
output = "body"
[[smb_link.profiles.data.transforms]]
type = "netbios"
```

**Why it blends:** Browser announcements use NetBIOS encoding naturally; this is native traffic mimicry.

---

## Choosing the Right Pipe

| Pipe | Best For | Traffic Volume | Inspection Risk |
|------|----------|----------------|-----------------|
| `spoolss` | General use | High | Low - binary print data expected |
| `srvsvc` | Domain environments | Very High | Low - constant share queries |
| `samr` | AD-heavy networks | High | Medium - security tools may monitor |
| `lsarpc` | Any domain | Very High | Medium - part of auth flow |
| `netlogon` | DC proximity | Very High | Medium - auth-related |
| `svcctl` | Managed environments | Medium | Low - admin tool traffic |
| `atsvc` | Scheduled job environments | Medium | Low - maintenance traffic |
| `browser` | Legacy networks | Low | Very Low - deprecated service |

---

## Profile Selection Strategy

**High-security environments:** Use `spoolss` or `srvsvc` - they generate the most "noise" and are rarely inspected.

**Domain controller adjacent:** Use `netlogon` or `lsarpc` - these are expected in high volume near DCs.

**Management server proximity:** Use `svcctl` or `atsvc` - aligns with SCCM/Intune patterns.

**Legacy networks:** Use `browser` with NetBIOS encoding for natural traffic mimicry.

---

## Related Documentation

- [Linked Agents](/docs/linked-agents/) - SMB agent architecture and link management
- [Malleable Profiles](/docs/malleable-profiles/) - HTTP profile transforms
- [Profile Management](/docs/profile-management/) - Upload and manage profiles via CLI
