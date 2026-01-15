---
title: "Import CNA Scripts"
description: "Load Cobalt Strike Aggressor (CNA) scripts to extend NexusC2 with third-party BOF collections."
weight: 5
---

NexusC2 includes a CNA interpreter that allows you to load Cobalt Strike Aggressor scripts from popular BOF (Beacon Object File) collections. This enables you to use existing offensive tooling without modification.

## What is CNA?

CNA (Cobalt Strike Aggressor) is a scripting language used by Cobalt Strike to extend its functionality. Many open-source BOF collections ship with CNA scripts that define:

- Command registrations
- BOF file locations
- Argument packing formats
- Help text and usage information

NexusC2 implements a subset of the CNA language focused specifically on BOF integration.

## Supported CNA Features

The interpreter supports these CNA constructs:

| Feature | Description |
|---------|-------------|
| `beacon_command_register` | Register new commands with help text |
| `beacon_inline_execute` | Execute BOF files |
| `alias` | Define command aliases |
| `bof_pack` | Pack arguments for BOF execution |
| `readbof` | Load BOF files relative to CNA script |
| `iff` | Basic conditional logic |
| `btask`, `blog`, `berror` | Logging functions |

## Loading a CNA Script

Use the `cna-load` command to load a script:

```
cna-load /path/to/bof.cna
```

The interpreter will:

1. Parse command registrations
2. Extract alias definitions
3. Map commands to their BOF implementations
4. Auto-locate BOF files relative to the CNA script

## Example: TrustedSec BOF Collection

The [TrustedSec SA (Situational Awareness)](https://github.com/trustedsec/CS-Situational-Awareness-BOF) BOF collection is a popular set of reconnaissance tools.

### Setup

```bash
# Clone the repository
git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF.git

# The CNA script is at the root
ls CS-Situational-Awareness-BOF/
# SA.cna  src/  ...
```

### Load the Scripts

In your NexusC2 client, with an active Windows agent:

```
cna-load /path/to/CS-Situational-Awareness-BOF/SA.cna
```

### Use the New Commands

After loading, the BOF commands become available:

```
# List network adapters
ipconfig

# List scheduled tasks
schtasksenum

# Enumerate local users
netLocalGroupList

# Check running AV products
enumLocalSessions
```

## Listing Loaded Scripts

View all loaded CNA scripts and their commands:

```
cna-list
```

This displays:
- Script file path
- Number of commands registered
- List of available commands from each script

## Popular BOF Collections

Here are some compatible BOF collections:

| Collection | Description | URL |
|------------|-------------|-----|
| **TrustedSec SA** | Situational awareness tools | [GitHub](https://github.com/trustedsec/CS-Situational-Awareness-BOF) |
| **TrustedSec Remote Ops** | Remote operations BOFs | [GitHub](https://github.com/trustedsec/CS-Remote-OPs-BOF) |
| **Outflank C2 Tool Collection** | Various offensive BOFs | [GitHub](https://github.com/outflanknl/C2-Tool-Collection) |
| **BOF Collection** | Community BOF compilation | Various sources |

## Troubleshooting

### "BOF file not found"

The interpreter looks for BOF files relative to the CNA script location. Ensure the directory structure matches what the CNA script expects:

```
my-bofs/
├── bof.cna          # CNA script
├── src/
│   ├── tool1.x64.o  # x64 BOF
│   └── tool1.x86.o  # x86 BOF
```

### "Command not registered"

Some CNA scripts use advanced features not yet supported. Check that the script uses supported constructs listed above.

### "Unsupported CNA function"

The interpreter implements a subset focused on BOF loading. Functions like `popup`, `menubar`, or GUI-related features are not supported.

## Script Persistence

Loaded CNA scripts are remembered between client sessions. When you restart the NexusC2 client, previously loaded scripts are automatically re-loaded.

To view persisted scripts, check:
- **Linux/macOS**: `~/.config/nexus/cna_scripts.json`
- **Windows**: `%APPDATA%\nexus\cna_scripts.json`

## Architecture Notes

- CNA scripts are processed **client-side** in the NexusC2 GUI
- BOF execution happens on the **agent** (target system)
- Only Windows agents support BOF execution
- x64 vs x86 BOF selection is automatic based on agent architecture
