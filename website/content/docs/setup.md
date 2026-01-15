---
title: "Setup Guide"
description: "Step-by-step guide to deploying NexusC2 server and generating your first payloads."
weight: 1
---
## Overview
The new `setup.sh` script is fully modular, allowing you to run individual components or the full installation. This is perfect for when one step fails and you need to re-run just that part.

## Basic Usage

### Full Installation (Default)
```bash
sudo ./setup.sh
# OR
sudo ./setup.sh --all
```
Runs all setup steps interactively.

### Get Help
```bash
sudo ./setup.sh --help
```
Shows all available options and examples.

## Individual Component Flags

### System Components
```bash
sudo ./setup.sh --packages    # Install system packages only
sudo ./setup.sh --go          # Install Go only
sudo ./setup.sh --protoc      # Install Protocol Buffers compiler only
sudo ./setup.sh --docker      # Install Docker only
```

### Project-Specific Components
```bash
sudo ./setup.sh --certs       # Generate certificates only
sudo ./setup.sh --secrets     # Generate database secrets only
sudo ./setup.sh --build       # Build server binaries only
sudo ./setup.sh --client      # Setup Python client venv only
```

## Combining Flags

You can combine multiple flags to run specific steps together:

```bash
# Only generate certs and secrets
sudo ./setup.sh --certs --secrets

# Regenerate everything project-specific
sudo ./setup.sh --certs --secrets --build --client

# Install just Go and protoc
sudo ./setup.sh --go --protoc
```

## Common Scenarios

### Scenario 1: Certificate Generation Failed
If certificate generation failed during initial setup:
```bash
sudo ./setup.sh --certs
```

### Scenario 2: Build Failed
If server binary build failed:
```bash
sudo ./setup.sh --build
```

### Scenario 3: Need to Rebuild Everything After Code Changes
```bash
sudo ./setup.sh --build
```

### Scenario 4: Need Fresh Python Virtual Environment
```bash
sudo ./setup.sh --client
```
This will remove the old venv and create a fresh one.

### Scenario 5: Docker Installation Failed
```bash
sudo ./setup.sh --docker
```

### Scenario 6: Complete Project Setup (Skip System Packages)
If you already have Go, Docker, etc. installed:
```bash
sudo ./setup.sh --certs --secrets --build --client
```

## Features

### ✅ Smart Detection
- Checks if binaries already exist
- Checks if Python venv already exists
- Shows appropriate next steps based on what's installed

### ✅ Error Handling
- Each component can succeed or fail independently
- Failed components are marked with ✗ in the summary
- Successful components are marked with ✓

### ✅ Interactive vs Non-Interactive
- `--all` mode: Interactive (asks about client setup)
- `--client` mode: Non-interactive (automatically sets up)

### ✅ Smart Summary
- Shows exactly what was run
- Shows what succeeded or failed
- Provides dynamic next steps based on current state

### ✅ Path Agnostic
- Uses relative paths from script location
- Can be run from anywhere

## Summary Output

After running, you'll see a clear summary:

```
============================================================
==> Setup Summary
============================================================

  ✓ System packages installed
  ✓ Go installed
  ✓ Protocol Buffers compiler installed
  ✓ Docker installed and configured
  ✓ User added to docker group
  ✓ Certificates generated
  ✓ Database secrets generated
  ✓ Server binaries built
  ✓ Python client virtual environment created

============================================================
==> Next Steps
============================================================

  1. Log out and log back in (for docker group changes)
  2. Start the server services:
     cd /path/to/server/docker
     docker-compose up -d

  3. Start the client:
     cd /path/to/client
     source venv/bin/activate
     python src/main.py
```

## Tips

1. **Always run with sudo**: Most operations require root privileges
2. **Check the summary**: Review what succeeded/failed after each run
3. **Re-run failed components**: Use individual flags to retry failed steps
4. **Use --help**: When in doubt, check the help message
5. **Combine flags**: Save time by running multiple components together

## Example Workflow

Initial setup fails at binary build:
```bash
# Initial attempt
sudo ./setup.sh
# ... build fails ...

# Check what happened in summary
# See: ⚠ Server binaries not built

# Re-run just the build
sudo ./setup.sh --build
# ... build succeeds ...

# Continue with next steps
cd ../server/docker
docker-compose up -d
```

## Color-Coded Output

- 🟢 Green: Successful operations and status messages
- 🟡 Yellow: Warnings and skipped operations
- 🔴 Red: Errors and failures
- 🔵 Blue: Informational headers and section markers