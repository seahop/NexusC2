---
title: "Log Viewer"
description: "Monitor and search through operation logs and events."
weight: 11
---
A command-line tool for analyzing and correlating C2 agent command logs, providing insights into agent activity, command execution, and system performance.

## Features

- **Log Correlation**: Automatically correlates commands with their outputs using command IDs
- **Multiple Output Formats**: Text, JSON, CSV, and table formats
- **Advanced Filtering**: Filter by agent, hostname, IP, username, command type, OS, and session
- **Real-time Following**: Follow logs in real-time (like `tail -f`)
- **Statistics**: View command execution statistics and agent summaries
- **Date Range Support**: Analyze logs from specific date ranges
- **Agent Enrichment**: Automatically enriches logs with cached agent information

---

## Log Location

Logs are stored in different locations depending on context:

| Context | Path |
|---------|------|
| Inside Docker containers | `/app/logs/commands/` |
| On the host machine | `server/docker/logs/commands/` |

The log directory is mounted as a volume, so logs persist across container restarts.

---

## Installation

### Building with Docker (Recommended)

If Go is not installed locally, build using Docker:

```bash
cd /path/to/NexusC2
docker run --rm -v $(pwd)/server:/src -w /src golang:1.25-alpine \
    go build -o /src/logviewer ./cmd/logviewer
```

The binary will be created at `server/logviewer`.

### Building Locally

If Go 1.25+ is installed:

```bash
cd server
go build -o logviewer ./cmd/logviewer
```

---

## Basic Usage

### View Recent Logs
```bash
# From host machine - specify the host log path
./logviewer -dir ./docker/logs/commands

# Inside Docker container - uses default path
./logviewer
```

### View Specific Log File
```bash
./logviewer -file ./docker/logs/commands/commands_2026-01-15.log
```

### Show Statistics
```bash
./logviewer -dir ./docker/logs/commands -stats
```

Example output:
```
=== Command Execution Statistics ===
Total commands: 11
Completed: 11
Pending: 0
Errors: 0
Avg response time: 11.204 seconds
Min response time: 4.710 seconds
Max response time: 18.755 seconds

=== Agent Statistics ===
Total unique agents: 1

Top agents by command count:
  04c0c127 (fsdev) - 192.168.21.129: 11 commands
```

### Show Agent Summary
```bash
./logviewer -dir ./docker/logs/commands -agents
```

Example output:
```
=== Agent Summary ===
Agent     Hostname  External IP     Internal IP     OS     User    Commands  Sessions  Last Seen
04c0c127  fsdev     192.168.21.129  192.168.21.129  linux  nexus   11        1         01/15 19:40
```

### Follow Logs in Real-time
```bash
./logviewer -dir ./docker/logs/commands -follow
```

---

## Filtering

### Filter by Agent
```bash
./logviewer -dir ./docker/logs/commands -agent 04c0c127
```

### Filter by Multiple Criteria
```bash
# Find all commands from a specific host by a specific user
./logviewer -dir ./docker/logs/commands -host fsdev -user nexus

# Find all BOF commands on Windows systems
./logviewer -dir ./docker/logs/commands -type bof -os windows

# Filter by IP address (matches internal or external)
./logviewer -dir ./docker/logs/commands -ip 192.168.21.129

# Filter by session ID
./logviewer -dir ./docker/logs/commands -session session_04c0c127
```

### Date Range Queries
```bash
# Last 7 days (default)
./logviewer -dir ./docker/logs/commands

# Specific date range
./logviewer -dir ./docker/logs/commands -from 2026-01-10 -to 2026-01-15

# Single day
./logviewer -dir ./docker/logs/commands -from 2026-01-15 -to 2026-01-15
```

---

## Output Formats

### Default Text Output
```bash
./logviewer -dir ./docker/logs/commands
```

Shows correlated command executions with full context:
```
=== Command Execution ===
Command ID: 1
Agent ID: 04c0c127-bc90-4f6b-b318-722949e18dce
User: nexus
Hostname: fsdev
IPs: 192.168.21.129 / 192.168.21.129
OS: linux
Session: session_04c0c127..._1768441601
Command: pwd
Sent: 2026-01-15T01:46:57Z
Status: completed
Output received: 2026-01-15T01:47:03Z
Response time: 6.076 seconds
Output size: 27 bytes
Output:
/home/sean/Desktop/payloads
```

### JSON Output
```bash
./logviewer -dir ./docker/logs/commands -json
# or
./logviewer -dir ./docker/logs/commands -format json
```

### CSV Export
```bash
./logviewer -dir ./docker/logs/commands -format csv > commands_export.csv
```

### Table Format
```bash
./logviewer -dir ./docker/logs/commands -format table
```

### Verbose Output
```bash
./logviewer -dir ./docker/logs/commands -v
```

---

## Special Views

### Show Only Pending Commands
```bash
./logviewer -dir ./docker/logs/commands -pending
```

### Show Only Errors
```bash
./logviewer -dir ./docker/logs/commands -errors
```

---

## Sorting Options

```bash
# Sort by time (default)
./logviewer -dir ./docker/logs/commands -sort time

# Sort by agent ID
./logviewer -dir ./docker/logs/commands -sort agent

# Sort by hostname
./logviewer -dir ./docker/logs/commands -sort host

# Sort by IP
./logviewer -dir ./docker/logs/commands -sort ip

# Sort by username
./logviewer -dir ./docker/logs/commands -sort user

# Sort by command
./logviewer -dir ./docker/logs/commands -sort command

# Reverse sort order
./logviewer -dir ./docker/logs/commands -sort time -reverse
```

---

## Command Flags Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-dir` | Log directory path | `/app/logs/commands` |
| `-file` | Specific log file | Today's log |
| `-agent` | Filter by agent ID (partial match) | None |
| `-host` | Filter by hostname (partial match) | None |
| `-ip` | Filter by IP (partial match) | None |
| `-user` | Filter by username (partial match) | None |
| `-type` | Filter by command type (ls, pwd, bof, etc.) | None |
| `-os` | Filter by OS | None |
| `-session` | Filter by session ID | None |
| `-format` | Output format: text, json, csv, table | `text` |
| `-json` | Output as JSON (shortcut for -format json) | `false` |
| `-v` | Verbose output (show all fields) | `false` |
| `-stats` | Show statistics | `false` |
| `-agents` | Show agent summary | `false` |
| `-pending` | Show pending commands only | `false` |
| `-errors` | Show errors only | `false` |
| `-follow` | Follow log file in real-time | `false` |
| `-from` | Start date (YYYY-MM-DD) | 7 days ago |
| `-to` | End date (YYYY-MM-DD) | Today |
| `-sort` | Sort by: time, agent, host, ip, user, command | `time` |
| `-reverse` | Reverse sort order | `false` |

---

## Log File Structure

Logs are stored as JSON lines (one JSON object per line) with the following fields:

```json
{
  "timestamp": "2026-01-15T01:46:57.316514126Z",
  "type": "command",
  "agent_id": "04c0c127-bc90-4f6b-b318-722949e18dce",
  "username": "nexus",
  "command": "pwd",
  "command_id": 1,
  "command_type": "pwd",
  "hostname": "fsdev",
  "external_ip": "192.168.21.129",
  "internal_ip": "192.168.21.129",
  "os": "linux",
  "arch": "amd64",
  "process": "https_go_amd64_HTTPS_payload.bin",
  "pid": "398071",
  "integrity": "medium",
  "session_id": "session_04c0c127..._1768441601"
}
```

### Log Entry Types

| Type | Description |
|------|-------------|
| `connection` | New agent connection with full agent details |
| `checkin` | Agent heartbeat/check-in |
| `command` | Command issued to an agent |
| `output` | Command output received from agent |
| `error` | Error during command execution |

---

## Log Rotation

### Daily Rotation
- New log file created at midnight each day
- Format: `commands_YYYY-MM-DD.log`

### Size-based Rotation
- Default maximum file size: 100MB
- When exceeded, files are numbered sequentially:
  - `commands_2026-01-15.log` (first file)
  - `commands_2026-01-15_1.log` (first rotation)
  - `commands_2026-01-15_2.log` (second rotation)

### Automatic Archiving
- Previous day's logs are automatically compressed to `archive/commands_YYYY-MM-DD.tar.gz`
- Original files are deleted after successful archiving

---

## Integration with Other Tools

### Export for External Analysis
```bash
# Export to JSON for processing with jq
./logviewer -dir ./docker/logs/commands -format json | jq '.[] | select(.command_type=="bof")'

# Export to CSV for Excel/Google Sheets
./logviewer -dir ./docker/logs/commands -format csv > analysis.csv

# Pipe to grep for additional filtering
./logviewer -dir ./docker/logs/commands | grep -i "error"
```

### Scheduled Reports
Create a cron job for daily reports:
```bash
0 2 * * * /path/to/logviewer -dir /path/to/logs/commands -stats -format json > /path/to/reports/daily_$(date +%Y%m%d).json
```

---

## Troubleshooting

### No logs found
- Verify the log directory path is correct
- On host: `server/docker/logs/commands/`
- In Docker: `/app/logs/commands/`
- Check the date range includes existing logs
- Ensure log files follow naming convention: `commands_YYYY-MM-DD.log`

### Missing agent information in some entries
- Agent information is cached when agents first connect
- After service restarts, checkin entries may lack enriched data until the agent reconnects
- Full agent context is restored on the next `connection` event

### Duplicate commands in output
- The correlator automatically deduplicates based on command ID
- Use `-v` to see command IDs and verify correlation

---

## Related Files

| Component | File Path |
|-----------|-----------|
| Log Viewer Source | `server/cmd/logviewer/main.go` |
| Logger Implementation | `server/internal/common/logging/command_logger.go` |
| Log Correlator | `server/internal/common/logging/correlator.go` |
| Log Directory (Host) | `server/docker/logs/commands/` |
| Log Archives | `server/docker/logs/commands/archive/` |
