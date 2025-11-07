# C2 Command Log Analyzer

A command-line tool for analyzing and correlating C2 (Command and Control) agent command logs, providing insights into agent activity, command execution, and system performance.

## Features

- **Log Correlation**: Automatically correlates commands with their outputs
- **Multiple Output Formats**: Text, JSON, CSV, and table formats
- **Advanced Filtering**: Filter by agent, hostname, IP, username, command type, OS, and session
- **Real-time Following**: Follow logs in real-time (like `tail -f`)
- **Statistics**: View command execution statistics and agent summaries
- **Date Range Support**: Analyze logs from specific date ranges
- **Agent Enrichment**: Automatically enriches logs with cached agent information

## Installation

The log analyzer is included in the C2 server and can be run directly:

```bash
cd /path/to/c2/server
go build ./cmd/logviewer
```

## Basic Usage

### View Today's Logs
```bash
./logviewer
```

### View Specific Log File
```bash
./logviewer -file /app/logs/commands/commands_2025-09-05.log
```

### Filter by Agent
```bash
./logviewer -agent 5b561c45-b596-403e-9254-7cbd31177e3e
```

### Show Statistics
```bash
./logviewer -stats
```

### Follow Logs in Real-time
```bash
./logviewer -follow
```

## Advanced Filtering

### Filter by Multiple Criteria
```bash
# Find all commands from a specific host by a specific user
./logviewer -host dev -user username1

# Find all BOF commands on Windows systems
./logviewer -type bof -os windows

# Filter by IP address (matches internal or external)
./logviewer -ip 192.168.44.128

# Filter by session ID
./logviewer -session session_5b561c45_1757080756
```

### Date Range Queries
```bash
# Last 7 days (default)
./logviewer

# Specific date range
./logviewer -from 2025-09-01 -to 2025-09-05

# Single day
./logviewer -from 2025-09-05 -to 2025-09-05
```

## Output Formats

### JSON Output
```bash
./logviewer -json
# or
./logviewer -format json
```

### CSV Export
```bash
./logviewer -format csv > commands_export.csv
```

### Table Format
```bash
./logviewer -format table
```

### Verbose Output (All Fields)
```bash
./logviewer -v
```

## Special Views

### Show Agent Summary
```bash
./logviewer -agents
```
Displays:
- Unique agents
- Hostnames and IPs
- Command counts per agent
- Session information
- Last seen times

### Show Only Pending Commands
```bash
./logviewer -pending
```

### Show Only Errors
```bash
./logviewer -errors
```

## Sorting Options

```bash
# Sort by time (default)
./logviewer -sort time

# Sort by agent ID
./logviewer -sort agent

# Sort by hostname
./logviewer -sort host

# Sort by IP
./logviewer -sort ip

# Sort by username
./logviewer -sort user

# Sort by command
./logviewer -sort command

# Reverse sort order
./logviewer -sort time -reverse
```

## Real-time Monitoring

Follow logs with filtering:
```bash
# Follow all logs
./logviewer -follow

# Follow specific agent
./logviewer -follow -agent 5b561c45

# Follow specific host
./logviewer -follow -host dev

# Follow by IP
./logviewer -follow -ip 192.168.44.128
```

## Log File Structure

Logs are stored in JSON format with the following fields:

```json
{
  "timestamp": "2025-09-05T13:59:22.476726502Z",
  "type": "command|output|error|checkin|connection",
  "agent_id": "5b561c45-b596-403e-9254-7cbd31177e3e",
  "username": "username1",
  "command": "pwd",
  "command_id": 1,
  "command_type": "pwd",
  "hostname": "dev",
  "external_ip": "192.168.44.128",
  "internal_ip": "192.168.44.128",
  "os": "linux",
  "arch": "amd64",
  "process": "https_go_amd64.bin",
  "pid": "1589483",
  "integrity": "medium",
  "session_id": "session_5b561c45_1757080756",
  "output": "...",
  "output_size": 52
}
```

## Command Flags Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-dir` | Log directory path | `/app/logs/commands` |
| `-file` | Specific log file | Today's log |
| `-agent` | Filter by agent ID | None |
| `-host` | Filter by hostname | None |
| `-ip` | Filter by IP | None |
| `-user` | Filter by username | None |
| `-type` | Filter by command type | None |
| `-os` | Filter by OS | None |
| `-session` | Filter by session ID | None |
| `-format` | Output format (text/json/csv/table) | `text` |
| `-json` | Output as JSON | `false` |
| `-v` | Verbose output | `false` |
| `-stats` | Show statistics | `false` |
| `-agents` | Show agent summary | `false` |
| `-pending` | Show pending commands | `false` |
| `-errors` | Show errors only | `false` |
| `-follow` | Follow log file | `false` |
| `-from` | Start date (YYYY-MM-DD) | 7 days ago |
| `-to` | End date (YYYY-MM-DD) | Today |
| `-sort` | Sort by field | `time` |
| `-reverse` | Reverse sort order | `false` |

## Examples

### Daily Operations Report
```bash
# Get today's statistics
./logviewer -stats

# Export today's commands as CSV
./logviewer -format csv > daily_report.csv
```

### Investigate Specific Agent
```bash
# View all activity from an agent
./logviewer -agent 5b561c45 -v

# Check pending commands for an agent
./logviewer -agent 5b561c45 -pending
```

### Security Audit
```bash
# Find all BOF executions
./logviewer -type bof -format json

# Check for errors in the last week
./logviewer -errors -from 2025-09-01
```

### Performance Analysis
```bash
# View command response time statistics
./logviewer -stats

# Find slow commands (will show min/max/avg response times)
./logviewer -stats -from 2025-09-01
```

### Multi-Day Analysis
```bash
# Analyze a week of activity
./logviewer -from 2025-09-01 -to 2025-09-07 -stats

# Get all Windows agent activity for the month
./logviewer -from 2025-09-01 -to 2025-09-30 -os windows
```

## Understanding Output

### Statistics View
Shows:
- Total commands executed
- Completed vs pending commands
- Error count
- Average, minimum, and maximum response times
- Top agents by command count

### Agent Summary View
Displays a table with:
- Agent ID (truncated)
- Hostname
- External/Internal IPs
- Operating system
- Username
- Command count
- Number of sessions
- Last seen timestamp

### Command Execution View
Each execution shows:
- Command ID
- Agent ID
- User who issued the command
- The command itself
- Timestamp when sent
- Status (sent/completed/error)
- Output (if completed)
- Response time (if completed)

## Tips and Best Practices

1. **Use filters to reduce noise**: When investigating issues, combine filters to focus on relevant data
2. **Export to CSV for reporting**: Use CSV format for importing into spreadsheets or other analysis tools
3. **Monitor pending commands**: Regularly check `-pending` to identify stuck or slow commands
4. **Follow mode for debugging**: Use `-follow` during active operations to see real-time command execution
5. **Check statistics regularly**: Use `-stats` to identify performance trends or issues

## Troubleshooting

### No logs found
- Check the log directory exists: `/app/logs/commands/`
- Verify the date range includes existing logs
- Ensure the log file naming convention matches: `commands_YYYY-MM-DD.log`

### Duplicate commands in output
- This is usually caused by logging commands both when received and when fetched
- The correlator should handle deduplication automatically
- Use `-v` to see command IDs and identify true duplicates

### Missing agent information
- Agent information is cached when agents first connect
- Use `-agents` to see which agents have cached information
- Check for "connection" type entries in the logs

## Log Rotation

Logs are automatically rotated based on two criteria:

### Daily Rotation
- New log file created at midnight each day
- Format: `commands_YYYY-MM-DD.log`

### Size-based Rotation
- Default maximum file size: 100MB (configurable)
- When a log file exceeds the size limit, it's automatically rotated
- Rotated files are numbered sequentially: 
  - `commands_2025-09-05.log` (first file of the day)
  - `commands_2025-09-05_1.log` (first rotation due to size)
  - `commands_2025-09-05_2.log` (second rotation due to size)
- Sequence numbers reset each day

### Retention Policy
Old logs are not automatically deleted. Implement your own retention policy based on storage requirements.

### Working with Rotated Logs
When analyzing logs with multiple rotations:
```bash
# Analyze all logs for a specific day (including rotated files)
./logviewer -from 2025-09-05 -to 2025-09-05

# The tool will automatically find and process:
# - commands_2025-09-05.log
# - commands_2025-09-05_1.log
# - commands_2025-09-05_2.log
# etc.
```

## Integration with Other Tools

### Export for External Analysis
```bash
# Export to JSON for processing with jq
./logviewer -format json | jq '.[] | select(.command_type=="bof")'

# Export to CSV for Excel/Google Sheets
./logviewer -format csv > analysis.csv

# Pipe to grep for additional filtering
./logviewer | grep -i "error"
```

### Scheduled Reports
Create a cron job for daily reports:
```bash
0 2 * * * /app/logviewer -stats -format json > /app/reports/daily_$(date +%Y%m%d).json
```

## HTTP API Endpoint

The log analyzer also exposes an HTTP endpoint for viewing recent logs:
```bash
curl http://localhost:PORT/logs/recent
```

This returns the current day's log file in plain text format.