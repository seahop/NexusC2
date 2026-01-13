# client/src/utils/error_codes.py
"""
Error code translation for agent output.

Agent payloads return short codes (E1, S0, etc.) to minimize signature-able strings.
This module translates those codes to human-readable messages for display in the GUI.
"""

import re
from typing import Optional

# Success code translations
SUCCESS_CODES = {
    "S0": "OK",
    "S1": "Created",
    "S2": "Removed",
    "S3": "Updated",
    "S4": "Started",
    "S5": "Completed",
    "S6": "Found",
    "S7": "Listed",
    "S8": "SOCKS started",
    "S9": "SOCKS stopped",
    # Token operations (S10-S15)
    "S10": "Token stolen successfully",
    "S11": "Token stored successfully",
    "S12": "Token switched successfully",
    "S13": "Network-only token set",
    "S14": "Token cleared",
    "S15": "Rekey initiated",
    # Job/output status (S16-S19)
    "S16": "Job killed",
    "S17": "Jobs cleaned",
    "S18": "No output captured yet",
    "S19": "Output truncated (exceeded limit)",
    # Token context status (S20-S24)
    "S20": "Using network-only token",
    "S21": "Using impersonation token",
    "S22": "No token context - using current user",
    "S23": "AMSI bypass applied",
    "S24": "WARNING: Regular impersonation may not work for network shares. Consider using 'make-token' with network-only flag for UNC paths",
    # Assembly execution info (S25-S29)
    "S25": "Executing assembly...",
    "S26": "Exit protection enabled (/runfor detected)",
    "S27": "WARNING: CLR state may be corrupted from previous execution. If execution fails, agent restart may be required",
    "S28": "Exit prevention active",
    "S29": "Keychain unlocked successfully",
}

# Error code translations
ERROR_CODES = {
    # General errors (E1-E19)
    "E1": "No arguments provided",
    "E2": "Invalid arguments",
    "E3": "Permission denied",
    "E4": "Not found",
    "E5": "Already exists",
    "E6": "Is a directory",
    "E7": "Is a file",
    "E8": "Binary file detected",
    "E9": "Operation timed out",
    "E10": "Read error",
    "E11": "Write error",
    "E12": "Network error",
    "E13": "Resource busy",
    "E14": "Read-only filesystem",
    "E15": "Operation not permitted",
    "E16": "Directory not empty",
    "E17": "Invalid path",
    "E18": "Decode/parse error",
    "E19": "Internal error",

    # Command-specific errors (E20-E39)
    "E20": "Flag requires argument",
    "E21": "Unknown flag",
    "E22": "Invalid flag value",
    "E23": "Missing required flag",
    "E24": "Transfer error",
    "E25": "Execution failed",
    "E26": "Job not found",
    "E27": "Job already running",
    "E28": "Invalid sleep value",
    "E29": "Invalid jitter value",
    "E30": "Session not active",
    "E31": "Authentication failed",

    # Windows-specific errors (E40-E59)
    "E40": "Logon failed - invalid credentials",
    "E41": "Account disabled or locked",
    "E42": "Token operation failed",
    "E43": "Process operation failed",
    "E44": "Memory allocation failed",
    "E45": "API call failed",
    "E46": "No tokens available",
    "E47": "Token not found",
    "E48": "Cannot remove active token",
    "E49": "Invalid token handle",
    "E50": "Privilege not held",
    "E51": "BOF execution failed",
    "E52": "Assembly execution failed",
}

# Windows logon error codes (for E40 context translation)
# These are returned as E40:0xNNN and translated here
WINDOWS_LOGON_ERRORS = {
    "0x52E": "Unknown user name or bad password",
    "0x52F": "Account disabled, expired, or locked",
    "0x530": "Invalid logon hours",
    "0x531": "User not allowed to log on at this computer",
    "0x532": "Account disabled",
    "0x533": "Account has expired",
    "0x534": "User not allowed to log on at this computer",
    "0x535": "Password has expired",
    "0x536": "NetLogon component not active",
    "0x537": "Account locked out",
    "0x569": "User not granted requested logon type",
    "0x56A": "Account password has expired",
    "0x56B": "User not allowed to log on from this computer",
    "0x6F7": "Domain controller not available",
    "0x773": "Password must be changed",
    "0x774": "Password reset by administrator",
}

# Combined for lookup
ALL_CODES = {**SUCCESS_CODES, **ERROR_CODES}

# Table headers - payload sends short marker, client adds full header
# Format: "T:X:count" followed by data rows
# Using single-letter identifiers (A-M) to avoid signature detection in payload
TABLE_HEADERS = {
    # A = Assembly jobs (was JOBS)
    "A": (
        "Job ID                               | Assembly Name        | Status      | Duration\n"
        "-------------------------------------+----------------------+-------------+-----------",
        "Assembly Jobs"
    ),
    # B = BOF jobs
    "B": (
        "Job ID                               | BOF Name             | Status      | Duration    | Chunks | Truncated\n"
        "-------------------------------------+----------------------+-------------+-------------+--------+-----------",
        "BOF Jobs"
    ),
    # C = Process tokens (was TOKENS)
    "C": (
        "PID      | Process Name         | User                           | Session | Integrity   | Flags\n"
        "---------+----------------------+--------------------------------+---------+-------------+-------",
        "Process Tokens"
    ),
    # D = Stored tokens
    "D": (
        "Name                 | Type        | User                           | Source\n"
        "---------------------+-------------+--------------------------------+-------",
        "Stored Tokens"
    ),
    # E = Directory listing (ls)
    "E": (
        "Permissions  Type        Size         Modified Time         Name\n"
        "------------ ----------- ------------ ------------------- ----------------------------------------",
        "Directory Listing"
    ),
    # F = Process listing (ps) - basic
    "F": (
        "PID     PPID    NAME\n"
        "----------------------------",
        "Processes"
    ),
    # G = Process listing extended (-x)
    "G": (
        "PID     PPID    NAME                            USER                  CPU%    MEM%  MEM(MB)       STATUS\n"
        "---------------------------------------------------------------------------------------------------------",
        "Processes (Extended)"
    ),
    # H = Process listing verbose (-v)
    "H": (
        "PID     PPID    NAME                            COMMAND\n"
        "------------------------------------------------------------",
        "Processes (Verbose)"
    ),
    # I = Process listing full (-x -v)
    "I": (
        "PID     PPID    NAME                            USER                  CPU%    MEM%  MEM(MB)       STATUS        COMMAND\n"
        "-----------------------------------------------------------------------------------------------------------------------------",
        "Processes (Full)"
    ),
    # J = Process token listing (steal-token --list)
    "J": (
        "PID      Process Name                   User                      Status\n"
        "-------- ------------------------------ ------------------------- ----------------------",
        "Process Tokens"
    ),
    # K = Stored tokens listing
    "K": (
        "Name            User                 Src Details                   Stored          Mode Status\n"
        "--------------- -------------------- --- ------------------------- --------------- ---- --------",
        "Stored Tokens"
    ),
    # L = Stats output
    "L": (
        "",
        "Stats"
    ),
    # M = Directory count output
    "M": (
        "",
        "Count"
    ),
}

# Row type markers for directory listing
ROW_TYPES = {
    "0": "file",
    "1": "dir ",
}

# Status value markers - client expands these
STATUS_VALUES = {
    "0": "[CURRENT]",
    "1": "[ACCESSIBLE]",
    "2": "[ACCESS DENIED]",
    "3": "[PROCESS ACCESS DENIED]",
    "4": "[ACTIVE]",
    "5": "[NETONLY]",
    "6": "N/A",
    "7": "Running",
    "8": "Sleeping",
    "9": "Disk sleep",
    "a": "Stopped",
    "b": "Zombie",
    "c": "Idle",
    "d": "Paging",
    "e": "Dead",
}

# Token source codes
TOKEN_SOURCE = {
    "s": "stolen",
    "c": "created",
}

# Token mode codes
TOKEN_MODE = {
    "0": "Full",
    "1": "NetOnly",
}

# Whoami output markers - client expands these
# v|uid|gid|home|shell -> UID: uid\nGID: gid\nHome: home\nShell: shell
# g|group1,group2 -> Groups: group1, group2
# |i -> (impersonated)
# ? -> (unknown)
WHOAMI_VERBOSE_MARKER = "v"
WHOAMI_GROUPS_MARKER = "g"
WHOAMI_IMPERSONATED_MARKER = "i"
WHOAMI_UNKNOWN_MARKER = "?"

# Regex pattern to match code at start of output: E1, E10, S0, etc.
# Matches: "E1", "E1:context", "S0", "S0:context"
CODE_PATTERN = re.compile(r'^([ES]\d{1,2})(?::(.*))?$')

# Regex pattern to match table markers: T:A:5, T:E:10, etc. (single letter type)
TABLE_PATTERN = re.compile(r'^T:([A-M]):(\d+)$')

# Regex pattern for directory count: T:M:files,dirs
LS_COUNT_PATTERN = re.compile(r'^T:M:(\d+),(\d+)$')


def _expand_row_types(line: str) -> str:
    """Expand row type markers (0/1) to full type names (file/dir)."""
    # Look for the row type marker in the type column position
    # Format: "perms  TYPE  size  time  name" where TYPE is 0 or 1
    parts = line.split()
    if len(parts) >= 5:
        # Check if second element is a type marker
        if parts[1] in ROW_TYPES:
            parts[1] = ROW_TYPES[parts[1]]
            return '  '.join(parts[:2]) + '  ' + '  '.join(parts[2:])
    return line


def _expand_status_values(line: str) -> str:
    """Expand status value markers to full names."""
    # Check the last column for status markers
    parts = line.rsplit(None, 1)
    if len(parts) == 2 and parts[1] in STATUS_VALUES:
        return parts[0] + " " + STATUS_VALUES[parts[1]]
    return line


def _translate_ls_count(output: str) -> str:
    """Translate ls count output: T:M:files,dirs -> formatted count."""
    lines = output.strip().split('\n')
    if not lines:
        return output

    first_line = lines[0].strip()
    match = LS_COUNT_PATTERN.match(first_line)

    if match:
        files = int(match.group(1))
        dirs = int(match.group(2))
        total = files + dirs
        return f"Files: {files}\nDirectories: {dirs}\nTotal: {total}"

    return output


def _translate_table_output(output: str) -> str:
    """
    Translate table markers to full headers and expand compact data.

    Handles format: "T:E:5\nrow1\nrow2..." -> "Directory Listing (5):\nHEADER\nexpanded rows..."

    Args:
        output: The raw output that may contain table markers

    Returns:
        Output with table markers replaced by full headers and expanded data
    """
    lines = output.strip().split('\n')
    if not lines:
        return output

    first_line = lines[0].strip()

    # Check for count format first (T:M:files,dirs)
    count_match = LS_COUNT_PATTERN.match(first_line)
    if count_match:
        return _translate_ls_count(output)

    # Check for table marker
    match = TABLE_PATTERN.match(first_line)

    if match:
        table_type = match.group(1)
        count = match.group(2)

        if table_type in TABLE_HEADERS:
            header_tuple = TABLE_HEADERS[table_type]
            header = header_tuple[0]
            title_name = header_tuple[1]
            title = f"{title_name} ({count}):\n"

            # Process remaining lines based on table type
            remaining_lines = lines[1:] if len(lines) > 1 else []

            # Expand row types for directory listing (type E)
            if table_type == "E":
                remaining_lines = [_expand_row_types(line) for line in remaining_lines]

            # Expand status values for process listings (types G, I) and token listings (J, K)
            if table_type in ("G", "I", "J", "K"):
                remaining_lines = [_expand_status_values(line) for line in remaining_lines]

            remaining = '\n'.join(remaining_lines)
            if header:
                result = title + header + ("\n" + remaining if remaining else "")
            else:
                result = title + remaining

            # Apply additional formatting for token listings
            if table_type == "J":
                result = _translate_token_summary(result)
            elif table_type == "K":
                result = _translate_stored_tokens_summary(result)

            return result

    return output


def _translate_token_summary(output: str) -> str:
    """
    Translate token listing summary from compact format.

    Input format: accessible,denied
    Output: Summary: X accessible, Y denied
    """
    lines = output.strip().split('\n')
    if not lines:
        return output

    # Check if last line is the summary format
    last_line = lines[-1].strip()
    if ',' in last_line and last_line.replace(',', '').isdigit():
        parts = last_line.split(',')
        if len(parts) == 2:
            accessible, denied = parts
            summary = f"\nSummary: {accessible} accessible, {denied} denied"
            return '\n'.join(lines[:-1]) + summary

    return output


def _translate_stored_tokens_summary(output: str) -> str:
    """
    Translate stored tokens summary from compact format.

    Input format: total|active_token|netonly_token|current_user
    Output: Formatted status block
    """
    lines = output.strip().split('\n')
    if not lines:
        return output

    # Check if last line is the summary format
    last_line = lines[-1].strip()
    if '|' in last_line:
        parts = last_line.split('|')
        if len(parts) == 4:
            total, active, netonly, current_user = parts
            summary_lines = [f"\nTotal: {total} tokens"]
            summary_lines.append(f"\nStatus:")
            summary_lines.append(f"Process User: {current_user}")
            if active:
                summary_lines.append(f"Impersonating: {active}")
            if netonly:
                summary_lines.append(f"NetOnly Token: {netonly}")
            return '\n'.join(lines[:-1]) + '\n'.join(summary_lines)

    return output


def _translate_assembly_job_output(output: str) -> str:
    """
    Translate assembly job output from compact format.

    Input format: job_id|status|truncated|duration_info\nactual_output
    Output: Formatted job status + output
    """
    lines = output.strip().split('\n')
    if not lines:
        return output

    first_line = lines[0].strip()
    if '|' in first_line:
        parts = first_line.split('|')
        if len(parts) >= 4:
            job_id, status, truncated, duration_info = parts[:4]

            result_lines = [f"Job: {job_id} ({status})"]

            if truncated == "1":
                result_lines.append("(OUTPUT TRUNCATED - exceeded 10MB limit)")

            # Parse duration info
            if duration_info.startswith("r:"):
                # Running: r:duration:buffer_size
                dur_parts = duration_info[2:].split(':')
                if len(dur_parts) >= 2:
                    result_lines.append(f"Running: {dur_parts[0]}")
                    result_lines.append(f"Buffer: {dur_parts[1]} bytes")
            elif duration_info.startswith("d:"):
                # Done: d:duration
                result_lines.append(f"Duration: {duration_info[2:]}")

            # Add remaining output
            if len(lines) > 1:
                remaining = '\n'.join(lines[1:])
                if remaining.strip() == "S18":
                    result_lines.append("No output captured yet")
                else:
                    result_lines.append(remaining)

            return '\n'.join(result_lines)

    return output


def _translate_windows_logon_error(context: str) -> str:
    """
    Translate Windows logon error hex code to human-readable message.

    Args:
        context: The hex code (e.g., "0x52E")

    Returns:
        Translated message or original context if not found
    """
    if context and context.upper() in WINDOWS_LOGON_ERRORS:
        return WINDOWS_LOGON_ERRORS[context.upper()]
    return f"Windows error {context}"


def _translate_whoami_output(output: str) -> str:
    """
    Translate whoami output from compact format to human-readable format.

    Handles:
    - v|uid|gid|home|shell -> UID: uid\nGID: gid\nHome: home\nShell: shell
    - g|group1,group2 -> Groups: group1, group2
    - DOMAIN\\user|i -> DOMAIN\\user (impersonated)
    - ? -> (unknown)

    Args:
        output: The raw whoami output

    Returns:
        Translated output with expanded markers
    """
    if not output:
        return output

    lines = output.split('\n')
    result_lines = []

    for line in lines:
        # Check for verbose marker: v|uid|gid|home|shell
        if line.startswith(WHOAMI_VERBOSE_MARKER + '|'):
            parts = line.split('|')
            if len(parts) >= 5:
                _, uid, gid, home, shell = parts[:5]
                # Expand ? to (unknown)
                if shell == WHOAMI_UNKNOWN_MARKER:
                    shell = "(unknown)"
                result_lines.append(f"UID: {uid}")
                result_lines.append(f"GID: {gid}")
                result_lines.append(f"Home: {home}")
                result_lines.append(f"Shell: {shell}")
            else:
                result_lines.append(line)
        # Check for groups marker: g|group1,group2
        elif line.startswith(WHOAMI_GROUPS_MARKER + '|'):
            groups_str = line[2:]  # Remove "g|"
            groups = groups_str.split(',')
            result_lines.append(f"Groups: {', '.join(groups)}")
        # Check for impersonated marker at end: user|i
        elif line.endswith('|' + WHOAMI_IMPERSONATED_MARKER):
            user = line[:-2]  # Remove "|i"
            result_lines.append(f"{user} (impersonated)")
        else:
            # Replace standalone ? with (unknown)
            if line == WHOAMI_UNKNOWN_MARKER:
                result_lines.append("(unknown)")
            else:
                result_lines.append(line)

    return '\n'.join(result_lines)


def translate_code(output: str) -> str:
    """
    Translate error/success codes in output to human-readable messages.

    Handles formats:
    - "E3" -> "Permission denied"
    - "E3:/etc/shadow" -> "Permission denied: /etc/shadow"
    - "E40:0x52E" -> "Logon failed: Unknown user name or bad password"
    - "S2:/tmp/file.txt" -> "Removed: /tmp/file.txt"
    - "T:JOBS:5\ndata..." -> "Jobs (5):\nHEADER\ndata..."
    - "regular output" -> "regular output" (unchanged)

    Args:
        output: The raw output from the agent

    Returns:
        Translated output with human-readable messages
    """
    if not output:
        return output

    # Check for table markers first
    output_stripped = output.strip()
    if output_stripped.startswith('T:'):
        return _translate_table_output(output)

    # Check for assembly job output format (starts with S5| or S18|)
    if output_stripped.startswith('S5|') or output_stripped.startswith('S18|'):
        return _translate_assembly_job_output(output)

    # Check for job status line format (job_id|status|truncated|duration)
    first_line = output_stripped.split('\n')[0]
    if '|' in first_line and len(first_line.split('|')) >= 4:
        # Likely a job output format
        return _translate_assembly_job_output(output)

    # Check if the entire output is just a code (possibly with context)
    match = CODE_PATTERN.match(output_stripped)

    if match:
        code = match.group(1)
        context = match.group(2)

        if code in ALL_CODES:
            message = ALL_CODES[code]
            if context:
                # Special handling for E40 (Windows logon errors)
                if code == "E40" and context.startswith("0x"):
                    win_msg = _translate_windows_logon_error(context)
                    return f"{message}: {win_msg}"
                return f"{message}: {context}"
            return message

    # Check for multi-line output where first line might be a code
    lines = output_stripped.split('\n')
    if len(lines) > 1:
        first_line = lines[0].strip()
        match = CODE_PATTERN.match(first_line)
        if match:
            code = match.group(1)
            context = match.group(2)
            if code in ALL_CODES:
                message = ALL_CODES[code]
                if context:
                    # Special handling for E40 (Windows logon errors)
                    if code == "E40" and context.startswith("0x"):
                        win_msg = _translate_windows_logon_error(context)
                        translated_first = f"{message}: {win_msg}"
                    else:
                        translated_first = f"{message}: {context}"
                else:
                    translated_first = message
                return translated_first + '\n' + '\n'.join(lines[1:])

    # Check for whoami output markers (v|, g|, |i)
    # These can appear in any line of the output
    has_whoami_markers = False
    for line in lines:
        if (line.startswith(WHOAMI_VERBOSE_MARKER + '|') or
            line.startswith(WHOAMI_GROUPS_MARKER + '|') or
            line.endswith('|' + WHOAMI_IMPERSONATED_MARKER)):
            has_whoami_markers = True
            break

    if has_whoami_markers:
        return _translate_whoami_output(output)

    return output


def is_error_code(output: str) -> bool:
    """
    Check if output starts with an error code.

    Args:
        output: The raw output from the agent

    Returns:
        True if output starts with an error code (E1-E99)
    """
    if not output:
        return False

    output_stripped = output.strip()
    match = CODE_PATTERN.match(output_stripped.split('\n')[0])

    if match:
        code = match.group(1)
        return code.startswith('E') and code in ERROR_CODES

    return False


def is_success_code(output: str) -> bool:
    """
    Check if output starts with a success code.

    Args:
        output: The raw output from the agent

    Returns:
        True if output starts with a success code (S0-S9)
    """
    if not output:
        return False

    output_stripped = output.strip()
    match = CODE_PATTERN.match(output_stripped.split('\n')[0])

    if match:
        code = match.group(1)
        return code.startswith('S') and code in SUCCESS_CODES

    return False


def get_code_type(output: str) -> Optional[str]:
    """
    Get the type of code in the output.

    Args:
        output: The raw output from the agent

    Returns:
        "error" if error code, "success" if success code, None otherwise
    """
    if is_error_code(output):
        return "error"
    if is_success_code(output):
        return "success"
    return None
