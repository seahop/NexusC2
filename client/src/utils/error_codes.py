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

# Combined for lookup
ALL_CODES = {**SUCCESS_CODES, **ERROR_CODES}

# Regex pattern to match code at start of output: E1, E10, S0, etc.
# Matches: "E1", "E1:context", "S0", "S0:context"
CODE_PATTERN = re.compile(r'^([ES]\d{1,2})(?::(.*))?$')


def translate_code(output: str) -> str:
    """
    Translate error/success codes in output to human-readable messages.

    Handles formats:
    - "E3" -> "Permission denied"
    - "E3:/etc/shadow" -> "Permission denied: /etc/shadow"
    - "S2:/tmp/file.txt" -> "Removed: /tmp/file.txt"
    - "regular output" -> "regular output" (unchanged)

    Args:
        output: The raw output from the agent

    Returns:
        Translated output with human-readable messages
    """
    if not output:
        return output

    # Check if the entire output is just a code (possibly with context)
    output_stripped = output.strip()
    match = CODE_PATTERN.match(output_stripped)

    if match:
        code = match.group(1)
        context = match.group(2)

        if code in ALL_CODES:
            message = ALL_CODES[code]
            if context:
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
                    translated_first = f"{message}: {context}"
                else:
                    translated_first = message
                return translated_first + '\n' + '\n'.join(lines[1:])

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
