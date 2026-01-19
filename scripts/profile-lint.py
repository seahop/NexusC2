#!/usr/bin/env python3
"""
profile-lint.py - Malleable Profile Validator and Visualizer

This script validates malleable HTTP profiles and shows a visual representation
of how data is transformed as it flows between agent and server.

Usage:
    ./profile-lint.py <profile.toml>                    # Validate a profile
    ./profile-lint.py <profile.toml> --simulate         # Show transformation examples
    ./profile-lint.py <profile.toml> --simulate --verbose  # Detailed step-by-step
    ./profile-lint.py <profile.toml> --packet           # Show HTTP packet visualization
"""

import argparse
import base64
import gzip
import io
import os
import random
import string
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # Fallback for older Python
    except ImportError:
        print("Error: Please install tomli: pip install tomli")
        sys.exit(1)


# =============================================================================
# ANSI Colors
# =============================================================================

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'


def color(text: str, c: str) -> str:
    return f"{c}{text}{Colors.ENDC}"


def bold(text: str) -> str:
    return color(text, Colors.BOLD)


def dim(text: str) -> str:
    return color(text, Colors.DIM)


# =============================================================================
# Transform Implementation (mirrors Go implementation)
# =============================================================================

CHARSETS = {
    "numeric": "0123456789",
    "alpha": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alphanumeric": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "hex": "0123456789abcdef",
}

VALID_TRANSFORM_TYPES = [
    "base64", "base64url", "hex", "gzip", "netbios", "xor",
    "prepend", "append", "random_prepend", "random_append"
]

VALID_OUTPUT_TYPES = ["body", "header", "cookie", "query", "uri_append"]


@dataclass
class TransformResult:
    data: bytes
    prepend_length: int = 0
    append_length: int = 0
    steps: List[str] = None

    def __post_init__(self):
        if self.steps is None:
            self.steps = []


def generate_random(length: int, charset: str = "alphanumeric") -> bytes:
    """Generate random padding of specified length and charset."""
    chars = CHARSETS.get(charset, CHARSETS["alphanumeric"])
    return ''.join(random.choice(chars) for _ in range(length)).encode()


def encode_base64(data: bytes) -> bytes:
    return base64.b64encode(data)


def decode_base64(data: bytes) -> bytes:
    return base64.b64decode(data)


def encode_base64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data)


def decode_base64url(data: bytes) -> bytes:
    return base64.urlsafe_b64decode(data)


def encode_hex(data: bytes) -> bytes:
    return data.hex().encode()


def decode_hex(data: bytes) -> bytes:
    return bytes.fromhex(data.decode())


def encode_gzip(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode='wb') as f:
        f.write(data)
    return buf.getvalue()


def decode_gzip(data: bytes) -> bytes:
    buf = io.BytesIO(data)
    with gzip.GzipFile(fileobj=buf, mode='rb') as f:
        return f.read()


def encode_netbios(data: bytes) -> bytes:
    """NetBIOS encoding: each byte becomes two characters."""
    result = []
    for b in data:
        result.append(chr(ord('a') + (b >> 4)))
        result.append(chr(ord('a') + (b & 0x0f)))
    return ''.join(result).encode()


def decode_netbios(data: bytes) -> bytes:
    """Decode NetBIOS encoded data."""
    if len(data) % 2 != 0:
        raise ValueError("NetBIOS data must have even length")
    result = []
    data_str = data.decode()
    for i in range(0, len(data_str), 2):
        high = ord(data_str[i]) - ord('a')
        low = ord(data_str[i + 1]) - ord('a')
        result.append((high << 4) | low)
    return bytes(result)


def apply_xor(data: bytes, key: bytes) -> bytes:
    """XOR data with key (repeating key as needed)."""
    if not key:
        return data
    result = []
    for i, b in enumerate(data):
        result.append(b ^ key[i % len(key)])
    return bytes(result)


def apply_transforms(data: bytes, transforms: List[Dict], verbose: bool = False) -> TransformResult:
    """Apply a chain of transforms to data."""
    result = TransformResult(data=data)

    for t in transforms:
        t_type = t.get("type", "")
        t_value = t.get("value", "")
        t_length = t.get("length", 0)
        t_charset = t.get("charset", "alphanumeric")

        original = result.data
        step_desc = ""

        if t_type == "base64":
            result.data = encode_base64(result.data)
            step_desc = "base64 encode"
        elif t_type == "base64url":
            result.data = encode_base64url(result.data)
            step_desc = "base64url encode"
        elif t_type == "hex":
            result.data = encode_hex(result.data)
            step_desc = "hex encode"
        elif t_type == "gzip":
            result.data = encode_gzip(result.data)
            step_desc = "gzip compress"
        elif t_type == "netbios":
            result.data = encode_netbios(result.data)
            step_desc = "netbios encode"
        elif t_type == "xor":
            result.data = apply_xor(result.data, t_value.encode())
            step_desc = f"xor with key={repr(t_value)}"
        elif t_type == "prepend":
            result.data = t_value.encode() + result.data
            step_desc = f"prepend {repr(t_value)}"
        elif t_type == "append":
            result.data = result.data + t_value.encode()
            step_desc = f"append {repr(t_value)}"
        elif t_type == "random_prepend":
            padding = generate_random(t_length, t_charset)
            result.data = padding + result.data
            result.prepend_length = t_length
            step_desc = f"random_prepend({t_length}, {t_charset}) = {repr(padding.decode())}"
        elif t_type == "random_append":
            padding = generate_random(t_length, t_charset)
            result.data = result.data + padding
            result.append_length = t_length
            step_desc = f"random_append({t_length}, {t_charset}) = {repr(padding.decode())}"

        if verbose:
            result.steps.append(f"  {step_desc}")
            result.steps.append(f"    Input:  {format_data(original, 60)}")
            result.steps.append(f"    Output: {format_data(result.data, 60)}")

    return result


def reverse_transforms(data: bytes, transforms: List[Dict], prepend_len: int = 0,
                       append_len: int = 0, verbose: bool = False) -> Tuple[bytes, List[str]]:
    """Reverse transforms to extract original data."""
    steps = []
    result = data

    # Apply in reverse order
    for t in reversed(transforms):
        t_type = t.get("type", "")
        t_value = t.get("value", "")
        t_length = t.get("length", 0)

        original = result
        step_desc = ""

        if t_type == "base64":
            result = decode_base64(result)
            step_desc = "base64 decode"
        elif t_type == "base64url":
            result = decode_base64url(result)
            step_desc = "base64url decode"
        elif t_type == "hex":
            result = decode_hex(result)
            step_desc = "hex decode"
        elif t_type == "gzip":
            result = decode_gzip(result)
            step_desc = "gzip decompress"
        elif t_type == "netbios":
            result = decode_netbios(result)
            step_desc = "netbios decode"
        elif t_type == "xor":
            result = apply_xor(result, t_value.encode())
            step_desc = f"xor with key={repr(t_value)}"
        elif t_type == "prepend":
            result = result[len(t_value):]
            step_desc = f"strip prepend {repr(t_value)}"
        elif t_type == "append":
            result = result[:-len(t_value)] if t_value else result
            step_desc = f"strip append {repr(t_value)}"
        elif t_type == "random_prepend":
            length = prepend_len or t_length
            result = result[length:]
            step_desc = f"strip random_prepend({length})"
        elif t_type == "random_append":
            length = append_len or t_length
            result = result[:-length] if length else result
            step_desc = f"strip random_append({length})"

        if verbose:
            steps.append(f"  {step_desc}")
            steps.append(f"    Input:  {format_data(original, 60)}")
            steps.append(f"    Output: {format_data(result, 60)}")

    return result, steps


def format_data(data: bytes, max_len: int = 80) -> str:
    """Format data for display, truncating if needed."""
    try:
        text = data.decode('utf-8')
        if len(text) > max_len:
            return repr(text[:max_len]) + "..."
        return repr(text)
    except UnicodeDecodeError:
        hex_str = data.hex()
        if len(hex_str) > max_len:
            return f"<{len(data)} bytes: {hex_str[:max_len]}...>"
        return f"<{len(data)} bytes: {hex_str}>"


# =============================================================================
# Validation Functions
# =============================================================================

def validate_transform(transform: Dict, context: str) -> List[str]:
    """Validate a single transform configuration."""
    errors = []
    t_type = transform.get("type", "")

    if not t_type:
        errors.append(f"{context}: transform missing 'type'")
        return errors

    if t_type not in VALID_TRANSFORM_TYPES:
        errors.append(f"{context}: unknown transform type '{t_type}', must be one of: {', '.join(VALID_TRANSFORM_TYPES)}")
        return errors

    if t_type == "xor":
        if not transform.get("value"):
            errors.append(f"{context}: xor transform requires 'value' (the XOR key)")

    if t_type in ("prepend", "append"):
        if not transform.get("value"):
            errors.append(f"{context}: {t_type} transform requires 'value'")

    if t_type in ("random_prepend", "random_append"):
        length = transform.get("length", 0)
        if not length or length <= 0:
            errors.append(f"{context}: {t_type} transform requires positive 'length'")
        charset = transform.get("charset", "")
        if charset and charset not in CHARSETS:
            errors.append(f"{context}: invalid charset '{charset}', must be: {', '.join(CHARSETS.keys())}")

    return errors


def validate_output(output: str, context: str) -> List[str]:
    """Validate an output specification."""
    errors = []

    if not output:
        errors.append(f"{context}: 'output' is required")
        return errors

    parts = output.split(":", 1)
    loc_type = parts[0]

    if loc_type not in VALID_OUTPUT_TYPES:
        errors.append(f"{context}: invalid output type '{loc_type}', must be: {', '.join(VALID_OUTPUT_TYPES)}")
        return errors

    if loc_type in ("header", "cookie", "query"):
        if len(parts) < 2 or not parts[1]:
            errors.append(f"{context}: {loc_type} output requires a name (e.g., '{loc_type}:name')")

    return errors


def validate_data_block(block: Dict, context: str) -> List[str]:
    """Validate a data block (client_id or data section)."""
    errors = []

    # Validate output
    errors.extend(validate_output(block.get("output", ""), context))

    # Validate transforms
    transforms = block.get("transforms", [])
    for i, t in enumerate(transforms):
        errors.extend(validate_transform(t, f"{context}.transforms[{i}]"))

    return errors


def validate_profile(profile_data: Dict) -> Tuple[bool, List[str], List[str]]:
    """
    Validate an entire profile TOML.
    Returns (is_valid, errors, warnings)
    """
    errors = []
    warnings = []

    http_profiles = profile_data.get("http_profiles", {})

    # Validate GET profiles
    for i, profile in enumerate(http_profiles.get("get", [])):
        ctx = f"http_profiles.get[{i}] ({profile.get('name', 'unnamed')})"

        if not profile.get("name"):
            errors.append(f"{ctx}: 'name' is required")
        if not profile.get("path"):
            errors.append(f"{ctx}: 'path' is required")

        # Validate client_id block if present
        if "client_id" in profile:
            errors.extend(validate_data_block(profile["client_id"], f"{ctx}.client_id"))
        elif not profile.get("params"):
            warnings.append(f"{ctx}: no 'client_id' block or 'params' defined - clientID placement unclear")

    # Validate POST profiles
    for i, profile in enumerate(http_profiles.get("post", [])):
        ctx = f"http_profiles.post[{i}] ({profile.get('name', 'unnamed')})"

        if not profile.get("name"):
            errors.append(f"{ctx}: 'name' is required")
        if not profile.get("path"):
            errors.append(f"{ctx}: 'path' is required")

        # Validate client_id block if present
        if "client_id" in profile:
            errors.extend(validate_data_block(profile["client_id"], f"{ctx}.client_id"))
        elif not profile.get("params"):
            warnings.append(f"{ctx}: no 'client_id' block or 'params' defined - clientID placement unclear")

        # Validate data block if present
        if "data" in profile:
            errors.extend(validate_data_block(profile["data"], f"{ctx}.data"))

    # Validate server response profiles
    for i, profile in enumerate(http_profiles.get("server_response", [])):
        ctx = f"http_profiles.server_response[{i}] ({profile.get('name', 'unnamed')})"

        if not profile.get("name"):
            errors.append(f"{ctx}: 'name' is required")

        # Validate data block if present
        if "data" in profile:
            errors.extend(validate_data_block(profile["data"], f"{ctx}.data"))

    is_valid = len(errors) == 0
    return is_valid, errors, warnings


# =============================================================================
# Visualization Functions
# =============================================================================

def print_header(text: str):
    print(f"\n{color('=' * 70, Colors.CYAN)}")
    print(f"{color(text, Colors.BOLD + Colors.CYAN)}")
    print(f"{color('=' * 70, Colors.CYAN)}")


def print_subheader(text: str):
    print(f"\n{color(text, Colors.YELLOW)}")
    print(color("-" * len(text), Colors.YELLOW))


def visualize_transforms(name: str, transforms: List[Dict]):
    """Print a visual representation of a transform chain."""
    if not transforms:
        print(f"  {dim('(no transforms)')}")
        return

    for i, t in enumerate(transforms):
        t_type = t.get("type", "unknown")
        arrow = color("->", Colors.DIM) if i > 0 else "  "

        if t_type in ("prepend", "append"):
            desc = f"{t_type}({repr(t.get('value', ''))})"
        elif t_type in ("random_prepend", "random_append"):
            desc = f"{t_type}(len={t.get('length', 0)}, charset={t.get('charset', 'alphanumeric')})"
        elif t_type == "xor":
            desc = f"xor(key={repr(t.get('value', ''))})"
        else:
            desc = t_type

        print(f"  {arrow} {color(desc, Colors.GREEN)}")


def simulate_get_request(profile: Dict, client_id: str, verbose: bool = False):
    """Simulate a GET request and show the transformation."""
    print_subheader(f"GET Profile: {profile.get('name', 'unnamed')}")

    print(f"\n  {bold('Path:')} {profile.get('path', '/')}")
    print(f"  {bold('Method:')} {profile.get('method', 'GET')}")

    # Check for client_id block
    client_id_block = profile.get("client_id")
    if client_id_block:
        print(f"\n  {bold('ClientID Transforms:')}")
        visualize_transforms("client_id", client_id_block.get("transforms", []))
        print(f"  {bold('Output:')} {color(client_id_block.get('output', 'body'), Colors.BLUE)}")

        # Show transformation
        print(f"\n  {bold('Transformation Example:')}")
        print(f"    Original ClientID: {color(repr(client_id), Colors.GREEN)}")

        result = apply_transforms(client_id.encode(), client_id_block.get("transforms", []), verbose)
        if verbose and result.steps:
            print(f"\n    {bold('Step-by-step:')}")
            for step in result.steps:
                print(f"    {step}")

        final_data = result.data.decode() if result.data else ""
        print(f"\n    Final output: {color(format_data(result.data, 60), Colors.CYAN)}")

        # Show where it goes
        output = client_id_block.get("output", "body")
        loc_type, loc_name = output.split(":", 1) if ":" in output else (output, "")
        if loc_type == "header":
            print(f"\n    {bold('HTTP Header:')} {loc_name}: {final_data}")
        elif loc_type == "cookie":
            print(f"\n    {bold('Cookie:')} {loc_name}={final_data}")
        elif loc_type == "query":
            print(f"\n    {bold('Query param:')} ?{loc_name}={final_data}")

        # Show server reversal
        print(f"\n  {bold('Server Extraction:')}")
        reversed_data, rev_steps = reverse_transforms(
            result.data,
            client_id_block.get("transforms", []),
            result.prepend_length,
            result.append_length,
            verbose
        )
        if verbose and rev_steps:
            for step in rev_steps:
                print(f"    {step}")
        print(f"    Extracted ClientID: {color(repr(reversed_data.decode()), Colors.GREEN)}")

    else:
        # Legacy params mode
        print(f"\n  {dim('(Using legacy params mode for clientID)')}")
        for param in profile.get("params", []):
            if param.get("type") == "clientID_param":
                print(f"    {param.get('location', 'query')}: {param.get('name')} = {param.get('format', '%CLIENTID%').replace('%CLIENTID%', client_id)}")


def simulate_post_request(profile: Dict, client_id: str, post_data: bytes, verbose: bool = False):
    """Simulate a POST request and show the transformation."""
    print_subheader(f"POST Profile: {profile.get('name', 'unnamed')}")

    print(f"\n  {bold('Path:')} {profile.get('path', '/')}")
    print(f"  {bold('Method:')} {profile.get('method', 'POST')}")
    print(f"  {bold('Content-Type:')} {profile.get('content_type', 'application/json')}")

    # ClientID
    client_id_block = profile.get("client_id")
    if client_id_block:
        print(f"\n  {bold('ClientID Transforms:')}")
        visualize_transforms("client_id", client_id_block.get("transforms", []))
        print(f"  {bold('Output:')} {color(client_id_block.get('output', 'body'), Colors.BLUE)}")

        result = apply_transforms(client_id.encode(), client_id_block.get("transforms", []), verbose)
        if verbose and result.steps:
            print(f"\n    {bold('Step-by-step:')}")
            for step in result.steps:
                print(f"    {step}")
        print(f"\n    ClientID transformed: {color(format_data(result.data, 60), Colors.CYAN)}")

    # POST body data
    data_block = profile.get("data")
    if data_block:
        print(f"\n  {bold('POST Body Transforms:')}")
        visualize_transforms("data", data_block.get("transforms", []))
        print(f"  {bold('Output:')} {color(data_block.get('output', 'body'), Colors.BLUE)}")

        print(f"\n  {bold('Transformation Example:')}")
        print(f"    Original data: {color(format_data(post_data, 60), Colors.GREEN)}")

        result = apply_transforms(post_data, data_block.get("transforms", []), verbose)
        if verbose and result.steps:
            print(f"\n    {bold('Step-by-step:')}")
            for step in result.steps:
                print(f"    {step}")

        print(f"\n    Final output: {color(format_data(result.data, 60), Colors.CYAN)}")
        print(f"    Transformed size: {len(post_data)} -> {len(result.data)} bytes")

        # Show server reversal
        print(f"\n  {bold('Server Extraction:')}")
        reversed_data, rev_steps = reverse_transforms(
            result.data,
            data_block.get("transforms", []),
            result.prepend_length,
            result.append_length,
            verbose
        )
        if verbose and rev_steps:
            for step in rev_steps:
                print(f"    {step}")
        print(f"    Extracted data: {color(format_data(reversed_data, 60), Colors.GREEN)}")


def simulate_response(profile: Dict, response_data: bytes, verbose: bool = False):
    """Simulate a server response and show the transformation."""
    print_subheader(f"Server Response Profile: {profile.get('name', 'unnamed')}")

    print(f"\n  {bold('Content-Type:')} {profile.get('content_type', 'application/json')}")
    print(f"  {bold('Status Field:')} {profile.get('status_field', 'status')}")
    print(f"  {bold('Data Field:')} {profile.get('data_field', 'data')}")

    data_block = profile.get("data")
    if data_block:
        print(f"\n  {bold('Response Data Transforms:')}")
        visualize_transforms("data", data_block.get("transforms", []))

        print(f"\n  {bold('Server sends (transformation):')}")
        print(f"    Original data: {color(format_data(response_data, 60), Colors.GREEN)}")

        result = apply_transforms(response_data, data_block.get("transforms", []), verbose)
        if verbose and result.steps:
            for step in result.steps:
                print(f"    {step}")

        print(f"\n    Transformed: {color(format_data(result.data, 60), Colors.CYAN)}")

        print(f"\n  {bold('Agent receives (extraction):')}")
        reversed_data, rev_steps = reverse_transforms(
            result.data,
            data_block.get("transforms", []),
            result.prepend_length,
            result.append_length,
            verbose
        )
        if verbose and rev_steps:
            for step in rev_steps:
                print(f"    {step}")
        print(f"    Extracted: {color(format_data(reversed_data, 60), Colors.GREEN)}")
    else:
        print(f"\n  {dim('(No transforms configured - data sent as-is)')}")


# =============================================================================
# HTTP Packet Visualization
# =============================================================================

def format_hex_dump(data: bytes, width: int = 16, prefix: str = "    ") -> List[str]:
    """Format data as a hex dump with ASCII representation."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{prefix}{i:04x}  {hex_part:<{width * 3}}  |{ascii_part}|")
    return lines


def annotate_data(data: bytes, annotations: List[Tuple[int, int, str, str]]) -> List[str]:
    """
    Create an annotated view of data showing where different parts are.
    annotations: List of (start, end, label, color)
    """
    lines = []

    # Create the data line
    try:
        text = data.decode('utf-8')
        display_text = text[:80] + ('...' if len(text) > 80 else '')
    except UnicodeDecodeError:
        display_text = data[:40].hex() + ('...' if len(data) > 40 else '')

    lines.append(f"    {display_text}")

    # Create annotation markers
    if annotations:
        marker_line = [' '] * min(len(display_text), 80)
        label_lines = []

        for start, end, label, col in annotations:
            # Clamp to display length
            start = min(start, len(marker_line) - 1)
            end = min(end, len(marker_line))

            if start < end:
                marker_line[start] = '['
                for i in range(start + 1, end - 1):
                    if i < len(marker_line):
                        marker_line[i] = '-'
                if end - 1 < len(marker_line):
                    marker_line[end - 1] = ']'

                # Add label below
                label_lines.append((start, color(f"    {' ' * start}^-- {label}", col)))

        lines.append(f"    {''.join(marker_line)}")
        for _, lbl in sorted(label_lines, key=lambda x: x[0]):
            lines.append(lbl)

    return lines


def visualize_packet_get(profile: Dict, client_id: str, host: str = "example.com"):
    """Visualize what a GET request packet would look like."""
    print_subheader(f"GET Packet Visualization: {profile.get('name', 'unnamed')}")

    path = profile.get('path', '/')
    method = profile.get('method', 'GET')
    client_id_block = profile.get("client_id")

    # Track where clientID ends up
    headers = {}
    cookies = []
    query_params = []
    uri_suffix = ""
    transformed_client_id = None
    prepend_len = 0
    append_len = 0

    if client_id_block:
        result = apply_transforms(client_id.encode(), client_id_block.get("transforms", []))
        transformed_client_id = result.data
        prepend_len = result.prepend_length
        append_len = result.append_length

        output = client_id_block.get("output", "body")
        loc_type, loc_name = output.split(":", 1) if ":" in output else (output, "")

        if loc_type == "header":
            headers[loc_name] = transformed_client_id.decode('utf-8', errors='replace')
        elif loc_type == "cookie":
            cookies.append((loc_name, transformed_client_id.decode('utf-8', errors='replace')))
        elif loc_type == "query":
            query_params.append((loc_name, transformed_client_id.decode('utf-8', errors='replace')))
        elif loc_type == "uri_append":
            uri_suffix = transformed_client_id.decode('utf-8', errors='replace')
    else:
        # Legacy params mode
        for param in profile.get("params", []):
            if param.get("type") == "clientID_param":
                loc = param.get("location", "query")
                name = param.get("name", "id")
                fmt = param.get("format", "%CLIENTID%")
                value = fmt.replace("%CLIENTID%", client_id)
                if loc == "query":
                    query_params.append((name, value))
                elif loc == "header":
                    headers[name] = value

    # Build the request line
    query_string = ""
    if query_params:
        query_string = "?" + "&".join(f"{k}={v}" for k, v in query_params)

    full_path = path + uri_suffix + query_string

    # Print the packet
    print(f"\n  {color('┌─ HTTP REQUEST ─────────────────────────────────────────────────────┐', Colors.CYAN)}")
    print(f"  {color('│', Colors.CYAN)}")

    # Request line
    request_line = f"{method} {full_path} HTTP/1.1"
    print(f"  {color('│', Colors.CYAN)} {bold(request_line)}")

    # Headers
    print(f"  {color('│', Colors.CYAN)} Host: {host}")
    print(f"  {color('│', Colors.CYAN)} User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...")
    print(f"  {color('│', Colors.CYAN)} Accept: */*")

    for name, value in headers.items():
        # This is where the clientID is
        print(f"  {color('│', Colors.CYAN)} {color(name, Colors.GREEN)}: {color(value, Colors.YELLOW)} {dim('<-- clientID')}")

    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies)
        print(f"  {color('│', Colors.CYAN)} Cookie: {color(cookie_str, Colors.YELLOW)} {dim('<-- clientID')}")

    print(f"  {color('│', Colors.CYAN)}")
    print(f"  {color('└───────────────────────────────────────────────────────────────────┘', Colors.CYAN)}")

    # Show clientID placement details
    if transformed_client_id:
        print(f"\n  {bold('ClientID Placement:')}")
        print(f"    Original:    {color(repr(client_id), Colors.GREEN)}")
        print(f"    Transformed: {color(format_data(transformed_client_id, 50), Colors.YELLOW)}")

        if prepend_len or append_len:
            print(f"\n  {bold('Padding Info (sent in headers):')}")
            if prepend_len:
                print(f"    X-Pad-Pre: {prepend_len}")
            if append_len:
                print(f"    X-Pad-App: {append_len}")

        # Show data breakdown if there's padding
        if prepend_len or append_len:
            print(f"\n  {bold('Data Structure:')}")
            try:
                data_str = transformed_client_id.decode('utf-8')
                if prepend_len and append_len:
                    print(f"    [{color(data_str[:prepend_len], Colors.DIM)}]" +
                          f"[{color(data_str[prepend_len:-append_len], Colors.GREEN)}]" +
                          f"[{color(data_str[-append_len:], Colors.DIM)}]")
                    print(f"     {dim('random pad')}  {dim('actual data')}  {dim('random pad')}")
                elif prepend_len:
                    print(f"    [{color(data_str[:prepend_len], Colors.DIM)}]" +
                          f"[{color(data_str[prepend_len:], Colors.GREEN)}]")
                    print(f"     {dim('random pad')}  {dim('actual data')}")
                elif append_len:
                    print(f"    [{color(data_str[:-append_len], Colors.GREEN)}]" +
                          f"[{color(data_str[-append_len:], Colors.DIM)}]")
                    print(f"     {dim('actual data')}  {dim('random pad')}")
            except:
                pass


def visualize_packet_post(profile: Dict, client_id: str, post_data: bytes, host: str = "example.com"):
    """Visualize what a POST request packet would look like."""
    print_subheader(f"POST Packet Visualization: {profile.get('name', 'unnamed')}")

    path = profile.get('path', '/')
    method = profile.get('method', 'POST')
    content_type = profile.get('content_type', 'application/json')
    client_id_block = profile.get("client_id")
    data_block = profile.get("data")

    # Track where things end up
    headers = {}
    cookies = []
    query_params = []
    uri_suffix = ""
    body_content = None
    body_is_clientid = False
    body_is_data = False

    client_prepend_len = 0
    client_append_len = 0
    data_prepend_len = 0
    data_append_len = 0

    transformed_client_id = None
    transformed_data = None

    # Process clientID placement
    if client_id_block:
        result = apply_transforms(client_id.encode(), client_id_block.get("transforms", []))
        transformed_client_id = result.data
        client_prepend_len = result.prepend_length
        client_append_len = result.append_length

        output = client_id_block.get("output", "body")
        loc_type, loc_name = output.split(":", 1) if ":" in output else (output, "")

        if loc_type == "header":
            headers[loc_name] = ("clientID", transformed_client_id.decode('utf-8', errors='replace'))
        elif loc_type == "cookie":
            cookies.append((loc_name, transformed_client_id.decode('utf-8', errors='replace'), "clientID"))
        elif loc_type == "query":
            query_params.append((loc_name, transformed_client_id.decode('utf-8', errors='replace'), "clientID"))
        elif loc_type == "uri_append":
            uri_suffix = transformed_client_id.decode('utf-8', errors='replace')
        elif loc_type == "body":
            body_content = transformed_client_id
            body_is_clientid = True

    # Process data placement
    if data_block:
        result = apply_transforms(post_data, data_block.get("transforms", []))
        transformed_data = result.data
        data_prepend_len = result.prepend_length
        data_append_len = result.append_length

        output = data_block.get("output", "body")
        loc_type, loc_name = output.split(":", 1) if ":" in output else (output, "")

        if loc_type == "body":
            body_content = transformed_data
            body_is_data = True
        elif loc_type == "header":
            headers[loc_name] = ("data", transformed_data.decode('utf-8', errors='replace'))
    else:
        # No data transforms, send post_data as-is (wrapped in JSON typically)
        body_content = post_data

    # Build the request
    query_string = ""
    if query_params:
        query_string = "?" + "&".join(f"{k}={v}" for k, v, _ in query_params)

    full_path = path + uri_suffix + query_string

    # Print the packet
    print(f"\n  {color('┌─ HTTP REQUEST ─────────────────────────────────────────────────────┐', Colors.CYAN)}")
    print(f"  {color('│', Colors.CYAN)}")

    # Request line
    request_line = f"{method} {full_path} HTTP/1.1"
    print(f"  {color('│', Colors.CYAN)} {bold(request_line)}")

    # Standard headers
    print(f"  {color('│', Colors.CYAN)} Host: {host}")
    print(f"  {color('│', Colors.CYAN)} User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...")
    print(f"  {color('│', Colors.CYAN)} Content-Type: {content_type}")

    if body_content:
        print(f"  {color('│', Colors.CYAN)} Content-Length: {len(body_content)}")

    # Padding headers
    total_prepend = client_prepend_len + data_prepend_len
    total_append = client_append_len + data_append_len
    if total_prepend:
        print(f"  {color('│', Colors.CYAN)} {color('X-Pad-Pre', Colors.YELLOW)}: {total_prepend} {dim('<-- padding length')}")
    if total_append:
        print(f"  {color('│', Colors.CYAN)} {color('X-Pad-App', Colors.YELLOW)}: {total_append} {dim('<-- padding length')}")

    # Custom headers with clientID or data
    for name, (data_type, value) in headers.items():
        label = f"<-- {data_type}"
        print(f"  {color('│', Colors.CYAN)} {color(name, Colors.GREEN)}: {color(value[:60], Colors.YELLOW)}{'...' if len(value) > 60 else ''} {dim(label)}")

    # Cookies
    if cookies:
        parts = []
        for k, v, data_type in cookies:
            parts.append(f"{k}={v[:30]}{'...' if len(v) > 30 else ''}")
        print(f"  {color('│', Colors.CYAN)} Cookie: {color('; '.join(parts), Colors.YELLOW)} {dim('<-- clientID')}")

    print(f"  {color('│', Colors.CYAN)}")

    # Body
    if body_content:
        print(f"  {color('│', Colors.CYAN)} {dim('[Body]')}")

        try:
            body_str = body_content.decode('utf-8')
            # Show first 70 chars
            display = body_str[:70]
            if len(body_str) > 70:
                display += "..."

            if body_is_data:
                print(f"  {color('│', Colors.CYAN)} {color(display, Colors.YELLOW)} {dim('<-- encrypted data (transformed)')}")
            elif body_is_clientid:
                print(f"  {color('│', Colors.CYAN)} {color(display, Colors.YELLOW)} {dim('<-- clientID (transformed)')}")
            else:
                print(f"  {color('│', Colors.CYAN)} {display}")
        except:
            hex_preview = body_content[:35].hex()
            print(f"  {color('│', Colors.CYAN)} {color(hex_preview, Colors.YELLOW)}... {dim('<-- binary data')}")

    print(f"  {color('│', Colors.CYAN)}")
    print(f"  {color('└───────────────────────────────────────────────────────────────────┘', Colors.CYAN)}")

    # Show detailed breakdown
    if transformed_client_id and client_id_block:
        print(f"\n  {bold('ClientID Transform:')}")
        print(f"    Original:    {color(repr(client_id), Colors.GREEN)} ({len(client_id)} bytes)")
        print(f"    Transformed: {color(format_data(transformed_client_id, 50), Colors.YELLOW)} ({len(transformed_client_id)} bytes)")
        output = client_id_block.get("output", "body")
        print(f"    Placed in:   {color(output, Colors.BLUE)}")

    if transformed_data and data_block:
        print(f"\n  {bold('POST Data Transform:')}")
        print(f"    Original:    {color(format_data(post_data, 50), Colors.GREEN)} ({len(post_data)} bytes)")
        print(f"    Transformed: {color(format_data(transformed_data, 50), Colors.YELLOW)} ({len(transformed_data)} bytes)")
        output = data_block.get("output", "body")
        print(f"    Placed in:   {color(output, Colors.BLUE)}")

        # Show data structure with padding
        if data_prepend_len or data_append_len:
            print(f"\n  {bold('Body Data Structure:')}")
            print(f"    {color('[ RANDOM PAD ]', Colors.DIM) if data_prepend_len else ''}" +
                  f"{color('[ ENCRYPTED DATA ]', Colors.GREEN)}" +
                  f"{color('[ RANDOM PAD ]', Colors.DIM) if data_append_len else ''}")
            if data_prepend_len:
                print(f"      ^-- {data_prepend_len} bytes (from X-Pad-Pre)")
            if data_append_len:
                print(f"      {'                          ' if data_prepend_len else ''}^-- {data_append_len} bytes (from X-Pad-App)")


def visualize_packet_response(profile: Dict, response_data: bytes):
    """Visualize what a server response packet would look like."""
    print_subheader(f"Response Packet Visualization: {profile.get('name', 'unnamed')}")

    content_type = profile.get('content_type', 'application/json')
    data_block = profile.get("data")

    transformed_data = None
    prepend_len = 0
    append_len = 0

    if data_block:
        result = apply_transforms(response_data, data_block.get("transforms", []))
        transformed_data = result.data
        prepend_len = result.prepend_length
        append_len = result.append_length
    else:
        transformed_data = response_data

    # Print the packet
    print(f"\n  {color('┌─ HTTP RESPONSE ────────────────────────────────────────────────────┐', Colors.CYAN)}")
    print(f"  {color('│', Colors.CYAN)}")

    # Status line
    print(f"  {color('│', Colors.CYAN)} {bold('HTTP/1.1 200 OK')}")

    # Headers
    print(f"  {color('│', Colors.CYAN)} Content-Type: {content_type}")
    print(f"  {color('│', Colors.CYAN)} Content-Length: {len(transformed_data)}")

    if prepend_len:
        print(f"  {color('│', Colors.CYAN)} {color('X-Pad-Pre', Colors.YELLOW)}: {prepend_len} {dim('<-- padding length')}")
    if append_len:
        print(f"  {color('│', Colors.CYAN)} {color('X-Pad-App', Colors.YELLOW)}: {append_len} {dim('<-- padding length')}")

    print(f"  {color('│', Colors.CYAN)}")

    # Body
    print(f"  {color('│', Colors.CYAN)} {dim('[Body]')}")
    try:
        body_str = transformed_data.decode('utf-8')
        display = body_str[:70]
        if len(body_str) > 70:
            display += "..."
        print(f"  {color('│', Colors.CYAN)} {color(display, Colors.YELLOW)}")
    except:
        hex_preview = transformed_data[:35].hex()
        print(f"  {color('│', Colors.CYAN)} {color(hex_preview, Colors.YELLOW)}...")

    print(f"  {color('│', Colors.CYAN)}")
    print(f"  {color('└───────────────────────────────────────────────────────────────────┘', Colors.CYAN)}")

    # Show agent processing
    if data_block:
        print(f"\n  {bold('Agent Processing:')}")
        print(f"    Received:  {color(format_data(transformed_data, 50), Colors.YELLOW)} ({len(transformed_data)} bytes)")

        # Reverse transforms
        reversed_data, _ = reverse_transforms(
            transformed_data,
            data_block.get("transforms", []),
            prepend_len,
            append_len
        )
        print(f"    Extracted: {color(format_data(reversed_data, 50), Colors.GREEN)} ({len(reversed_data)} bytes)")

        if prepend_len or append_len:
            print(f"\n  {bold('Data Structure (agent strips padding using header values):')}")
            print(f"    {color('[ RANDOM PAD ]', Colors.DIM) if prepend_len else ''}" +
                  f"{color('[ COMMAND DATA ]', Colors.GREEN)}" +
                  f"{color('[ RANDOM PAD ]', Colors.DIM) if append_len else ''}")


def visualize_full_flow(profile_data: Dict, client_id: str, post_data: bytes, host: str = "example.com"):
    """Show the complete request/response flow."""
    http_profiles = profile_data.get("http_profiles", {})

    print_header("Full Communication Flow")

    # GET request (polling for commands)
    get_profiles = http_profiles.get("get", [])
    if get_profiles:
        print(f"\n{bold('1. Agent polls for commands (GET):')}")
        visualize_packet_get(get_profiles[0], client_id, host)

    # Server response
    response_profiles = http_profiles.get("server_response", [])
    if response_profiles:
        print(f"\n{bold('2. Server sends command (Response):')}")
        response_data = b'{"cmd":"whoami","id":12345}'
        visualize_packet_response(response_profiles[0], response_data)

    # POST request (sending results)
    post_profiles = http_profiles.get("post", [])
    if post_profiles:
        print(f"\n{bold('3. Agent sends results (POST):')}")
        visualize_packet_post(post_profiles[0], client_id, post_data, host)

    # Legend
    print(f"\n{bold('Legend:')}")
    print(f"  {color('Green', Colors.GREEN)}  = Original/extracted data")
    print(f"  {color('Yellow', Colors.YELLOW)} = Transformed/encrypted data")
    print(f"  {dim('Dim')}    = Random padding (stripped using header values)")
    print(f"  {color('Blue', Colors.BLUE)}   = Output location")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Validate and visualize malleable HTTP profiles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s profile.toml                    # Validate profile
  %(prog)s profile.toml --simulate         # Show transformation examples
  %(prog)s profile.toml --simulate -v      # Verbose step-by-step
  %(prog)s profile.toml --packet           # Show HTTP packet visualization
  %(prog)s profile.toml --flow             # Show full GET -> Response -> POST flow
  %(prog)s profile.toml --client-id ABC123 # Custom test clientID
  %(prog)s profile.toml --host c2.evil.com # Custom host for visualization
        """
    )
    parser.add_argument("profile", help="Path to profile TOML file")
    parser.add_argument("--simulate", "-s", action="store_true",
                        help="Simulate transformations with example data")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show step-by-step transformation details")
    parser.add_argument("--packet", "-p", action="store_true",
                        help="Show HTTP packet visualization")
    parser.add_argument("--flow", "-f", action="store_true",
                        help="Show full communication flow (GET -> Response -> POST)")
    parser.add_argument("--client-id", default="CLIENT-ABC123-XYZ",
                        help="ClientID to use for simulation (default: CLIENT-ABC123-XYZ)")
    parser.add_argument("--post-data", default='{"result":"command output here","status":"ok"}',
                        help="POST body data for simulation")
    parser.add_argument("--host", default="example.com",
                        help="Host to use in packet visualization (default: example.com)")

    args = parser.parse_args()

    # Read profile file
    if not os.path.exists(args.profile):
        print(color(f"Error: File not found: {args.profile}", Colors.RED))
        sys.exit(1)

    try:
        with open(args.profile, "rb") as f:
            profile_data = tomllib.load(f)
    except Exception as e:
        print(color(f"Error parsing TOML: {e}", Colors.RED))
        sys.exit(1)

    print_header(f"Profile: {args.profile}")

    # Validate
    is_valid, errors, warnings = validate_profile(profile_data)

    if errors:
        print(f"\n{color('ERRORS:', Colors.RED + Colors.BOLD)}")
        for err in errors:
            print(f"  {color('X', Colors.RED)} {err}")

    if warnings:
        print(f"\n{color('WARNINGS:', Colors.YELLOW + Colors.BOLD)}")
        for warn in warnings:
            print(f"  {color('!', Colors.YELLOW)} {warn}")

    if is_valid:
        print(f"\n{color('Profile is valid!', Colors.GREEN + Colors.BOLD)}")
    else:
        print(f"\n{color('Profile has errors - please fix before using', Colors.RED + Colors.BOLD)}")
        sys.exit(1)

    # Simulation
    if args.simulate:
        http_profiles = profile_data.get("http_profiles", {})

        # Simulate GET profiles
        for profile in http_profiles.get("get", []):
            simulate_get_request(profile, args.client_id, args.verbose)

        # Simulate POST profiles
        for profile in http_profiles.get("post", []):
            simulate_post_request(profile, args.client_id, args.post_data.encode(), args.verbose)

        # Simulate server responses
        for profile in http_profiles.get("server_response", []):
            response_data = b'{"status":"ok","data":"SGVsbG8gV29ybGQh","id":12345}'
            simulate_response(profile, response_data, args.verbose)

    # Packet visualization
    if args.packet:
        http_profiles = profile_data.get("http_profiles", {})

        # GET packets
        for profile in http_profiles.get("get", []):
            visualize_packet_get(profile, args.client_id, args.host)

        # POST packets
        for profile in http_profiles.get("post", []):
            visualize_packet_post(profile, args.client_id, args.post_data.encode(), args.host)

        # Response packets
        for profile in http_profiles.get("server_response", []):
            response_data = b'{"cmd":"execute","args":["whoami"],"id":12345}'
            visualize_packet_response(profile, response_data)

    # Full flow visualization
    if args.flow:
        visualize_full_flow(profile_data, args.client_id, args.post_data.encode(), args.host)

    # Summary
    http_profiles = profile_data.get("http_profiles", {})
    print(f"\n{bold('Profile Summary:')}")
    print(f"  GET profiles:      {len(http_profiles.get('get', []))}")
    print(f"  POST profiles:     {len(http_profiles.get('post', []))}")
    print(f"  Response profiles: {len(http_profiles.get('server_response', []))}")


if __name__ == "__main__":
    main()
