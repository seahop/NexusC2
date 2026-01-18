#!/usr/bin/env python3
"""
NexusC2 REST API Client

A command-line tool to interact with the NexusC2 REST API.
Credentials can be provided via:
  1. Environment variables (NEXUS_API_TOKEN, NEXUS_API_URL, NEXUS_API_PASSWORD)
  2. Command-line flags
  3. Interactive login

Usage:
    ./nexus-api.py login -u operator1                    # Uses API_PASSWORD from env
    ./nexus-api.py login -u operator1 -p mypassword      # Explicit password
    ./nexus-api.py agents list
    ./nexus-api.py agents get <agent_id>
    ./nexus-api.py command <agent_id> "whoami"

Environment Variables:
    NEXUS_API_URL       - API base URL (default: https://localhost:8443)
    NEXUS_API_TOKEN     - JWT access token (for authenticated requests)
    NEXUS_API_PASSWORD  - Shared API password (for login without -p flag)
    NEXUS_API_CERT      - Path to CA certificate for TLS verification
"""

import argparse
import json
import os
import sys
import urllib3
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# Suppress SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except ImportError:
    print("Error: 'requests' module not found. Install with: pip install requests")
    sys.exit(1)

# Default configuration
DEFAULT_API_URL = "https://localhost:8443"
ENV_FILE = Path.home() / ".nexus_api_env"


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def color(text: str, color_code: str) -> str:
    """Apply color to text if terminal supports it."""
    if sys.stdout.isatty():
        return f"{color_code}{text}{Colors.ENDC}"
    return text


class NexusAPIClient:
    """Client for interacting with the NexusC2 REST API."""

    def __init__(self, base_url: str = None, token: str = None, username: str = None,
                 cert_path: str = None):
        self.base_url = (base_url or os.environ.get("NEXUS_API_URL", DEFAULT_API_URL)).rstrip("/")
        self.token = token or os.environ.get("NEXUS_API_TOKEN")
        self.username = username or os.environ.get("NEXUS_API_USERNAME")
        self.refresh_token = os.environ.get("NEXUS_API_REFRESH_TOKEN")
        self.cert_path = cert_path or os.environ.get("NEXUS_API_CERT")
        self.session = requests.Session()

        # Use certificate for verification if provided, otherwise skip verification
        if self.cert_path and os.path.exists(self.cert_path):
            self.session.verify = self.cert_path
        else:
            self.session.verify = False  # Allow self-signed certs without explicit cert

    def _headers(self) -> Dict[str, str]:
        """Get request headers with auth token."""
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(self, method: str, endpoint: str, data: Dict = None,
                 stream: bool = False) -> requests.Response:
        """Make an API request."""
        url = f"{self.base_url}/api/v1{endpoint}"
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=self._headers(),
                json=data if data else None,
                stream=stream,
                timeout=120  # Long timeout for payload builds
            )
            return response
        except requests.exceptions.ConnectionError:
            print(color(f"Error: Cannot connect to {self.base_url}", Colors.RED))
            print("Make sure the REST API server is running.")
            sys.exit(1)

    def _handle_response(self, response: requests.Response,
                         raw: bool = False) -> Optional[Dict]:
        """Handle API response and errors."""
        if response.status_code == 401:
            print(color("Error: Unauthorized. Please login first.", Colors.RED))
            print(f"Run: {sys.argv[0]} login -u <username> -p <password>")
            sys.exit(1)

        if response.status_code == 429:
            print(color("Error: Rate limit exceeded. Please wait and try again.", Colors.YELLOW))
            sys.exit(1)

        if raw:
            return response

        try:
            data = response.json()
        except json.JSONDecodeError:
            if response.status_code >= 400:
                print(color(f"Error: HTTP {response.status_code}", Colors.RED))
                print(response.text)
                sys.exit(1)
            return None

        if response.status_code >= 400:
            error_msg = data.get("error", "Unknown error")
            print(color(f"Error: {error_msg}", Colors.RED))
            sys.exit(1)

        return data

    # -------------------------------------------------------------------------
    # Authentication
    # -------------------------------------------------------------------------

    def login(self, username: str, password: Optional[str] = None) -> Dict:
        """Login and get JWT tokens.

        Password resolution order:
        1. Explicit password argument
        2. NEXUS_API_PASSWORD environment variable
        3. Certificate-based login (if no password available)
        """
        # Try to get password from environment if not provided
        if password is None:
            password = os.environ.get("NEXUS_API_PASSWORD")

        if password:
            # Password-based login (shared API password or user-specific)
            response = self._request("POST", "/auth/login", {
                "username": username,
                "password": password
            })
        else:
            # Certificate-based login (no password needed if you have the cert)
            response = self._request("POST", "/auth/cert-login", {
                "username": username
            })
        data = self._handle_response(response)

        if data:
            self.token = data.get("access_token")
            self.refresh_token = data.get("refresh_token")
            self.username = data.get("username")

            # Save to environment file
            self._save_credentials()

            print(color("Login successful!", Colors.GREEN))
            print(f"Username: {color(self.username, Colors.CYAN)}")
            print(f"Token expires in: {data.get('expires_in', 3600)} seconds")
            print(f"\nCredentials saved to: {ENV_FILE}")
            print("\nTo use in shell:")
            print(color(f"  source {ENV_FILE}", Colors.YELLOW))

        return data

    def refresh(self) -> Dict:
        """Refresh access token."""
        if not self.refresh_token:
            print(color("Error: No refresh token available. Please login.", Colors.RED))
            sys.exit(1)

        response = self._request("POST", "/auth/refresh", {
            "refresh_token": self.refresh_token
        })
        data = self._handle_response(response)

        if data:
            self.token = data.get("access_token")
            self.refresh_token = data.get("refresh_token")
            self.username = data.get("username")
            self._save_credentials()
            print(color("Token refreshed successfully!", Colors.GREEN))

        return data

    def logout(self) -> None:
        """Logout and invalidate refresh token."""
        if self.refresh_token:
            self._request("POST", "/auth/logout", {
                "refresh_token": self.refresh_token
            })

        self.token = None
        self.refresh_token = None
        self.username = None

        # Remove credentials file
        if ENV_FILE.exists():
            ENV_FILE.unlink()

        print(color("Logged out successfully!", Colors.GREEN))

    def me(self) -> Dict:
        """Get current user info."""
        response = self._request("GET", "/auth/me")
        return self._handle_response(response)

    def _save_credentials(self) -> None:
        """Save credentials to environment file."""
        content = f"""# NexusC2 API Credentials
# Source this file: source {ENV_FILE}
export NEXUS_API_URL="{self.base_url}"
export NEXUS_API_TOKEN="{self.token}"
export NEXUS_API_USERNAME="{self.username}"
export NEXUS_API_REFRESH_TOKEN="{self.refresh_token or ''}"
"""
        ENV_FILE.write_text(content)
        ENV_FILE.chmod(0o600)  # Secure permissions

    # -------------------------------------------------------------------------
    # Agents
    # -------------------------------------------------------------------------

    def list_agents(self, page: int = 1, limit: int = 50,
                    status: str = None, os_filter: str = None,
                    search: str = None) -> Dict:
        """List all agents."""
        params = f"?page={page}&limit={limit}"
        if status:
            params += f"&status={status}"
        if os_filter:
            params += f"&os={os_filter}"
        if search:
            params += f"&search={search}"

        response = self._request("GET", f"/agents{params}")
        return self._handle_response(response)

    def get_agent(self, agent_id: str) -> Dict:
        """Get agent details."""
        response = self._request("GET", f"/agents/{agent_id}")
        return self._handle_response(response)

    def delete_agent(self, agent_id: str) -> Dict:
        """Remove an agent."""
        response = self._request("DELETE", f"/agents/{agent_id}")
        return self._handle_response(response)

    def update_agent(self, agent_id: str, alias: str = None,
                     note: str = None) -> Dict:
        """Update agent properties."""
        data = {}
        if alias is not None:
            data["alias"] = alias
        if note is not None:
            data["note"] = note

        response = self._request("PATCH", f"/agents/{agent_id}", data)
        return self._handle_response(response)

    def add_tag(self, agent_id: str, name: str, color: str = None) -> Dict:
        """Add a tag to an agent."""
        # Note: field name depends on whether WS proxy is enabled
        # WS proxy uses "tag", direct handler uses "tag_name"
        # Try "tag" first (proxy), which is more commonly used
        data = {"tag": name}
        if color:
            data["color"] = color

        response = self._request("POST", f"/agents/{agent_id}/tags", data)
        return self._handle_response(response)

    def remove_tag(self, agent_id: str, tag_name: str) -> Dict:
        """Remove a tag from an agent."""
        response = self._request("DELETE", f"/agents/{agent_id}/tags/{tag_name}")
        return self._handle_response(response)

    # -------------------------------------------------------------------------
    # Commands
    # -------------------------------------------------------------------------

    def send_command(self, agent_id: str, command: str,
                     data: str = None) -> Dict:
        """Send a command to an agent."""
        payload = {"command": command}
        if data:
            payload["data"] = data

        response = self._request("POST", f"/agents/{agent_id}/commands", payload)
        return self._handle_response(response)

    def get_command_history(self, agent_id: str, page: int = 1,
                            limit: int = 50) -> Dict:
        """Get command history for an agent."""
        response = self._request("GET",
            f"/agents/{agent_id}/commands?page={page}&limit={limit}")
        return self._handle_response(response)

    def get_command(self, command_id: int) -> Dict:
        """Get a specific command with output."""
        response = self._request("GET", f"/commands/{command_id}")
        return self._handle_response(response)

    def get_latest_command(self, agent_id: str) -> Dict:
        """Get the most recent command for an agent with its output."""
        response = self._request("GET", f"/agents/{agent_id}/commands/latest")
        return self._handle_response(response)

    def clear_queue(self, agent_id: str) -> Dict:
        """Clear pending commands for an agent."""
        response = self._request("DELETE", f"/agents/{agent_id}/commands/queue")
        return self._handle_response(response)

    # -------------------------------------------------------------------------
    # Listeners
    # -------------------------------------------------------------------------

    def list_listeners(self) -> Dict:
        """List all listeners."""
        response = self._request("GET", "/listeners")
        return self._handle_response(response)

    def get_listener(self, name: str) -> Dict:
        """Get a listener by name."""
        response = self._request("GET", f"/listeners/{name}")
        return self._handle_response(response)

    def create_listener(self, name: str, protocol: str, port: int = None,
                        ip: str = None, pipe_name: str = None,
                        get_profile: str = None, post_profile: str = None,
                        server_response_profile: str = None) -> Dict:
        """Create a new listener with optional malleable profile bindings."""
        data = {
            "name": name,
            "protocol": protocol
        }
        if port is not None:
            data["port"] = port
        if ip:
            data["ip"] = ip
        if pipe_name:
            data["pipe_name"] = pipe_name
        if get_profile:
            data["get_profile"] = get_profile
        if post_profile:
            data["post_profile"] = post_profile
        if server_response_profile:
            data["server_response"] = server_response_profile  # API expects "server_response"

        response = self._request("POST", "/listeners", data)
        return self._handle_response(response)

    def delete_listener(self, name: str) -> Dict:
        """Delete a listener."""
        response = self._request("DELETE", f"/listeners/{name}")
        return self._handle_response(response)

    # -------------------------------------------------------------------------
    # Profiles
    # -------------------------------------------------------------------------

    def list_profiles(self) -> Dict:
        """List all available malleable profiles."""
        response = self._request("GET", "/profiles")
        return self._handle_response(response)

    def list_get_profiles(self) -> Dict:
        """List GET profiles."""
        response = self._request("GET", "/profiles/get")
        return self._handle_response(response)

    def get_get_profile(self, name: str) -> Dict:
        """Get a specific GET profile by name."""
        response = self._request("GET", f"/profiles/get/{name}")
        return self._handle_response(response)

    def list_post_profiles(self) -> Dict:
        """List POST profiles."""
        response = self._request("GET", "/profiles/post")
        return self._handle_response(response)

    def get_post_profile(self, name: str) -> Dict:
        """Get a specific POST profile by name."""
        response = self._request("GET", f"/profiles/post/{name}")
        return self._handle_response(response)

    def list_server_response_profiles(self) -> Dict:
        """List server response profiles."""
        response = self._request("GET", "/profiles/server-response")
        return self._handle_response(response)

    def get_server_response_profile(self, name: str) -> Dict:
        """Get a specific server response profile by name."""
        response = self._request("GET", f"/profiles/server-response/{name}")
        return self._handle_response(response)

    # -------------------------------------------------------------------------
    # Payloads
    # -------------------------------------------------------------------------

    def build_payload(self, listener: str, os_type: str, arch: str,
                      output_file: str = None, language: str = None,
                      payload_type: str = None, pipe_name: str = None,
                      safety_checks: Dict = None) -> None:
        """Build a payload and save to file."""
        data = {
            "listener": listener,
            "os": os_type,
            "arch": arch
        }

        if language:
            data["language"] = language
        if payload_type:
            data["payload_type"] = payload_type
        if pipe_name:
            data["pipe_name"] = pipe_name
        if safety_checks:
            data["safety_checks"] = safety_checks

        print(f"Building payload for {os_type}/{arch}...")
        print(f"Listener: {listener}")

        response = self._request("POST", "/payloads/build", data, stream=True)

        if response.status_code != 200:
            self._handle_response(response)
            return

        # Determine output filename
        if not output_file:
            content_disp = response.headers.get("Content-Disposition", "")
            if "filename=" in content_disp:
                output_file = content_disp.split("filename=")[1].strip('"')
            else:
                ext = ".exe" if os_type == "windows" else ""
                output_file = f"payload_{os_type}_{arch}{ext}"

        # Save binary
        with open(output_file, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        build_time = response.headers.get("X-Build-Duration", "unknown")
        file_size = os.path.getsize(output_file)

        print(color(f"\nPayload built successfully!", Colors.GREEN))
        print(f"Output: {color(output_file, Colors.CYAN)}")
        print(f"Size: {file_size:,} bytes")
        print(f"Build time: {build_time}")

    # -------------------------------------------------------------------------
    # Events
    # -------------------------------------------------------------------------

    def stream_events(self) -> None:
        """Stream SSE events."""
        print(f"Connecting to event stream at {self.base_url}...")
        print("Press Ctrl+C to stop\n")

        url = f"{self.base_url}/api/v1/events"
        try:
            response = self.session.get(
                url,
                headers=self._headers(),
                stream=True,
                timeout=None  # No timeout for SSE
            )

            if response.status_code == 401:
                print(color("Error: Unauthorized. Please login first.", Colors.RED))
                return

            for line in response.iter_lines():
                if line:
                    line = line.decode("utf-8")
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                        print(color(f"[{event_type}]", Colors.YELLOW), end=" ")
                    elif line.startswith("data:"):
                        data = line[5:].strip()
                        try:
                            parsed = json.loads(data)
                            print(json.dumps(parsed, indent=2))
                        except json.JSONDecodeError:
                            print(data)
                    print()

        except KeyboardInterrupt:
            print("\nDisconnected from event stream.")

    # -------------------------------------------------------------------------
    # Health
    # -------------------------------------------------------------------------

    def health(self) -> Dict:
        """Check API health."""
        try:
            response = self.session.get(
                f"{self.base_url}/health",
                verify=False,
                timeout=5
            )
            return response.json()
        except Exception as e:
            return {"status": "error", "message": str(e)}


# =============================================================================
# CLI Functions
# =============================================================================

def print_json(data: Any) -> None:
    """Pretty print JSON data."""
    print(json.dumps(data, indent=2, default=str))


def print_agents_table(agents: list) -> None:
    """Print agents in a table format."""
    if not agents:
        print("No agents found.")
        return

    # Header
    print(f"\n{'ID':<38} {'Hostname':<20} {'Username':<20} {'OS':<10} {'Last Seen':<20}")
    print("-" * 110)

    for agent in agents:
        agent_id = agent.get("id", "")[:36]
        hostname = agent.get("hostname", "")[:18]
        username = agent.get("username", "")[:18]
        os_name = agent.get("os", "")[:8]
        last_seen = agent.get("last_seen", "")[:19]

        print(f"{agent_id:<38} {hostname:<20} {username:<20} {os_name:<10} {last_seen:<20}")

    print()


def print_listeners_table(listeners: list) -> None:
    """Print listeners in a table format."""
    if not listeners:
        print("No listeners found.")
        return

    print(f"\n{'Name':<20} {'Protocol':<8} {'Port':<6} {'IP':<15} {'GET Profile':<20} {'POST Profile':<20} {'Response':<20}")
    print("-" * 115)

    for listener in listeners:
        name = listener.get("name", "")[:18]
        protocol = listener.get("protocol", "")[:6]
        port = str(listener.get("port", ""))[:4]
        ip = listener.get("ip", "")[:13]
        get_profile = listener.get("get_profile", "default-get")[:18]
        post_profile = listener.get("post_profile", "default-post")[:18]
        response_profile = listener.get("server_response_profile", "default-response")[:18]

        print(f"{name:<20} {protocol:<8} {port:<6} {ip:<15} {get_profile:<20} {post_profile:<20} {response_profile:<20}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="NexusC2 REST API Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Login with shared API password (from environment):
    export NEXUS_API_PASSWORD="your-api-password"
    %(prog)s login -u operator1

  Login with explicit password:
    %(prog)s login -u admin -p password

  List agents:
    %(prog)s agents list
    %(prog)s agents list --status active --os windows

  Send a command:
    %(prog)s command <agent_id> "whoami"
    %(prog)s command <agent_id> "dir C:\\" --wait

  Build a payload:
    %(prog)s payload build -l https-listener -o windows -a amd64

  Stream events:
    %(prog)s events

Environment Variables:
  NEXUS_API_URL       API base URL (default: https://localhost:8443)
  NEXUS_API_TOKEN     JWT access token (saved after login)
  NEXUS_API_PASSWORD  Shared API password (used for login if -p not specified)
  NEXUS_API_CERT      Path to server certificate for TLS verification
        """
    )

    parser.add_argument("--url", "-U", help="API base URL")
    parser.add_argument("--token", "-T", help="JWT access token")
    parser.add_argument("--cert", "-c", help="Path to server certificate (e.g., api_server.crt)")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output raw JSON")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Login
    login_parser = subparsers.add_parser("login", help="Login to API")
    login_parser.add_argument("-u", "--username", required=True, help="Username")
    login_parser.add_argument("-p", "--password", help="Password (uses NEXUS_API_PASSWORD env var if not specified)")

    # Logout
    subparsers.add_parser("logout", help="Logout from API")

    # Refresh
    subparsers.add_parser("refresh", help="Refresh access token")

    # Me
    subparsers.add_parser("me", help="Show current user info")

    # Health
    subparsers.add_parser("health", help="Check API health")

    # Agents
    agents_parser = subparsers.add_parser("agents", help="Agent operations")
    agents_sub = agents_parser.add_subparsers(dest="action")

    # agents list
    agents_list = agents_sub.add_parser("list", help="List agents")
    agents_list.add_argument("--page", type=int, default=1)
    agents_list.add_argument("--limit", type=int, default=50)
    agents_list.add_argument("--status", choices=["active", "inactive", "all"])
    agents_list.add_argument("--os", dest="os_filter")
    agents_list.add_argument("--search", "-s")

    # agents get
    agents_get = agents_sub.add_parser("get", help="Get agent details")
    agents_get.add_argument("agent_id", help="Agent UUID")

    # agents delete
    agents_del = agents_sub.add_parser("delete", help="Remove agent")
    agents_del.add_argument("agent_id", help="Agent UUID")

    # agents update
    agents_upd = agents_sub.add_parser("update", help="Update agent")
    agents_upd.add_argument("agent_id", help="Agent UUID")
    agents_upd.add_argument("--alias", help="Set alias")
    agents_upd.add_argument("--note", help="Set note")

    # agents tag
    agents_tag = agents_sub.add_parser("tag", help="Manage tags")
    agents_tag.add_argument("agent_id", help="Agent UUID")
    agents_tag.add_argument("--add", help="Add tag")
    agents_tag.add_argument("--remove", help="Remove tag")
    agents_tag.add_argument("--color", help="Tag color (hex)")

    # Command
    cmd_parser = subparsers.add_parser("command", aliases=["cmd"],
                                        help="Send command to agent")
    cmd_parser.add_argument("agent_id", help="Agent UUID")
    cmd_parser.add_argument("cmd", help="Command to execute")
    cmd_parser.add_argument("--data", "-d", help="Additional data")

    # Command history
    history_parser = subparsers.add_parser("history", help="Command history")
    history_parser.add_argument("agent_id", help="Agent UUID")
    history_parser.add_argument("--page", type=int, default=1)
    history_parser.add_argument("--limit", type=int, default=20)

    # Get command output
    output_parser = subparsers.add_parser("output", help="Get command output")
    output_parser.add_argument("command_id", type=int, help="Command ID")

    # Get latest command
    latest_parser = subparsers.add_parser("latest", help="Get latest command for agent")
    latest_parser.add_argument("agent_id", help="Agent UUID")

    # Clear queue
    clear_parser = subparsers.add_parser("clear", help="Clear command queue")
    clear_parser.add_argument("agent_id", help="Agent UUID")

    # Listeners
    listeners_parser = subparsers.add_parser("listeners", help="Listener operations")
    listeners_sub = listeners_parser.add_subparsers(dest="action")

    listeners_sub.add_parser("list", help="List listeners")

    listeners_get = listeners_sub.add_parser("get", help="Get listener")
    listeners_get.add_argument("name", help="Listener name")

    listeners_create = listeners_sub.add_parser("create", help="Create listener")
    listeners_create.add_argument("-n", "--name", required=True, help="Listener name")
    listeners_create.add_argument("-P", "--protocol", required=True,
                                   choices=["HTTP", "HTTPS", "SMB", "RPC"])
    listeners_create.add_argument("-p", "--port", type=int, help="Port number")
    listeners_create.add_argument("-i", "--ip", help="Bind IP")
    listeners_create.add_argument("--pipe", help="Pipe name (for SMB)")
    listeners_create.add_argument("--get-profile", help="GET malleable profile name")
    listeners_create.add_argument("--post-profile", help="POST malleable profile name")
    listeners_create.add_argument("--response-profile", help="Server response profile name")

    listeners_del = listeners_sub.add_parser("delete", help="Delete listener")
    listeners_del.add_argument("name", help="Listener name")

    # Profiles
    profiles_parser = subparsers.add_parser("profiles", help="Malleable profile operations")
    profiles_sub = profiles_parser.add_subparsers(dest="action")

    profiles_sub.add_parser("list", help="List all profiles")
    profiles_sub.add_parser("list-get", help="List GET profiles")
    profiles_sub.add_parser("list-post", help="List POST profiles")
    profiles_sub.add_parser("list-response", help="List server response profiles")

    profiles_get = profiles_sub.add_parser("get", help="Get profile details")
    profiles_get.add_argument("type", choices=["get", "post", "response"], help="Profile type")
    profiles_get.add_argument("name", help="Profile name")

    # Payload
    payload_parser = subparsers.add_parser("payload", help="Payload operations")
    payload_sub = payload_parser.add_subparsers(dest="action")

    payload_build = payload_sub.add_parser("build", help="Build payload")
    payload_build.add_argument("-l", "--listener", required=True,
                                help="Listener name")
    payload_build.add_argument("-o", "--os", required=True, dest="os_type",
                                choices=["windows", "linux", "darwin"])
    payload_build.add_argument("-a", "--arch", required=True,
                                choices=["amd64", "arm64"])
    payload_build.add_argument("-O", "--output", help="Output filename")
    payload_build.add_argument("--language", choices=["go", "goproject"])
    payload_build.add_argument("--type", dest="payload_type",
                                choices=["http", "smb"])
    payload_build.add_argument("--pipe", help="Pipe name (for SMB payloads)")
    payload_build.add_argument("--hostname", help="Safety check: hostname")
    payload_build.add_argument("--username", help="Safety check: username")
    payload_build.add_argument("--domain", help="Safety check: domain")
    payload_build.add_argument("--kill-date", help="Safety check: kill date (YYYY-MM-DD)")
    payload_build.add_argument("--process", help="Safety check: process must be running")
    payload_build.add_argument("--file-path", help="Safety check: file path to check")
    payload_build.add_argument("--file-must-exist", action="store_true",
                                help="Safety check: file must exist (default: must not exist)")
    payload_build.add_argument("--work-start", help="Safety check: working hours start (HH:MM)")
    payload_build.add_argument("--work-end", help="Safety check: working hours end (HH:MM)")

    # Events
    subparsers.add_parser("events", help="Stream SSE events")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Create client
    client = NexusAPIClient(
        base_url=args.url,
        token=args.token,
        cert_path=args.cert
    )

    # Load saved credentials if available
    if ENV_FILE.exists() and not args.token:
        # Read env file and parse
        content = ENV_FILE.read_text()
        for line in content.split("\n"):
            if line.startswith("export "):
                line = line[7:]
                if "=" in line:
                    key, value = line.split("=", 1)
                    value = value.strip('"')
                    if key == "NEXUS_API_TOKEN" and not client.token:
                        client.token = value
                    elif key == "NEXUS_API_USERNAME" and not client.username:
                        client.username = value
                    elif key == "NEXUS_API_REFRESH_TOKEN":
                        client.refresh_token = value
                    elif key == "NEXUS_API_URL" and not args.url:
                        client.base_url = value

    output_json = args.json

    # Handle commands
    if args.command == "login":
        client.login(args.username, args.password)

    elif args.command == "logout":
        client.logout()

    elif args.command == "refresh":
        client.refresh()

    elif args.command == "me":
        data = client.me()
        if output_json:
            print_json(data)
        else:
            print(f"User ID:  {data.get('user_id')}")
            print(f"Username: {data.get('username')}")

    elif args.command == "health":
        data = client.health()
        if output_json:
            print_json(data)
        else:
            status = data.get("status", "unknown")
            status_color = Colors.GREEN if status == "healthy" else Colors.RED
            print(f"Status: {color(status, status_color)}")
            if "goroutines" in data:
                print(f"Goroutines: {data['goroutines']}")
                print(f"Memory: {data.get('memory_mb', 0)} MB")
                print(f"SSE Clients: {data.get('sse_clients', 0)}")
                print(f"gRPC Connected: {data.get('grpc_connected', False)}")

    elif args.command == "agents":
        if args.action == "list":
            data = client.list_agents(
                page=args.page,
                limit=args.limit,
                status=args.status,
                os_filter=args.os_filter,
                search=args.search
            )
            if output_json:
                print_json(data)
            else:
                agents = data.get("agents", [])
                pagination = data.get("pagination", {})
                print_agents_table(agents)
                print(f"Page {pagination.get('page', 1)} of {(pagination.get('total', 0) // pagination.get('limit', 50)) + 1} "
                      f"(Total: {pagination.get('total', 0)} agents)")

        elif args.action == "get":
            data = client.get_agent(args.agent_id)
            print_json(data)

        elif args.action == "delete":
            data = client.delete_agent(args.agent_id)
            print(color(data.get("message", "Agent removed"), Colors.GREEN))

        elif args.action == "update":
            data = client.update_agent(args.agent_id, alias=args.alias, note=args.note)
            print(color(data.get("message", "Agent updated"), Colors.GREEN))

        elif args.action == "tag":
            if args.add:
                data = client.add_tag(args.agent_id, args.add, args.color)
                print(color("Tag added", Colors.GREEN))
                print_json(data.get("tags", []))
            elif args.remove:
                data = client.remove_tag(args.agent_id, args.remove)
                print(color("Tag removed", Colors.GREEN))
            else:
                print("Specify --add or --remove")

    elif args.command in ["command", "cmd"]:
        data = client.send_command(args.agent_id, args.cmd, args.data)
        if output_json:
            print_json(data)
        else:
            status = data.get("status", "unknown")
            status_color = Colors.GREEN if status == "sent" else Colors.YELLOW
            print(f"Status: {color(status, status_color)}")
            print(f"Command ID: {data.get('command_id')}")
            print(f"DB ID: {data.get('db_id')}")
            if data.get("message"):
                print(f"Message: {data['message']}")

    elif args.command == "history":
        data = client.get_command_history(args.agent_id, args.page, args.limit)
        if output_json:
            print_json(data)
        else:
            commands = data.get("commands", [])
            for cmd in commands:
                print(f"\n[{cmd.get('id')}] {color(cmd.get('command'), Colors.CYAN)}")
                print(f"    User: {cmd.get('username')} | Time: {cmd.get('timestamp')}")
                if cmd.get("output"):
                    print(f"    Output: {cmd['output'][:100]}...")

    elif args.command == "output":
        data = client.get_command(args.command_id)
        if output_json:
            print_json(data)
        else:
            cmd = data.get("command", {})
            outputs = data.get("outputs", [])
            print(f"Command: {color(cmd.get('command'), Colors.CYAN)}")
            print(f"Agent: {cmd.get('guid')}")
            print(f"Time: {cmd.get('timestamp')}")
            print(f"\n{'-' * 40}")
            for out in outputs:
                print(out.get("output", ""))

    elif args.command == "latest":
        data = client.get_latest_command(args.agent_id)
        if output_json:
            print_json(data)
        else:
            cmd = data.get("command", {})
            outputs = data.get("outputs", [])
            status = data.get("status", "unknown")
            has_output = data.get("has_output", False)

            status_color = Colors.GREEN if status == "completed" else Colors.YELLOW
            print(f"Status: {color(status, status_color)}")
            print(f"Command ID: {cmd.get('id')}")
            print(f"Command: {color(cmd.get('command'), Colors.CYAN)}")
            print(f"User: {cmd.get('username')}")
            print(f"Time: {cmd.get('timestamp')}")

            if has_output:
                print(f"\n{'-' * 40}")
                for out in outputs:
                    print(out.get("output", ""))
            else:
                print(f"\n{color('No output yet (command pending)', Colors.YELLOW)}")

    elif args.command == "clear":
        data = client.clear_queue(args.agent_id)
        print(color(data.get("message", "Queue cleared"), Colors.GREEN))

    elif args.command == "listeners":
        if args.action == "list":
            data = client.list_listeners()
            if output_json:
                print_json(data)
            else:
                print_listeners_table(data.get("listeners", []))

        elif args.action == "get":
            data = client.get_listener(args.name)
            print_json(data)

        elif args.action == "create":
            data = client.create_listener(
                name=args.name,
                protocol=args.protocol,
                port=args.port,
                ip=args.ip,
                pipe_name=args.pipe,
                get_profile=args.get_profile,
                post_profile=args.post_profile,
                server_response_profile=args.response_profile
            )
            print(color(data.get("message", "Listener created"), Colors.GREEN))
            print_json(data.get("listener", {}))

        elif args.action == "delete":
            data = client.delete_listener(args.name)
            print(color(data.get("message", "Listener deleted"), Colors.GREEN))

    elif args.command == "profiles":
        if args.action == "list":
            data = client.list_profiles()
            if output_json:
                print_json(data)
            else:
                print(color("\nGET Profiles:", Colors.CYAN))
                for p in data.get("get_profiles", []):
                    print(f"  - {p.get('name', p) if isinstance(p, dict) else p}")
                print(color("\nPOST Profiles:", Colors.CYAN))
                for p in data.get("post_profiles", []):
                    print(f"  - {p.get('name', p) if isinstance(p, dict) else p}")
                print(color("\nServer Response Profiles:", Colors.CYAN))
                for p in data.get("server_response_profiles", []):
                    print(f"  - {p.get('name', p) if isinstance(p, dict) else p}")
                print()

        elif args.action == "list-get":
            data = client.list_get_profiles()
            if output_json:
                print_json(data)
            else:
                print(color("\nGET Profiles:", Colors.CYAN))
                for p in data.get("profiles", []):
                    name = p.get("name", "") if isinstance(p, dict) else p
                    path = p.get("path", "") if isinstance(p, dict) else ""
                    print(f"  {name:<25} {path}")
                print()

        elif args.action == "list-post":
            data = client.list_post_profiles()
            if output_json:
                print_json(data)
            else:
                print(color("\nPOST Profiles:", Colors.CYAN))
                for p in data.get("profiles", []):
                    name = p.get("name", "") if isinstance(p, dict) else p
                    path = p.get("path", "") if isinstance(p, dict) else ""
                    print(f"  {name:<25} {path}")
                print()

        elif args.action == "list-response":
            data = client.list_server_response_profiles()
            if output_json:
                print_json(data)
            else:
                print(color("\nServer Response Profiles:", Colors.CYAN))
                for p in data.get("profiles", []):
                    name = p.get("name", "") if isinstance(p, dict) else p
                    content_type = p.get("content_type", "") if isinstance(p, dict) else ""
                    print(f"  {name:<25} {content_type}")
                print()

        elif args.action == "get":
            if args.type == "get":
                data = client.get_get_profile(args.name)
            elif args.type == "post":
                data = client.get_post_profile(args.name)
            elif args.type == "response":
                data = client.get_server_response_profile(args.name)
            print_json(data)

    elif args.command == "payload":
        if args.action == "build":
            safety_checks = {}
            if args.hostname:
                safety_checks["hostname"] = args.hostname
            if args.username:
                safety_checks["username"] = args.username
            if args.domain:
                safety_checks["domain"] = args.domain
            if args.kill_date:
                safety_checks["kill_date"] = args.kill_date
            if args.process:
                safety_checks["process"] = args.process
            if args.file_path:
                safety_checks["file_check"] = {
                    "path": args.file_path,
                    "must_exist": args.file_must_exist
                }
            if args.work_start and args.work_end:
                safety_checks["working_hours"] = {
                    "start": args.work_start,
                    "end": args.work_end
                }

            client.build_payload(
                listener=args.listener,
                os_type=args.os_type,
                arch=args.arch,
                output_file=args.output,
                language=args.language,
                payload_type=args.payload_type,
                pipe_name=args.pipe,
                safety_checks=safety_checks if safety_checks else None
            )

    elif args.command == "events":
        client.stream_events()


if __name__ == "__main__":
    main()
