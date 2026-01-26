# client/src/gui/widgets/command_validator.py
import tomli
from pathlib import Path
from typing import Tuple, Optional, List, Union, Dict
import os
import base64
import json
import uuid
from datetime import datetime

class CommandValidator:
    def __init__(self, config_path: str = "commands.toml"):
        self.commands = {}
        self.command_os_compatibility = {}
        # These lists will be populated from TOML
        self.bof_commands = []
        self.inline_assembly_commands = []
        self.load_commands(config_path)
    
    def load_commands(self, config_path: str):
        try:
            with open(config_path, "rb") as f:
                config = tomli.load(f)
                self.commands = config.get("commands", {})
                print(f"Loaded {len(self.commands)} commands from config")
                
                # Clear and rebuild command lists
                self.bof_commands = []
                self.inline_assembly_commands = []
                
                # Process OS compatibility for each command
                for cmd_key, cmd_data in self.commands.items():
                    os_compat = cmd_data.get('os_compatibility', 'all')
                    command_name = cmd_data.get('name', cmd_key)
                    
                    # Normalize OS compatibility to always be a list
                    if os_compat == 'all':
                        self.command_os_compatibility[command_name] = ['all']
                    elif isinstance(os_compat, str):
                        self.command_os_compatibility[command_name] = [os_compat]
                    elif isinstance(os_compat, list):
                        self.command_os_compatibility[command_name] = os_compat
                    else:
                        self.command_os_compatibility[command_name] = ['all']
                    
                    # Build BOF and inline-assembly command lists from TOML
                    if 'bof' in command_name and '-' in command_name:
                        self.bof_commands.append(command_name)
                    elif command_name == 'bof':
                        self.bof_commands.append(command_name)
                    elif 'inline' in command_name or 'assembly' in command_name or command_name in ['execute-assembly', 'inline-execute']:
                        self.inline_assembly_commands.append(command_name)
                
                # Debug: print all loaded command names and their OS compatibility
                print(f"Available commands: {list(self.commands.keys())}")
                print(f"BOF commands from TOML: {self.bof_commands}")
                print(f"Inline-assembly commands from TOML: {self.inline_assembly_commands}")
                for cmd, compat in self.command_os_compatibility.items():
                    print(f"  {cmd}: {compat}")
                    
        except Exception as e:
            print(f"Error loading commands config: {e}")
            self.commands = {}
            # Fallback to default lists if TOML load fails
            self.bof_commands = [
                'bof', 'bof-async', 'bof-jobs', 'bof-output', 
                'bof-kill', 'bof-load', 'bof-exec', 'bof-list', 
                'bof-unload'
            ]
            self.inline_assembly_commands = [
                'inline-assembly', 'inline-assembly-async', 
                'inline-assembly-jobs', 'inline-assembly-output',
                'inline-assembly-kill', 'inline-assembly-jobs-clean',
                'inline-assembly-jobs-stats', 'execute-assembly', 
                'inline-execute'
            ]
    
    def is_command_compatible(self, command_name: str, agent_os: str) -> bool:
        """Check if a command is compatible with the agent's OS"""
        # Get compatibility list for the command
        compatibility = self.command_os_compatibility.get(command_name, ['all'])
        
        # If it's compatible with 'all', it works everywhere
        if 'all' in compatibility:
            return True
        
        # Normalize the agent OS name
        agent_os_normalized = agent_os.lower() if agent_os else 'unknown'
        
        # Map common OS variations to standard names
        # Expanded mappings to handle more variations
        os_mappings = {
            'win': 'windows',
            'win32': 'windows',
            'win64': 'windows',
            'windows': 'windows',
            'windows_amd64': 'windows',
            'windows_386': 'windows',
            'linux': 'linux',
            'ubuntu': 'linux',
            'debian': 'linux',
            'centos': 'linux',
            'rhel': 'linux',
            'fedora': 'linux',
            'linux_amd64': 'linux',
            'linux_386': 'linux',
            'linux_arm64': 'linux',
            'darwin': 'darwin',
            'macos': 'darwin',
            'osx': 'darwin',
            'mac': 'darwin',
            'darwin_amd64': 'darwin',
            'darwin_arm64': 'darwin'
        }
        
        agent_os_standard = os_mappings.get(agent_os_normalized, agent_os_normalized)
        
        # Debug logging
        print(f"OS Compatibility check: command={command_name}, agent_os={agent_os}, "
              f"normalized={agent_os_normalized}, standard={agent_os_standard}, "
              f"compatible_with={compatibility}")
        
        # Check compatibility - normalize compatibility list items too
        compatible_os_list = [os.lower() for os in compatibility]
        return agent_os_standard in compatible_os_list
    
    def validate_command_for_os(self, command_str: str, agent_os: str) -> Tuple[bool, Optional[str]]:
        """Validate if a command is allowed for the given agent OS"""
        # Parse the base command
        parts = command_str.strip().split()
        if not parts:
            return False, "Empty command"
        
        base_cmd = parts[0].lower()
        
        # Check compatibility
        if not self.is_command_compatible(base_cmd, agent_os):
            compatible_os = self.command_os_compatibility.get(base_cmd, ['all'])
            
            # Format the compatible OS list for display
            if compatible_os == ['all']:
                os_display = "all platforms"
            elif len(compatible_os) == 1:
                if compatible_os[0] == 'windows':
                    os_display = "Windows"
                elif compatible_os[0] == 'linux':
                    os_display = "Linux"
                elif compatible_os[0] == 'darwin':
                    os_display = "macOS/Darwin"
                else:
                    os_display = compatible_os[0].capitalize()
            else:
                display_names = []
                for os_name in compatible_os[:-1]:
                    if os_name == 'darwin':
                        display_names.append('macOS')
                    else:
                        display_names.append(os_name.capitalize())
                last_os = compatible_os[-1]
                if last_os == 'darwin':
                    last_os = 'macOS'
                else:
                    last_os = last_os.capitalize()
                os_display = ", ".join(display_names) + f" and {last_os}"
            
            # Provide more informative error message
            error_msg = f"Command '{base_cmd}' is only available on {os_display}.\n"
            error_msg += f"This agent is running {agent_os}."
            
            # Add suggestion for similar cross-platform commands if applicable
            if base_cmd in self.bof_commands:
                error_msg += "\n\nNote: BOF commands are Windows-specific features."
                error_msg += "\nFor cross-platform execution, use the 'shell' command."
            elif base_cmd in self.inline_assembly_commands:
                error_msg += "\n\nNote: Inline-assembly commands are Windows-specific features."
                error_msg += "\nFor cross-platform execution, use the 'shell' command."
            elif base_cmd == 'sudo-session':
                error_msg += "\n\nNote: sudo-session is only available on Unix-like systems."
                if agent_os and 'windows' in agent_os.lower():
                    error_msg += "\nFor Windows privilege escalation, use appropriate Windows commands via 'shell'."
            
            return False, error_msg
        
        return True, None
    
    def get_commands_for_os(self, agent_os: str) -> List[str]:
        """Get a list of all commands compatible with the given OS"""
        compatible_commands = []
        
        # Check all commands from TOML configuration
        for cmd_name in self.command_os_compatibility.keys():
            if self.is_command_compatible(cmd_name, agent_os):
                compatible_commands.append(cmd_name)
        
        return sorted(list(set(compatible_commands)))
    
    def validate_command(self, command_str: str, agent_os: str = None) -> Tuple[bool, Optional[str]]:
        """Main validation method with OS checking"""
        if not command_str:
            return False, "Empty command"
        
        # First check OS compatibility if agent_os is provided
        if agent_os:
            is_valid, error = self.validate_command_for_os(command_str, agent_os)
            if not is_valid:
                return False, error
        
        # Then proceed with existing validation logic
        cmd_parts = command_str.split()
        base_cmd = cmd_parts[0].lower()
        
        # Special handling for BOF commands - they might have hyphens
        if base_cmd in self.bof_commands:
            return self.validate_bof_command(cmd_parts)
        
        # Special handling for inline-assembly commands
        if base_cmd in self.inline_assembly_commands:
            return self.validate_inline_assembly_command(cmd_parts)
            
        # For commands in the config, check with dash replaced by underscore
        # since TOML keys can't have dashes
        config_key = base_cmd.replace('-', '_')
        
        # Shell command validation
        if base_cmd == "shell":
            if len(cmd_parts) < 2:
                return False, "shell command requires at least one argument\nUsage: shell [--timeout <seconds>] <command>"
            
            # Check for timeout option
            if cmd_parts[1] == "--timeout":
                if len(cmd_parts) < 4:
                    return False, "shell --timeout requires a timeout value and a command\nUsage: shell --timeout <seconds> <command>"
                
                # Validate timeout is a number
                try:
                    timeout = int(cmd_parts[2])
                    if timeout <= 0:
                        return False, "Timeout must be a positive number"
                except ValueError:
                    return False, f"Invalid timeout value: {cmd_parts[2]}. Must be a number."
            
            return True, None

        # Check if command exists in TOML configuration
        if base_cmd not in self.commands and config_key not in self.commands:
            # Check if it's a known command type
            if base_cmd.startswith('bof'):
                # Might be a BOF variant not in TOML
                if agent_os and not self.is_command_compatible('bof', agent_os):
                    return False, "BOF commands are only available on Windows"
                return True, None
            if base_cmd.startswith('inline') or base_cmd == 'execute-assembly':
                # Might be an inline-assembly variant
                if agent_os and not self.is_command_compatible('inline-assembly', agent_os):
                    return False, "Inline-assembly commands are only available on Windows"
                return True, None

            # Check if it's a CNA-registered BOF command (needs 'bof' prefix)
            if hasattr(self, 'cna_bof_commands') and base_cmd in self.cna_bof_commands:
                return False, f"'{base_cmd}' is a CNA BOF command. Use: bof {base_cmd} [args]"

            return False, f"Unknown command: {base_cmd}"
            
        return True, None
    
    def validate_bof_command(self, cmd_parts: list) -> Tuple[bool, Optional[str]]:
        """Validate BOF-specific commands"""
        base_cmd = cmd_parts[0].lower()

        if base_cmd in ['bof', 'bof-async', 'bof-load']:
            if len(cmd_parts) < 2:
                return False, f"{base_cmd} requires a BOF file path or CNA command name"

            bof_arg = cmd_parts[1]

            # Check if it's a CNA-registered BOF command (valid subcommand)
            if hasattr(self, 'cna_bof_commands') and bof_arg in self.cna_bof_commands:
                return True, None

            # Otherwise, check if file exists
            bof_path = bof_arg if base_cmd != 'bof-load' else cmd_parts[2] if len(cmd_parts) > 2 else None
            if bof_path and not Path(bof_path).exists():
                return False, f"BOF file not found: {bof_path}"

            # Check file extension
            if bof_path and not bof_path.endswith(('.o', '.obj')):
                return False, f"Invalid BOF file extension. Expected .o or .obj"
        
        elif base_cmd in ['bof-output', 'bof-kill']:
            if len(cmd_parts) < 2:
                return False, f"{base_cmd} requires a job ID"
            
            # Check if job ID is valid format
            job_id = cmd_parts[1]
            # Allow various job ID formats
            if not (job_id.isdigit() or job_id.startswith('bof_') or job_id.startswith('BOF_')):
                return False, f"Invalid job ID format: {job_id}"
        
        elif base_cmd == 'bof-exec':
            if len(cmd_parts) < 2:
                return False, "bof-exec requires a BOF name"
        
        elif base_cmd == 'bof-unload':
            if len(cmd_parts) < 2:
                return False, "bof-unload requires a BOF name or 'all'"
        
        return True, None
    
    def validate_inline_assembly_command(self, cmd_parts: list) -> Tuple[bool, Optional[str]]:
        """Validate inline-assembly specific commands"""
        base_cmd = cmd_parts[0].lower()
        
        # Commands that require an assembly file
        if base_cmd in ['inline-assembly', 'inline-assembly-async', 
                        'execute-assembly', 'inline-execute']:
            if len(cmd_parts) < 2:
                return False, f"{base_cmd} requires an assembly file path"
            
            # Check if file exists
            assembly_path = cmd_parts[1]
            if not Path(assembly_path).exists():
                return False, f"Assembly file not found: {assembly_path}"
            
            # Check file extension
            if not assembly_path.endswith(('.exe', '.dll')):
                return False, f"Invalid assembly file extension. Expected .exe or .dll"
            
            # Validate it's a .NET assembly (basic check)
            try:
                with open(assembly_path, 'rb') as f:
                    header = f.read(2)
                    if header != b'MZ':
                        return False, f"File is not a valid executable: {assembly_path}"
            except Exception as e:
                return False, f"Failed to read assembly file: {e}"
        
        # Commands that require a job ID
        elif base_cmd in ['inline-assembly-output', 'inline-assembly-kill']:
            if len(cmd_parts) < 2:
                return False, f"{base_cmd} requires a job ID"
            
            # Check if job ID is valid format
            job_id = cmd_parts[1]
            # Allow both numeric and inline_asm_* format
            if not (job_id.isdigit() or job_id.startswith('inline_asm_')):
                return False, f"Invalid job ID format: {job_id}"
        
        # Commands for job management that may or may not have arguments
        elif base_cmd == 'inline-assembly-jobs-clean':
            # This command can be called with or without a job ID
            if len(cmd_parts) > 1:
                job_id = cmd_parts[1]
                if not (job_id.isdigit() or job_id.startswith('inline_asm_')):
                    return False, f"Invalid job ID format: {job_id}"
        
        return True, None
    
    def prepare_inline_assembly_command(self, command_str: str, agent_id: str) -> dict:
        """
        Prepare an inline-assembly command for sending to the server
        
        Args:
            command_str: The full command string (e.g., "inline-assembly /path/to/tool.exe arg1 arg2")
            agent_id: The target agent ID
            
        Returns:
            Dictionary ready to be sent via WebSocket
        """
        cmd_parts = command_str.split()
        base_cmd = cmd_parts[0].lower()
        
        # Handle job management commands
        if base_cmd == 'inline-assembly-jobs':
            return {
                "type": "agent_command",
                "data": {
                    "command": "inline-assembly-jobs",
                    "agent_id": agent_id,
                    "command_id": str(uuid.uuid4()),
                    "timestamp": datetime.now().isoformat()
                }
            }
        
        elif base_cmd in ['inline-assembly-output', 'inline-assembly-kill']:
            job_id = cmd_parts[1] if len(cmd_parts) > 1 else ""
            return {
                "type": "agent_command",
                "data": {
                    "command": base_cmd,
                    "agent_id": agent_id,
                    "command_id": str(uuid.uuid4()),
                    "job_id": job_id,
                    "timestamp": datetime.now().isoformat()
                }
            }
        
        # Handle assembly execution commands
        if base_cmd in ['inline-assembly', 'inline-assembly-async', 
                       'execute-assembly', 'inline-execute']:
            
            assembly_path = cmd_parts[1]
            
            # Parse arguments and options
            assembly_args = []
            options = {
                'bypass_amsi': False,  # Default to NOT bypassing
                'bypass_etw': False,   # Default to NOT bypassing
                'revert_etw': False,
                'app_domain': 'InlineAssembly',
                'use_pipe': True
            }
            
            i = 2
            while i < len(cmd_parts):
                arg = cmd_parts[i]
                
                # Updated flag parsing
                if arg == '--amsi':
                    options['bypass_amsi'] = True
                elif arg == '--etw':
                    options['bypass_etw'] = True
                elif arg == '--revert-etw':
                    options['revert_etw'] = True
                elif arg == '--app-domain' and i + 1 < len(cmd_parts):
                    options['app_domain'] = cmd_parts[i + 1]
                    i += 1
                elif not arg.startswith('--'):
                    assembly_args.append(arg)
                
                i += 1
            
            # Load and encode the assembly
            try:
                with open(assembly_path, 'rb') as f:
                    assembly_data = f.read()
                assembly_b64 = base64.b64encode(assembly_data).decode('utf-8')
            except Exception as e:
                raise ValueError(f"Failed to read assembly file: {e}")
            
            # Determine if async
            is_async = 'async' in base_cmd
            
            # Build configuration
            config = {
                "assembly_b64": assembly_b64,
                "arguments": assembly_args,
                "app_domain": options['app_domain'],
                "bypass_amsi": options['bypass_amsi'],
                "bypass_etw": options['bypass_etw'],
                "revert_etw": options['revert_etw'],
                "entry_point": "Main(string[] args)" if assembly_args else "Main()",
                "use_pipe": options['use_pipe'],
                "pipe_name": ""
            }
            
            # Create command
            return {
                "type": "agent_command",
                "data": {
                    "command": "inline-assembly-async" if is_async else "inline-assembly",
                    "agent_id": agent_id,
                    "command_id": str(uuid.uuid4()),
                    "data": json.dumps(config),
                    "timestamp": datetime.now().isoformat()
                }
            }
        
        return None
    
    def get_help(self, command=None, include_extensions=True, agent_os=None) -> str:
            """Get help text for commands

            Args:
                command: Specific command to get help for, or None for general help
                include_extensions: Whether to include extension commands
                agent_os: The agent's OS for filtering OS-specific help (e.g., 'linux', 'darwin', 'windows')
            """
            if not command:
                # General help - show all commands grouped by category
                help_text = "Available commands:\n\n"

                # Group commands by category
                categories = {
                    "Shell & System": ['shell', 'ps', 'whoami', 'sudo-session', 'env'],
                    "File Operations": ['upload', 'download', 'ls', 'pwd', 'cd', 'cat', 'rm', 'hash', 'hashdir'],
                    "Windows Token": ['token', 'rev2self'],
                    "Lateral Movement": ['link', 'links', 'unlink'],
                    "Process Execution": ['inline-assembly', 'inline-assembly-async',
                                        'execute-assembly', 'inline-execute'],
                    "BOF Operations": ['bof', 'bof-async', 'bof-jobs', 'bof-output',
                                    'bof-kill'],
                    "Assembly Jobs": ['inline-assembly-jobs', 'inline-assembly-output',
                                    'inline-assembly-kill', 'inline-assembly-jobs-clean',
                                    'inline-assembly-jobs-stats'],
                    "CNA Scripts": ['cna-load', 'cna-list'],
                    "Network": ['socks'],
                    "Agent Control": ['sleep', 'rekey', 'clear', 'exit'],
                    "Job Management": ['jobs', 'jobkill'],
                    "Help": ['help']
                }

                for category, cmds in categories.items():
                    help_text += f"\n{category}:\n"
                    for cmd in cmds:
                        # For display, convert underscores back to dashes
                        display_cmd = cmd.replace('_', '-')

                        # Look for the command in self.commands dict (not self.command_validator.commands)
                        if cmd in self.commands:
                            desc = self.commands[cmd].get('description', 'No description')
                            help_text += f"  {display_cmd:<30} {desc}\n"
                        else:
                            # Also try with dashes converted to underscores
                            config_key = cmd.replace('-', '_')
                            if config_key in self.commands:
                                desc = self.commands[config_key].get('description', 'No description')
                                help_text += f"  {display_cmd:<30} {desc}\n"

                help_text += "\nType 'help <command>' for detailed information about a specific command."
                return help_text

            # Get help for specific command
            # Find the best matching command entry, considering OS compatibility
            cmd_data = self._find_command_for_help(command, agent_os)

            if cmd_data is None:
                return f"No help available for '{command}'"

            # Build detailed help text
            help_text = f"Command: {cmd_data.get('name', command)}\n"
            help_text += f"Description: {cmd_data.get('description', 'No description available')}\n\n"

            if 'syntax' in cmd_data:
                help_text += f"Syntax:\n{cmd_data['syntax']}\n\n"

            if 'examples' in cmd_data:
                help_text += "Examples:\n"
                for example in cmd_data['examples']:
                    help_text += f"  {example}\n"
                help_text += "\n"

            if 'help' in cmd_data:
                help_text += f"Details:\n{cmd_data['help']}\n"

            return help_text

    def _find_command_for_help(self, command: str, agent_os: str = None):
        """Find the best matching command entry for help, considering OS compatibility.

        When multiple entries have the same command name but different OS compatibility,
        this returns the one matching the agent's OS.
        """
        # Normalize agent OS
        agent_os_normalized = None
        if agent_os:
            agent_os_lower = agent_os.lower()
            os_mappings = {
                'win': 'windows', 'win32': 'windows', 'win64': 'windows',
                'windows': 'windows', 'windows_amd64': 'windows',
                'linux': 'linux', 'ubuntu': 'linux', 'debian': 'linux',
                'darwin': 'darwin', 'macos': 'darwin', 'osx': 'darwin',
            }
            agent_os_normalized = os_mappings.get(agent_os_lower, agent_os_lower)

        # First, collect all command entries that match the command name
        matching_entries = []

        for cmd_key, cmd_data in self.commands.items():
            cmd_name = cmd_data.get('name', cmd_key)
            # Check if this entry's name matches the requested command
            if cmd_name == command or cmd_key == command or cmd_key.replace('_', '-') == command or cmd_key.replace('-', '_') == command:
                matching_entries.append((cmd_key, cmd_data))

        if not matching_entries:
            return None

        # If only one match, return it
        if len(matching_entries) == 1:
            return matching_entries[0][1]

        # Multiple matches - filter by OS compatibility
        if agent_os_normalized:
            for cmd_key, cmd_data in matching_entries:
                os_compat = cmd_data.get('os_compatibility', 'all')

                # Normalize os_compat to list
                if os_compat == 'all':
                    compat_list = ['all']
                elif isinstance(os_compat, str):
                    compat_list = [os_compat]
                else:
                    compat_list = os_compat

                # Check if this entry is compatible with the agent OS
                if 'all' in compat_list or agent_os_normalized in compat_list:
                    return cmd_data

        # No OS-specific match found, return the first entry
        return matching_entries[0][1]

    def _format_os_compatibility(self, os_compat):
        """Format OS compatibility for display"""
        if os_compat == 'all':
            return "All platforms"
        elif isinstance(os_compat, str):
            if os_compat == 'windows':
                return "Windows only"
            elif os_compat == 'linux':
                return "Linux only"
            elif os_compat == 'darwin':
                return "macOS/Darwin only"
            else:
                return os_compat.capitalize()
        elif isinstance(os_compat, list):
            formatted = []
            for os_name in os_compat:
                if os_name == 'darwin':
                    formatted.append('macOS')
                else:
                    formatted.append(os_name.capitalize())
            if len(formatted) == 1:
                return f"{formatted[0]} only"
            else:
                return ", ".join(formatted[:-1]) + f" and {formatted[-1]}"
        return str(os_compat)