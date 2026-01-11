# client/src/gui/widgets/terminal/handlers/command_handler.py

import json
import uuid
import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path

class CommandHandler:
    """Handles command sending and validation with OS-aware filtering"""
    
    def __init__(self, terminal):
        self.terminal = terminal
        self.ws_thread = terminal.ws_thread
        self.agent_guid = terminal.agent_guid
        # Get OS directly from terminal if available
        self.agent_os = terminal.agent_os if hasattr(terminal, 'agent_os') else None
        self.command_validator = terminal.command_validator
        self.bof_handler = terminal.bof_handler
        self.inline_assembly_handler = terminal.inline_assembly_handler
        self.file_uploader = terminal.file_uploader
        
        print(f"CommandHandler initialized with agent_os: {self.agent_os}")
        
        # Initialize CNA interpreter
        from ...cna_interpreter import CNAInterpreter
        self.cna_interpreter = CNAInterpreter(terminal)
        # Set to BOF mode by default to avoid duplication
        self.cna_interpreter.set_registration_mode("bof")
        
        # Update tab completer with agent OS
        if self.agent_os and hasattr(self.terminal, 'tab_completer'):
            self.terminal.tab_completer.set_agent_os(self.agent_os)
        
        # Build command lists from TOML configuration
        self.bof_commands = []
        self.inline_assembly_commands = []
        
        # Extract Windows-only commands from the loaded configuration
        for cmd_key, cmd_data in self.command_validator.commands.items():
            cmd_name = cmd_data.get('name', cmd_key)
            os_compat = cmd_data.get('os_compatibility', 'all')
            
            # Identify BOF and inline-assembly commands
            if os_compat == 'windows' or (isinstance(os_compat, list) and 'windows' in os_compat):
                if 'bof' in cmd_name:
                    self.bof_commands.append(cmd_name)
                elif 'inline' in cmd_name or 'assembly' in cmd_name or 'execute' in cmd_name:
                    self.inline_assembly_commands.append(cmd_name)
        
        # Also include any hardcoded ones not in TOML yet
        additional_bof = ['bof', 'bof-async', 'bof-jobs', 'bof-output', 'bof-kill', 'bof-load', 'bof-exec', 'bof-list', 'bof-unload']
        additional_inline = ['inline-assembly', 'inline-assembly-async', 'execute-assembly', 'inline-execute', 
                            'inline-assembly-jobs', 'inline-assembly-output', 'inline-assembly-kill',
                            'inline-assembly-jobs-clean', 'inline-assembly-jobs-stats']
        
        for cmd in additional_bof:
            if cmd not in self.bof_commands:
                self.bof_commands.append(cmd)
        
        for cmd in additional_inline:
            if cmd not in self.inline_assembly_commands:
                self.inline_assembly_commands.append(cmd)
        
        print(f"Loaded BOF commands: {self.bof_commands}")
        print(f"Loaded inline-assembly commands: {self.inline_assembly_commands}")
    
    def load_cna_script(self, script_path: str, mode: str = "bof") -> bool:
        """Load a CNA script file with specified registration mode"""
        # Check if main window has a debug console open
        main_window = self.terminal.window() if hasattr(self.terminal, 'window') else None
        if main_window and hasattr(main_window, 'cna_debug_console') and main_window.cna_debug_console.isVisible():
            self.cna_interpreter.set_debug_console(main_window.cna_debug_console)
            main_window.cna_debug_console.cna_interpreter = self.cna_interpreter
        
        # Set the registration mode
        self.cna_interpreter.set_registration_mode(mode)
        
        success = self.cna_interpreter.load_cna_script(script_path)
        if success:
            self.terminal.terminal_output.append(
                f"\n[+] Loaded CNA script: {os.path.basename(script_path)}"
            )
            # Update command lists - only show BOF commands
            if hasattr(self.command_validator, 'cna_bof_commands'):
                self.terminal.terminal_output.append(
                    f"    - Registered {len(self.command_validator.cna_bof_commands)} BOF commands"
                )
        else:
            self.terminal.terminal_output.append(
                f"\n[-] Failed to load CNA script: {script_path}"
            )
        return success
        
    def send_command(self, command):
        """Process and send command with OS-aware filtering"""
        if not command:
            return False
            
        print(f"DEBUG: Raw command: '{command}'")
        print(f"DEBUG: Agent OS: '{self.agent_os}'")
        
        # Parse command first to get base command
        parts = command.strip().split()
        if not parts:
            return False
        
        base_command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        print(f"DEBUG: Base command: '{base_command}'")
        print(f"DEBUG: Arguments: {args}")
        
        # EARLY OS VALIDATION - Check compatibility BEFORE any special handlers
        # Exclude only local-only commands that don't go to the agent
        local_only_commands = ['help', 'cna-load', 'cna-list']
        
        if self.agent_os and base_command not in local_only_commands:
            is_valid, error = self.command_validator.validate_command_for_os(command, self.agent_os)
            
            if not is_valid:
                # Display error in terminal
                # Use UTC timestamp to match server format for proper sorting
                timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                username = self.terminal.command_buffer.username or "user"
                
                # Echo the command
                self.terminal.command_buffer.add_output({
                    "timestamp": timestamp,
                    "output": f"[{timestamp}] {username} > {command}",
                    "type": "command"
                })
                
                # Show the error with OS information
                self.terminal.command_buffer.add_output({
                    "timestamp": timestamp,
                    "output": f"\n{error}",
                    "type": "error"
                })
                
                self.terminal.update_display()
                return False
        
        # Now proceed with special command handling (after OS validation)
        
        # Check if it's a CNA load command
        if base_command == 'cna-load':
            if args:
                # Check for mode flag
                mode = "bof"  # Default to BOF mode to avoid duplication
                script_path = ' '.join(args)
                
                # Allow optional mode specification
                if args[0] in ['--direct', '--bof', '--both']:
                    mode = args[0].replace('--', '')
                    script_path = ' '.join(args[1:]) if len(args) > 1 else ''
                
                script_path = os.path.expanduser(script_path)
                if script_path and os.path.exists(script_path):
                    return self.load_cna_script(script_path, mode)
                else:
                    self.terminal.terminal_output.append(
                        f"\n[-] CNA script not found: {script_path}"
                    )
            else:
                self.terminal.terminal_output.append(
                    "\n[-] Usage: cna-load [--bof|--direct|--both] <path_to_cna_file>"
                )
            return True
        
        # Check if it's a CNA list command
        elif base_command == 'cna-list':
            return self._handle_cna_list_command()
        
        # Check if it's a BOF command (NOW ALREADY VALIDATED FOR OS)
        elif base_command in self.bof_commands:
            print(f"DEBUG: Handling as BOF command via BOFHandler")
            
            # Check if first arg is a CNA-registered BOF subcommand
            if args and hasattr(self.command_validator, 'cna_bof_commands'):
                potential_subcommand = args[0]
                if potential_subcommand in self.command_validator.cna_bof_commands:
                    print(f"DEBUG: Detected CNA BOF subcommand: {potential_subcommand}")
                    # Execute via CNA interpreter as BOF subcommand
                    remaining_args = args[1:] if len(args) > 1 else []
                    async_mode = base_command == 'bof-async'
                    result = self.cna_interpreter.execute_as_bof_subcommand(
                        potential_subcommand, remaining_args, async_mode
                    )
                    if result:
                        return True
            
            # Otherwise handle as normal BOF command
            try:
                result = self.bof_handler.handle_bof_command(base_command, args)
                print(f"DEBUG: BOF handler returned: {result}")
                if result:
                    return True
            except Exception as e:
                print(f"DEBUG: BOF handler exception: {e}")
                import traceback
                traceback.print_exc()
        
        # Check if it's an inline-assembly command (NOW ALREADY VALIDATED FOR OS)
        elif base_command in self.inline_assembly_commands:
            print(f"DEBUG: Handling as inline-assembly command via InlineAssemblyHandler")
            try:
                result = self.inline_assembly_handler.handle_inline_assembly_command(base_command, args)
                print(f"DEBUG: Inline-assembly handler returned: {result}")
                if result:
                    return True
            except Exception as e:
                print(f"DEBUG: Inline-assembly handler exception: {e}")
                import traceback
                traceback.print_exc()
        
        # Check if it's a CNA-registered command (removed since we're in BOF-only mode)
        # This section is removed to avoid duplication
        
        # Handle help command locally
        elif base_command == 'help':
            return self._handle_help_command(command)
        
        # For all other commands, validate and send via WebSocket
        print(f"DEBUG: Validating command with CommandValidator")
        is_valid, error = self.command_validator.validate_command(command, self.agent_os)
        print(f"DEBUG: Validation result: valid={is_valid}, error={error}")
        
        if not is_valid:
            print(f"DEBUG: Command validation failed: {error}")
            self.terminal.terminal_output.append(f"\nError: {error}")
            return False
        
        # Check WebSocket connection
        print(f"DEBUG: Checking WebSocket connection")
        if not self.ws_thread or not self.ws_thread.is_connected():
            print(f"DEBUG: WebSocket not connected")
            self.terminal.terminal_output.append("\nError: Not connected to server")
            return False
        
        if not self.agent_guid:
            print(f"DEBUG: No agent GUID available")
            self.terminal.terminal_output.append("\nError: No agent GUID available")
            return False
        
        # Send command via WebSocket
        return self._send_via_websocket(command)
    
    def _handle_cna_list_command(self):
        """Handle the cna-list command to show loaded scripts and commands"""
        self.terminal.terminal_output.append("\n=== Loaded CNA Scripts ===")
        
        if not self.cna_interpreter.loaded_scripts:
            self.terminal.terminal_output.append("No CNA scripts loaded")
        else:
            for script_path in self.cna_interpreter.loaded_scripts:
                self.terminal.terminal_output.append(f"\n[+] {script_path}")
        
        if self.cna_interpreter.commands:
            self.terminal.terminal_output.append(f"\n=== Registered CNA BOF Commands ({len(self.cna_interpreter.commands)}) ===")
            self.terminal.terminal_output.append("Use 'bof <command>' or 'bof-async <command>' to execute")
            for cmd_name, cmd in self.cna_interpreter.commands.items():
                if cmd.bof_path:  # Only show commands that have BOF files
                    self.terminal.terminal_output.append(f"\n  bof {cmd_name:<20} - {cmd.description}")
                    if cmd.ttp:
                        self.terminal.terminal_output.append(f"    MITRE ATT&CK: {cmd.ttp}")
        else:
            self.terminal.terminal_output.append("\nNo CNA commands registered")
        
        return True
    
    def _handle_help_command(self, command):
        """Handle help commands locally with OS-aware filtering"""
        print(f"DEBUG: Processing as help command")
        cmd_parts = command.split()
        
        if len(cmd_parts) > 1:
            # Check if it's help for a BOF subcommand
            if cmd_parts[1] == 'bof' and len(cmd_parts) > 2:
                # Help for 'bof <subcommand>'
                subcommand = cmd_parts[2]
                if hasattr(self.command_validator, 'cna_bof_commands') and subcommand in self.command_validator.cna_bof_commands:
                    cmd_info = self.command_validator.cna_bof_commands[subcommand]
                    help_text = f"""Command: bof {subcommand}
Description: {cmd_info['description']}

Synopsis:
{cmd_info['synopsis']}

Usage: bof {subcommand} [arguments]
       bof-async {subcommand} [arguments]  (for async execution)

(Imported from CNA script)
BOF Path: {cmd_info.get('bof_path', 'Not resolved')}"""
                    
                    # Echo and display
                    # Use UTC timestamp to match server format for proper sorting
                    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                    username = self.terminal.command_buffer.username or "user"
                    
                    self.terminal.command_buffer.add_output({
                        "timestamp": timestamp,
                        "output": f"[{timestamp}] {username} > {command}"
                    })
                    self.terminal.command_buffer.add_output({
                        "timestamp": timestamp,
                        "output": help_text
                    })
                    self.terminal.update_display()
                    return True
            else:
                # Get help for specific command
                help_text = self.command_validator.get_help(cmd_parts[1])
        else:
            # Get general help filtered by OS
            help_text = "Available commands"
            if self.agent_os:
                help_text += f" (filtered for {self.agent_os})"
            help_text += ":\n\n"
            
            # Get OS-compatible commands
            if self.agent_os:
                compatible_commands = self.command_validator.get_commands_for_os(self.agent_os)
            else:
                compatible_commands = None
            
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
                "Linux Exploitation": ['inject', 'memdump', 'capabilities', 'selinux',
                                    'suid-enum', 'container-detect', 'ld-preload'],
                "Linux Persistence": ['persist', 'persist-cron'],
                "macOS Exploitation": ['suid-enum', 'keychain', 'dyld-inject'],
                "macOS Persistence": ['persist'],
                "CNA Scripts": ['cna-load', 'cna-list'],
                "Network": ['socks'],
                "Agent Control": ['sleep', 'rekey', 'clear', 'exit'],
                "Job Management": ['jobs', 'jobkill'],
                "Help": ['help']
            }
            
            for category, cmds in categories.items():
                category_has_commands = False
                category_text = f"\n{category}:\n"
                
                for cmd in cmds:
                    # Skip if not compatible with agent OS
                    if compatible_commands is not None and cmd not in compatible_commands:
                        continue
                    
                    category_has_commands = True
                    # Convert underscore to dash for display
                    display_cmd = cmd.replace('_', '-')
                    config_key = cmd.replace('-', '_')
                    
                    if config_key in self.command_validator.commands:
                        desc = self.command_validator.commands[config_key].get('description', 'No description')
                        category_text += f"  {display_cmd:<30} {desc}\n"
                    elif cmd in self.command_validator.commands:
                        desc = self.command_validator.commands[cmd].get('description', 'No description')
                        category_text += f"  {display_cmd:<30} {desc}\n"
                
                # Only add the category if it has commands
                if category_has_commands:
                    help_text += category_text
            
            help_text += "\nType 'help <command>' for detailed information about a specific command."
            
            # Only show CNA BOF commands (no duplication with direct commands)
            if hasattr(self.command_validator, 'cna_bof_commands') and self.command_validator.cna_bof_commands:
                help_text += "\n\nCNA BOF Commands (use: bof <command> or bof-async <command>):"
                for cmd_name in sorted(self.command_validator.cna_bof_commands.keys()):
                    cmd_info = self.command_validator.cna_bof_commands[cmd_name]
                    # Handle both dictionary and object cases
                    if isinstance(cmd_info, dict):
                        description = cmd_info.get('description', 'No description')
                    else:
                        description = getattr(cmd_info, 'description', 'No description')
                    help_text += f"\n  {cmd_name:<25} {description}"
        
        # Echo the command and show help
        # Use UTC timestamp to match server format for proper sorting
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        username = self.terminal.command_buffer.username or "user"
        
        self.terminal.command_buffer.add_output({
            "timestamp": timestamp,
            "output": f"[{timestamp}] {username} > {command}"
        })
        self.terminal.command_buffer.add_output({
            "timestamp": timestamp,
            "output": help_text
        })
        self.terminal.update_display()
        
        return True
    
    def _send_via_websocket(self, command):
        """Send command via WebSocket"""
        print(f"DEBUG: Creating command message")

        # Use UTC timestamp to match server format for proper sorting
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        command_id = str(uuid.uuid4())

        command_msg = {
            "type": "agent_command",
            "data": {
                "command": command,
                "agent_id": self.agent_guid,
                "command_id": command_id,
                "filename": "",
                "currentChunk": 0,
                "totalChunks": 0,
                "data": "",
                "timestamp": timestamp
            }
        }

        print(f"DEBUG: Command message: {json.dumps(command_msg, indent=2)}")

        try:
            print(f"DEBUG: Sending command via WebSocket")
            future = asyncio.run_coroutine_threadsafe(
                self.ws_thread.ws_client.send_message(json.dumps(command_msg)),
                self.ws_thread.loop
            )
            result = future.result(timeout=5)
            print(f"DEBUG: WebSocket send result: {result}")

            # Track this command_id so we skip the server's command_queued broadcast
            # (we're echoing the command locally instead to avoid duplication)
            if hasattr(self.ws_thread, 'add_local_command'):
                self.ws_thread.add_local_command(command_id)
                print(f"DEBUG: Tracked locally sent command: {command_id[:8]}")

            # Echo the command locally in the terminal
            # Add blank line after command for consistent spacing
            username = self.terminal.command_buffer.username or "user"
            self.terminal.command_buffer.add_output({
                "timestamp": timestamp,
                "output": f"[{timestamp}] {username} > {command}\n\n",
                "type": "command"
            })
            self.terminal.update_display(incremental=True)

            # Handle upload commands specially
            if command.startswith('upload'):
                print(f"DEBUG: Handling upload command")
                self.file_uploader.original_command = command
                self.file_uploader.handle_upload_command(command)

            print(f"DEBUG: Command sent successfully")
            return True
            
        except asyncio.TimeoutError:
            print(f"DEBUG: WebSocket send timeout")
            self.terminal.terminal_output.append(f"\nError sending command: Timeout")
            return False
        except Exception as e:
            print(f"DEBUG: WebSocket send exception: {e}")
            import traceback
            traceback.print_exc()
            self.terminal.terminal_output.append(f"\nError sending command: {str(e)}")
            return False