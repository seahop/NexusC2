# client/src/gui/widgets/cna_interpreter.py

import re
import os
import json
import base64
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class CNACommand:
    """Represents a parsed CNA command registration"""
    name: str
    description: str
    synopsis: str
    handler: str  # The alias name that handles this command
    source_script: str = None 
    ttp: Optional[str] = None  # MITRE ATT&CK reference
    bof_path: Optional[str] = None  # Resolved BOF file path

@dataclass 
class CNAAlias:
    """Represents a parsed CNA alias (command implementation)"""
    name: str
    parameters: List[str]
    code: str
    bof_name: Optional[str] = None  # Associated BOF if any
    pack_format: Optional[str] = None  # BOF packing format

class CNAInterpreter:
    """
    Interprets Cobalt Strike Aggressor (CNA) scripts for BOF integration
    Translates CNA commands to native client commands
    """
    
    def __init__(self, agent_terminal=None):
        self.agent_terminal = agent_terminal
        self.commands = {}  # name -> CNACommand
        self.aliases = {}   # name -> CNAAlias
        self.variables = {} # CNA script variables
        self.bof_mappings = {}  # Maps command name to BOF file path
        self.loaded_scripts = []  # Track loaded script paths
        self.debug_console = None  # Debug console reference
        self.registration_mode = "bof"  # Changed default to "bof" to avoid duplication
        
        # BOF argument type mappings (CNA -> our format)
        self.type_mappings = {
            'z': 's',  # string
            'Z': 's',  # string (wide in CNA, we handle as string)
            'i': 'i',  # int32
            'I': 'I',  # int64
            's': 'h',  # short
            'S': 'H',  # unsigned short
            'b': 'b',  # binary data
        }
    
    def set_debug_console(self, console):
        """Set the debug console for logging"""
        self.debug_console = console
    
    def set_registration_mode(self, mode: str):
        """Set how commands are registered: 'direct', 'bof', or 'both'"""
        if mode in ["direct", "bof", "both"]:
            self.registration_mode = mode
            if self.debug_console:
                self.debug_console.log("INFO", "CONFIG", f"Registration mode set to: {mode}")
    
    def load_cna_script(self, script_path: str) -> bool:
        """Load and parse a CNA script file"""
        try:
            if self.debug_console:
                self.debug_console.log("INFO", "LOADER", f"Loading CNA script: {script_path}")
            
            with open(script_path, 'r') as f:
                content = f.read()
            
            # Store the script path for BOF resolution
            self.loaded_scripts.append(os.path.dirname(script_path))
            
            # Parse the script
            self._parse_script(content, script_path)
            
            # Resolve BOF paths for all commands
            self._resolve_bof_paths()
            
            # Register commands with the terminal based on mode
            self._register_with_terminal()
            
            print(f"CNA: Successfully loaded script from {script_path}")
            print(f"CNA: Registered {len(self.commands)} commands and {len(self.aliases)} aliases")
            
            if self.debug_console:
                self.debug_console.log_script_load(script_path, True)
                self.debug_console.refresh_status()
            
            return True
            
        except Exception as e:
            print(f"Error loading CNA script: {e}")
            if self.debug_console:
                self.debug_console.log_script_load(script_path, False, str(e))
            import traceback
            traceback.print_exc()
            return False
    
    def _parse_script(self, content: str, script_path: str = None):
        """Parse CNA script content"""
        # Remove comments (but preserve strings containing #)
        lines = content.split('\n')
        cleaned_lines = []
        for line in lines:
            # Simple comment removal - doesn't handle # in strings perfectly but works for most cases
            comment_pos = line.find('#')
            if comment_pos >= 0:
                # Check if it's not within quotes
                before_comment = line[:comment_pos]
                if before_comment.count('"') % 2 == 0 and before_comment.count("'") % 2 == 0:
                    line = before_comment
            cleaned_lines.append(line)
        content = '\n'.join(cleaned_lines)
        
        # Parse beacon_command_register calls
        register_pattern = r'beacon_command_register\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]*?)"\s*\)'
        for match in re.finditer(register_pattern, content, re.DOTALL):
            name = match.group(1)
            description = match.group(2)
            synopsis = match.group(3).replace('\n', ' ').replace('\t', ' ').strip()
            
            # Clean up synopsis - remove extra whitespace
            synopsis = ' '.join(synopsis.split())
            
            self.commands[name] = CNACommand(
                name=name,
                description=description,
                synopsis=synopsis,
                handler=name,  # Default to same name
                source_script=script_path
            )
            print(f"CNA: Registered command '{name}'")
            if self.debug_console:
                self.debug_console.log_command_registration(name, description)
        
        # Parse alias definitions with better brace matching
        alias_starts = []
        for match in re.finditer(r'alias\s+(\w+)\s*\{', content):
            alias_starts.append((match.group(1), match.end()))
        
        for alias_name, start_pos in alias_starts:
            # Find the matching closing brace by counting depth
            brace_count = 1
            pos = start_pos
            in_string = False
            escape_next = False
            
            while pos < len(content) and brace_count > 0:
                char = content[pos]
                
                # Handle string boundaries
                if char == '"' and not escape_next:
                    in_string = not in_string
                elif char == '\\':
                    escape_next = not escape_next
                else:
                    escape_next = False
                
                # Only count braces outside of strings
                if not in_string:
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                
                pos += 1
            
            if brace_count == 0:
                alias_body = content[start_pos:pos-1]
                
                # Extract parameters
                params = re.findall(r'\$(\d+)', alias_body)
                params = list(set(params))
                
                # Look for BOF execution patterns with improved detection
                bof_name = None
                
                # Pattern 1: readbof($1, "bof_name", ...) - most common
                bof_match = re.search(r'readbof\s*\(\s*\$\d+\s*,\s*"([^"]+)"', alias_body)
                if bof_match:
                    bof_name = bof_match.group(1)
                    print(f"CNA: Found BOF via readbof: {bof_name}")
                
                # Pattern 2: Direct beacon_inline_execute with inline data
                # Some commands construct the BOF data inline without readbof
                if not bof_name and 'beacon_inline_execute' in alias_body:
                    # Check if there's a readbof call anywhere in the body
                    if 'readbof' in alias_body:
                        # Extract from readbof call even if nested
                        matches = re.findall(r'readbof\s*\([^,]+,\s*"([^"]+)"', alias_body)
                        if matches:
                            bof_name = matches[0]
                            print(f"CNA: Found BOF via nested readbof: {bof_name}")
                    else:
                        # No readbof, assume the alias name is the BOF name
                        bof_name = alias_name
                        print(f"CNA: No readbof found, using alias name as BOF: {bof_name}")
                
                # Special case handling for commands with sub-functions
                # (like bnetgroup, bnetlocalgroup, etc.)
                if not bof_name and 'beacon_inline_execute' not in alias_body:
                    # Check if this alias calls a sub-function that has the BOF
                    sub_call_match = re.search(r'^\s*b(\w+)\s*\(', alias_body, re.MULTILINE)
                    if sub_call_match:
                        # It's calling a sub-function, we'll need to handle this specially
                        print(f"CNA: Alias '{alias_name}' calls sub-function: {sub_call_match.group(1)}")
                
                # Extract pack format
                pack_format = self._extract_pack_format(alias_body)
                
                self.aliases[alias_name] = CNAAlias(
                    name=alias_name,
                    parameters=params,
                    code=alias_body,
                    bof_name=bof_name,
                    pack_format=pack_format
                )
                print(f"CNA: Registered alias '{alias_name}' (BOF: {bof_name}, pack: {pack_format})")
                if self.debug_console:
                    self.debug_console.log_alias_registration(alias_name, bof_name)
        
        # Now parse sub-functions to find their BOFs and link them to aliases
        sub_pattern = r'sub\s+(\w+)\s*\{((?:[^{}]|(?:\{[^}]*\})|(?:\{[^{}]*\{[^}]*\}[^}]*\}))*)\}'
        for match in re.finditer(sub_pattern, content, re.DOTALL):
            sub_name = match.group(1)
            sub_body = match.group(2)
            
            # Look for BOF in the sub
            bof_match = re.search(r'readbof\s*\([^,]+,\s*"([^"]+)"', sub_body)
            if bof_match:
                bof_name = bof_match.group(1)
                print(f"CNA: Found BOF '{bof_name}' in sub '{sub_name}'")
                
                # Find aliases that call this sub and update their BOF name
                for alias_name, alias in self.aliases.items():
                    if f'{sub_name}(' in alias.code and not alias.bof_name:
                        alias.bof_name = bof_name
                        print(f"CNA: Updated alias '{alias_name}' with BOF '{bof_name}' from sub")

    def _resolve_bof_paths(self):
        """Pre-resolve BOF file paths for all commands"""
        for cmd_name, cmd in self.commands.items():
            if cmd_name in self.aliases:
                alias = self.aliases[cmd_name]
                if alias.bof_name:
                    bof_path = self._find_bof_file(alias.bof_name)
                    if bof_path:
                        cmd.bof_path = bof_path
                        self.bof_mappings[cmd_name] = bof_path
                        if self.debug_console:
                            self.debug_console.log("INFO", "BOF_RESOLVE", 
                                f"Resolved BOF for '{cmd_name}': {bof_path}")
                    else:
                        # Even if BOF file not found, keep the command registered
                        print(f"CNA: Warning - BOF file not found for '{cmd_name}' (looking for '{alias.bof_name}')")
    
    def _register_with_terminal(self):
        """Register parsed commands with the terminal's command validator"""
        if not self.agent_terminal:
            return
        
        # Add commands to the validator's command list
        if hasattr(self.agent_terminal, 'command_validator'):
            validator = self.agent_terminal.command_validator
            
            # Initialize CNA command storage if needed
            if not hasattr(validator, 'cna_commands'):
                validator.cna_commands = {}
            if not hasattr(validator, 'cna_bof_commands'):
                validator.cna_bof_commands = {}
            
            # Register based on mode
            for cmd_name, cmd in self.commands.items():
                # For BOF mode, register ALL commands that have an alias with beacon_inline_execute
                if self.registration_mode in ["bof", "both"]:
                    # Check if this command has an alias that uses beacon_inline_execute
                    if cmd_name in self.aliases:
                        alias = self.aliases[cmd_name]
                        # Register as BOF subcommand even if BOF path not resolved
                        # (we'll try to find it at execution time)
                        validator.cna_bof_commands[cmd_name] = {
                            'name': cmd.name,
                            'description': cmd.description,
                            'synopsis': cmd.synopsis,
                            'bof_path': cmd.bof_path,  # May be None
                            'alias': alias
                        }
                        
                        # Add to BOF subcommands list for tab completion
                        if not hasattr(self.agent_terminal, 'bof_subcommands'):
                            self.agent_terminal.bof_subcommands = []
                        if cmd_name not in self.agent_terminal.bof_subcommands:
                            self.agent_terminal.bof_subcommands.append(cmd_name)
                        
                        print(f"CNA: Registered '{cmd_name}' as BOF subcommand")
                        if self.debug_console:
                            self.debug_console.log("INFO", "REGISTER", 
                                f"Command '{cmd_name}' available as: bof {cmd_name}")
                
                # Also register as direct if in "direct" or "both" mode
                if self.registration_mode in ["direct", "both"]:
                    validator.cna_commands[cmd_name] = {
                        'name': cmd.name,
                        'description': cmd.description,
                        'synopsis': cmd.synopsis,
                        'handler': self.execute_cna_command,
                        'bof_path': cmd.bof_path
                    }
                    print(f"CNA: Registered '{cmd_name}' as direct command")
    
    def execute_cna_command(self, command: str, args: List[str]) -> bool:
        """Execute a CNA command by translating it to native BOF execution"""
        print(f"CNA: Executing command '{command}' with args {args}")
        if self.debug_console:
            self.debug_console.log_command_execution(command, args)
        
        # Find the alias handler for this command
        if command not in self.aliases:
            print(f"CNA: No alias found for command '{command}'")
            self._log_error(f"Command '{command}' not found in loaded CNA scripts")
            if self.debug_console:
                self.debug_console.log("ERROR", "EXEC", f"Command '{command}' has no alias handler")
            return False
        
        alias = self.aliases[command]
        
        # If it's a BOF command, translate to our BOF handler
        if alias.bof_name:
            return self._execute_as_bof(alias, args)
        
        # Otherwise, try to interpret the CNA code
        return self._interpret_alias(alias, args)
    
    def execute_as_bof_subcommand(self, subcommand: str, args: List[str], async_mode: bool = False) -> bool:
        """Execute a CNA command as a BOF subcommand (called via 'bof <cmd>')"""
        print(f"CNA: Executing as BOF subcommand: {subcommand} (async: {async_mode})")
        
        # Check if this is a registered CNA BOF command
        if not hasattr(self.agent_terminal.command_validator, 'cna_bof_commands'):
            return False
        
        if subcommand not in self.agent_terminal.command_validator.cna_bof_commands:
            return False
        
        cmd_info = self.agent_terminal.command_validator.cna_bof_commands[subcommand]
        alias = cmd_info.get('alias')
        
        # Try to find BOF path - either pre-resolved or find it now
        bof_path = cmd_info.get('bof_path')
        if not bof_path and alias and alias.bof_name:
            # Try to find it now
            bof_path = self._find_bof_file(alias.bof_name)
        
        if not bof_path:
            self._log_error(f"No BOF file found for command '{subcommand}'")
            return False
        
        # Build the BOF command
        if self.agent_terminal and hasattr(self.agent_terminal, 'bof_handler'):
            bof_handler = self.agent_terminal.bof_handler
            
            # Format arguments based on alias pack format if available
            formatted_args = args
            if alias and alias.pack_format:
                formatted_args = self._format_bof_args(args, alias.pack_format)
            
            # Execute via BOF handler
            full_args = [bof_path] + formatted_args
            
            print(f"CNA: Calling BOF handler with args: {full_args}")
            
            # Use async or sync based on request
            command_type = 'bof-async' if async_mode else 'bof'
            return bof_handler.handle_bof_command(command_type, full_args)
        
        return False
    
    def _execute_as_bof(self, alias: CNAAlias, args: List[str]) -> bool:
        """Execute a CNA alias as a BOF command"""
        bof_name = alias.bof_name
        
        print(f"CNA: Executing BOF '{bof_name}' for alias '{alias.name}'")
        
        # Find the BOF file
        bof_path = self._find_bof_file(bof_name)
        if not bof_path:
            self._log_error(f"BOF file not found for '{bof_name}'. Expected in script directory.")
            return False
        
        print(f"CNA: Found BOF at {bof_path}")
        
        # Build the BOF command
        if self.agent_terminal and hasattr(self.agent_terminal, 'bof_handler'):
            bof_handler = self.agent_terminal.bof_handler
            
            # Format arguments based on pack format
            formatted_args = self._format_bof_args(args, alias.pack_format)
            
            # Execute via BOF handler
            full_args = [bof_path] + formatted_args
            
            print(f"CNA: Calling BOF handler with args: {full_args}")
            
            return bof_handler.handle_bof_command('bof', full_args)
        else:
            self._log_error("BOF handler not available")
            return False
    
    def _format_bof_args(self, args: List[str], pack_format: str) -> List[str]:
        """Format arguments based on CNA pack format

        CNA/Cobalt Strike bof_pack format specifiers:
        - z = null-terminated string (char*)
        - Z = null-terminated wide string (wchar_t*)
        - i = 32-bit integer
        - I = 64-bit integer
        - s = 16-bit short integer
        - b = binary data (length-prefixed)
        """
        if not pack_format:
            return args

        formatted = []
        format_chars = list(pack_format)

        for i, (arg, fmt) in enumerate(zip(args, format_chars)):
            if fmt == 'z':  # Narrow string (char*)
                formatted.append(f"-s:{arg}")
            elif fmt == 'Z':  # Wide string (wchar_t*)
                formatted.append(f"-w:{arg}")
            elif fmt == 'i':  # 32-bit int
                formatted.append(f"-i:{arg}")
            elif fmt == 'I':  # 64-bit int
                formatted.append(f"-I:{arg}")
            elif fmt == 's':  # Short (16-bit)
                formatted.append(f"-h:{arg}")
            elif fmt == 'b':  # Binary data
                formatted.append(f"-z:{arg}")
            else:
                formatted.append(arg)

        # Add any remaining args
        if len(args) > len(format_chars):
            formatted.extend(args[len(format_chars):])

        return formatted
    
    def _find_bof_file(self, bof_name: str) -> Optional[str]:
        """Find BOF file in loaded script directories"""
        # Determine architecture
        arch = 'x64'  # Default, should get from agent
        if self.agent_terminal and hasattr(self.agent_terminal, 'agent_arch'):
            arch = self.agent_terminal.agent_arch
        
        # BOF filename patterns to try
        bof_patterns = [
            f"{bof_name}.{arch}.o",
            f"{bof_name}.o",
            f"{bof_name}/{bof_name}.{arch}.o",
            f"{bof_name}/{bof_name}.o"
        ]
        
        search_paths = []
        
        # Search in script directories
        for script_dir in self.loaded_scripts:
            for pattern in bof_patterns:
                # Check in script dir
                bof_path = os.path.join(script_dir, pattern)
                search_paths.append(bof_path)
                if os.path.exists(bof_path):
                    if self.debug_console:
                        self.debug_console.log_bof_search(bof_name, search_paths, bof_path)
                    return bof_path
                
                # Check one level up (common structure for BOF repos)
                parent_dir = os.path.dirname(script_dir)
                bof_path = os.path.join(parent_dir, pattern)
                search_paths.append(bof_path)
                if os.path.exists(bof_path):
                    if self.debug_console:
                        self.debug_console.log_bof_search(bof_name, search_paths, bof_path)
                    return bof_path
                
                # Check in 'src' subdirectory (another common pattern)
                src_path = os.path.join(script_dir, 'src', pattern)
                search_paths.append(src_path)
                if os.path.exists(src_path):
                    if self.debug_console:
                        self.debug_console.log_bof_search(bof_name, search_paths, src_path)
                    return src_path
        
        print(f"CNA: Could not find BOF file for '{bof_name}' in paths: {self.loaded_scripts}")
        if self.debug_console:
            self.debug_console.log_bof_search(bof_name, search_paths, None)
        return None
    
    def _extract_pack_format(self, alias_code: str) -> str:
        """Extract BOF packing format from alias code"""
        # Look for bof_pack calls
        pack_match = re.search(r'bof_pack\([^,]+,\s*"([^"]+)"', alias_code)
        if pack_match:
            return pack_match.group(1)
        return ""
    
    def _interpret_alias(self, alias: CNAAlias, args: List[str]) -> bool:
        """Interpret non-BOF alias code (limited implementation)"""
        # This is a simplified interpreter for basic CNA operations
        code = alias.code
        
        # Replace parameter references
        for i, arg in enumerate(args):
            code = code.replace(f'${i+1}', arg)
            code = code.replace(f'@_{i+1}', arg)  # Handle array notation
        
        # Execute line by line (very simplified)
        for line in code.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Handle basic function calls
            if 'btask(' in line:
                self._execute_line(line)
            elif 'blog(' in line:
                self._execute_line(line)
            elif 'berror(' in line:
                self._execute_line(line)
            elif 'println(' in line:
                # Handle println statements
                match = re.search(r'println\((.*)\)', line)
                if match:
                    content = match.group(1).strip().strip('"')
                    self._log_message(content)
        
        return True
    
    def _execute_line(self, line: str):
        """Execute a single line of CNA code (simplified)"""
        # Extract function call
        match = re.match(r'(\w+)\((.*)\)', line)
        if match:
            func_name = match.group(1)
            args_str = match.group(2)
            
            # Parse arguments (simplified - handles basic strings)
            args = []
            if args_str:
                # Split by comma but respect quotes
                parts = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', args_str)
                for part in parts:
                    part = part.strip()
                    if part.startswith('"') and part.endswith('"'):
                        args.append(part[1:-1])
                    else:
                        args.append(part)
            
            # Call appropriate function
            if func_name == 'btask':
                self._log_task(*args)
            elif func_name == 'blog':
                self._log_message(*args)
            elif func_name == 'berror':
                self._log_error(*args)
            elif func_name == 'println':
                self._log_message(*args)
    
    # CNA function implementations
    def _log_task(self, *args):
        """btask implementation"""
        if self.agent_terminal:
            message = args[1] if len(args) > 1 else (args[0] if args else "")
            timestamp = datetime.now().isoformat()
            self.agent_terminal.command_buffer.add_output({
                "timestamp": timestamp,
                "output": f"[*] {message}"
            })
            self.agent_terminal.update_display()
    
    def _log_message(self, *args):
        """blog implementation"""
        if self.agent_terminal:
            message = args[1] if len(args) > 1 else (args[0] if args else "")
            timestamp = datetime.now().isoformat()
            self.agent_terminal.command_buffer.add_output({
                "timestamp": timestamp,
                "output": f"[+] {message}"
            })
            self.agent_terminal.update_display()
    
    def _log_error(self, *args):
        """berror implementation"""
        if self.agent_terminal:
            message = args[1] if len(args) > 1 else (args[0] if args else "")
            timestamp = datetime.now().isoformat()
            self.agent_terminal.command_buffer.add_output({
                "timestamp": timestamp,
                "output": f"[-] Error: {message}"
            })
            self.agent_terminal.update_display()
    
    # ... rest of the methods remain the same ...
    
    def unload_script(self, script_path: str) -> bool:
        """Unload a specific CNA script and clean up its registrations"""
        if script_path not in self.loaded_scripts:
            return False
        
        # Find all commands and aliases associated with this script path
        script_dir = os.path.dirname(script_path)
        
        # Track what we're removing
        commands_to_remove = []
        aliases_to_remove = []
        
        # Find commands that belong to this script
        for cmd_name, cmd in self.commands.items():
            if cmd.bof_path and script_dir in cmd.bof_path:
                commands_to_remove.append(cmd_name)
        
        # Find aliases that belong to this script
        for alias_name, alias in self.aliases.items():
            # Check if the BOF file for this alias is in the script directory
            if alias.bof_name:
                bof_path = self._find_bof_file(alias.bof_name)
                if bof_path and script_dir in bof_path:
                    aliases_to_remove.append(alias_name)
        
        # Remove from interpreter
        for cmd_name in commands_to_remove:
            del self.commands[cmd_name]
            
        for alias_name in aliases_to_remove:
            del self.aliases[alias_name]
        
        # Remove from loaded scripts
        self.loaded_scripts.remove(script_path)
        
        # Clean up from command validator if terminal is available
        if self.agent_terminal and hasattr(self.agent_terminal, 'command_validator'):
            validator = self.agent_terminal.command_validator
            
            # Remove from CNA commands
            if hasattr(validator, 'cna_commands'):
                for cmd_name in commands_to_remove:
                    if cmd_name in validator.cna_commands:
                        del validator.cna_commands[cmd_name]
            
            # Remove from BOF commands
            if hasattr(validator, 'cna_bof_commands'):
                for cmd_name in commands_to_remove:
                    if cmd_name in validator.cna_bof_commands:
                        del validator.cna_bof_commands[cmd_name]
            
            # Remove from BOF subcommands list
            if hasattr(self.agent_terminal, 'bof_subcommands'):
                for cmd_name in commands_to_remove:
                    if cmd_name in self.agent_terminal.bof_subcommands:
                        self.agent_terminal.bof_subcommands.remove(cmd_name)
        
        if self.debug_console:
            self.debug_console.log("INFO", "UNLOAD", 
                f"Unloaded script: {script_path}, removed {len(commands_to_remove)} commands")
        
        return True

    def unload_all_scripts(self):
        """Unload all CNA scripts and clean up everything"""
        scripts_to_unload = list(self.loaded_scripts)  # Make a copy
        
        for script_path in scripts_to_unload:
            self.unload_script(script_path)
        
        # Clear everything
        self.commands.clear()
        self.aliases.clear()
        self.loaded_scripts.clear()
        self.bof_mappings.clear()
        
        # Clear from validator
        if self.agent_terminal and hasattr(self.agent_terminal, 'command_validator'):
            validator = self.agent_terminal.command_validator
            if hasattr(validator, 'cna_commands'):
                validator.cna_commands.clear()
            if hasattr(validator, 'cna_bof_commands'):
                validator.cna_bof_commands.clear()
        
        if self.debug_console:
            self.debug_console.log("INFO", "UNLOAD", "All scripts unloaded")