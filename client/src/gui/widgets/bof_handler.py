# client/src/gui/widgets/bof_handler.py

import os
import json
import base64
import hashlib
import threading
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class BOFFile:
    """Represents a BOF file to be sent to agent"""
    path: str
    name: str
    arch: str  # x86 or x64
    size: int
    hash: str
    data: bytes

class BOFArgumentParser:
    """Parses BOF arguments according to Cobalt Strike format"""
    
    @staticmethod
    def parse_arguments(args: List[str]) -> bytes:
        """
        Parse arguments into BOF format
        Argument types:
        - -s:string : String (char*)
        - -w:string : Wide string (wchar_t*)
        - -i:number : 32-bit integer
        - -I:number : 64-bit integer
        - -h:number : 16-bit short integer
        - -z:data   : Binary data (base64)
        - -Z:data   : Binary data with size
        - plain str : Treated as string
        """
        buffer = bytearray()

        for arg in args:
            if arg.startswith('-'):
                # Typed argument
                if ':' not in arg:
                    # Plain string if no type specifier
                    buffer.extend(BOFArgumentParser._pack_string(arg))
                    continue

                arg_type, value = arg.split(':', 1)

                if arg_type == '-s':
                    # String
                    buffer.extend(BOFArgumentParser._pack_string(value))
                elif arg_type == '-w':
                    # Wide string
                    buffer.extend(BOFArgumentParser._pack_wstring(value))
                elif arg_type == '-i':
                    # 32-bit int
                    buffer.extend(BOFArgumentParser._pack_int32(int(value)))
                elif arg_type == '-I':
                    # 64-bit int
                    buffer.extend(BOFArgumentParser._pack_int64(int(value)))
                elif arg_type == '-h':
                    # 16-bit short int
                    buffer.extend(BOFArgumentParser._pack_int16(int(value)))
                elif arg_type == '-z':
                    # Binary data (base64)
                    buffer.extend(base64.b64decode(value))
                elif arg_type == '-Z':
                    # Binary data with size
                    data = base64.b64decode(value)
                    buffer.extend(BOFArgumentParser._pack_int32(len(data)))
                    buffer.extend(data)
            else:
                # Plain string argument - pack as 'z' type for BOF
                buffer.extend(BOFArgumentParser._pack_bof_string(arg))
        
        return bytes(buffer)
    
    @staticmethod
    def _pack_string(s: str) -> bytes:
        """Pack a string in BOF format with length prefix"""
        # Format: length (4 bytes) + string data + null terminator
        # BeaconDataExtract expects length-prefixed data
        data = s.encode('utf-8') + b'\x00'
        length = len(data)
        result = bytearray(4)
        result[0] = length & 0xFF
        result[1] = (length >> 8) & 0xFF
        result[2] = (length >> 16) & 0xFF
        result[3] = (length >> 24) & 0xFF
        result.extend(data)
        return bytes(result)
    
    @staticmethod
    def _pack_bof_string(s: str) -> bytes:
        """Pack a string in BOF format with length prefix"""
        # Format: length (4 bytes) + string data + null terminator
        data = s.encode('utf-8') + b'\x00'
        length = len(data)
        result = bytearray(4)
        result[0] = length & 0xFF
        result[1] = (length >> 8) & 0xFF
        result[2] = (length >> 16) & 0xFF
        result[3] = (length >> 24) & 0xFF
        result.extend(data)
        return bytes(result)
    
    @staticmethod
    def _pack_wstring(s: str) -> bytes:
        """Pack a wide string in BOF format with length prefix"""
        # Format: length (4 bytes) + wide string data + null terminator
        # BeaconDataExtract expects length-prefixed data
        data = s.encode('utf-16le') + b'\x00\x00'
        length = len(data)
        result = bytearray(4)
        result[0] = length & 0xFF
        result[1] = (length >> 8) & 0xFF
        result[2] = (length >> 16) & 0xFF
        result[3] = (length >> 24) & 0xFF
        result.extend(data)
        return bytes(result)
    
    @staticmethod
    def _pack_int16(i: int) -> bytes:
        """Pack a 16-bit short integer (little endian)"""
        return i.to_bytes(2, 'little', signed=True)

    @staticmethod
    def _pack_int32(i: int) -> bytes:
        """Pack a 32-bit integer (little endian)"""
        return i.to_bytes(4, 'little', signed=True)
    
    @staticmethod
    def _pack_int64(i: int) -> bytes:
        """Pack a 64-bit integer (little endian)"""
        return i.to_bytes(8, 'little', signed=True)

class BOFHandler:
    """Handles BOF command execution and management"""
    
    CHUNK_SIZE = 512 * 1024  # 512KB chunks
    
    def __init__(self, websocket_client, agent_terminal):
        """Initialize BOF handler with websocket and terminal references"""
        print(f"DEBUG BOF: Initializing BOFHandler")
        print(f"DEBUG BOF: websocket_client: {websocket_client}")
        print(f"DEBUG BOF: agent_terminal: {agent_terminal}")
        
        self.ws_client = websocket_client
        self.agent_terminal = agent_terminal
        self.loaded_bofs: Dict[str, BOFFile] = {}
        self.async_jobs: Dict[str, Dict] = {}
        self.upload_lock = threading.Lock()
        
        print(f"DEBUG BOF: BOFHandler initialized")
        print(f"DEBUG BOF: ws_client set to: {self.ws_client}")
        print(f"DEBUG BOF: agent_terminal set to: {self.agent_terminal}")
        if self.agent_terminal:
            print(f"DEBUG BOF: agent_terminal.agent_guid: {self.agent_terminal.agent_guid}")
        
    def handle_bof_command(self, command: str, args: List[str]) -> bool:
        """
        Main entry point for BOF command handling
        Returns True if command was handled, False otherwise
        """
        print(f"DEBUG BOF: handle_bof_command called")
        print(f"DEBUG BOF: command: {command}")
        print(f"DEBUG BOF: args: {args}")
        
        # First, add the full command to history
        self._add_to_history(command, args)
        
        if command == "bof":
            return self._handle_bof_execute(args, async_mode=False)
        elif command == "bof-async":
            return self._handle_bof_execute(args, async_mode=True)
        elif command == "bof-jobs":
            return self._handle_bof_jobs()
        elif command == "bof-output":
            return self._handle_bof_output(args)
        elif command == "bof-kill":
            return self._handle_bof_kill(args)
        elif command == "bof-load":
            return self._handle_bof_load(args)
        elif command == "bof-exec":
            return self._handle_bof_exec(args)
        elif command == "bof-list":
            return self._handle_bof_list()
        elif command == "bof-unload":
            return self._handle_bof_unload(args)
        
        print(f"DEBUG BOF: Command not recognized: {command}")
        return False
    
    def _add_to_history(self, command: str, args: List[str]):
        """Add the full command to the command history buffer"""
        if self.agent_terminal and hasattr(self.agent_terminal, 'command_buffer'):
            # Reconstruct the full command string
            full_command = command
            if args:
                full_command += " " + " ".join(args)
            
            # Add to the command buffer for history
            timestamp = datetime.now().isoformat()
            username = self.agent_terminal.command_buffer.username or "user"
            formatted_command = {
                "timestamp": timestamp,
                "output": f"[{timestamp}] {username} > {full_command}"
            }
            #self.agent_terminal.command_buffer.add_output(formatted_command)
            #self.agent_terminal.update_display()
            self.agent_terminal.command_history.add_command(full_command)
    
    def _handle_bof_execute(self, args: List[str], async_mode: bool = False) -> bool:
        """Execute a BOF file"""
        print(f"DEBUG BOF: _handle_bof_execute called")
        print(f"DEBUG BOF: args: {args}")
        print(f"DEBUG BOF: async_mode: {async_mode}")
        
        if len(args) < 1:
            self._print_error("Usage: bof[-async] <path_to_bof.o> [arguments...]")
            return True
            
        bof_path = args[0]
        bof_args = args[1:] if len(args) > 1 else []
        
        print(f"DEBUG BOF: BOF path: {bof_path}")
        print(f"DEBUG BOF: BOF args: {bof_args}")
        
        # Validate BOF file exists
        if not os.path.exists(bof_path):
            print(f"DEBUG BOF: File does not exist: {bof_path}")
            self._print_error(f"BOF file not found: {bof_path}")
            return True
        
        print(f"DEBUG BOF: File exists, loading...")
        
        # Load BOF file
        try:
            bof_file = self._load_bof_file(bof_path)
            print(f"DEBUG BOF: BOF file loaded successfully")
            print(f"DEBUG BOF: File details - name: {bof_file.name}, size: {bof_file.size}, arch: {bof_file.arch}")
        except Exception as e:
            print(f"DEBUG BOF: Failed to load BOF: {e}")
            import traceback
            traceback.print_exc()
            self._print_error(f"Failed to load BOF: {e}")
            return True
        
        # Keep the FULL original command string including the file path
        full_args_string = " ".join(args) if args else ""  # This includes file path + arguments
        
        try:
            packed_args = BOFArgumentParser.parse_arguments(bof_args)
            print(f"DEBUG BOF: Arguments parsed, packed size: {len(packed_args)} bytes")
        except Exception as e:
            print(f"DEBUG BOF: Failed to parse arguments: {e}")
            import traceback
            traceback.print_exc()
            self._print_error(f"Failed to parse arguments: {e}")
            return True
        
        print(f"DEBUG BOF: Calling _send_bof_command...")
        
        # Send BOF to agent with the FULL original command string
        try:
            self._send_bof_command(bof_file, packed_args, async_mode, full_args_string)
            print(f"DEBUG BOF: _send_bof_command completed")
        except Exception as e:
            print(f"DEBUG BOF: Exception in _send_bof_command: {e}")
            import traceback
            traceback.print_exc()
            self._print_error(f"Failed to send BOF: {e}")
        
        return True

    def _send_bof_command(self, bof_file: BOFFile, args: bytes, async_mode: bool, full_args_string: str = ""):
        """Send BOF command to agent via websocket"""
        print(f"DEBUG BOF: Starting to send BOF command")
        print(f"DEBUG BOF: File: {bof_file.name}, Size: {bof_file.size}, Arch: {bof_file.arch}")
        print(f"DEBUG BOF: Async mode: {async_mode}")
        print(f"DEBUG BOF: Arguments length: {len(args)} bytes")
        print(f"DEBUG BOF: Full args string: {full_args_string}")
        
        # Calculate total chunks
        total_chunks = (len(bof_file.data) + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
        print(f"DEBUG BOF: Total chunks: {total_chunks}")
        
        # Generate command ID
        import uuid
        command_id = str(uuid.uuid4())
        print(f"DEBUG BOF: Command ID: {command_id}")
        
        # Check if we have agent_terminal and agent_guid
        print(f"DEBUG BOF: Agent terminal exists: {self.agent_terminal is not None}")
        if self.agent_terminal:
            print(f"DEBUG BOF: Agent GUID: {self.agent_terminal.agent_guid}")
        else:
            print(f"DEBUG BOF: ERROR - No agent terminal!")
            self._print_error("No agent terminal available")
            return
        
        if not self.agent_terminal.agent_guid:
            print(f"DEBUG BOF: ERROR - No agent GUID!")
            self._print_error("No agent selected")
            return
        
        # Check WebSocket client
        print(f"DEBUG BOF: WebSocket client exists: {self.ws_client is not None}")
        if not self.ws_client:
            print(f"DEBUG BOF: ERROR - No WebSocket client!")
            self._print_error("Not connected to server")
            return
        
        # Build the FULL command string for the server (including file path and arguments)
        full_command = "bof-async" if async_mode else "bof"
        if full_args_string:
            full_command += " " + full_args_string  # This now includes the file path
        
        # Prepare base command
        base_command = {
            "type": "agent_command",
            "data": {
                "command": full_command,  # Send the FULL command string including file path
                "agent_id": self.agent_terminal.agent_guid,
                "command_id": command_id,
                "filename": bof_file.name,
                "arch": bof_file.arch,
                "totalChunks": total_chunks,
                "file_size": bof_file.size,
                "file_hash": bof_file.hash,
                "arguments": base64.b64encode(args).decode('utf-8'),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        print(f"DEBUG BOF: Base command structure created with full command: {full_command}")
        
        # Send chunks
        #self._print_info(f"Sending BOF '{bof_file.name}' ({bof_file.arch}) in {total_chunks} chunks...")
        
        for chunk_num in range(total_chunks):
            start = chunk_num * self.CHUNK_SIZE
            end = min(start + self.CHUNK_SIZE, len(bof_file.data))
            chunk_data = bof_file.data[start:end]
            
            chunk_command = base_command.copy()
            chunk_command["data"] = base_command["data"].copy()  # Deep copy the data dict
            chunk_command["data"]["currentChunk"] = chunk_num
            chunk_command["data"]["data"] = base64.b64encode(chunk_data).decode('utf-8')
            
            print(f"DEBUG BOF: Sending chunk {chunk_num + 1}/{total_chunks}, size: {len(chunk_data)} bytes")
            
            try:
                # Send via websocket
                # The ws_client is actually the WebSocketThread object
                if hasattr(self.ws_client, 'ws_client') and self.ws_client.ws_client:
                    # Access the actual WebSocket client through the thread
                    print(f"DEBUG BOF: Using WebSocketThread's ws_client.send_message()")
                    import asyncio
                    
                    # Check if we have access to the event loop
                    if hasattr(self.ws_client, 'loop') and self.ws_client.loop:
                        future = asyncio.run_coroutine_threadsafe(
                            self.ws_client.ws_client.send_message(json.dumps(chunk_command)),
                            self.ws_client.loop
                        )
                        future.result(timeout=5)
                    else:
                        print(f"DEBUG BOF: ERROR - No event loop available")
                        raise RuntimeError("No event loop available for async operation")
                elif hasattr(self.ws_client, 'send_message'):
                    # Direct WebSocket client (shouldn't happen with current setup)
                    print(f"DEBUG BOF: Using direct ws_client.send_message()")
                    self.ws_client.send_message(json.dumps(chunk_command))
                else:
                    print(f"DEBUG BOF: ERROR - Cannot find send method")
                    print(f"DEBUG BOF: ws_client type: {type(self.ws_client)}")
                    print(f"DEBUG BOF: ws_client attributes: {dir(self.ws_client)}")
                    raise RuntimeError("Cannot find appropriate send method")
                    
                #print(f"DEBUG BOF: Chunk {chunk_num + 1} sent successfully")
                    
            except Exception as e:
                print(f"DEBUG BOF: Failed to send chunk {chunk_num + 1}: {e}")
                import traceback
                traceback.print_exc()
                self._print_error(f"Failed to send chunk {chunk_num + 1}: {e}")
                return
        
        #self._print_success(f"BOF '{bof_file.name}' sent successfully")

    # Also update _handle_bof_exec to use the full command string
    def _handle_bof_exec(self, args: List[str]) -> bool:
        """Execute loaded BOF"""
        if len(args) < 1:
            self._print_error("Usage: bof-exec <name> [arguments...]")
            return True
            
        name = args[0]
        bof_args = args[1:] if len(args) > 1 else []
        
        if name not in self.loaded_bofs:
            self._print_error(f"BOF '{name}' not loaded")
            return True
        
        bof_file = self.loaded_bofs[name]
        
        # When using bof-exec, we need to include the file path in the command
        # that gets broadcast (even though we're using a pre-loaded BOF)
        full_args_string = f"{bof_file.path} " + " ".join(bof_args) if bof_args else bof_file.path
        
        try:
            packed_args = BOFArgumentParser.parse_arguments(bof_args)
            self._send_bof_command(bof_file, packed_args, False, full_args_string)
        except Exception as e:
            self._print_error(f"Failed to execute BOF: {e}")
        
        return True

    def _load_bof_file(self, path: str) -> BOFFile:
        """Load and validate a BOF file"""
        with open(path, 'rb') as f:
            data = f.read()
        
        # Detect architecture from COFF header
        if len(data) < 2:
            raise ValueError("Invalid BOF file: too small")
            
        machine_type = int.from_bytes(data[0:2], 'little')
        if machine_type == 0x8664:
            arch = "x64"
        elif machine_type == 0x014c:
            arch = "x86"
        else:
            raise ValueError(f"Unknown machine type: 0x{machine_type:04x}")
        
        # Create BOF file object
        return BOFFile(
            path=path,
            name=os.path.basename(path),
            arch=arch,
            size=len(data),
            hash=hashlib.sha256(data).hexdigest(),
            data=data
        )
    
    def _handle_bof_jobs(self) -> bool:
        """List async BOF jobs"""
        if not self.async_jobs:
            self._print_info("No active BOF jobs")
        else:
            self._print_info(f"Active BOF jobs ({len(self.async_jobs)}):")
            for job_id, job in self.async_jobs.items():
                status = job.get('status', 'unknown')
                bof_name = job.get('bof_name', 'unknown')
                self._print_info(f"  [{job_id[:8]}...] {bof_name} - {status}")
        return True
    
    def _handle_bof_output(self, args: List[str]) -> bool:
        """Get output from async BOF job"""
        if len(args) < 1:
            self._print_error("Usage: bof-output <job_id>")
            return True
            
        job_id = args[0]
        if job_id not in self.async_jobs:
            self._print_error(f"Job not found: {job_id}")
        else:
            job = self.async_jobs[job_id]
            output = job.get('output', 'No output yet')
            self._print_info(f"Output for job {job_id}:\n{output}")
        return True
    
    def _handle_bof_kill(self, args: List[str]) -> bool:
        """Terminate async BOF job"""
        if len(args) < 1:
            self._print_error("Usage: bof-kill <job_id>")
            return True
            
        job_id = args[0]
        if job_id not in self.async_jobs:
            self._print_error(f"Job not found: {job_id}")
        else:
            # Send kill command to agent
            # TODO: Implement actual kill command
            del self.async_jobs[job_id]
            self._print_success(f"Job {job_id} terminated")
        return True
    
    def _handle_bof_load(self, args: List[str]) -> bool:
        """Load BOF into memory"""
        if len(args) < 2:
            self._print_error("Usage: bof-load <name> <path_to_bof.o>")
            return True
            
        name = args[0]
        path = args[1]
        
        try:
            bof_file = self._load_bof_file(path)
            self.loaded_bofs[name] = bof_file
            self._print_success(f"BOF '{name}' loaded ({bof_file.arch}, {bof_file.size} bytes)")
        except Exception as e:
            self._print_error(f"Failed to load BOF: {e}")
        
        return True

    def _handle_bof_list(self) -> bool:
        """List loaded BOFs"""
        if not self.loaded_bofs:
            self._print_info("No BOFs loaded")
        else:
            self._print_info(f"Loaded BOFs ({len(self.loaded_bofs)}):")
            for name, bof in self.loaded_bofs.items():
                self._print_info(f"  {name}: {bof.name} ({bof.arch}, {bof.size} bytes)")
        return True
    
    def _handle_bof_unload(self, args: List[str]) -> bool:
        """Unload BOF from memory"""
        if len(args) < 1:
            self._print_error("Usage: bof-unload <name>")
            return True
            
        name = args[0]
        if name not in self.loaded_bofs:
            self._print_error(f"BOF '{name}' not loaded")
        else:
            del self.loaded_bofs[name]
            self._print_success(f"BOF '{name}' unloaded")
        
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
    
    def handle_bof_response(self, response_data):
        """Handle BOF execution responses from the server"""
        
        # Check if it's in the output field (from the agent)
        if "output" in response_data:
            output = response_data.get("output", "")
            
            # Parse BOF_ASYNC_STARTED messages
            if output.startswith("BOF_ASYNC_STARTED|"):
                parts = output.split("|", 2)
                if len(parts) >= 3:
                    job_id = parts[1]
                    bof_name = parts[2]
                    
                    # Track the job locally
                    self.async_jobs[job_id] = {
                        "status": "running",
                        "bof_name": bof_name,
                        "start_time": datetime.now().isoformat(),
                        "output": ""
                    }
                    
                    self.command_buffer.add_output({
                        "timestamp": datetime.now().isoformat(),
                        "output": f"[+] Async BOF '{bof_name}' started with job ID: {job_id}"
                    })
                    self.agent_terminal.update_display()
                    return