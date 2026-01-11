# client/src/gui/widgets/terminal/handlers/response_handler.py

from datetime import datetime, timezone
import re
from utils.error_codes import translate_code

class ResponseHandler:
    """Handles various response types from the server"""
    
    def __init__(self, terminal):
        self.terminal = terminal
        self.agent_guid = terminal.agent_guid
        self.command_buffer = terminal.command_buffer
        self.file_uploader = terminal.file_uploader
        self.bof_handler = terminal.bof_handler if hasattr(terminal, 'bof_handler') else None
        self.inline_assembly_handler = terminal.inline_assembly_handler if hasattr(terminal, 'inline_assembly_handler') else None
        self.bof_chunks = {}  # Store pending BOF chunks

    def handle_command_output(self, output_data):
        """Handle command output from server"""
        print(f"DEBUG: AgentTerminal [{self.terminal.agent_name}] handling command output: {output_data}")
        
        try:
            # Handle command validation messages specially
            if output_data.get('type') == 'command_validation':
                return self._handle_validation_message(output_data)
            
            # Ensure the output belongs to the correct agent
            if not self._verify_agent_id(output_data):
                return
            
            # Extract and format output
            timestamp, username, command, message = self._extract_output_fields(output_data)
            
            # Format the output message
            output_text = f"\n[{timestamp}] {username} > {command}"
            if message:
                output_text += f"\n{message}"
            
            # Add to buffer and update display
            self._add_to_buffer_and_update(timestamp, output_text)
            
        except Exception as e:
            print(f"ERROR in handle_command_output: {e}")
    
    def handle_command_result(self, result_data):
        """Handle command execution results"""
        # Ensure the result belongs to the correct agent
        # If agent_guid is None (general terminal), accept all messages
        if self.agent_guid is not None and self.agent_guid != result_data.get('agent_id'):
            print(f"AgentTerminal [{self.terminal.agent_name}]: Skipping result not meant for this agent.")
            return

        print(f"AgentTerminal [{self.terminal.agent_name}]: Handling command result: {result_data}")

        timestamp = result_data.get('timestamp', datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
        output = result_data.get('output', '')
        command_id = result_data.get('command_id', '')  # Get command ID for chunk tracking
        status = result_data.get('status', '')

        # Translate error/success codes to human-readable messages
        output = translate_code(output)

        # For 'queued' status (API command prompts), the output is already formatted
        # from dialogs.py with proper newlines - just display it as-is
        if status == 'queued':
            formatted_output = {
                "timestamp": timestamp,
                "output": output
            }
            self.command_buffer.add_output(formatted_output)
            self.terminal.update_display(incremental=True)
            return
        
        # Check for BOF chunks FIRST (handles multi-chunk BOF output)
        if self._is_bof_chunk(output):
            complete_output = self._handle_bof_chunk(output, command_id, timestamp)
            if complete_output:
                # All chunks received, display the complete output
                formatted_output = {
                    "timestamp": timestamp,
                    "output": f"\n{complete_output}"
                }
                self.command_buffer.add_output(formatted_output)
                self.terminal.update_display(incremental=True)
            # If not complete, don't display anything yet
            return
        
        # Check if this is compressed BOF output (single chunk without [BOF Chunk] header)
        # This handles cases where BOF output comes in a single response
        if output.strip().startswith('H4sI'):
            try:
                import base64
                import gzip
                import io
                
                # Split by newlines in case there are multiple compressed blocks
                lines = output.strip().split('\n')
                decompressed_parts = []
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('H4sI'):
                        try:
                            # Decode and decompress each compressed block
                            compressed_data = base64.b64decode(line)
                            with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz:
                                decompressed = gz.read().decode('utf-8', errors='replace')
                                decompressed_parts.append(decompressed)
                        except Exception as e:
                            print(f"Failed to decompress line: {e}")
                            decompressed_parts.append(line)  # Keep original if decompression fails
                    elif line:  # Non-compressed, non-empty lines
                        decompressed_parts.append(line)
                
                # Join all decompressed parts
                if decompressed_parts:
                    decompressed_output = '\n'.join(decompressed_parts)
                    formatted_output = {
                        "timestamp": timestamp,
                        "output": f"\n{decompressed_output}"
                    }
                    self.command_buffer.add_output(formatted_output)
                    self.terminal.update_display(incremental=True)
                    return
                
            except Exception as e:
                print(f"Failed to decompress output: {e}")
                # Fall through to display as-is if decompression completely fails
        
        # Check for inline-assembly results
        if self._is_inline_assembly_result(output):
            formatted_output = {
                "timestamp": timestamp,
                "output": f"\n[Inline-Assembly Result]\n{output}"
            }
            self.command_buffer.add_output(formatted_output)
            self.terminal.update_display(incremental=True)
            return
        
        # Parse BOF async status messages
        if output.startswith("BOF_ASYNC_"):
            self._handle_bof_async_status(output, timestamp)
            return
        
        # Check if output contains a completion message that should be shown
        # This handles messages like "[BOF completed - X bytes output sent in Y chunks]"
        if "[BOF completed" in output or "BOF chunk" in output:
            # These are status messages, display them as-is
            formatted_output = {
                "timestamp": timestamp,
                "output": f"\n{output}"
            }
            self.command_buffer.add_output(formatted_output)
            self.terminal.update_display(incremental=True)
            return
        
        # Default formatting for other outputs
        # End with \n\n to create blank line before next command prompt
        formatted_output = {
            "timestamp": timestamp,
            "output": f"{output}\n\n"
        }
        self.command_buffer.add_output(formatted_output)
        self.terminal.update_display(incremental=True)

    def handle_upload_response(self, response_data):
        """Handle upload chunk responses"""
        self.file_uploader.handle_upload_response(response_data)
    
    def handle_bof_response(self, response_data):
        """Handle BOF execution responses from the server"""
        response_type = response_data.get("type", "")
        
        if response_type == "bof_output":
            output = response_data.get("output", "")
            error = response_data.get("error", "")
            
            if output:
                self.command_buffer.add_output({
                    "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    "output": f"[BOF Output]\n{output}"
                })
            if error:
                self.command_buffer.add_output({
                    "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    "output": f"[BOF Error]\n{error}"
                })
        
        self.terminal.update_display(incremental=True)
    
    def handle_inline_assembly_response(self, response_data):
        """Handle inline-assembly execution responses from the server"""
        response_type = response_data.get("type", "")
        
        if response_type == "inline_assembly_result":
            output = response_data.get("output", "")
            error = response_data.get("error", "")
            
            if output:
                self.command_buffer.add_output({
                    "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    "output": f"[Inline-Assembly Output]\n{output}"
                })
            if error:
                self.command_buffer.add_output({
                    "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    "output": f"[Inline-Assembly Error]\n{error}"
                })
                
        elif response_type == "inline_assembly_async_started":
            job_id = response_data.get("job_id", "")
            assembly_name = response_data.get("assembly_name", "")
            self.command_buffer.add_output({
                "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                "output": f"[+] Async assembly '{assembly_name}' started with job ID: {job_id}"
            })
            
        elif response_type == "inline_assembly_async_completed":
            job_id = response_data.get("job_id", "")
            self.command_buffer.add_output({
                "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                "output": f"[+] Async assembly job {job_id[:8]}... completed"
            })
        
        self.terminal.update_display(incremental=True)
    
    # Private helper methods
    def _handle_validation_message(self, output_data):
        """Handle command validation messages"""
        if 'data' in output_data and 'agent_id' in output_data['data']:
            if self.agent_guid != output_data['data']['agent_id']:
                print(f"DEBUG: Skipping output - agent mismatch")
                return
        
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        if 'data' in output_data:
            timestamp = output_data['data'].get('timestamp', timestamp)
            username = output_data['data'].get('username', 'Unknown User')
            command = output_data['data'].get('command', 'Unknown Command')
            
            # Check for stored full upload command
            if command.startswith('upload') and self.file_uploader.original_command:
                command = self.file_uploader.original_command
        
        output_text = f"\n[{timestamp}] {username} > {command}"
        if output_data.get('message'):
            output_text += f"\n{output_data['message']}"
        
        self._add_to_buffer_and_update(timestamp, output_text)
    
    def _verify_agent_id(self, output_data):
        """Verify the output belongs to the correct agent"""
        if 'data' in output_data and 'agent_id' in output_data['data']:
            if self.agent_guid != output_data['data']['agent_id']:
                print(f"DEBUG: Skipping output - agent mismatch")
                return False
        return True
    
    def _extract_output_fields(self, output_data):
        """Extract relevant fields from output data"""
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        if 'data' in output_data:
            timestamp = output_data['data'].get('timestamp', timestamp)
            username = output_data['data'].get('username', 'Unknown User')
            command = output_data['data'].get('command', 'Unknown Command')
            message = output_data.get('message', '')
        else:
            username = "System"
            command = output_data.get('message', 'Command Validation')
            message = f"Status: {output_data.get('status', 'unknown')}"
        
        return timestamp, username, command, message
    
    def _add_to_buffer_and_update(self, timestamp, output_text):
        """Add output to buffer and update display"""
        formatted_output = {
            "timestamp": timestamp,
            "output": output_text
        }
        print(f"DEBUG: Adding to command buffer: {formatted_output}")
        self.command_buffer.add_output(formatted_output)
        
        print("DEBUG: Updating terminal display")
        self.terminal.update_display(incremental=True)
    
    def _is_inline_assembly_result(self, output):
        """Check if output is an inline-assembly result"""
        markers = ["[*] Assembly type:", "[+] Assembly executed", "[Assembly Output]"]
        return any(marker in output for marker in markers)
    
    def _is_bof_chunk(self, output):
        """Check if output is a BOF chunk"""
        pattern = r'\[BOF Chunk \d+/\d+\]'
        return re.search(pattern, output) is not None
    
    def _handle_bof_chunk(self, output, command_id, timestamp):
        """Handle BOF chunk and return complete output when all chunks are received"""
        import base64
        import gzip
        import io
        
        # Parse chunk info
        match = re.search(r'\[BOF Chunk (\d+)/(\d+)\]', output)
        if not match:
            return output  # Not a valid chunk format, return as-is
        
        current_chunk = int(match.group(1))
        total_chunks = int(match.group(2))
        
        # Extract chunk content (everything after the chunk header)
        # Look for content after the chunk header, including newlines
        chunk_pattern = r'\[BOF Chunk \d+/\d+\]\n?'
        chunk_content = re.sub(chunk_pattern, '', output)
        
        # Use command_id or create a unique key if not provided
        chunk_key = command_id if command_id else f"unknown_{timestamp}"
        
        # Initialize storage for this command if needed
        if chunk_key not in self.bof_chunks:
            self.bof_chunks[chunk_key] = {
                'chunks': {},
                'total': total_chunks,
                'timestamp': timestamp
            }
            print(f"BOF: Starting chunk collection for {chunk_key}, expecting {total_chunks} chunks")
        
        # Store this chunk (just the content, not the header)
        self.bof_chunks[chunk_key]['chunks'][current_chunk] = chunk_content
        
        print(f"BOF: Chunk {current_chunk}/{total_chunks} received for {chunk_key} ({len(chunk_content)} bytes)")
        
        # Check if all chunks received
        received_chunks = len(self.bof_chunks[chunk_key]['chunks'])
        if received_chunks == total_chunks:
            # Reassemble in order
            complete_output = ""
            for i in range(1, total_chunks + 1):
                if i in self.bof_chunks[chunk_key]['chunks']:
                    complete_output += self.bof_chunks[chunk_key]['chunks'][i]
                else:
                    print(f"BOF: WARNING - Missing chunk {i} during reassembly")
            
            # Clean up
            del self.bof_chunks[chunk_key]
            
            print(f"BOF: All {total_chunks} chunks received and reassembled ({len(complete_output)} bytes)")
            
            # Check if this is compressed data (starts with gzip header in base64)
            if complete_output.strip().startswith('H4sI'):
                try:
                    # Handle multiple compressed blocks separated by newlines
                    lines = complete_output.strip().split('\n')
                    decompressed_parts = []
                    
                    for line in lines:
                        line = line.strip()
                        if line.startswith('H4sI'):
                            try:
                                # Decode base64
                                compressed_data = base64.b64decode(line)
                                
                                # Decompress gzip data
                                with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz:
                                    decompressed = gz.read().decode('utf-8', errors='replace')
                                    decompressed_parts.append(decompressed)
                                    
                            except Exception as e:
                                print(f"BOF: Failed to decompress chunk line: {e}")
                                decompressed_parts.append(line)
                        elif line:  # Keep non-compressed, non-empty lines
                            decompressed_parts.append(line)
                    
                    if decompressed_parts:
                        decompressed_output = '\n'.join(decompressed_parts)
                        print(f"BOF: Decompressed {len(complete_output)} bytes to {len(decompressed_output)} bytes")
                        return decompressed_output
                    
                except Exception as e:
                    print(f"BOF: Failed to decompress output: {e}")
                    # Return the raw data if decompression fails
                    return complete_output
            
            # Return as-is if not compressed
            return complete_output
        
        # Still waiting for more chunks
        print(f"BOF: Waiting for more chunks: {received_chunks}/{total_chunks}")
        return None

    def _handle_bof_async_status(self, output, timestamp):
        """Handle BOF async status messages"""
        parts = output.split("|", 2)
        if len(parts) >= 3:
            status_type = parts[0]
            job_id = parts[1]
            message = parts[2] if len(parts) > 2 else ""
            
            # For BOF_ASYNC_OUTPUT chunks, check if it's chunked
            if status_type == "BOF_ASYNC_OUTPUT" and message.startswith("CHUNK_"):
                # This is a chunked async output
                chunk_parts = message.split("|", 1)
                if len(chunk_parts) > 1:
                    chunk_info = chunk_parts[0]  # e.g., "CHUNK_1"
                    chunk_content = chunk_parts[1] if len(chunk_parts) > 1 else ""
                    
                    # Check if this is also in the [BOF Chunk X/Y] format
                    if self._is_bof_chunk(chunk_content):
                        complete_output = self._handle_bof_chunk(chunk_content, f"async_{job_id}", timestamp)
                        if complete_output:
                            # All chunks received for this async job
                            formatted_output = {
                                "timestamp": timestamp,
                                "output": f"\n[BOF Async Output - Job {job_id}]\n{complete_output}"
                            }
                        else:
                            # Still collecting chunks
                            return
                    else:
                        # Single chunk of async output
                        formatted_output = {
                            "timestamp": timestamp,
                            "output": f"\n[BOF Async Output - Job {job_id}]\n{chunk_content}"
                        }
                else:
                    formatted_output = {
                        "timestamp": timestamp,
                        "output": f"\n{output}"
                    }
            elif status_type == "BOF_ASYNC_STARTED":
                if self.bof_handler:
                    self.bof_handler.async_jobs[job_id] = {
                        "status": "running",
                        "bof_name": message,
                        "start_time": timestamp,
                        "output": ""
                    }
                
                formatted_output = {
                    "timestamp": timestamp,
                    "output": f"\n[+] Async BOF '{message}' started with job ID: {job_id}"
                }
            elif status_type == "BOF_ASYNC_COMPLETED":
                if self.bof_handler and job_id in self.bof_handler.async_jobs:
                    self.bof_handler.async_jobs[job_id]["status"] = "completed"
                    self.bof_handler.async_jobs[job_id]["output"] = message
                
                formatted_output = {
                    "timestamp": timestamp,
                    "output": f"\n[+] BOF job {job_id} completed:\n{message}"
                }
            elif status_type == "BOF_ASYNC_CRASHED":
                if self.bof_handler and job_id in self.bof_handler.async_jobs:
                    self.bof_handler.async_jobs[job_id]["status"] = "crashed"
                    self.bof_handler.async_jobs[job_id]["output"] = message
                
                formatted_output = {
                    "timestamp": timestamp,
                    "output": f"\n[-] BOF job {job_id} crashed:\n{message}"
                }
            else:
                formatted_output = {
                    "timestamp": timestamp,
                    "output": f"\n{output}"
                }
        else:
            formatted_output = {
                "timestamp": timestamp,
                "output": f"\n{output}"
            }
        
        self.command_buffer.add_output(formatted_output)
        self.terminal.update_display(incremental=True)