from PyQt6.QtWidgets import QFileDialog
import base64
import os
import json
import uuid
import asyncio
from datetime import datetime

class FileUploader:
    CHUNK_SIZE = 512 * 1024  # 512KB chunks

    def __init__(self, agent_terminal):
        self.agent_terminal = agent_terminal
        self.current_upload = None
        self.total_chunks = 0
        self.current_chunk = 0
        self.original_command = None  # Store the original command

    def handle_upload_command(self, command):
        """Handle upload command with multiple formats
        Formats supported:
        - upload                     -> Opens file dialog
        - upload /local/path         -> Upload to CWD with original filename
        - upload /local/path newname -> Upload to CWD with new filename
        - upload /local/path /remote/path
        - upload /local/path /remote/dir/
        """
        # Echo the command to the terminal first
        self.agent_terminal.terminal_output.append(f"\n{self.agent_terminal.command_buffer.username} > {command}")
        
        parts = command.split()
        
        if len(parts) == 1:
            # Just 'upload' command - open file dialog
            self._open_file_dialog()
        elif len(parts) >= 2:
            local_path = parts[1]
            
            if len(parts) == 2:
                # If only local path provided, use original filename in current working directory
                remote_path = os.path.basename(local_path)
            else:
                # Multiple parts after local path - join them back together
                # This handles paths with spaces
                remote_path = ' '.join(parts[2:])
                
                # Check if remote path ends with directory separator
                if remote_path.endswith('\\') or remote_path.endswith('/'):
                    # It's a directory path, append the filename from local path
                    remote_path = remote_path + os.path.basename(local_path)
                    
            self._start_upload(local_path, remote_path)
        else:
            self.agent_terminal.terminal_output.append(
                "\nError: Invalid upload command. Use one of:\n" +
                "  - upload                     (opens file selection dialog)\n" +
                "  - upload /local/path         (uploads to CWD with original filename)\n" +
                "  - upload /local/path newname (uploads to CWD with new filename)\n" +
                "  - upload /local/path /remote/path\n"
            )

    def _open_file_dialog(self):
        """Open file dialog for selection"""
        file_path, _ = QFileDialog.getOpenFileName(
            self.agent_terminal,
            "Select File to Upload",
            "",
            "All Files (*);;Text Files (*.txt);;Binary Files (*.bin);;Executables (*.exe *.dll);;No Extension Files (*[!.]*)"
        )
        
        if file_path:
            # Ask for remote path after file selection
            self.agent_terminal.command_input.clear()
            self.agent_terminal.command_input.setPlaceholderText("Enter remote path for upload (or press Enter for default)...")
            self.agent_terminal.command_input.returnPressed.disconnect()
            self.agent_terminal.command_input.returnPressed.connect(
                lambda: self._handle_remote_path_input(file_path)
            )

    def _handle_remote_path_input(self, local_path):
        """Handle remote path input after file selection"""
        remote_path = self.agent_terminal.command_input.text().strip()
        
        # If remote path is empty, use original filename
        if not remote_path:
            remote_path = os.path.basename(local_path)
        else:
            # Check if remote path ends with directory separator
            if remote_path.endswith('\\') or remote_path.endswith('/'):
                # It's a directory path, append the filename from local path
                remote_path = remote_path + os.path.basename(local_path)

        # Construct the full command
        full_command = f"upload {local_path} {remote_path}"
        
        # Reset input handling first
        self.agent_terminal.command_input.setPlaceholderText("")
        self.agent_terminal.command_input.returnPressed.disconnect()
        self.agent_terminal.command_input.returnPressed.connect(
            self.agent_terminal.send_command
        )

        # Set the full command in the input and send it
        self.agent_terminal.command_input.setText(full_command)
        self.agent_terminal.send_command()  # This will trigger the normal command flow

    def _start_upload(self, local_path, remote_path):
        """Start the upload process"""
        if not os.path.exists(local_path):
            self.agent_terminal.terminal_output.append(
                f"\nError: Local file '{local_path}' does not exist"
            )
            return

        try:
            file_size = os.path.getsize(local_path)
            self.total_chunks = (file_size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
            self.current_chunk = 0
            self.current_upload = {
                'id': str(uuid.uuid4()),
                'local_path': local_path,
                'remote_path': remote_path,
                'file_size': file_size,
                'file_name': os.path.basename(local_path)
            }

            # Start upload with first chunk
            self._send_next_chunk()
            
        except Exception as e:
            self.agent_terminal.terminal_output.append(
                f"\nError preparing upload: {str(e)}"
            )

    def _send_next_chunk(self):
        """Send the next chunk of the current upload"""
        print(f"DEBUG FileUploader: _send_next_chunk called, current_chunk={self.current_chunk}, "
            f"total_chunks={self.total_chunks}")

        if not self.current_upload:
            print("DEBUG FileUploader: No current upload")
            return
        
        if self.current_chunk >= self.total_chunks:
            print("DEBUG FileUploader: All chunks sent")
            return

        try:
            with open(self.current_upload['local_path'], 'rb') as f:
                # Seek to current chunk position
                chunk_pos = self.current_chunk * self.CHUNK_SIZE
                print(f"DEBUG FileUploader: Seeking to position {chunk_pos}")
                f.seek(chunk_pos)
                
                # Read chunk
                chunk_data = f.read(self.CHUNK_SIZE)
                print(f"DEBUG FileUploader: Read chunk of size {len(chunk_data)} bytes")
                
                if not chunk_data:
                    raise Exception(f"Failed to read chunk {self.current_chunk}")
                    
                # Base64 encode chunk
                encoded_chunk = base64.b64encode(chunk_data).decode('utf-8')
                print(f"DEBUG FileUploader: Encoded chunk size: {len(encoded_chunk)}")
                
                # Prepare upload message
                upload_msg = {
                    "type": "file_upload",
                    "data": {
                        "upload_id": self.current_upload['id'],
                        "agent_id": self.agent_terminal.agent_guid,
                        "file_name": self.current_upload['file_name'],
                        "remote_path": self.current_upload['remote_path'],
                        "chunk_num": self.current_chunk,
                        "total_chunks": self.total_chunks,
                        "chunk_data": encoded_chunk,
                        "file_size": self.current_upload['file_size'],
                        "timestamp": datetime.now().isoformat()
                    }
                }

                print(f"DEBUG FileUploader: Sending chunk {self.current_chunk}/{self.total_chunks} "
                    f"for file {self.current_upload['file_name']}")

                # Send via WebSocket
                if not self.agent_terminal.ws_thread:
                    raise Exception("No WebSocket thread available")
                    
                if not self.agent_terminal.ws_thread.ws_client:
                    raise Exception("No WebSocket client available")
                    
                if not self.agent_terminal.ws_thread.loop:
                    raise Exception("No event loop available")

                future = asyncio.run_coroutine_threadsafe(
                    self.agent_terminal.ws_thread.ws_client.send_message(
                        json.dumps(upload_msg)
                    ),
                    self.agent_terminal.ws_thread.loop
                )
                
                try:
                    print("DEBUG FileUploader: Waiting for send to complete")
                    future.result(timeout=10)
                    print("DEBUG FileUploader: Send completed successfully")
                except asyncio.TimeoutError:
                    raise Exception(f"Timeout sending chunk {self.current_chunk}")
                except Exception as e:
                    raise Exception(f"Error sending chunk {self.current_chunk}: {str(e)}")

        except Exception as e:
            print(f"DEBUG FileUploader: Error in _send_next_chunk: {e}")
            self.agent_terminal.terminal_output.append(
                f"\nError processing chunk {self.current_chunk}: {str(e)}"
            )
            self.current_upload = None

    def handle_upload_response(self, response_data):
        """Handle server response for upload chunks"""
        print(f"DEBUG FileUploader: Received response: {response_data}")

        if not self.current_upload:
            print("DEBUG FileUploader: No current upload in progress")
            return

        try:
            if response_data.get('status') == 'success':
                complete = response_data.get('data', {}).get('complete', False)
                chunk_num = response_data.get('data', {}).get('chunk_num', -1)
                upload_id = response_data.get('data', {}).get('upload_id')

                print(f"DEBUG FileUploader: Processing response for chunk {chunk_num}, "
                      f"current_chunk={self.current_chunk}, complete={complete}")

                # Verify this is a response for the current upload
                if upload_id != self.current_upload['id']:
                    error_msg = f"Received response for wrong upload ID"
                    print(f"DEBUG FileUploader: {error_msg}")
                    raise Exception(error_msg)

                # If this chunk was successful, send the next one
                if chunk_num == self.current_chunk:
                    self.current_chunk += 1
                    if not complete and self.current_chunk < self.total_chunks:
                        print(f"DEBUG FileUploader: Sending next chunk {self.current_chunk}")
                        self._send_next_chunk()
                    elif complete:
                        print("DEBUG FileUploader: Upload complete")
                        self.current_upload = None
                else:
                    error_msg = f"Upload chunk mismatch: expected {self.current_chunk}, got {chunk_num}"
                    print(f"DEBUG FileUploader: {error_msg}")
                    raise Exception(error_msg)
            else:
                error_msg = response_data.get('message', 'Unknown error')
                print(f"DEBUG FileUploader: Upload error: {error_msg}")
                raise Exception(error_msg)

        except Exception as e:
            print(f"DEBUG FileUploader: Error in handle_upload_response: {e}")
            self.agent_terminal.terminal_output.append(
                f"\nError uploading {self.current_upload['file_name']}: {str(e)}"
            )
            self.current_upload = None