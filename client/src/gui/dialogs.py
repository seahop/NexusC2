#dialogs.py
from PyQt6.QtWidgets import (QDialog, QSpinBox, QFormLayout,
                            QLineEdit, QPushButton, QComboBox, QHBoxLayout,
                            QVBoxLayout, QMessageBox, QFileDialog, QProgressDialog, QTabWidget, QWidget,
                            QLabel, QFrame, QCheckBox, QGroupBox, QDateTimeEdit, QTimeEdit)
from PyQt6.QtCore import QThread, pyqtSignal, QDateTime, QTime, pyqtSlot
from PyQt6.QtCore import Qt
from version import get_version_info, APP_NAME, APP_DESCRIPTION
from utils.websocket_client import WebSocketClient
import asyncio
import json
from utils.database import StateDatabase
from pathlib import Path

class LoadingProgressDialog(QProgressDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Loading Data")
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setMinimumDuration(0)
        self.setCancelButton(None)
        self.setRange(0, 100)
        self.setMinimumWidth(300)
        
    def update_status(self, message, progress):
        self.setLabelText(message)
        self.setValue(progress)

class WebSocketThread(QThread):
    connected = pyqtSignal(bool, str)
    disconnected = pyqtSignal()
    message_received = pyqtSignal(str)
    log_message = pyqtSignal(str)
    listener_update = pyqtSignal(str, dict)
    state_received = pyqtSignal()
    connection_update = pyqtSignal(dict)
    command_response = pyqtSignal(dict)
    command_result = pyqtSignal(dict)
    downloads_update = pyqtSignal(list)
    download_chunk = pyqtSignal(dict)
    upload_response = pyqtSignal(dict)
    link_update = pyqtSignal(dict) 

    def __init__(self, username, host, port, parent=None):
        super().__init__(parent)
        self.username = username
        self.host = host
        self.port = port
        self.db = StateDatabase()
        self.ws_client = None
        self.running = True
        self.loop = None
        self.current_dialog = None
        self.shutdown_event = None  # Add shutdown event for clean stopping

    async def _run_async(self):
        """Async implementation of the run logic"""
        reconnect_attempts = 0
        max_reconnect_attempts = 3
        initial_connection = True
        
        while self.running:
            # Create a fresh WebSocketClient instance
            print("WebSocketThread: Creating fresh WebSocketClient instance")
            self.ws_client = WebSocketClient()

            # Set up the client references if needed
            if hasattr(self, 'db'):
                self.ws_client.db = self.db

            # Link terminal_widget and agent_tree_widget to ws_client
            if hasattr(self.parent(), 'terminal_widget'):
                terminal_widget = self.parent().terminal_widget
                self.ws_client.terminal_widget = terminal_widget
                if hasattr(terminal_widget, 'agent_tree'):
                    self.ws_client.agent_tree_widget = terminal_widget.agent_tree
                    print("WebSocketThread: Linked terminal_widget and agent_tree_widget to ws_client")

            print(f"WebSocketThread: Attempting connection (initial={initial_connection}, attempt={reconnect_attempts+1})")
            
            # Try to connect with interruption support
            try:
                connect_task = asyncio.create_task(
                    self.ws_client.connect(self.username, self.host, self.port)
                )
                shutdown_task = asyncio.create_task(self.shutdown_event.wait())
                
                # Wait for either connection or shutdown signal
                done, pending = await asyncio.wait(
                    {connect_task, shutdown_task},
                    return_when=asyncio.FIRST_COMPLETED
                )
                
                # Cancel pending tasks
                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                
                # Check if shutdown was requested
                if shutdown_task in done:
                    print("WebSocketThread: Shutdown requested during connection")
                    return
                    
            except Exception as e:
                print(f"WebSocketThread: Connection attempt failed: {e}")
                self.ws_client.connected = False

            if not self.ws_client.connected:
                if initial_connection:
                    # First connection attempt failed - don't retry
                    print("WebSocketThread: Initial connection failed - no retry")
                    self.connected.emit(False, "Failed to connect to server. Please ensure the server is running and try again.")
                    self.ws_client = None
                    return  # Exit immediately without retrying
                else:
                    # Reconnection attempt failed
                    reconnect_attempts += 1
                    print(f"WebSocketThread: Reconnection attempt {reconnect_attempts}/{max_reconnect_attempts} failed")
                    
                    if reconnect_attempts >= max_reconnect_attempts:
                        print("WebSocketThread: Max reconnection attempts reached, giving up")
                        self.connected.emit(False, f"Failed to reconnect after {max_reconnect_attempts} attempts. Please reconnect manually.")
                        self.ws_client = None
                        return  # Exit after max attempts
                    
                    # Clean up the failed client
                    self.ws_client = None
                    
                    # Wait before retrying (with interruptible sleep)
                    wait_time = min(5 * reconnect_attempts, 15)  # Exponential backoff, max 15 seconds
                    print(f"WebSocketThread: Waiting {wait_time} seconds before retry...")
                    self.connected.emit(False, f"Connection lost. Retrying in {wait_time} seconds... (Attempt {reconnect_attempts}/{max_reconnect_attempts})")
                    
                    try:
                        await asyncio.wait_for(self.shutdown_event.wait(), timeout=wait_time)
                        # If we get here, shutdown was requested
                        print("WebSocketThread: Shutdown requested during reconnection wait")
                        return
                    except asyncio.TimeoutError:
                        # Normal timeout, continue with reconnection
                        pass
                    
                    continue

            # Connection successful
            print("WebSocketThread: Connection successful")
            self.connected.emit(True, "Connected successfully.")
            initial_connection = False  # Mark that we've successfully connected once
            reconnect_attempts = 0  # Reset reconnect counter on successful connection
            
            # Main message processing loop
            while self.running and self.ws_client and self.ws_client.connected:
                try:
                    # Use select with timeout to make it interruptible
                    receive_task = asyncio.create_task(self.ws_client.receive_messages())
                    shutdown_task = asyncio.create_task(self.shutdown_event.wait())
                    
                    done, pending = await asyncio.wait(
                        {receive_task, shutdown_task},
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    
                    # Cancel pending tasks
                    for task in pending:
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                    
                    # Check what completed
                    if shutdown_task in done:
                        print("WebSocketThread: Shutdown requested during message processing")
                        # Properly disconnect before returning
                        if self.ws_client:
                            try:
                                await self.ws_client.disconnect()
                            except Exception as e:
                                print(f"WebSocketThread: Error during shutdown disconnect: {e}")
                        return
                        
                    if receive_task in done:
                        message_data = receive_task.result()
                        if message_data:
                            self._process_message(message_data)
                            
                except Exception as e:
                    print(f"WebSocketThread: Error processing message: {e}")
                    self.log_message.emit(f"Error processing message: {str(e)}")
                    
                    # Set connected to False to exit the inner loop
                    if self.ws_client:
                        self.ws_client.connected = False
                    break  # Break the loop to attempt reconnection

            # Connection lost or error occurred
            if self.running:
                print("WebSocketThread: Connection lost, cleaning up...")
                
                # Properly disconnect and clean up
                if self.ws_client:
                    try:
                        await self.ws_client.disconnect()
                    except Exception as e:
                        print(f"WebSocketThread: Error during disconnect: {e}")
                    
                    # Set ws_client to None so next iteration creates a fresh one
                    self.ws_client = None
                
                # If we're still running, we'll loop back to try reconnecting
            else:
                # We're shutting down, make sure to disconnect
                if self.ws_client:
                    try:
                        await self.ws_client.disconnect()
                    except Exception as e:
                        print(f"WebSocketThread: Error during final disconnect: {e}")
                break  # Exit if we're supposed to stop

    def cleanup(self):
        """Clean up resources"""
        print("WebSocketThread: Starting cleanup")
        
        # Clean up the WebSocket client
        self.ws_client = None
        
        # Clean up event loop
        if self.loop:
            if not self.loop.is_closed():
                print("WebSocketThread: Cleaning up event loop")
                try:
                    # Get all pending tasks
                    pending = asyncio.all_tasks(self.loop)
                    
                    if pending:
                        print(f"WebSocketThread: Cancelling {len(pending)} pending tasks")
                        # Cancel all pending tasks
                        for task in pending:
                            task.cancel()
                        
                        # Run the loop one more time to process cancellations
                        # Use gather with return_exceptions to handle any errors
                        self.loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True)
                        )
                    
                except RuntimeError as e:
                    # This can happen if the loop is already stopped
                    print(f"WebSocketThread: RuntimeError during task cleanup: {e}")
                except Exception as e:
                    print(f"WebSocketThread: Error during task cleanup: {e}")
                
                try:
                    # Stop the loop if it's still running
                    if self.loop.is_running():
                        self.loop.stop()
                        # Give it a moment to stop
                        import time
                        time.sleep(0.1)
                    
                    # Now close the loop
                    self.loop.close()
                    print("WebSocketThread: Event loop closed successfully")
                except Exception as e:
                    print(f"WebSocketThread: Error closing event loop: {e}")
            
            self.loop = None
        else:
            print("WebSocketThread: No event loop to clean up")

    def run(self):
        """Main thread run method"""
        print("WebSocketThread: Starting run method")
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.shutdown_event = asyncio.Event()  # Create shutdown event
            
            # Run the async implementation
            self.loop.run_until_complete(self._run_async())
            
        except Exception as e:
            print(f"WebSocketThread: Run method error: {e}")
            self.connected.emit(False, f"Error: {str(e)}")
        finally:
            print("WebSocketThread: Cleaning up connection")
            if self.ws_client and self.ws_client.connected:
                try:
                    self.loop.run_until_complete(self.ws_client.disconnect())
                except:
                    pass
            self.cleanup()
            self.disconnected.emit()

    def stop(self):
        """Stop the thread cleanly"""
        print("WebSocketThread: Stop requested")
        self.running = False
        
        # Signal shutdown event if it exists
        if self.shutdown_event and self.loop and not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self.shutdown_event.set)
        
        # Mark client as disconnected to break inner loop
        if self.ws_client:
            self.ws_client.connected = False
            
            # Try to disconnect gracefully
            if self.loop and not self.loop.is_closed():
                try:
                    future = asyncio.run_coroutine_threadsafe(
                        self.ws_client.disconnect(), 
                        self.loop
                    )
                    # Wait briefly for disconnect to complete
                    future.result(timeout=2)
                except:
                    pass  # Ignore errors during shutdown
        
        # Stop the event loop
        if self.loop and not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self.loop.stop)

    def is_connected(self):
        result = bool(self.ws_client and self.ws_client.connected and self.ws_client.websocket)
        return result

    def get_ws_client(self):
        return self.ws_client

    def _process_message(self, message_data):
        try:
            #print(f"WebSocketThread: Parsed message: {message_data}")
            message_type = message_data.get('type')

            # Handle command_queued just like command_result
            if message_type == 'command_queued':
                data = message_data.get('data', {})
                # Format it to look like a command result with the command as output
                formatted_data = {
                    'agent_id': data.get('agent_id'),
                    'command_id': data.get('command_id'),
                    'output': f"[{data.get('timestamp')}] {data.get('username')} > {data.get('command')}",
                    'timestamp': data.get('timestamp'),
                    'status': 'queued'
                }
                # Emit through the existing command_result signal
                self.command_result.emit(formatted_data)
                #print(f"WebSocketThread: Processed command_queued for agent {data.get('agent_id', '')[:8]}")
                return

            elif message_type == 'upload_response':
                print(f"DEBUG: Upload Response Data: {json.dumps(message_data, indent=2)}")
                data = message_data.get('data', {})
                print(f"DEBUG: Emitting upload_response signal with data: {data}")
                self.upload_response.emit(message_data)
                print("DEBUG: Successfully emitted upload_response signal")
                
            elif message_type == 'upload_error':
                print(f"WebSocketThread: Received upload error: {message_data}")
                self.upload_response.emit({
                    'status': 'error',
                    'message': message_data.get('message', 'Unknown upload error'),
                    'upload_id': message_data.get('upload_id')
                })
            elif message_type == 'agent_renamed':
                print(f"WebSocketThread: Processing agent_renamed message")
                if hasattr(self.parent(), 'terminal_widget'):
                    terminal_widget = self.parent().terminal_widget
                    if terminal_widget and hasattr(terminal_widget, 'agent_tree'):
                        rename_data = message_data.get('data', {})
                        terminal_widget.agent_tree.handle_agent_renamed(rename_data)
                        print(f"WebSocketThread: Forwarded rename to agent_tree")
                else:
                    print("WebSocketThread: No terminal_widget available")

            elif message_type == 'link_update':
                print(f"WebSocketThread: Processing link_update message")
                link_data = message_data.get('data', {})
                print(f"WebSocketThread: Emitting link_update signal with data: {link_data}")
                self.link_update.emit(link_data)

            elif message_type == 'agent_update':
                pass

            elif message_type == 'agent_checkin':
                agent_id = message_data['data'].get('agent_id')
                last_seen = message_data['data'].get('last_seen')
                print(f"WebSocketThread: Processing agent_checkin for agent {agent_id}")
                
                if hasattr(self.parent(), 'terminal_widget'):
                    terminal_widget = self.parent().terminal_widget
                    if terminal_widget.agent_tree:
                        print("WebSocketThread: Current agents in tree:")
                        for agent in terminal_widget.agent_tree.agent_data:
                            print(f"  - {agent['guid']}")
                        
                        timestamp = QDateTime.fromSecsSinceEpoch(int(last_seen))
                        print(f"WebSocketThread: Converted timestamp: {timestamp}")
                        
                        for agent in terminal_widget.agent_tree.agent_data:
                            if agent['guid'] == agent_id:
                                print(f"WebSocketThread: Found matching agent {agent_id}")
                                print(f"WebSocketThread: Old timestamp: {agent['last_seen_timestamp']}")
                                agent['last_seen_timestamp'] = timestamp
                                # If agent was marked as deleted, reactivate it
                                if agent.get('deleted', False):
                                    agent['deleted'] = False
                                    # Emit signal to update UI in main thread
                                    self.connection_update.emit({
                                        'new_client_id': agent['guid'],
                                        'hostname': agent['details'][0].split(': ')[1],
                                        'int_ip': agent['details'][1].split(': ')[1],
                                        'ext_ip': agent['details'][2].split(': ')[1],
                                        'username': agent['details'][3].split(': ')[1],
                                        'protocol': agent['details'][4].split(': ')[1],
                                        'process': agent['details'][5].split(': ')[1],
                                        'pid': agent['details'][6].split(': ')[1],
                                        'arch': agent['details'][7].split(': ')[1],
                                        'os': agent['details'][8].split(': ')[1],
                                        'client_id': agent['details'][9].split(': ')[1],
                                        'last_seen': timestamp.toString(Qt.DateFormat.ISODate)
                                    })
                                print(f"WebSocketThread: Updated timestamp to: {timestamp}")
                                break

            elif message_type == 'initial_state':
                print("WebSocketThread: Processing initial state")
                # Pass is_initial_state=True to clear stale cached data
                if self.db.store_state(message_data.get("data", {}), is_initial_state=True):
                    print("WebSocketThread: Successfully stored initial state data")
                    self.db.verify_database_state()
                    self.state_received.emit()

            elif message_type == 'agent_checkin':
                agent_id = message_data['data'].get('agent_id')
                last_seen = message_data['data'].get('last_seen')
                print(f"WebSocketThread: Processing agent_checkin for agent {agent_id}")
                
                if hasattr(self.parent(), 'terminal_widget'):
                    terminal_widget = self.parent().terminal_widget
                    if terminal_widget.agent_tree:
                        print("WebSocketThread: Current agents in tree:")
                        for agent in terminal_widget.agent_tree.agent_data:
                            print(f"  - {agent['guid']}")
                        
                        timestamp = QDateTime.fromSecsSinceEpoch(int(last_seen))
                        print(f"WebSocketThread: Converted timestamp: {timestamp}")
                        
                        found = False
                        for agent in terminal_widget.agent_tree.agent_data:
                            if agent['guid'] == agent_id:
                                print(f"WebSocketThread: Found matching agent {agent_id}")
                                print(f"WebSocketThread: Old timestamp: {agent['last_seen_timestamp']}")
                                agent['last_seen_timestamp'] = timestamp
                                
                                # If agent was marked as deleted, make it visible again
                                if hasattr(agent, 'deleted') and agent['deleted']:
                                    agent['deleted'] = False
                                    if agent['name'] in terminal_widget.agent_tree.agent_items:
                                        item = terminal_widget.agent_tree.agent_items[agent['name']]
                                        if item.isHidden():
                                            item.setHidden(False)
                                
                                print(f"WebSocketThread: Updated timestamp to: {timestamp}")
                                found = True
                                break

            elif message_type == 'command_validation':
                #print(f"DEBUG: Command validation message received: {message_data}")
                validation_data = {
                    'type': 'command_validation',
                    'status': message_data.get('status'),
                    'message': message_data.get('message'),
                    'data': message_data.get('data'),
                }
                #print(f"DEBUG: Emitting command validation: {validation_data}")
                self.command_response.emit(validation_data)

            elif message_type == 'command_result':
                #print(f"DEBUG: Processing command result: {message_data}")
                result_data = {
                    'output': message_data['data']['output'],
                    'command_id': message_data['data']['command_id'],
                    'agent_id': message_data['data'].get('agent_id'),  # Note: Check if this exists
                    'timestamp': message_data['data']['timestamp'],
                    'status': message_data['data']['status']
                }
                #print(f"DEBUG: Emitting command result: {result_data}")
                self.command_result.emit(result_data)

            elif message_type == 'agent_connection':
                agent_data = message_data['data']['agent']
                conn_data = {
                    'new_client_id': agent_data['new_client_id'],
                    'hostname': agent_data['hostname'],
                    'int_ip': agent_data['int_ip'],
                    'ext_ip': agent_data['ext_ip'],
                    'username': agent_data['username'],
                    'protocol': agent_data['protocol'],
                    'process': agent_data['process'],
                    'pid': agent_data['pid'],
                    'arch': agent_data['arch'],
                    'os': agent_data['os'],
                    'client_id': agent_data['client_id'],
                    'last_seen': agent_data.get('last_seen', ''),
                    'parent_client_id': agent_data.get('parent_client_id', ''),  # For linked agents
                    'link_type': agent_data.get('link_type', ''),  # Link type (e.g., "smb")
                }
                print("WebSocketThread: About to emit connection_update with data:", conn_data)
                self.connection_update.emit(conn_data)
                #print("WebSocketThread: Emitted connection_update signal")

            elif message_type == 'listener_update':
                event = message_data['data']['event']
                listener_data = message_data['data'].get('listener', message_data['data'])
                self.listener_update.emit(event, listener_data)

            elif message_type == 'connection_update':
                if message_data['data']['event'] == 'connected':
                    conn_data = message_data['data']['connection']
                    if 'new_client_id' in conn_data and 'guid' not in conn_data:
                        conn_data['guid'] = conn_data['new_client_id']
                    self.connection_update.emit(conn_data)

            elif message_type == 'downloads_manifest':
                downloads = message_data.get('data', [])
                self.downloads_update.emit(downloads)
                #print("WebSocketThread: Emitted downloads_update signal")

            elif message_type == 'download_chunk':
                # Handle incoming file chunks
                self.download_chunk.emit(message_data.get('data', {}))
                #print("WebSocketThread: Emitted download_chunk signal")

            elif message_type == 'binary_chunk':
                print(f"WebSocketThread: About to emit binary_chunk {message_data.get('chunk_num')}")
                self.message_received.emit(json.dumps(message_data))
                print(f"WebSocketThread: Emitted binary_chunk {message_data.get('chunk_num')}")

            elif message_type == 'binary_transfer_complete':
                # Forward this to MainWindow handler
                print("WebSocketThread: Forwarding binary_transfer_complete")
                self.message_received.emit(json.dumps(message_data))

            elif message_type == 'error':
                print("WebSocketThread: Handling error message")
                error_message = message_data.get('message', 'Unknown error occurred')
                self.log_message.emit(f"Error received: {error_message}")
                self.ws_client.connected = False

            elif message_data.get('status') in ['success', 'error']:
                if self.current_dialog:
                    if message_data['status'] == 'error':
                        self.current_dialog.error_signal.emit(message_data['message'])
                    else:
                        self.current_dialog.success_signal.emit()
                        self.current_dialog = None

            else:
                print(f"WebSocketThread: Unrecognized message type: {message_type}")
                self.log_message.emit(f"Unrecognized message type received: {message_type}")

        except Exception as e:
            print(f"WebSocketThread: Error processing message: {e}")
            self.log_message.emit(f"Error processing message: {str(e)}")


    async def request_downloads_manifest(self):
        """Request the downloads manifest from the server"""
        if not self.ws_client or not self.ws_client.connected:
            print("WebSocketThread: Not connected to server")
            return

        request = {
            "type": "request_downloads",
            "data": {}
        }

        try:
            await self.ws_client.send_message(json.dumps(request))
            print("WebSocketThread: Sent downloads manifest request")
        except Exception as e:
            print(f"WebSocketThread: Error requesting downloads manifest: {e}")

    def request_downloads_manifest_sync(self):
        """Synchronous wrapper for requesting downloads manifest"""
        if self.loop:
            asyncio.run_coroutine_threadsafe(
                self.request_downloads_manifest(),
                self.loop
            )

    async def request_file_download(self, request_message):
        """Request a file download from the server"""
        if not self.ws_client or not self.ws_client.connected:
            print("WebSocketThread: Not connected to server")
            return
            
        try:
            await self.ws_client.send_message(request_message)
            print("WebSocketThread: Sent file download request")
        except Exception as e:
            print(f"WebSocketThread: Error requesting file download: {e}")
            
    def request_file_download_sync(self, request_message):
        """Synchronous wrapper for requesting file download"""
        if self.loop:
            asyncio.run_coroutine_threadsafe(
                self.request_file_download(request_message),
                self.loop
            )
        
        
class ServerConnectDialog(QDialog):
    def __init__(self, parent=None, terminal_widget=None):
        super().__init__(parent)
        self.setWindowTitle("Connect to Server")
        self.setMinimumWidth(350)
        self.terminal_widget = terminal_widget
        self.saved_servers = self.load_saved_servers()

        layout = QFormLayout()

        # Server presets dropdown
        self.server_preset = QComboBox()
        self.server_preset.addItem("-- New Connection --")
        for name in self.saved_servers.keys():
            self.server_preset.addItem(name)
        self.server_preset.currentTextChanged.connect(self.load_preset)
        layout.addRow("Server Preset:", self.server_preset)

        # Add separator line
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addRow(line)

        # Server connection fields
        self.username = QLineEdit("nexus")
        self.host = QLineEdit("localhost")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(3131)

        layout.addRow("Username:", self.username)
        layout.addRow("Host:", self.host)
        layout.addRow("Port:", self.port)

        # Add separator line
        line2 = QFrame()
        line2.setFrameShape(QFrame.Shape.HLine)
        line2.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addRow(line2)

        # Save configuration section
        save_layout = QHBoxLayout()
        self.save_config = QCheckBox("Save as:")
        self.save_name = QLineEdit()
        self.save_name.setPlaceholderText("Enter preset name")
        self.save_name.setEnabled(False)
        self.save_config.toggled.connect(self.save_name.setEnabled)
        save_layout.addWidget(self.save_config)
        save_layout.addWidget(self.save_name)
        layout.addRow(save_layout)

        # Connect button
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.handle_connect)
        layout.addRow(self.connect_button)

        # Delete preset button (only shown when a preset is selected)
        self.delete_button = QPushButton("Delete Selected Preset")
        self.delete_button.clicked.connect(self.delete_preset)
        self.delete_button.setVisible(False)
        layout.addRow(self.delete_button)

        self.setLayout(layout)
        self.ws_thread = None

    def load_preset(self, preset_name):
        """Load a saved server configuration"""
        if preset_name == "-- New Connection --":
            self.username.setText("nexus")
            self.host.setText("localhost")
            self.port.setValue(3131)
            self.delete_button.setVisible(False)
        elif preset_name in self.saved_servers:
            config = self.saved_servers[preset_name]
            self.username.setText(config.get('username', 'nexus'))
            self.host.setText(config.get('host', 'localhost'))
            self.port.setValue(config.get('port', 3131))
            self.delete_button.setVisible(True)

    def load_saved_servers(self):
        """Load saved server configurations"""
        import json
        from pathlib import Path
        
        config_file = Path.home() / '.c2_client' / 'servers.json'
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def save_server_config(self, name, username, host, port):
        """Save a server configuration"""
        import json
        from pathlib import Path
        
        config_file = Path.home() / '.c2_client' / 'servers.json'
        config_file.parent.mkdir(exist_ok=True)
        
        servers = self.load_saved_servers()
        servers[name] = {
            'username': username,
            'host': host,
            'port': port
        }
        
        with open(config_file, 'w') as f:
            json.dump(servers, f, indent=2)

    def delete_preset(self):
        """Delete the currently selected preset"""
        current_preset = self.server_preset.currentText()
        if current_preset != "-- New Connection --" and current_preset in self.saved_servers:
            reply = QMessageBox.question(self, 'Delete Preset', 
                                        f'Delete preset "{current_preset}"?',
                                        QMessageBox.StandardButton.Yes | 
                                        QMessageBox.StandardButton.No)
            
            if reply == QMessageBox.StandardButton.Yes:
                # Remove from saved servers
                del self.saved_servers[current_preset]
                
                # Save updated config
                import json
                from pathlib import Path
                config_file = Path.home() / '.c2_client' / 'servers.json'
                with open(config_file, 'w') as f:
                    json.dump(self.saved_servers, f, indent=2)
                
                # Remove from dropdown
                index = self.server_preset.findText(current_preset)
                if index >= 0:
                    self.server_preset.removeItem(index)
                
                # Reset to new connection
                self.server_preset.setCurrentIndex(0)
                QMessageBox.information(self, "Deleted", f'Preset "{current_preset}" has been deleted.')

    def handle_connect(self):
        print("ServerConnectDialog: Handling connect request")
        
        # Save configuration if requested
        if self.save_config.isChecked() and self.save_name.text():
            self.save_server_config(
                self.save_name.text(),
                self.username.text(),
                self.host.text(),
                self.port.value()
            )
            
            # Add to dropdown if it's new
            if self.save_name.text() not in self.saved_servers:
                self.server_preset.addItem(self.save_name.text())
                self.saved_servers[self.save_name.text()] = {
                    'username': self.username.text(),
                    'host': self.host.text(),
                    'port': self.port.value()
                }
        
        # Rest of existing handle_connect code
        if self.ws_thread is not None and self.ws_thread.isRunning():
            self.ws_thread.stop()
            self.ws_thread.wait()

        self.progress = LoadingProgressDialog(self)
        self.progress.show()
        self.progress.update_status("Initializing connection...", 10)

        self.ws_thread = WebSocketThread(
            username=self.username.text(),
            host=self.host.text(),
            port=self.port.value(),
            parent=self.parent()
        )

        # Connect progress updates
        self.ws_thread.connected.connect(lambda success, msg: self.progress.update_status("Connected to server...", 30))
        self.ws_thread.state_received.connect(lambda: self.progress.update_status("Loading initial state...", 60))
        self.ws_thread.state_received.connect(lambda: self.progress.update_status("Complete", 100))
        
        self.ws_thread.connected.connect(self.on_connected)
        self.ws_thread.disconnected.connect(self.on_disconnected)
        
        print("ServerConnectDialog: Starting WebSocket thread")
        self.ws_thread.start()

    def on_connected(self, success, message):
        if success:
            self.progress.update_status("Connection established", 100)
            self.progress.close()
            self.terminal_widget.log_message(message)
            self.parent().ws_thread = self.ws_thread
            self.parent().is_connected = True
            self.parent().updateMenuState()
            self.accept()
        else:
            self.progress.close()
            self.connect_button.setEnabled(True)

    def on_disconnected(self):
        if self.ws_thread:
            self.ws_thread.wait()
            self.ws_thread = None

    def closeEvent(self, event):
        # Gracefully stop the thread when the dialog is closed
        if self.ws_thread:
            self.ws_thread.stop()
            self.ws_thread.wait()
            self.ws_thread = None
        super().closeEvent(event)

    def on_error(self, message):
        print(f"Error: {message}")

class CreateListenerDialog(QDialog):
    success_signal = pyqtSignal()
    error_signal = pyqtSignal(str)

    def __init__(self, parent=None, ws_thread=None):
        super().__init__(parent)
        self.setWindowTitle("Create Listener")
        self.setMinimumWidth(400)
        self.setMinimumHeight(250)
        self.ws_thread = ws_thread
        self.listener_name = None  # Keep track of the listener being created

        # Connect our signals to the slots
        self.success_signal.connect(self.handle_success)
        print("CreateListenerDialog: Connected success_signal to handle_success")

        self.error_signal.connect(self.show_error)
        print("CreateListenerDialog: Connected error_signal to show_error")

        if self.ws_thread:
            # Connect the listener_update signal to handle_listener_update
            self.ws_thread.listener_update.connect(self.handle_listener_update)
            print("CreateListenerDialog: Connected listener_update signal to handle_listener_update")

        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Create tab widget for different listener types
        self.tab_widget = QTabWidget()
        
        # Network Listener Tab (HTTP/HTTPS/RPC/TCP) - UNCHANGED
        self.network_tab = QWidget()
        self.setup_network_tab()
        self.tab_widget.addTab(self.network_tab, "Network Listener")
        
        # SMB Listener Tab - NEW SIMPLIFIED
        #self.smb_tab = QWidget()
        #self.setup_smb_tab()
        #self.tab_widget.addTab(self.smb_tab, "SMB Listener")
        
        layout.addWidget(self.tab_widget)

        # Buttons layout
        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")

        self.ok_button.clicked.connect(self.handle_ok)
        self.cancel_button.clicked.connect(self.reject)

        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def setup_network_tab(self):
        """Setup listener configuration with SMB support"""
        layout = QVBoxLayout()
        form_layout = QFormLayout()

        # Listener name field
        self.name = QLineEdit()
        form_layout.addRow("Name:", self.name)

        # Protocol dropdown - includes SMB
        self.protocol = QComboBox()
        self.protocol.addItems(["HTTPS", "HTTP", "SMB"])
        self.protocol.currentTextChanged.connect(self.on_protocol_changed)
        form_layout.addRow("Protocol:", self.protocol)

        # Port number field (hidden for SMB)
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(443)
        self.port_label = QLabel("Port:")
        form_layout.addRow(self.port_label, self.port)

        # IP/Hostname field (hidden for SMB)
        self.host = QLineEdit()
        self.host.setText("0.0.0.0")
        self.host_label = QLabel("IP/Hostname:")
        form_layout.addRow(self.host_label, self.host)

        # Pipe name field (only shown for SMB)
        self.pipe_name = QLineEdit()
        self.pipe_name.setText("spoolss")
        self.pipe_name.setPlaceholderText("e.g., spoolss, netlogon, lsarpc")
        self.pipe_name_label = QLabel("Pipe Name:")
        form_layout.addRow(self.pipe_name_label, self.pipe_name)
        # Initially hide pipe name since HTTPS is default
        self.pipe_name_label.hide()
        self.pipe_name.hide()

        layout.addLayout(form_layout)
        layout.addStretch()
        self.network_tab.setLayout(layout)

    def on_protocol_changed(self, protocol):
        """Show/hide fields based on selected protocol"""
        is_smb = protocol == "SMB"

        # Hide port and host for SMB
        self.port_label.setVisible(not is_smb)
        self.port.setVisible(not is_smb)
        self.host_label.setVisible(not is_smb)
        self.host.setVisible(not is_smb)

        # Show pipe name only for SMB
        self.pipe_name_label.setVisible(is_smb)
        self.pipe_name.setVisible(is_smb)
    
    #def setup_smb_tab(self):
    #    """Setup SMB listener configuration - SIMPLIFIED"""
    #    layout = QVBoxLayout()
        
        # Add description
    #    description = QLabel("Configure SMB listener for named pipe communication.\n"
    #                       "Agents will connect via SMB to the specified pipe.")
    #    description.setWordWrap(True)
    #    layout.addWidget(description)
        
        # Add separator
    #    line = QFrame()
    #    line.setFrameShape(QFrame.Shape.HLine)
    #    line.setFrameShadow(QFrame.Shadow.Sunken)
    #    layout.addWidget(line)
        
    #    form_layout = QFormLayout()
        
        # Listener name field
    #    self.smb_name = QLineEdit()
    #    self.smb_name.setPlaceholderText("e.g., smb-primary")
    #    form_layout.addRow("Name:", self.smb_name)
        
        # Pipe name field
    #    self.pipe_name = QLineEdit()
    #    self.pipe_name.setText("\\pipe\\msagent")
    #    self.pipe_name.setPlaceholderText("e.g., \\pipe\\msagent")
    #    form_layout.addRow("Pipe Name:", self.pipe_name)
        
    #    layout.addLayout(form_layout)
    #    layout.addStretch()
        
    #    self.smb_tab.setLayout(layout)

    def handle_ok(self):
        if not self.ws_thread or not self.ws_thread.is_connected():
            return

        # Store dialog reference for async callback
        self.ws_thread.current_dialog = self

        # Validate name
        self.listener_name = self.name.text()
        if not self.listener_name:
            QMessageBox.warning(self, "Error", "Please enter a listener name")
            return

        # Get selected protocol
        protocol = self.protocol.currentText()

        # Build listener data based on protocol
        if protocol == "SMB":
            # SMB listener - uses pipe name instead of port/host
            pipe_name = self.pipe_name.text()
            if not pipe_name:
                QMessageBox.warning(self, "Error", "Please enter a pipe name")
                return

            listener_data = {
                "type": "create_listener",
                "data": {
                    "name": self.listener_name,
                    "protocol": "SMB",
                    "pipe_name": pipe_name
                }
            }
            print(f"CreateListenerDialog: Creating SMB listener with pipe: {pipe_name}")
        else:
            # Network listener (HTTP/HTTPS)
            listener_data = {
                "type": "create_listener",
                "data": {
                    "name": self.listener_name,
                    "protocol": protocol,
                    "port": self.port.value(),
                    "host": self.host.text()
                }
            }

        message = json.dumps(listener_data)
        print(f"CreateListenerDialog: Sending listener creation message for {self.listener_name}")

        # Run in the event loop to avoid blocking the GUI
        future = asyncio.run_coroutine_threadsafe(
            self.ws_thread.ws_client.send_message(message), 
            self.ws_thread.loop
        )
        try:
            future.result()  # This line ensures that if there's an exception, it will be raised here
        except Exception as e:
            print(f"CreateListenerDialog: Error while sending listener creation message: {e}")

        # Don't close dialog yet - wait for server response
        self.ok_button.setEnabled(False)
        self.ok_button.setText("Creating...")

    @pyqtSlot(str)
    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)
        self.ok_button.setEnabled(True)
        self.ok_button.setText("OK")

    @pyqtSlot()
    def handle_success(self):
        print("CreateListenerDialog: Listener creation successful, closing dialog.")
        self.accept()

    @pyqtSlot(str, dict)
    def handle_listener_update(self, event, listener_data):
        """Handles listener update broadcasts to determine if the dialog should close"""
        print(f"CreateListenerDialog: Received listener_update signal - Event: {event}, Listener Data: {listener_data}")
        if event == "created" and listener_data.get("name") == self.listener_name:
            print(f"CreateListenerDialog: Matching listener '{self.listener_name}' found. Closing dialog.")
            self.handle_success()

class CreatePayloadDialog(QDialog):
    def __init__(self, parent=None, ws_thread=None, agent_tree=None):
        super().__init__(parent)
        self.setWindowTitle("Create Payload")
        self.setMinimumWidth(500)
        self.setMinimumHeight(400)
        self.ws_thread = ws_thread
        self.agent_tree = agent_tree
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Create tab widget for organized options
        self.tab_widget = QTabWidget()
        
        # Basic Configuration Tab
        self.basic_tab = QWidget()
        self.setup_basic_tab()
        self.tab_widget.addTab(self.basic_tab, "Basic Configuration")
        
        # Safety Checks Tab
        self.safety_tab = QWidget()
        self.setup_safety_tab()
        self.tab_widget.addTab(self.safety_tab, "Safety Checks")
        
        layout.addWidget(self.tab_widget)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("Generate")
        self.cancel_button = QPushButton("Cancel")
        
        self.ok_button.clicked.connect(self.handle_ok)
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)

    def setup_basic_tab(self):
        layout = QVBoxLayout()
        form_layout = QFormLayout()
        
        # Listener dropdown
        self.listener = QComboBox()
        self.populate_listeners()
        self.listener.currentTextChanged.connect(self.on_listener_changed)
        form_layout.addRow("Listener:", self.listener)
        
        # Connection Type - only visible for SMB listeners
        self.connection_type_label = QLabel("Connection Type:")
        self.connection_type = QComboBox()
        self.connection_type.addItems(["Direct", "SMB"])
        form_layout.addRow(self.connection_type_label, self.connection_type)
        
        # Initially hide connection type (will show only for SMB listeners)
        self.connection_type_label.setVisible(False)
        self.connection_type.setVisible(False)
        
        # Language dropdown
        self.language = QComboBox()
        self.language.addItem("Go")
        self.language.addItem("GoProject")
        form_layout.addRow("Language:", self.language)
        
        # OS dropdown
        self.os = QComboBox()
        self.os.addItems(["Linux", "Darwin", "Windows"])
        form_layout.addRow("Operating System:", self.os)
        
        # Architecture dropdown
        self.arch = QComboBox()
        self.arch.addItems(["amd64", "arm64"])
        form_layout.addRow("Architecture:", self.arch)
        
        # Output path
        path_layout = QHBoxLayout()
        self.output_path = QLineEdit()
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_output_path)
        path_layout.addWidget(self.output_path)
        path_layout.addWidget(self.browse_button)
        form_layout.addRow("Output Path:", path_layout)
        
        layout.addLayout(form_layout)
        layout.addStretch()
        self.basic_tab.setLayout(layout)

    def setup_safety_tab(self):
        layout = QVBoxLayout()
        
        # Add description
        description = QLabel("Optional safety checks to restrict payload execution.\n"
                           "Leave fields empty to disable specific checks.")
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # Add separator
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)
        
        form_layout = QFormLayout()
        
        # Hostname pinning
        self.hostname_check = QCheckBox("Enable Hostname Check")
        self.hostname_input = QLineEdit()
        self.hostname_input.setPlaceholderText("e.g., DESKTOP-ABC123 or workstation.local")
        self.hostname_input.setEnabled(False)
        self.hostname_check.toggled.connect(self.hostname_input.setEnabled)
        form_layout.addRow(self.hostname_check, self.hostname_input)
        
        # Username pinning
        self.username_check = QCheckBox("Enable Username Check")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("e.g., administrator or john.doe")
        self.username_input.setEnabled(False)
        self.username_check.toggled.connect(self.username_input.setEnabled)
        form_layout.addRow(self.username_check, self.username_input)
        
        # Domain pinning (Windows)
        self.domain_check = QCheckBox("Enable Domain Check")
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("e.g., CORPORATE or corporate.local")
        self.domain_input.setEnabled(False)
        self.domain_check.toggled.connect(self.domain_input.setEnabled)
        form_layout.addRow(self.domain_check, self.domain_input)
        
        # File existence check
        self.file_check = QCheckBox("Enable File Check")
        self.file_check_widget = QWidget()
        file_check_layout = QVBoxLayout()
        file_check_layout.setContentsMargins(0, 0, 0, 0)
        
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("e.g., C:\\ProgramData\\marker.txt or /etc/marker.conf")
        self.file_path_input.setEnabled(False)
        
        # File check mode
        self.file_check_mode = QComboBox()
        self.file_check_mode.addItems(["File Must Exist", "File Must NOT Exist"])
        self.file_check_mode.setEnabled(False)
        
        file_check_layout.addWidget(self.file_path_input)
        file_check_layout.addWidget(self.file_check_mode)
        self.file_check_widget.setLayout(file_check_layout)
        
        self.file_check.toggled.connect(self.file_path_input.setEnabled)
        self.file_check.toggled.connect(self.file_check_mode.setEnabled)
        form_layout.addRow(self.file_check, self.file_check_widget)
        
        # Process check
        self.process_check = QCheckBox("Enable Process Check")
        self.process_input = QLineEdit()
        self.process_input.setPlaceholderText("e.g., outlook.exe or firefox")
        self.process_input.setEnabled(False)
        self.process_check.toggled.connect(self.process_input.setEnabled)
        form_layout.addRow(self.process_check, self.process_input)
        
        # Add advanced options section
        advanced_group = QGroupBox("Advanced Safety Options")
        advanced_layout = QFormLayout()
        
        # Kill switch date
        self.killdate_check = QCheckBox("Enable Kill Date")
        self.killdate_input = QDateTimeEdit()
        self.killdate_input.setDateTime(QDateTime.currentDateTime().addDays(30))
        self.killdate_input.setCalendarPopup(True)
        self.killdate_input.setEnabled(False)
        self.killdate_check.toggled.connect(self.killdate_input.setEnabled)
        advanced_layout.addRow(self.killdate_check, self.killdate_input)
        
        # Working hours restriction
        self.workhours_check = QCheckBox("Enable Working Hours")
        self.workhours_widget = QWidget()
        workhours_layout = QHBoxLayout()
        workhours_layout.setContentsMargins(0, 0, 0, 0)
        
        self.workhours_start = QTimeEdit()
        self.workhours_start.setTime(QTime(8, 0))
        self.workhours_start.setEnabled(False)
        
        workhours_layout.addWidget(QLabel("From:"))
        workhours_layout.addWidget(self.workhours_start)
        
        self.workhours_end = QTimeEdit()
        self.workhours_end.setTime(QTime(18, 0))
        self.workhours_end.setEnabled(False)
        
        workhours_layout.addWidget(QLabel("To:"))
        workhours_layout.addWidget(self.workhours_end)
        workhours_layout.addStretch()
        
        self.workhours_widget.setLayout(workhours_layout)
        self.workhours_check.toggled.connect(self.workhours_start.setEnabled)
        self.workhours_check.toggled.connect(self.workhours_end.setEnabled)
        advanced_layout.addRow(self.workhours_check, self.workhours_widget)
        
        advanced_group.setLayout(advanced_layout)
        
        layout.addLayout(form_layout)
        layout.addWidget(advanced_group)
        layout.addStretch()
        self.safety_tab.setLayout(layout)

    def on_listener_changed(self, listener_name):
        """Handle listener selection changes"""
        # Check if this is an SMB listener
        is_smb_listener = False
        
        if self.agent_tree:
            # Get listener data to check protocol
            listeners = self.agent_tree.listener_data
            for listener in listeners:
                if listener.get('name') == listener_name:
                    is_smb_listener = (listener.get('protocol') == 'SMB')
                    break
        
        # Show connection type only for SMB listeners
        if is_smb_listener:
            self.connection_type_label.setVisible(True)
            self.connection_type.setVisible(True)
            self.connection_type.setCurrentText("SMB")  # Default to SMB
        else:
            self.connection_type_label.setVisible(False)
            self.connection_type.setVisible(False)
            self.connection_type.setCurrentText("Direct")  # Reset to Direct

    def populate_listeners(self):
        if self.agent_tree:
            listeners = self.agent_tree.get_listener_names()
            self.listener.clear()
            self.listener.addItems(listeners)

    def browse_output_path(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if directory:
            self.output_path.setText(directory)

    def handle_ok(self):
        if not self.ws_thread or not self.ws_thread.is_connected():
            return
        
        if not self.output_path.text():
            QMessageBox.warning(self, "Error", "Please select an output path")
            return
        
        # Build safety checks configuration
        safety_checks = {}
        
        if self.hostname_check.isChecked() and self.hostname_input.text():
            safety_checks["hostname"] = self.hostname_input.text()
        
        if self.username_check.isChecked() and self.username_input.text():
            safety_checks["username"] = self.username_input.text()
        
        if self.domain_check.isChecked() and self.domain_input.text():
            safety_checks["domain"] = self.domain_input.text()
        
        if self.file_check.isChecked() and self.file_path_input.text():
            safety_checks["file_check"] = {
                "path": self.file_path_input.text(),
                "must_exist": self.file_check_mode.currentText() == "File Must Exist"
            }
        
        if self.process_check.isChecked() and self.process_input.text():
            safety_checks["process"] = self.process_input.text()
        
        if self.killdate_check.isChecked():
            safety_checks["kill_date"] = self.killdate_input.dateTime().toString("yyyy-MM-dd HH:mm:ss")
        
        if self.workhours_check.isChecked():
            safety_checks["working_hours"] = {
                "start": self.workhours_start.time().toString("HH:mm"),
                "end": self.workhours_end.time().toString("HH:mm")
            }
        
        # Build payload data
        payload_data = {
            "type": "create_payload",
            "data": {
                "listener": self.listener.currentText(),
                "language": self.language.currentText().lower(),
                "os": self.os.currentText().lower(),
                "arch": self.arch.currentText(),
                "output_path": self.output_path.text(),
                "safety_checks": safety_checks
            }
        }
        
        # Only add connection_type if it's visible and set to SMB
        if self.connection_type.isVisible() and self.connection_type.currentText() == "SMB":
            payload_data["data"]["connection_type"] = "smb"
        
        message = json.dumps(payload_data)
        print(f"CreatePayloadDialog: Sending payload creation message")
        if payload_data["data"].get("connection_type") == "smb":
            print(f"CreatePayloadDialog: Creating SMB beacon for listener: {self.listener.currentText()}")
        
        # Send the message
        asyncio.run_coroutine_threadsafe(
            self.ws_thread.ws_client.send_message(message),
            self.ws_thread.loop
        )
        
        # Close dialog immediately - MainWindow will handle chunks
        self.accept()

class SettingsDialog(QDialog):
    """Settings dialog for application preferences"""
    theme_changed = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(350)
        self.setMinimumHeight(150)
        self.settings = self.load_settings()
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Appearance Group
        appearance_group = QGroupBox("Appearance")
        appearance_layout = QFormLayout()
        
        # Theme selection - ADD ALL NEW THEMES HERE
        self.theme_combo = QComboBox()
        self.theme_combo.addItems([
            "Dark",
            "Light",
            "Dracula",
            "Monokai",
            "Nord",
            "Solarized Dark",
            "Gruvbox",
            "One Dark"
        ])
        self.theme_combo.setCurrentText(self.settings.get('theme', 'Dark'))
        appearance_layout.addRow("Theme:", self.theme_combo)
        
        appearance_group.setLayout(appearance_layout)
        layout.addWidget(appearance_group)
        
        # Add stretch to push everything up
        layout.addStretch()
        
        # Buttons
        button_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        
        save_btn.clicked.connect(self.save_settings)
        cancel_btn.clicked.connect(self.reject)
        
        button_layout.addStretch()
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def load_settings(self):
        """Load settings from file"""
        config_file = Path.home() / '.c2_client' / 'settings.json'
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def save_settings(self):
        """Save settings to file"""
        config_file = Path.home() / '.c2_client' / 'settings.json'
        config_file.parent.mkdir(exist_ok=True)
        
        settings = {
            'theme': self.theme_combo.currentText()
        }
        
        with open(config_file, 'w') as f:
            json.dump(settings, f, indent=2)
        
        # Emit theme change signal if theme changed
        if settings['theme'] != self.settings.get('theme', 'Dark'):
            self.theme_changed.emit(settings['theme'])
        
        self.accept()
    
    def get_settings(self):
        """Return current settings"""
        return self.settings


class VersionDialog(QDialog):
    """Version information dialog"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About")
        self.setMinimumWidth(350)
        self.setFixedHeight(200)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        info_layout = QVBoxLayout()
        info_layout.setSpacing(10)
        
        # Get version info from central config
        version_info = get_version_info()
        
        # App name
        app_name = QLabel(version_info["app_name"])
        app_name.setStyleSheet("font-size: 18px; font-weight: bold;")
        app_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_layout.addWidget(app_name)
        
        # Version with optional codename
        version_text = f"Version {version_info['version']}"
        if version_info.get("codename"):
            version_text += f" ({version_info['codename']})"
        
        version_label = QLabel(version_text)
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version_label.setStyleSheet("font-size: 14px;")
        info_layout.addWidget(version_label)
        
        # Build date
        build_date = QLabel(f"Build: {version_info['build_date']}")
        build_date.setAlignment(Qt.AlignmentFlag.AlignCenter)
        build_date.setStyleSheet("font-size: 10px; color: gray;")
        info_layout.addWidget(build_date)
        
        # Description
        description = QLabel(version_info["description"])
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description.setStyleSheet("font-size: 11px; color: gray;")
        info_layout.addWidget(description)
        
        layout.addLayout(info_layout)
        layout.addStretch()
        
        # Close button
        button_layout = QHBoxLayout()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addStretch()
        button_layout.addWidget(close_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        self.setLayout(layout)