# websocket_client.py
import asyncio
import ssl
import websockets
import os
import pathlib
import json
from datetime import datetime
from collections import deque
from .database import StateDatabase
from gui.widgets import AgentTreeWidget
from .logger import get_logger
from .constants import (
    WEBSOCKET_MAX_SIZE, WEBSOCKET_READ_LIMIT, WEBSOCKET_WRITE_LIMIT,
    WEBSOCKET_MAX_QUEUE, WEBSOCKET_SEND_TIMEOUT, WEBSOCKET_DISCONNECT_TIMEOUT,
    MESSAGE_QUEUE_MAX_SIZE, MESSAGE_BATCH_SIZE, MESSAGE_BATCH_TIMEOUT,
    MESSAGE_QUEUE_BACKOFF_DELAY, MAX_RETRIES, INITIAL_RETRY_DELAY,
    MAX_RETRY_DELAY, HIGH_PRIORITY_MESSAGE_TYPES
)

logger = get_logger('websocket')

class WebSocketClient:
    def __init__(self):
        self.websocket = None
        self.connected = False
        self.cert_path = os.path.join(pathlib.Path(__file__).parents[2], 'certs', 'ws_server.crt')
        self.message_queue = deque()
        self.send_lock = asyncio.Lock()
        self.running = True
        self.terminal_widget = None
        self.loop = None
        self.agent_tree_widget = None

        # Use constants for configuration
        self.MAX_QUEUE_SIZE = MESSAGE_QUEUE_MAX_SIZE
        self.SEND_TIMEOUT = WEBSOCKET_SEND_TIMEOUT
        self.MAX_RETRIES = MAX_RETRIES
        self.retry_delay = INITIAL_RETRY_DELAY
        self.queue_task = None

        # Track chunked transfers (thread-safe with asyncio.Lock)
        self.active_chunks = {}  # track_id -> chunk_info
        self.chunk_buffers = {}  # For storing incomplete chunks
        self.output_chunks = {}  # session_id -> chunk data for command outputs
        self.chunks_lock = asyncio.Lock()  # Protect chunk dictionaries

        # Message batching configuration
        self.batch_size = MESSAGE_BATCH_SIZE
        self.batch_timeout = MESSAGE_BATCH_TIMEOUT
        self.high_priority_types = HIGH_PRIORITY_MESSAGE_TYPES

    async def connect(self, username, host, port):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.load_verify_locations(self.cert_path)
        ssl_context.check_hostname = False

        uri = f"wss://{host}:{port}"
        try:
            logger.info(f"Attempting to connect to {uri}")
            self.websocket = await websockets.connect(
                uri,
                ssl=ssl_context,
                extra_headers={'Username': username},
                max_size=WEBSOCKET_MAX_SIZE,
                read_limit=WEBSOCKET_READ_LIMIT,
                write_limit=WEBSOCKET_WRITE_LIMIT,
                max_queue=WEBSOCKET_MAX_QUEUE
            )
            self.connected = True
            self.running = True
            logger.info("Connection successful")
            
            # Store the task reference so we can cancel it later
            self.queue_task = asyncio.create_task(self.process_message_queue())
            
        except Exception as e:
            logger.error(f"Connection failed: {str(e)}")
            self.connected = False

    async def disconnect(self):
        """Disconnect cleanly from the server"""
        logger.info("Starting disconnect")
        self.running = False
        self.connected = False  # Mark as disconnected immediately

        # Cancel the queue processing task if it exists
        if self.queue_task and not self.queue_task.done():
            logger.debug("Cancelling queue processing task")
            self.queue_task.cancel()
            try:
                await self.queue_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Error cancelling queue task: {e}")
        
        # Close the websocket connection
        if self.websocket:
            try:
                # Use wait_for to prevent hanging
                await asyncio.wait_for(self.websocket.close(), timeout=WEBSOCKET_DISCONNECT_TIMEOUT)
                logger.info("WebSocket closed successfully")
            except asyncio.TimeoutError:
                logger.warning("WebSocket close timed out")
                # Force close the transport if it's still open
                if self.websocket.transport:
                    self.websocket.transport.close()
            except Exception as e:
                logger.error(f"Error closing websocket: {e}")
        
        # Clear all data (thread-safe)
        async with self.chunks_lock:
            self.active_chunks.clear()
            self.chunk_buffers.clear()
            self.output_chunks.clear()
        self.websocket = None

        logger.info("Disconnected from server")

    async def _handle_message_sent(self, message):
        """Handle successful message sending"""
        if self.terminal_widget:
            # Only log non-chunk messages to avoid spam
            try:
                msg_data = json.loads(message)
                if msg_data.get('type') == 'agent_command':
                    data = msg_data.get('data', {})
                    if data.get('totalChunks', 1) > 1:
                        chunk_num = data.get('currentChunk', 0)
                        total = data.get('totalChunks', 1)
                        filename = data.get('filename', 'unknown')
                        self.terminal_widget.log_message(
                            f"Chunk {chunk_num + 1}/{total} sent for {filename}"
                        )
                    else:
                        self.terminal_widget.log_message(f"Command sent successfully")
                else:
                    self.terminal_widget.log_message(f"Message sent successfully")
            except:
                pass
        self.retry_delay = 1  # Reset retry delay after successful send
        
    async def _handle_send_timeout(self):
        """Handle timeout when sending message"""
        if self.terminal_widget:
            self.terminal_widget.log_message("Message send timeout, will retry")
        self.retry_delay = min(self.retry_delay * 2, MAX_RETRY_DELAY)  # Exponential backoff
        await asyncio.sleep(self.retry_delay)
        
    async def _handle_send_error(self, error):
        """Handle general send errors"""
        if self.terminal_widget:
            self.terminal_widget.log_message(f"Error sending message: {str(error)}")
        self.retry_delay = min(self.retry_delay * 2, MAX_RETRY_DELAY)  # Exponential backoff
        await asyncio.sleep(self.retry_delay)
        
    async def _handle_queue_error(self, error):
        """Handle queue processing errors"""
        if self.terminal_widget:
            self.terminal_widget.log_message(f"Queue processing error: {str(error)}")
        logger.debug(f"Queue processing error: {error}")
        await asyncio.sleep(self.retry_delay)
        
    def connect_sync(self, username, host, port):
        logger.debug("Starting synchronous connection attempt...")
        self.loop = asyncio.get_event_loop()
        try:
            asyncio.run_coroutine_threadsafe(self.connect(username, host, port), self.loop).result()
            logger.debug("Completed synchronous connection attempt")
        except Exception as e:
            logger.debug(f"Synchronous connection failed: {str(e)}")

    def queue_message(self, message):
        """Queue a message for sending"""
        self.message_queue.append(message)
        
        # Check if this is a chunked message
        try:
            msg_data = json.loads(message)
            if msg_data.get('type') == 'agent_command':
                data = msg_data.get('data', {})
                if data.get('totalChunks', 1) > 1:
                    chunk_num = data.get('currentChunk', 0)
                    total = data.get('totalChunks', 1)
                    if self.terminal_widget:
                        self.terminal_widget.log_message(
                            f"Chunk {chunk_num + 1}/{total} queued. Queue size: {len(self.message_queue)}"
                        )
                else:
                    if self.terminal_widget:
                        self.terminal_widget.log_message(f"Message queued. Queue size: {len(self.message_queue)}")
        except:
            if self.terminal_widget:
                self.terminal_widget.log_message(f"Message queued. Queue size: {len(self.message_queue)}")
        
        logger.debug(f"Message queued. Queue size: {len(self.message_queue)}")

    async def process_message_queue(self):
        """Process queued messages with batching and prioritization."""
        batch = []
        last_send_time = asyncio.get_event_loop().time()

        while self.running and self.connected:
            try:
                # Add backpressure handling with message dropping
                if len(self.message_queue) > self.MAX_QUEUE_SIZE:
                    # Drop oldest low-priority messages to prevent memory exhaustion
                    dropped_count = 0
                    while len(self.message_queue) > self.MAX_QUEUE_SIZE:
                        if self.message_queue:
                            dropped_msg = self.message_queue.popleft()
                            # Try to determine if it's low priority
                            try:
                                msg_data = json.loads(dropped_msg)
                                if msg_data.get('type') not in self.high_priority_types:
                                    dropped_count += 1
                                else:
                                    # Put high-priority back at front
                                    self.message_queue.appendleft(dropped_msg)
                                    break
                            except:
                                dropped_count += 1

                    if dropped_count > 0 and self.terminal_widget:
                        self.terminal_widget.log_message(
                            f"Warning: Dropped {dropped_count} messages due to queue overflow"
                        )
                    await asyncio.sleep(MESSAGE_QUEUE_BACKOFF_DELAY)  # Back off when queue is full
                    continue

                current_time = asyncio.get_event_loop().time()
                time_since_last_send = current_time - last_send_time

                if len(self.message_queue) > 0:
                    message = self.message_queue.popleft()

                    # Check if this is a high-priority message (skip batching)
                    try:
                        msg_data = json.loads(message)
                        msg_type = msg_data.get('type', '')
                        is_high_priority = msg_type in self.high_priority_types
                    except:
                        is_high_priority = False

                    if is_high_priority:
                        # Send immediately without batching
                        async with self.send_lock:
                            if self.websocket and self.connected:
                                try:
                                    await asyncio.wait_for(
                                        self.websocket.send(message),
                                        timeout=self.SEND_TIMEOUT
                                    )
                                    await self._handle_message_sent(message)
                                    last_send_time = asyncio.get_event_loop().time()
                                except asyncio.TimeoutError:
                                    self.message_queue.appendleft(message)
                                    await self._handle_send_timeout()
                                except Exception as e:
                                    self.message_queue.appendleft(message)
                                    await self._handle_send_error(e)
                    else:
                        # Add to batch
                        batch.append(message)

                        # Send batch if full or timeout reached
                        should_send = (
                            len(batch) >= self.batch_size or
                            time_since_last_send >= self.batch_timeout
                        )

                        if should_send and batch:
                            await self._send_batch(batch)
                            batch.clear()
                            last_send_time = asyncio.get_event_loop().time()

                # Send pending batch if timeout reached
                elif batch and time_since_last_send >= self.batch_timeout:
                    await self._send_batch(batch)
                    batch.clear()
                    last_send_time = asyncio.get_event_loop().time()

                # Adaptive sleep
                sleep_time = 0.01 if batch else min(0.1 * (1 + len(self.message_queue) / 100), 1.0)
                await asyncio.sleep(sleep_time)

            except Exception as e:
                await self._handle_queue_error(e)
                await asyncio.sleep(1)

    async def _send_batch(self, batch):
        """Send a batch of messages together."""
        if not batch:
            return

        async with self.send_lock:
            if self.websocket and self.connected:
                for message in batch:
                    try:
                        await asyncio.wait_for(
                            self.websocket.send(message),
                            timeout=self.SEND_TIMEOUT
                        )
                        await self._handle_message_sent(message)
                    except asyncio.TimeoutError:
                        self.message_queue.appendleft(message)
                        await self._handle_send_timeout()
                    except Exception as e:
                        self.message_queue.appendleft(message)
                        await self._handle_send_error(e)

    async def send_message(self, message):
        """Public method to send messages - adds to queue instead of sending directly."""
        if self.connected:
            self.queue_message(message)
            return True
        return False

    async def receive_messages(self):
        """Receive and process messages with chunk progress handling"""
        try:
            while self.running and self.connected:
                if self.websocket is None:
                    break
                message = await self.websocket.recv()
                
                # Try to parse the message first
                try:
                    message_data = json.loads(message)
                    message_type = message_data.get('type')
                    
                    # Handle different message types
                    if message_type == 'chunk_progress':
                        self._handle_chunk_progress(message_data)
                    elif message_type == 'chunk_received':
                        self._handle_chunk_received(message_data)
                    elif message_type == 'command_assembled':
                        self._handle_command_assembled(message_data)
                    # NEW: Handle command output chunks
                    elif message_type == 'command_output_chunk_start':
                        self._handle_command_output_chunk_start(message_data)
                        return None  # Don't return yet, still assembling
                    elif message_type == 'command_output_chunk':
                        self._handle_command_output_chunk(message_data)
                        return None  # Don't return yet, still assembling
                    elif message_type == "agent_renamed":
                        print("WebSocketClient: Handling agent rename broadcast.")
                        rename_data = message_data.get("data", {})

                        if self.agent_tree_widget:
                            self.agent_tree_widget.handle_agent_renamed(rename_data)
                        else:
                            print("WebSocketClient: No agent_tree_widget linked.")

                        if self.terminal_widget:
                            self.terminal_widget.handle_agent_renamed(rename_data)
                        else:
                            print("WebSocketClient: No terminal_widget linked.")
                    elif message_type == 'command_output_chunk_complete':
                        return self._handle_command_output_chunk_complete(message_data)
                    elif message_type == 'binary_chunk':
                        # Handle binary chunks silently
                        chunk_num = message_data.get('chunk_num')
                        total_chunks = message_data.get('total_chunks')
                        file_name = message_data.get('file_name')
                        logger.debug(f"Received binary chunk {chunk_num}/{total_chunks} for {file_name}")
                    else:
                        # Log other message types
                        if self.terminal_widget:
                            # Don't log huge messages
                            if len(message) < 10000:
                                self.terminal_widget.log_message(f"Received: {message}")
                            else:
                                self.terminal_widget.log_message(f"Received large message: {message_type}")
                    
                    # IMPORTANT: Just return the message data for WebSocketThread to handle
                    # INCLUDING command_queued messages
                    return message_data
                    
                except json.JSONDecodeError as e:
                    logger.debug(f"Failed to decode message as JSON: {e}")
                    if self.terminal_widget:
                        self.terminal_widget.log_message(f"Failed to decode message as JSON: {message[:100]}...")
                        
        except Exception as e:
            self.connected = False
            # Clear chunking state on connection errors (async-safe)
            async with self.chunks_lock:
                self.active_chunks.clear()
                self.chunk_buffers.clear()
                self.output_chunks.clear()
            return {"type": "error", "message": f"Error receiving message: {str(e)}"}

    async def _handle_chunk_progress(self, message_data):
        """Handle chunk progress updates from server (thread-safe)"""
        data = message_data.get('data', {})
        agent_id = data.get('agent_id')
        command_id = data.get('command_id')
        filename = data.get('filename')
        current_chunk = data.get('current_chunk')
        total_chunks = data.get('total_chunks')
        progress = data.get('progress', 0)

        # Update tracking (thread-safe)
        track_id = f"{agent_id}_{command_id}"
        async with self.chunks_lock:
            self.active_chunks[track_id] = {
                'filename': filename,
                'current': current_chunk,
                'total': total_chunks,
                'progress': progress
            }

        # Log progress
        if self.terminal_widget:
            self.terminal_widget.log_message(
                f"BOF Transfer: {filename} - {current_chunk}/{total_chunks} ({progress:.1f}%)"
            )

        logger.debug(f"Chunk progress - {filename}: {current_chunk}/{total_chunks} ({progress:.1f}%)")

    def _handle_chunk_received(self, message_data):
        """Handle chunk received acknowledgment from server"""
        data = message_data.get('data', {})
        current_chunk = data.get('current_chunk')
        total_chunks = data.get('total_chunks')
        filename = data.get('filename')
        
        if self.terminal_widget:
            self.terminal_widget.log_message(
                f"Server acknowledged chunk {current_chunk}/{total_chunks} for {filename}"
            )

    async def _handle_command_assembled(self, message_data):
        """Handle command assembled notification from server (thread-safe)"""
        data = message_data.get('data', {})
        command_id = data.get('command_id')
        agent_id = data.get('agent_id')
        filename = data.get('filename')
        total_chunks = data.get('total_chunks')
        duration = data.get('duration', 0)

        # Remove from tracking (thread-safe)
        track_id = f"{agent_id}_{command_id}"
        async with self.chunks_lock:
            if track_id in self.active_chunks:
                del self.active_chunks[track_id]

        if self.terminal_widget:
            self.terminal_widget.log_message(
                f"✓ {filename} assembled ({total_chunks} chunks in {duration:.2f}s) and sent to agent"
            )

        logger.debug(f"Command assembled - {filename} ({total_chunks} chunks in {duration:.2f}s)")

    # NEW METHODS FOR COMMAND OUTPUT CHUNKING:
    async def _handle_command_output_chunk_start(self, message_data):
        """Handle the start of a chunked command output (thread-safe)"""
        data = message_data.get('data', {})
        session_id = data.get('session_id')
        agent_id = data.get('agent_id')
        command_id = data.get('command_id')
        total_chunks = data.get('total_chunks')
        total_size = data.get('total_size')
        timestamp = data.get('timestamp')
        status = data.get('status')

        # Initialize tracking for this session (thread-safe)
        async with self.chunks_lock:
            self.output_chunks[session_id] = {
                'agent_id': agent_id,
                'command_id': command_id,
                'total_chunks': total_chunks,
                'total_size': total_size,
                'timestamp': timestamp,
                'status': status,
                'chunks': {},
                'start_time': datetime.now()
            }

        if self.terminal_widget:
            self.terminal_widget.log_message(
                f"Receiving large command output: {total_chunks} chunks, {total_size} bytes"
            )

        logger.debug(f"Started receiving chunked output session {session_id}")

    async def _handle_command_output_chunk(self, message_data):
        """Handle individual chunks of command output (thread-safe)"""
        data = message_data.get('data', {})
        session_id = data.get('session_id')
        chunk_number = data.get('chunk_number')
        chunk_data = data.get('chunk_data')
        total_chunks = data.get('total_chunks')

        async with self.chunks_lock:
            if session_id not in self.output_chunks:
                logger.debug(f"Unknown session {session_id}")
                return

            # Store the chunk
            self.output_chunks[session_id]['chunks'][chunk_number] = chunk_data

            # Calculate and display progress
            received = len(self.output_chunks[session_id]['chunks'])
            progress = (received / total_chunks * 100) if total_chunks > 0 else 0

        # Log progress every 10 chunks or at the end
        if chunk_number % 10 == 0 or chunk_number == total_chunks - 1:
            if self.terminal_widget:
                self.terminal_widget.log_message(
                    f"Output progress: {received}/{total_chunks} chunks ({progress:.1f}%)"
                )

        logger.debug(f"Chunk {chunk_number + 1}/{total_chunks} received for session {session_id}")

    async def _handle_command_output_chunk_complete(self, message_data):
        """Reassemble and return the complete command output (thread-safe)"""
        data = message_data.get('data', {})
        session_id = data.get('session_id')

        async with self.chunks_lock:
            if session_id not in self.output_chunks:
                logger.debug(f"Unknown session {session_id} at completion")
                return None

            session = self.output_chunks[session_id]
            chunks = session['chunks']
            total_chunks = session['total_chunks']

            # Verify we have all chunks
            missing_chunks = []
            for i in range(total_chunks):
                if i not in chunks:
                    missing_chunks.append(i)

            if missing_chunks:
                logger.debug(f"Missing {len(missing_chunks)} chunks for session {session_id}")
                logger.debug(f"Missing chunk numbers: {missing_chunks[:10]}...")
                if self.terminal_widget:
                    self.terminal_widget.log_message(
                        f"Warning: Missing {len(missing_chunks)} chunks in output"
                    )

            # Reassemble the output
            output_parts = []
            for i in range(total_chunks):
                if i in chunks:
                    output_parts.append(chunks[i])
                else:
                    output_parts.append(f"[MISSING CHUNK {i}]")

            complete_output = ''.join(output_parts)

            # Calculate duration
            duration = (datetime.now() - session['start_time']).total_seconds()

            if self.terminal_widget:
                self.terminal_widget.log_message(
                    f"✓ Command output assembled: {total_chunks} chunks in {duration:.2f}s"
                )

            # Create the final command_result message
            final_message = {
                'type': 'command_result',
                'data': {
                    'output': complete_output,
                    'agent_id': session['agent_id'],
                    'command_id': session['command_id'],
                    'timestamp': session['timestamp'],
                    'status': session['status']
                }
            }

            # Clean up session data
            del self.output_chunks[session_id]

        logger.debug(f"Successfully reassembled output for session {session_id}")

        return final_message

    def set_terminal_widget(self, widget):
        self.terminal_widget = widget

    def disconnect_sync(self):
        if self.connected:
            try:
                future = asyncio.run_coroutine_threadsafe(self.disconnect(), self.loop)
                future.result()
            except Exception as e:
                if self.terminal_widget:
                    self.terminal_widget.log_message(f"Error during synchronous disconnection: {e}")
                logger.debug(f"Error during synchronous disconnection: {e}")

    def receive_messages_sync(self):
        """Synchronously processes incoming messages."""
        try:
            future = asyncio.run_coroutine_threadsafe(self.receive_async(), self.loop)
            future.result()
        except Exception as e:
            if self.terminal_widget:
                self.terminal_widget.log_message(f"Error during synchronous message receiving: {e}")
            logger.debug(f"Error during synchronous message receiving: {e}")

    async def receive_async(self):
        while self.connected:
            try:
                message = await self.websocket.recv()
                
                # Parse and handle message
                try:
                    message_data = json.loads(message)
                    message_type = message_data.get('type')
                    
                    # Handle chunk-related messages
                    if message_type in ['chunk_progress', 'chunk_received', 'command_assembled']:
                        # These are handled in receive_messages
                        pass
                    elif message_type in ['command_output_chunk_start', 'command_output_chunk', 'command_output_chunk_complete']:
                        # These are handled in receive_messages
                        pass
                    elif self.terminal_widget:
                        # Log other messages
                        if len(message) < 10000:
                            self.terminal_widget.log_message(f"Received: {message}")
                        else:
                            self.terminal_widget.log_message(f"Received large {message_type} message")
                            
                except json.JSONDecodeError:
                    if self.terminal_widget:
                        self.terminal_widget.log_message(f"Received non-JSON message")
                        
            except websockets.exceptions.ConnectionClosed:
                self.connected = False
                # Clear chunking state on connection close (thread-safe)
                async with self.chunks_lock:
                    self.active_chunks.clear()
                    self.chunk_buffers.clear()
                    self.output_chunks.clear()
                if self.terminal_widget:
                    self.terminal_widget.log_message("Connection closed by server.")
                break
            except Exception as e:
                self.connected = False
                # Clear chunking state on error (thread-safe)
                async with self.chunks_lock:
                    self.active_chunks.clear()
                    self.chunk_buffers.clear()
                    self.output_chunks.clear()
                if self.terminal_widget:
                    self.terminal_widget.log_message(f"Error receiving message: {e}")
                break
    
    async def handle_messages(self):
        """Main message handler with chunk support"""
        while self.running and self.connected:
            try:
                message = await self.websocket.recv()
                message_data = json.loads(message)

                # Log the received message (except for chunks)
                message_type = message_data.get("type")
                
                # Skip logging for chunk-related messages
                if message_type not in ['chunk_progress', 'chunk_received', 'binary_chunk', 
                                       'command_output_chunk_start', 'command_output_chunk', 
                                       'command_output_chunk_complete', 'command_queued']:
                    logger.debug(f"Received message: {json.dumps(message_data, indent=4)[:500]}...")

                if message_type == 'initial_state':
                    logger.debug("Processing initial state")
                    state_data = message_data.get("data", {})
                    
                    # DEBUG: Log what we received
                    logger.debug(f"Initial state has {len(state_data.get('connections', []))} connections")
                    logger.debug(f"Initial state has {len(state_data.get('listeners', []))} listeners")
                    
                    # DEBUG: Check for aliases in connections
                    for conn in state_data.get('connections', []):
                        logger.debug(f"Connection {conn.get('newclient_id')[:8]}... has alias: {conn.get('alias', 'NONE')}")
                    
                    if self.db.store_state(state_data):
                        logger.debug("Successfully stored initial state data")
                        self.db.verify_database_state()
                        self.state_received.emit()

                elif message_type == "agent_renamed":
                    print("WebSocketClient: Handling agent rename broadcast.")
                    rename_data = message_data.get("data", {})

                    if self.agent_tree_widget:
                        self.agent_tree_widget.handle_agent_renamed(rename_data)
                    else:
                        print("WebSocketClient: No agent_tree_widget linked.")

                    if self.terminal_widget:
                        self.terminal_widget.handle_agent_renamed(rename_data)
                    else:
                        print("WebSocketClient: No terminal_widget linked.")

                elif message_type == "new_connection":
                    print("WebSocketClient: Handling new connection.")
                    if self.agent_tree_widget:
                        connection_data = message_data.get("content")
                        # Check if alias is included
                        if connection_data and 'alias' in connection_data:
                            logger.debug(f"New connection includes alias: {connection_data['alias']}")
                        self.agent_tree_widget.handle_new_connection(connection_data)
                    else:
                        print("WebSocketClient: No agent_tree_widget linked.")

                elif message_type == "connection_update":
                    print("WebSocketClient: Handling connection update.")
                    if self.agent_tree_widget:
                        connection_data = message_data.get("data")
                        self.agent_tree_widget.update_existing_connection(connection_data)
                    else:
                        print("WebSocketClient: No agent_tree_widget linked.")
                
                elif message_type in ['chunk_progress', 'chunk_received', 'command_assembled']:
                    # These are handled by specific methods in receive_messages
                    pass
                
                elif message_type == 'command_output_chunk_start':
                    self._handle_command_output_chunk_start(message_data)
                
                elif message_type == 'command_output_chunk':
                    self._handle_command_output_chunk(message_data)
                
                elif message_type == 'command_output_chunk_complete':
                    # Reassemble and process the complete output
                    complete_message = self._handle_command_output_chunk_complete(message_data)
                    if complete_message and self.terminal_widget:
                        # Process as a normal command_result
                        self.terminal_widget.display_command_result(complete_message['data'])
                        
                elif message_type == 'command_result':
                    # Handle regular non-chunked command results
                    if self.terminal_widget:
                        self.terminal_widget.display_command_result(message_data.get('data'))
                        
                else:
                    if message_type not in ['binary_chunk', 'command_queued']:
                        logger.debug(f"Unhandled message type: {message_type}")

            except json.JSONDecodeError as e:
                logger.debug(f"Failed to decode JSON: {e}")
            except websockets.exceptions.ConnectionClosed:
                self.connected = False
                # Clear chunking state on connection close (thread-safe)
                async with self.chunks_lock:
                    self.active_chunks.clear()
                    self.chunk_buffers.clear()
                    self.output_chunks.clear()
                logger.debug("Connection closed by server.")
                break
            except Exception as e:
                # Clear chunking state on error (thread-safe)
                async with self.chunks_lock:
                    self.active_chunks.clear()
                    self.chunk_buffers.clear()
                    self.output_chunks.clear()
                logger.debug(f"Error in handle_messages: {e}")
                break

    def process_connection_update(self, connection_data, update=False):
        """Process new or updated connection data."""
        action = "Updating" if update else "Adding"
        logger.debug(f"{action} connection data: {json.dumps(connection_data, indent=4)}")

        # Check if AgentTreeWidget is linked
        if not self.agent_tree_widget:
            logger.debug("No agent_tree_widget linked!")
            return

        # Process the connection
        if update:
            self.agent_tree_widget.update_existing_connection(connection_data)
        else:
            self.agent_tree_widget.handle_new_connection(connection_data)
    
    def get_active_chunks(self):
        """Get information about active chunk transfers

        Note: This is a synchronous method that accesses shared state.
        For thread-safe access, consider using an async version with chunks_lock.
        """
        # TODO: Make async if this causes race conditions in practice
        return self.active_chunks.copy()