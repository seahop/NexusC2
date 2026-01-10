# client/src/gui/widgets/terminal/command_buffer.py
from datetime import datetime, timezone
from collections import deque
import threading

class CommandBuffer:
    def __init__(self, max_size=1000):  # Increased buffer size
        self.max_size = max_size
        self.received_outputs = deque(maxlen=max_size)  # Use deque for efficiency
        self.username = None
        self._lock = threading.Lock()  # Thread safety for concurrent updates
        
        # Track chunked transfers
        self.chunk_progress = {}  # command_id -> progress info
        
    def set_username(self, username):
        self.username = username
    
    def add_output(self, output_data):
        """Add output with thread safety"""
        with self._lock:
            # Check if this is a chunk progress update
            if self._is_chunk_progress(output_data):
                self._update_chunk_progress(output_data)
            else:
                self.received_outputs.append(output_data)
    
    def _is_chunk_progress(self, output_data):
        """Check if this is a chunk progress message"""
        output_text = output_data.get('output', '')
        return any(marker in output_text for marker in [
            'Chunk', 'chunk', 'BOF Transfer:', 'assembled', 
            'Received chunk', 'Server acknowledged'
        ])
    
    def _update_chunk_progress(self, output_data):
        """Update chunk progress tracking"""
        output_text = output_data.get('output', '')
        
        # Extract progress information if available
        if 'BOF Transfer:' in output_text:
            # Parse progress from message like "BOF Transfer: file.o - 5/10 (50.0%)"
            try:
                parts = output_text.split(' - ')
                if len(parts) > 1:
                    filename = parts[0].split(': ')[1]
                    progress_part = parts[1]
                    # Store progress info
                    self.chunk_progress[filename] = {
                        'message': output_text,
                        'timestamp': output_data.get('timestamp', datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
                    }
            except:
                pass
        
        # Always add to output buffer for display
        self.received_outputs.append(output_data)
    
    def get_display_content(self):
        """Get formatted display content with efficient string building"""
        with self._lock:
            if not self.received_outputs:
                return ""
            
            # Use list comprehension and join for efficiency
            lines = []
            for output in self.received_outputs:
                output_text = output.get('output', '')
                # Skip empty outputs
                if output_text:
                    lines.append(output_text)
            
            return "\n".join(lines)
    
    def get_recent_outputs(self, count=50):
        """Get the most recent outputs"""
        with self._lock:
            # Get last 'count' items efficiently
            recent = list(self.received_outputs)[-count:]
            return "\n".join([output.get('output', '') for output in recent if output.get('output')])
    
    def clear(self):
        """Clear the buffer"""
        with self._lock:
            self.received_outputs.clear()
            self.chunk_progress.clear()
    
    def get_chunk_status(self):
        """Get current chunk transfer status"""
        with self._lock:
            return self.chunk_progress.copy()
    
    def format_timestamp(self, timestamp):
        """Format timestamp for display"""
        try:
            if isinstance(timestamp, str):
                # Handle ISO format timestamps
                if 'T' in timestamp:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            else:
                dt = timestamp
            
            return dt.strftime('%H:%M:%S')
        except Exception as e:
            # Return original if parsing fails
            return str(timestamp)
    
    def add_command(self, command_text, username=None):
        """Add a command to the buffer"""
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        user = username or self.username or "user"
        
        output_data = {
            'timestamp': timestamp,
            'output': f"[{self.format_timestamp(timestamp)}] {user} > {command_text}",
            'type': 'command'
        }
        
        with self._lock:
            self.received_outputs.append(output_data)
    
    def add_chunk_notification(self, filename, current, total, status="sending"):
        """Add a chunk notification to the buffer"""
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        progress = (current / total * 100) if total > 0 else 0
        
        message = f"[{self.format_timestamp(timestamp)}] Chunk {status}: {filename} - {current}/{total} ({progress:.1f}%)"
        
        output_data = {
            'timestamp': timestamp,
            'output': message,
            'type': 'chunk_progress'
        }
        
        with self._lock:
            # Update progress tracking
            self.chunk_progress[filename] = {
                'current': current,
                'total': total,
                'progress': progress,
                'status': status,
                'timestamp': timestamp
            }
            
            # Add to output
            self.received_outputs.append(output_data)
    
    def remove_chunk_tracking(self, filename):
        """Remove chunk tracking for a completed transfer"""
        with self._lock:
            if filename in self.chunk_progress:
                del self.chunk_progress[filename]
    
    def get_buffer_stats(self):
        """Get statistics about the buffer"""
        with self._lock:
            return {
                'total_outputs': len(self.received_outputs),
                'max_size': self.max_size,
                'usage_percent': (len(self.received_outputs) / self.max_size * 100) if self.max_size > 0 else 0,
                'active_chunks': len(self.chunk_progress),
                'oldest_output': self.received_outputs[0].get('timestamp') if self.received_outputs else None,
                'newest_output': self.received_outputs[-1].get('timestamp') if self.received_outputs else None
            }