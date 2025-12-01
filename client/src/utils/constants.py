"""
Client configuration constants.
Centralized location for all magic numbers and configuration values.
"""

# WebSocket Configuration
WEBSOCKET_MAX_SIZE = 10 * 1024 * 1024  # 10 MB
WEBSOCKET_READ_LIMIT = 10 * 1024 * 1024  # 10 MB
WEBSOCKET_WRITE_LIMIT = 10 * 1024 * 1024  # 10 MB
WEBSOCKET_MAX_QUEUE = 100
WEBSOCKET_SEND_TIMEOUT = 30  # seconds
WEBSOCKET_DISCONNECT_TIMEOUT = 2.0  # seconds

# Message Queue Configuration
MESSAGE_QUEUE_MAX_SIZE = 40  # messages
MESSAGE_BATCH_SIZE = 10  # messages per batch
MESSAGE_BATCH_TIMEOUT = 0.05  # 50ms
MESSAGE_QUEUE_BACKOFF_DELAY = 0.5  # seconds

# Retry Configuration
MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 1  # second
MAX_RETRY_DELAY = 10  # seconds

# Agent Tree Configuration
AGENT_TREE_UPDATE_INTERVAL = 1000  # milliseconds (1 second)

# Terminal Configuration
TERMINAL_MAX_MESSAGE_DISPLAY_LENGTH = 10000  # characters

# Logging Configuration
LOG_ROTATION_SIZE = 100 * 1024 * 1024  # 100 MB

# High Priority Message Types
HIGH_PRIORITY_MESSAGE_TYPES = {'agent_command', 'bof', 'inline-assembly'}
