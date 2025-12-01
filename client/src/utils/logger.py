"""
Centralized logging configuration for the C2 client.
"""
import logging
import sys
from pathlib import Path

# Create logger
logger = logging.getLogger('c2_client')
logger.setLevel(logging.DEBUG)

# Create console handler with formatting
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)  # Only INFO and above to console by default

# Create formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
console_handler.setFormatter(formatter)

# Add handler to logger
logger.addHandler(console_handler)

# Optional: Add file handler for debug logs
try:
    log_dir = Path.home() / '.c2_client' / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(log_dir / 'client.log')
    file_handler.setLevel(logging.DEBUG)  # All levels to file
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
except Exception as e:
    logger.warning(f"Could not create log file: {e}")

def set_log_level(level):
    """Set the logging level dynamically"""
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(level)
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
            handler.setLevel(level)

def get_logger(name=None):
    """Get a logger instance"""
    if name:
        return logging.getLogger(f'c2_client.{name}')
    return logger
